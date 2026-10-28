"""Compile-time placement of framework operations on the HostRouter path."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from types import FunctionType
from typing import Any, Protocol, cast, runtime_checkable

from langchain_core.runnables import Runnable, RunnableConfig
from langgraph.pregel._io import _OutputEnvelope
from langgraph.types import Command, Send

from langgraph.prebuilt.security.admission import (
    DESCRIPTOR_CHANGED,
    UNSUPPORTED_ASYNC,
    AdmittedDescriptor,
    _CapturedApplication,
    _CapturedBranch,
    _CapturedModel,
    _CapturedToolNode,
    _CapturedTrustedBranch,
    recheck,
)
from langgraph.prebuilt.security.binding import next_call_index, principal_from
from langgraph.prebuilt.security.host_router import HostRouter
from langgraph.prebuilt.security.object_manager import ObjectManagerHost
from langgraph.prebuilt.security.objects import (
    DispatchKind,
    DispatchRequest,
    LabeledValue,
    ModelInvocationRequest,
    ObjectAuthorization,
    OutputRequest,
    SecurityLabels,
    StateOperation,
    StateRequest,
)
from langgraph.prebuilt.security.stack import coerce_approval
from langgraph.prebuilt.security.types import Principal


class OutputApprovalRequired(PermissionError):
    """Withhold one output until its bound approval is consumed.

    The exception exposes only the redacted escalation payload. Calling
    `resume()` or `aresume()` runs `resume_permission` and the complete output
    hook chain again; the content is returned only after that chain allows it.
    """

    def __init__(
        self,
        payload: Mapping[str, Any],
        resume: Callable[[Any], Any],
        aresume: Callable[[Any], Awaitable[Any]],
    ) -> None:
        super().__init__("output:approval_required")
        self.payload = dict(payload)
        self._resume = resume
        self._aresume = aresume

    def resume(self, response: Any) -> Any:
        """Consume a human response and release the authorized output."""
        return self._resume(response)

    async def aresume(self, response: Any) -> Any:
        """Asynchronously consume a response and release authorized output."""
        return await self._aresume(response)


class NodeTrust(str, Enum):
    """Legacy operator classification assigned to a graph node at compile time.

    `TRUSTED` permits coordinator Python execution. It does not mean the node
    passed language-sandbox admission or has a proof of mediated effects.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class NodeKind(str, Enum):
    """Placement role used to select the refusing router operation."""

    STANDARD = "standard"
    MODEL = "model"
    SUBGRAPH = "subgraph"
    SUBAGENT = "subagent"
    NESTED_AGENT = "nested_agent"


@runtime_checkable
class UntrustedNodeHost(Protocol):
    """Separate-process host for an untrusted node unit of work.

    Implementations own the authenticated framework-object channel. The worker
    receives serialized input and the principal ID, never `RunnableConfig`, the
    coordinator's router, grants, modules, or audit sink.
    """

    def invoke(self, node_name: str, value: Any, principal_id: str) -> Any: ...

    async def ainvoke(self, node_name: str, value: Any, principal_id: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class PlacementSpec:
    """Resolved trust and object role for one graph node."""

    name: str
    trust: NodeTrust
    kind: NodeKind
    promoted: bool = False
    promotion_reason: str = ""


class MediatedNode(Runnable[Any, Any]):
    """Route dispatch, model context, and state writes around one graph node.

    With a captured `descriptor` (set by `configure_graph` under
    `closed_admission=True`) the wrapper dispatches only the admitted
    implementation: see `_invoke_admitted` for the exact invariants. Without a
    descriptor the legacy path is unchanged.
    """

    def __init__(
        self,
        runnable: Runnable[Any, Any],
        spec: PlacementSpec,
        router: HostRouter,
        *,
        untrusted_host: UntrustedNodeHost | None = None,
        descriptor: AdmittedDescriptor | None = None,
    ) -> None:
        if descriptor is not None:
            _bind_node_descriptor(descriptor, runnable, spec)
        self.runnable = runnable
        self.spec = spec
        self.router = router
        self.untrusted_host = untrusted_host
        self.descriptor = descriptor

    def invoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        if self.descriptor is not None:
            return self._invoke_admitted(input, config, kwargs)
        principal, bound_config = _principal(config)
        self._dispatch(principal, bound_config)
        effective = self._model_input(principal, input, bound_config)
        if self.spec.trust is NodeTrust.UNTRUSTED:
            if self.untrusted_host is None:
                raise PermissionError("placement:untrusted_node_has_no_host")
            result = self.untrusted_host.invoke(
                self.spec.name, effective, principal.user_id
            )
        else:
            result = self.runnable.invoke(effective, bound_config, **kwargs)
        return self._state_writes(principal, result)

    async def ainvoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        if self.descriptor is not None:
            return await self._ainvoke_admitted(input, config, kwargs)
        principal, bound_config = _principal(config)
        await self._adispatch(principal, bound_config)
        effective = await self._amodel_input(principal, input, bound_config)
        if self.spec.trust is NodeTrust.UNTRUSTED:
            if self.untrusted_host is None:
                raise PermissionError("placement:untrusted_node_has_no_host")
            result = await self.untrusted_host.ainvoke(
                self.spec.name, effective, principal.user_id
            )
        else:
            result = await self.runnable.ainvoke(effective, bound_config, **kwargs)
        return await self._astate_writes(principal, result)

    def _invoke_admitted(
        self, input: Any, config: RunnableConfig | None, kwargs: dict[str, Any]
    ) -> Any:
        """Dispatch only the captured implementation of this wrapper's descriptor.

        A `MODEL_CALL` descriptor routes to `_invoke_model_call` and a
        `TRUSTED_APPLICATION` descriptor to `_invoke_application` right after
        the shared checks of step 2; every other admitted node is a `ToolNode`.

        Invariants, in order and all before any candidate or router call:

        1. `kwargs` must be empty: override dictionaries are refused.
        2. `self.descriptor` is an exact `AdmittedDescriptor` whose captured
           node is `self.runnable`; `self.spec` is the admitted placement
           (`TRUSTED`/`STANDARD`); `recheck` passes; the node's instance
           dictionary shadows no class-level function. Any drift refuses with
           `admission:descriptor_changed`.
        3. `input` is an exact `dict` with `str` keys or an exact `list`; a
           shallow copy is what the framework primitive receives.
        4. The principal comes only from the native config; the exact
           framework `Runtime` is read from `configurable`.
        5. The existing dispatch mediation (`router.dispatch`) runs as today.
        6. The pinned class function `ToolNode._func` is called with the
           captured node as receiver, the bounded copy, a narrowed config and
           the framework `Runtime`. `self.runnable.invoke`, the mutable
           `func`/`afunc` attributes and any dynamically returned `Runnable`
           are never used.
        7. The result passes through `_state_writes` as today.

        Inputs that still flow, and why: the exact framework `ToolNode` is
        framework code, not candidate code; it receives the narrowed config
        (`configurable`, `metadata`, `tags`, concurrency limits; never
        `callbacks`, `run_name` or `run_id`) because the framework-owned
        principal, call counter and `Runtime` live there and the admitted
        host executor binds each call to them. Candidate tool bodies run only
        inside the admitted host (language sandbox, broker, Docker or Linux
        worker) and receive validated arguments plus the authenticated call;
        admission refuses injected `state`/`store`/`runtime` arguments, so no
        tool body can reach `bound_config`, the `Runtime`, the router, the
        callbacks or any provider object from the coordinator.
        """
        captured = _admitted_node(self, kwargs)
        if type(captured) is _CapturedModel:
            return self._invoke_model_call(captured, input, config)
        if type(captured) is _CapturedApplication:
            return self._invoke_application(captured, input, config)
        data = _bounded_input(input)
        principal, bound_config = _principal(config)
        runtime = _framework_runtime(bound_config)
        narrowed = _narrowed_config(bound_config)
        function, _ = _pinned_tool_node_functions(captured.node)
        self._dispatch(principal, bound_config)
        result = function(captured.node, data, narrowed, runtime)
        return self._state_writes(principal, result)

    async def _ainvoke_admitted(
        self, input: Any, config: RunnableConfig | None, kwargs: dict[str, Any]
    ) -> Any:
        """Asynchronous form of `_invoke_admitted` with one extra invariant.

        Async dispatch is permitted only when the captured executor and
        dispatcher each define their own coroutine `ainvoke` in their exact
        class (the language sandbox's async terminals, the Linux, broker and
        Docker async routes). Otherwise `admission:unsupported_async` is raised
        before any router or candidate call. The pinned `ToolNode._afunc` is
        awaited with the captured node as receiver; `self.runnable.ainvoke` and
        the mutable `afunc` attribute are never used.
        """
        captured = _admitted_node(self, kwargs)
        if type(captured) is _CapturedModel:
            return await self._ainvoke_model_call(captured, input, config)
        if type(captured) is _CapturedApplication:
            return await self._ainvoke_application(captured, input, config)
        _require_async_route(captured)
        data = _bounded_input(input)
        principal, bound_config = _principal(config)
        runtime = _framework_runtime(bound_config)
        narrowed = _narrowed_config(bound_config)
        _, afunction = _pinned_tool_node_functions(captured.node)
        await self._adispatch(principal, bound_config)
        result = await afunction(captured.node, data, narrowed, runtime)
        return await self._astate_writes(principal, result)

    def _invoke_model_call(
        self, captured: _CapturedModel, input: Any, config: RunnableConfig | None
    ) -> Any:
        """Run the model-invocation hook, then the captured model's pinned `invoke`.

        `captured` is the rechecked `MODEL_CALL` implementation returned by
        `_admitted_node`; this wrapper's placement is `TRUSTED`/`MODEL`. Steps,
        in order: bounded copy of the state, native principal, existing
        dispatch mediation, the model hook `_model_input` (each state field is
        a `MODEL_READ` and `router.model_invoke` decides the capability to call
        the model; any non-allow decision raises before the call), then the
        class-level `invoke` resolved at admission is called with the captured
        model as receiver, the effective `messages` and the narrowed config.
        The reply is written back as `{"messages": [reply]}` through
        `_state_writes`. `self.runnable.invoke` is never used. The hook decides
        whether the call happens; it gives no guarantee about reply content.
        """
        data = _bounded_input(input)
        principal, bound_config = _principal(config)
        narrowed = _narrowed_config(bound_config)
        function = captured.call
        self._dispatch(principal, bound_config)
        effective = self._model_input(principal, data, bound_config)
        messages = _model_messages(effective)
        result = function(captured.node, messages, narrowed)
        return self._state_writes(principal, _model_update(result))

    async def _ainvoke_model_call(
        self, captured: _CapturedModel, input: Any, config: RunnableConfig | None
    ) -> Any:
        """Asynchronous form of `_invoke_model_call` with the pinned `ainvoke`."""
        data = _bounded_input(input)
        principal, bound_config = _principal(config)
        narrowed = _narrowed_config(bound_config)
        afunction = captured.acall
        await self._adispatch(principal, bound_config)
        effective = await self._amodel_input(principal, data, bound_config)
        messages = _model_messages(effective)
        result = await afunction(captured.node, messages, narrowed)
        return await self._astate_writes(principal, _model_update(result))

    def _invoke_application(
        self,
        captured: _CapturedApplication,
        input: Any,
        config: RunnableConfig | None,
    ) -> Any:
        """Run a declared trusted application node's captured function.

        This is trust, not containment (D11). `captured` is the rechecked
        `TRUSTED_APPLICATION` implementation returned by `_admitted_node`, so
        the node name, function object and loaded code still match the
        inventory. Steps, in order: native principal, the framework keyword
        injection computed from the plan captured at admission, the existing
        dispatch mediation, then the function pinned at admission is called with
        the graph input as is and the normal config (and `Runtime` fields) it
        declared; it is not narrowed, because the body is trusted code. The
        update passes through `_state_writes`. `self.runnable.invoke`, the
        mutable `func`/`afunc` attributes and any returned `Runnable` are never
        used. An async-only body refuses with `admission:unsupported_async`.
        Tools the body reaches through a `ToolNode` and generated code it hands
        to the compute operation remain contained by their own routes.
        """
        if captured.is_async:
            raise PermissionError(UNSUPPORTED_ASYNC)
        principal, bound_config = _principal(config)
        injected = _application_kwargs(captured, bound_config)
        function = captured.function
        self._dispatch(principal, bound_config)
        result = _run_application(function, input, injected)
        return self._state_writes(principal, result)

    async def _ainvoke_application(
        self,
        captured: _CapturedApplication,
        input: Any,
        config: RunnableConfig | None,
    ) -> Any:
        """Asynchronous form of `_invoke_application`.

        A coroutine body is awaited directly; a synchronous body runs through
        the framework's `run_in_executor`, as `RunnableCallable` would.
        """
        principal, bound_config = _principal(config)
        injected = _application_kwargs(captured, bound_config)
        function = captured.function
        await self._adispatch(principal, bound_config)
        if captured.is_async:
            result = await _run_application(function, input, injected)
        else:
            result = await _run_application_in_executor(function, input, injected)
        return await self._astate_writes(principal, result)

    def _dispatch(self, principal: Principal, config: RunnableConfig) -> None:
        if _is_send(config):
            return
        request = DispatchRequest(
            _dispatch_kind(self.spec.kind, config),
            principal,
            principal,
            _operation_id(config, self.spec.name, "dispatch"),
        )
        self.router.dispatch(principal, request)

    async def _adispatch(self, principal: Principal, config: RunnableConfig) -> None:
        if _is_send(config):
            return
        request = DispatchRequest(
            _dispatch_kind(self.spec.kind, config),
            principal,
            principal,
            _operation_id(config, self.spec.name, "dispatch"),
        )
        await self.router.adispatch(principal, request)

    def _model_input(
        self, principal: Principal, value: Any, config: RunnableConfig
    ) -> Any:
        if self.spec.kind is not NodeKind.MODEL:
            return value
        if isinstance(value, Mapping):
            context = tuple(
                _as_labeled(
                    name,
                    self.router.state(
                        principal,
                        StateRequest(
                            StateOperation.MODEL_READ,
                            str(name),
                            principal.user_id,
                            value=item,
                        ),
                    ),
                )
                for name, item in value.items()
            )
            rebuild = _rebuild_mapping
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            context = (
                _as_labeled(
                    "messages",
                    self.router.state(
                        principal,
                        StateRequest(
                            StateOperation.MODEL_READ,
                            "messages",
                            principal.user_id,
                            value=value,
                        ),
                    ),
                ),
            )
            rebuild = _rebuild_sequence
        else:
            raise TypeError("placement:model_input_must_be_mapping_or_sequence")
        effective = cast(
            Sequence[LabeledValue],
            self.router.model_invoke(
                principal,
                ModelInvocationRequest(
                    self.spec.name,
                    context,
                    _operation_id(config, self.spec.name, "model"),
                ),
            ),
        )
        return rebuild(effective)

    async def _amodel_input(
        self, principal: Principal, value: Any, config: RunnableConfig
    ) -> Any:
        if self.spec.kind is not NodeKind.MODEL:
            return value
        context: list[LabeledValue] = []
        if isinstance(value, Mapping):
            values = value.items()
            rebuild = _rebuild_mapping
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            values = (("messages", value),)
            rebuild = _rebuild_sequence
        else:
            raise TypeError("placement:model_input_must_be_mapping_or_sequence")
        for name, item in values:
            read = await self.router.astate(
                principal,
                StateRequest(
                    StateOperation.MODEL_READ,
                    str(name),
                    principal.user_id,
                    value=item,
                ),
            )
            context.append(_as_labeled(name, read))
        effective = cast(
            Sequence[LabeledValue],
            await self.router.amodel_invoke(
                principal,
                ModelInvocationRequest(
                    self.spec.name,
                    tuple(context),
                    _operation_id(config, self.spec.name, "model"),
                ),
            ),
        )
        return rebuild(effective)

    def _state_writes(self, principal: Principal, result: Any) -> Any:
        if isinstance(result, Mapping):
            return {
                name: self.router.state(
                    principal,
                    StateRequest(
                        StateOperation.WRITE,
                        str(name),
                        principal.user_id,
                        labels=_result_labels(self.spec, item),
                        value=_raw_value(item),
                    ),
                )
                for name, item in result.items()
            }
        if isinstance(result, Command) and result.update is not None:
            result = replace(
                result, update=self._state_writes(principal, result.update)
            )
        if isinstance(result, Command):
            _route_sends(self.router, principal, result.goto, None, self.spec.name)
            return result
        if result is None:
            return None
        raise TypeError("placement:node_update_must_be_mapping_command_or_none")

    async def _astate_writes(self, principal: Principal, result: Any) -> Any:
        if isinstance(result, Mapping):
            written: dict[Any, Any] = {}
            for name, item in result.items():
                written[name] = await self.router.astate(
                    principal,
                    StateRequest(
                        StateOperation.WRITE,
                        str(name),
                        principal.user_id,
                        labels=_result_labels(self.spec, item),
                        value=_raw_value(item),
                    ),
                )
            return written
        if isinstance(result, Command) and result.update is not None:
            result = replace(
                result, update=await self._astate_writes(principal, result.update)
            )
        if isinstance(result, Command):
            await _aroute_sends(
                self.router, principal, result.goto, None, self.spec.name
            )
            return result
        if result is None:
            return None
        raise TypeError("placement:node_update_must_be_mapping_command_or_none")


class MediatedBranch(Runnable[Any, Any]):
    """Authorize every `Send` before the runtime schedules any child task."""

    def __init__(
        self,
        runnable: Runnable[Any, Any],
        name: str,
        router: HostRouter,
        *,
        trust: NodeTrust,
        untrusted_host: UntrustedNodeHost | None = None,
        descriptor: AdmittedDescriptor | None = None,
    ) -> None:
        if descriptor is not None:
            _bind_branch_descriptor(descriptor, runnable, trust)
        self.runnable = runnable
        self.name = name
        self.router = router
        self.trust = trust
        self.untrusted_host = untrusted_host
        self.descriptor = descriptor

    def invoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        if self.descriptor is not None:
            return self._invoke_admitted(input, config, kwargs)
        principal, bound_config = _principal(config)
        if self.trust is NodeTrust.UNTRUSTED:
            if self.untrusted_host is None:
                raise PermissionError("placement:untrusted_branch_has_no_host")
            result = self.untrusted_host.invoke(self.name, input, principal.user_id)
        else:
            result = self.runnable.invoke(input, bound_config, **kwargs)
        _route_sends(self.router, principal, result, bound_config, self.name)
        return result

    def _invoke_admitted(
        self, input: Any, config: RunnableConfig | None, kwargs: dict[str, Any]
    ) -> Any:
        """Dispatch only the pinned framework function of the captured branch.

        Invariants, in order: `kwargs` empty; exact descriptor whose captured
        `path` is `self.runnable` and whose trust is `TRUSTED`; `recheck`
        passes (pinned function object and loaded code, framework executor
        shim, empty `path.kwargs`, exact routing map); `input` is an exact
        `dict`/`list` and a shallow copy is passed; the principal comes only
        from the native config. The pinned function receives the bounded copy
        and nothing else: no config, callbacks, router or `Runtime`. Its
        result must be an exact `str` destination; `Send` routing is then
        authorized as today. `self.runnable.invoke`, `path.func`,
        `path.afunc` and `path.kwargs` are never used for dispatch.
        """
        captured = _admitted_branch(self, kwargs)
        if type(captured) is _CapturedTrustedBranch:
            return self._invoke_trusted_branch(captured, input, config)
        data = _bounded_input(input)
        principal, bound_config = _principal(config)
        result = captured.function(data)
        if type(result) is not str:
            raise PermissionError(DESCRIPTOR_CHANGED)
        _route_sends(self.router, principal, result, bound_config, self.name)
        return result

    async def _ainvoke_admitted(
        self, input: Any, config: RunnableConfig | None, kwargs: dict[str, Any]
    ) -> Any:
        """Asynchronous form of `_invoke_admitted`.

        A framework branch has no asynchronous body: the pinned synchronous
        function is called inline on the event loop. The `run_in_executor`
        shim stored in `path.afunc` is never started, so no candidate
        lifecycle exists to manage.
        """
        captured = _admitted_branch(self, kwargs)
        if type(captured) is _CapturedTrustedBranch:
            return await self._ainvoke_trusted_branch(captured, input, config)
        data = _bounded_input(input)
        principal, bound_config = _principal(config)
        result = captured.function(data)
        if type(result) is not str:
            raise PermissionError(DESCRIPTOR_CHANGED)
        await _aroute_sends(self.router, principal, result, bound_config, self.name)
        return result

    def _invoke_trusted_branch(
        self,
        captured: _CapturedTrustedBranch,
        input: Any,
        config: RunnableConfig | None,
    ) -> Any:
        """Run a declared trusted branch's captured function.

        This is trust, not containment (D11). `captured` is the rechecked
        `TRUSTED_APPLICATION_BRANCH` implementation returned by
        `_admitted_branch`. The function pinned at admission receives the
        branch input as is; its result goes back to the framework's
        `BranchSpec._finish` unchanged, after every `Send` it names is
        authorized as today. `self.runnable.invoke` and `path.func` are never
        used.
        """
        principal, bound_config = _principal(config)
        function = captured.function
        result = _run_application(function, input, {})
        _route_sends(self.router, principal, result, bound_config, self.name)
        return result

    async def _ainvoke_trusted_branch(
        self,
        captured: _CapturedTrustedBranch,
        input: Any,
        config: RunnableConfig | None,
    ) -> Any:
        """Asynchronous form of `_invoke_trusted_branch`.

        The synchronous body runs through the framework's `run_in_executor`,
        as the `RunnableCallable` path would.
        """
        principal, bound_config = _principal(config)
        function = captured.function
        result = await _run_application_in_executor(function, input, {})
        await _aroute_sends(self.router, principal, result, bound_config, self.name)
        return result

    async def ainvoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        if self.descriptor is not None:
            return await self._ainvoke_admitted(input, config, kwargs)
        principal, bound_config = _principal(config)
        if self.trust is NodeTrust.UNTRUSTED:
            if self.untrusted_host is None:
                raise PermissionError("placement:untrusted_branch_has_no_host")
            result = await self.untrusted_host.ainvoke(
                self.name, input, principal.user_id
            )
        else:
            result = await self.runnable.ainvoke(input, bound_config, **kwargs)
        await _aroute_sends(self.router, principal, result, bound_config, self.name)
        return result


class OutputMediator:
    """Apply `output_emit` to every externally yielded graph item."""

    __slots__ = ("router", "host", "destination", "clearance")

    def __init__(
        self,
        router: HostRouter,
        host: ObjectManagerHost,
        *,
        destination: str,
        clearance: frozenset[str],
    ) -> None:
        if type(self) is not OutputMediator:
            raise PermissionError("output:unsupported_mediator")
        _require_output_host(router, host)
        self.router = router
        self.host = host
        self.destination = destination
        self.clearance = clearance

    def __call__(self, value: Any, config: RunnableConfig) -> Any:
        return OutputMediator._emit(self, value, config, _identity)

    def callback(
        self, value: Any, config: RunnableConfig, deliver: Callable[[Any], Any]
    ) -> Any:
        return OutputMediator._emit(
            self, value, config, deliver, callback_delivery=True
        )

    async def acallback(
        self,
        value: Any,
        config: RunnableConfig,
        deliver: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        return await OutputMediator._aemit(
            self, value, config, deliver, callback_delivery=True
        )

    def stream(self, envelope: _OutputEnvelope, config: RunnableConfig) -> Any:
        if type(self) is not OutputMediator:
            raise PermissionError("output:unsupported_mediator")
        if type(envelope) is not _OutputEnvelope:
            raise PermissionError("output:missing_framework_envelope")
        return OutputMediator._emit(self, envelope.content, config, envelope.rebuild)

    def _emit(
        self,
        content: Any,
        config: RunnableConfig,
        rebuild: Callable[[Any], Any],
        *,
        callback_delivery: bool = False,
    ) -> Any:
        router, host, destination, clearance = _output_mediator_fields(self)
        _require_output_host(router, host)
        principal, bound_config = _principal(config)
        request = OutputRequest(
            destination,
            content,
            host.labels_for_output(principal, content),
            clearance,
            _operation_id(bound_config, "__graph__", "output"),
        )
        _require_output_host(router, host)
        result = router.output_emit(principal, request)
        if isinstance(result, ObjectAuthorization):
            raise self._approval_required(
                principal,
                result,
                rebuild,
                router=router,
                host=host,
                callback_delivery=callback_delivery,
            )
        return rebuild(result)

    async def acall(self, value: Any, config: RunnableConfig) -> Any:
        return await OutputMediator._aemit(self, value, config, _identity)

    async def astream(self, envelope: _OutputEnvelope, config: RunnableConfig) -> Any:
        if type(self) is not OutputMediator:
            raise PermissionError("output:unsupported_mediator")
        if type(envelope) is not _OutputEnvelope:
            raise PermissionError("output:missing_framework_envelope")
        return await OutputMediator._aemit(
            self, envelope.content, config, envelope.rebuild
        )

    async def _aemit(
        self,
        content: Any,
        config: RunnableConfig,
        rebuild: Callable[[Any], Any],
        *,
        callback_delivery: bool = False,
    ) -> Any:
        router, host, destination, clearance = _output_mediator_fields(self)
        _require_output_host(router, host)
        principal, bound_config = _principal(config)
        request = OutputRequest(
            destination,
            content,
            host.labels_for_output(principal, content),
            clearance,
            _operation_id(bound_config, "__graph__", "output"),
        )
        _require_output_host(router, host)
        result = await router.aoutput_emit(principal, request)
        if isinstance(result, ObjectAuthorization):
            raise self._approval_required(
                principal,
                result,
                rebuild,
                router=router,
                host=host,
                callback_delivery=callback_delivery,
            )
        effective = rebuild(result)
        if callback_delivery and inspect.isawaitable(effective):
            return await effective
        return effective

    def _approval_required(
        self,
        principal: Principal,
        authorization: ObjectAuthorization,
        rebuild: Callable[[Any], Any],
        *,
        router: HostRouter,
        host: ObjectManagerHost,
        callback_delivery: bool = False,
    ) -> OutputApprovalRequired:
        if type(self) is not OutputMediator:
            raise PermissionError("output:unsupported_mediator")
        _require_output_host(router, host)
        escalation = authorization.decision.escalation
        if escalation is None:
            raise PermissionError("output:invalid_escalation")

        def resume(response: Any) -> Any:
            _require_output_host(router, host)
            approval = coerce_approval(response, escalation)
            _require_output_host(router, host)
            return rebuild(router.resume(principal, authorization.request, approval))

        async def aresume(response: Any) -> Any:
            _require_output_host(router, host)
            approval = coerce_approval(response, escalation)
            _require_output_host(router, host)
            result = await router.aresume(principal, authorization.request, approval)
            effective = rebuild(result)
            if callback_delivery and inspect.isawaitable(effective):
                return await effective
            return effective

        return OutputApprovalRequired(
            escalation.to_payload(),
            resume,
            aresume,
        )


def _output_mediator_fields(
    mediator: OutputMediator,
) -> tuple[HostRouter, ObjectManagerHost, str, frozenset[str]]:
    """Read native mediator slots without publishing a missing-slot receiver."""
    if type(mediator) is not OutputMediator:
        raise PermissionError("output:unsupported_mediator")
    try:
        return mediator.router, mediator.host, mediator.destination, mediator.clearance
    except AttributeError:
        pass
    raise PermissionError("output:unsupported_mediator")


def _require_output_host(router: HostRouter, host: ObjectManagerHost) -> None:
    """Check the captured receiver pair without invoking candidate methods.

    Exact types and fixed slots exclude instance method shadowing. This does
    not establish input shape, class-code integrity or concurrent stability.
    """
    if type(router) is not HostRouter:
        raise PermissionError("output:unsupported_router")
    if type(host) is not ObjectManagerHost:
        raise PermissionError("output:unsupported_host")
    try:
        router.policy
        if router.host is host:
            return
    except AttributeError:
        pass
    # AttributeError.obj can retain the router. Raise after its handler so the
    # new refusal does not retain that exception as its cause or context.
    raise PermissionError("output:host_binding_changed")


_pinned_tool_node: tuple[FunctionType, FunctionType] | None = None


def _bind_node_descriptor(descriptor: Any, runnable: Any, spec: Any) -> None:
    """Require a node wrapper to be built around exactly its admitted node."""
    if type(descriptor) is not AdmittedDescriptor:
        raise PermissionError(DESCRIPTOR_CHANGED)
    implementation = descriptor.implementation
    if type(implementation) is _CapturedToolNode:
        kind = NodeKind.STANDARD
    elif type(implementation) is _CapturedModel:
        kind = NodeKind.MODEL
    elif type(implementation) is _CapturedApplication:
        kind = NodeKind.STANDARD
    else:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if (
        implementation.node is not runnable
        or type(spec) is not PlacementSpec
        or spec.trust is not NodeTrust.TRUSTED
        or spec.kind is not kind
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)


def _bind_branch_descriptor(descriptor: Any, runnable: Any, trust: Any) -> None:
    """Require a branch wrapper to be built around exactly its admitted path."""
    if type(descriptor) is not AdmittedDescriptor:
        raise PermissionError(DESCRIPTOR_CHANGED)
    implementation = descriptor.implementation
    if (
        type(implementation) is not _CapturedBranch
        and type(implementation) is not _CapturedTrustedBranch
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    if implementation.path is not runnable or trust is not NodeTrust.TRUSTED:
        raise PermissionError(DESCRIPTOR_CHANGED)


def _admitted_node(
    mediated: MediatedNode, kwargs: Any
) -> _CapturedToolNode | _CapturedModel | _CapturedApplication:
    """Re-read the wrapper's links and recheck its descriptor before dispatch."""
    if type(kwargs) is not dict or kwargs:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if type(mediated) is not MediatedNode:
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        descriptor = mediated.descriptor
        runnable = mediated.runnable
        spec = mediated.spec
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(DESCRIPTOR_CHANGED)
    _bind_node_descriptor(descriptor, runnable, spec)
    recheck(descriptor)
    captured = descriptor.implementation
    _require_no_shadowed_methods(captured.node)
    return captured


def _admitted_branch(
    mediated: MediatedBranch, kwargs: Any
) -> _CapturedBranch | _CapturedTrustedBranch:
    """Re-read the wrapper's links and recheck its descriptor before dispatch."""
    if type(kwargs) is not dict or kwargs:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if type(mediated) is not MediatedBranch:
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        descriptor = mediated.descriptor
        runnable = mediated.runnable
        trust = mediated.trust
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(DESCRIPTOR_CHANGED)
    _bind_branch_descriptor(descriptor, runnable, trust)
    recheck(descriptor)
    captured = descriptor.implementation
    if type(captured.function) is not FunctionType:
        raise PermissionError(DESCRIPTOR_CHANGED)
    return captured


def _pinned_tool_node_functions(node: Any) -> tuple[FunctionType, FunctionType]:
    """Return the class functions `ToolNode._func`/`_afunc` pinned at first use.

    The captured node's `func`/`afunc` bound methods must still wrap exactly
    these functions; dispatch then calls the pinned function with the node as
    receiver instead of reading the mutable bound attributes.
    """
    global _pinned_tool_node
    from langgraph.prebuilt.tool_node import ToolNode

    pinned = _pinned_tool_node
    if pinned is None:
        function = ToolNode.__dict__.get("_func")
        afunction = ToolNode.__dict__.get("_afunc")
        if type(function) is not FunctionType or type(afunction) is not FunctionType:
            raise PermissionError(DESCRIPTOR_CHANGED)
        pinned = (function, afunction)
        _pinned_tool_node = pinned
    if type(node) is not ToolNode:
        raise PermissionError(DESCRIPTOR_CHANGED)
    try:
        func = node.func
        afunc = node.afunc
    except AttributeError:
        raise PermissionError(DESCRIPTOR_CHANGED) from None
    if (
        getattr(func, "__func__", None) is not pinned[0]
        or getattr(func, "__self__", None) is not node
        or getattr(afunc, "__func__", None) is not pinned[1]
        or getattr(afunc, "__self__", None) is not node
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    return pinned


def _require_no_shadowed_methods(node: Any) -> None:
    """Refuse a node whose instance dictionary shadows a class-level function.

    `ToolNode._func` reaches its helpers through `self`; an instance attribute
    named like one of them would redirect the admitted dispatch to candidate
    code. `func`/`afunc` are the `RunnableCallable` instance slots already
    pinned by `_pinned_tool_node_functions`.
    """
    try:
        instance = vars(node)
    except TypeError:
        raise PermissionError(DESCRIPTOR_CHANGED) from None
    if type(instance) is not dict:
        raise PermissionError(DESCRIPTOR_CHANGED)
    for klass in type(node).__mro__:
        for name, value in vars(klass).items():
            if name in ("func", "afunc") or name not in instance:
                continue
            if type(value) in (FunctionType, staticmethod, classmethod, property):
                raise PermissionError(DESCRIPTOR_CHANGED)


def _application_kwargs(
    captured: _CapturedApplication, config: RunnableConfig
) -> dict[str, Any]:
    """Compute the framework keyword injection from the plan captured at admission.

    Mirrors `RunnableCallable.invoke`: `config` receives the normal config,
    `error` the node error from `configurable`, `runtime` the framework
    `Runtime`, and other declared keywords the matching `Runtime` field, each
    falling back to the captured default.
    """
    from langgraph._internal._constants import (
        CONF,
        CONFIG_KEY_NODE_ERROR,
        CONFIG_KEY_RUNTIME,
    )

    configurable = config.get(CONF)
    if type(configurable) is not dict:
        configurable = {}
    runtime = configurable.get(CONFIG_KEY_RUNTIME)
    missing = object()
    injected: dict[str, Any] = {}
    for keyword, runtime_key, default in captured.accepts:
        value: Any = missing
        if keyword == "config":
            value = config
        elif keyword == "error":
            value = configurable.get(CONFIG_KEY_NODE_ERROR, missing)
        elif runtime is not None:
            if keyword == "runtime":
                value = runtime
            else:
                value = getattr(runtime, runtime_key, missing)
        if value is missing:
            if default is inspect.Parameter.empty:
                raise ValueError(
                    f"Missing required config key '{runtime_key}' for "
                    f"'{captured.name}'."
                )
            value = default
        injected[keyword] = value
    return injected


def _run_application(
    function: FunctionType, value: Any, injected: dict[str, Any]
) -> Any:
    return function(value, **injected)


async def _run_application_in_executor(
    function: FunctionType, value: Any, injected: dict[str, Any]
) -> Any:
    from langgraph._internal._runnable import run_in_executor

    return await run_in_executor(None, function, value, **injected)


def _require_async_route(captured: _CapturedToolNode) -> None:
    """Permit async only where the admitted adapter owns its async route."""
    adapters = (captured.executor,)
    if captured.dispatcher is not None:
        adapters = (captured.executor, captured.dispatcher)
    for adapter in adapters:
        route = type(adapter).__dict__.get("ainvoke")
        if type(route) is not FunctionType or not inspect.iscoroutinefunction(route):
            raise PermissionError(UNSUPPORTED_ASYNC)


def _model_messages(effective: Any) -> list[Any]:
    """Return the hook's effective `messages` list for the model call."""
    if type(effective) is not dict:
        raise TypeError("placement:model_input_requires_messages")
    messages = effective.get("messages")
    if type(messages) is not list:
        raise TypeError("placement:model_input_requires_messages")
    return list(messages)


def _model_update(result: Any) -> dict[str, Any]:
    """Wrap an exact `AIMessage` reply as the node's `messages` update."""
    from langchain_core.messages import AIMessage

    if type(result) is not AIMessage:
        raise TypeError("placement:model_output_must_be_ai_message")
    return {"messages": [result]}


def _bounded_input(value: Any) -> Any:
    """Copy an exact `dict` with `str` keys or an exact `list`; refuse others."""
    kind = type(value)
    if kind is dict:
        if any(type(key) is not str for key in value):
            raise PermissionError(DESCRIPTOR_CHANGED)
        return dict(value)
    if kind is list:
        return list(value)
    raise PermissionError(DESCRIPTOR_CHANGED)


def _framework_runtime(config: RunnableConfig) -> Any:
    """Read the exact framework `Runtime` from the native configurable dict."""
    from langgraph._internal._constants import CONF, CONFIG_KEY_RUNTIME
    from langgraph.runtime import Runtime

    if type(config) is not dict:
        raise PermissionError(DESCRIPTOR_CHANGED)
    configurable = config.get(CONF)
    if type(configurable) is not dict:
        raise PermissionError(DESCRIPTOR_CHANGED)
    runtime = configurable.get(CONFIG_KEY_RUNTIME)
    if type(runtime) is not Runtime:
        raise PermissionError(DESCRIPTOR_CHANGED)
    return runtime


def _narrowed_config(config: RunnableConfig) -> RunnableConfig:
    """Project the keys the framework primitive needs; drop callbacks and run ids."""
    from langgraph._internal._constants import CONF

    configurable = config.get(CONF)
    if type(configurable) is not dict:
        raise PermissionError(DESCRIPTOR_CHANGED)
    narrowed: dict[str, Any] = {CONF: dict(configurable)}
    metadata = config.get("metadata")
    if type(metadata) is dict:
        narrowed["metadata"] = dict(metadata)
    tags = config.get("tags")
    if type(tags) is list:
        narrowed["tags"] = list(tags)
    for key in ("max_concurrency", "recursion_limit"):
        limit = config.get(key)
        if type(limit) is int:
            narrowed[key] = limit
    return cast(RunnableConfig, narrowed)


def resolve_placement(name: str, runnable: Any, metadata: Any) -> PlacementSpec:
    """Resolve explicit metadata and conservative defaults for one node."""
    values = metadata if isinstance(metadata, Mapping) else {}
    explicit_trust = values.get("security_trust")
    if explicit_trust not in {None, "trusted", "untrusted"}:
        raise ValueError(f"invalid security_trust for node:{name}")
    imported = not _operator_callable(runnable)
    inferred = NodeTrust.UNTRUSTED if imported else NodeTrust.TRUSTED
    trust = NodeTrust(explicit_trust) if explicit_trust else inferred
    promoted = imported and trust is NodeTrust.TRUSTED
    reason = values.get("security_promotion_reason", "")
    if promoted and (not isinstance(reason, str) or not reason.strip()):
        raise ValueError(f"trusted promotion requires a reason for node:{name}")
    explicit_kind = values.get("security_kind")
    if explicit_kind is None:
        kind = NodeKind.MODEL if _is_model(runnable) else NodeKind.STANDARD
    else:
        try:
            kind = NodeKind(explicit_kind)
        except ValueError as exc:
            raise ValueError(f"invalid security_kind for node:{name}") from exc
    return PlacementSpec(name, trust, kind, promoted, str(reason).strip())


def _operator_callable(runnable: Any) -> bool:
    current = runnable
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        candidate = getattr(current, "func", None) or getattr(current, "afunc", None)
        if inspect.isfunction(candidate) or inspect.ismethod(candidate):
            module = getattr(candidate, "__module__", "")
            return not module.startswith(("langchain_core.", "langgraph."))
        current = getattr(current, "bound", None)
    return False


def _is_model(runnable: Any) -> bool:
    current = runnable
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        module = type(current).__module__
        name = type(current).__name__.lower()
        if "language_model" in module or "chatmodel" in name or "llm" in name:
            return True
        current = getattr(current, "bound", None)
    return False


def _principal(
    config: RunnableConfig | None,
) -> tuple[Principal, RunnableConfig]:
    bound: RunnableConfig = {} if config is None else config
    principal = principal_from(bound)
    if principal is None:
        raise PermissionError("placement:missing_principal")
    return principal, bound


def _operation_id(config: RunnableConfig, node: str, operation: str) -> str:
    return f"{node}:{operation}:{next_call_index(config)}"


def _dispatch_kind(kind: NodeKind, config: RunnableConfig) -> DispatchKind:
    if _is_send(config):
        return DispatchKind.SEND
    return {
        NodeKind.SUBGRAPH: DispatchKind.SUBGRAPH,
        NodeKind.SUBAGENT: DispatchKind.SUBAGENT,
        NodeKind.NESTED_AGENT: DispatchKind.NESTED_AGENT,
    }.get(kind, DispatchKind.PARALLEL_BRANCH)


def _is_send(config: RunnableConfig) -> bool:
    metadata = config.get("metadata")
    triggers = (
        metadata.get("langgraph_triggers", ()) if isinstance(metadata, Mapping) else ()
    )
    return "__pregel_push" in triggers


def _sends(value: Any) -> tuple[Send, ...]:
    if isinstance(value, Send):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(item for item in value if isinstance(item, Send))
    return ()


def _route_sends(
    router: HostRouter,
    principal: Principal,
    value: Any,
    config: RunnableConfig | None,
    source: str,
) -> None:
    errors: list[PermissionError] = []
    for index, send in enumerate(_sends(value)):
        try:
            router.dispatch(
                principal,
                DispatchRequest(
                    DispatchKind.SEND,
                    principal,
                    principal,
                    _send_id(config, source, send.node, index),
                ),
            )
        except PermissionError as exc:
            errors.append(exc)
    if errors:
        raise errors[0]


async def _aroute_sends(
    router: HostRouter,
    principal: Principal,
    value: Any,
    config: RunnableConfig | None,
    source: str,
) -> None:
    errors: list[PermissionError] = []
    for index, send in enumerate(_sends(value)):
        try:
            await router.adispatch(
                principal,
                DispatchRequest(
                    DispatchKind.SEND,
                    principal,
                    principal,
                    _send_id(config, source, send.node, index),
                ),
            )
        except PermissionError as exc:
            errors.append(exc)
    if errors:
        raise errors[0]


def _send_id(
    config: RunnableConfig | None,
    source: str,
    target: str,
    index: int,
) -> str:
    if config is None:
        return f"{source}:send:{target}:{index}"
    return f"{source}:send:{target}:{index}:{next_call_index(config)}"


def _as_labeled(name: Any, value: Any) -> LabeledValue:
    if isinstance(value, LabeledValue):
        return LabeledValue(str(name), value.value, value.labels)
    return LabeledValue(str(name), value)


def _rebuild_mapping(items: Sequence[LabeledValue]) -> dict[str, Any]:
    return {item.name: item.value for item in items}


def _rebuild_sequence(items: Sequence[LabeledValue]) -> Any:
    if not items:
        return []
    if len(items) != 1 or items[0].name != "messages":
        raise PermissionError("placement:invalid_effective_model_context")
    return items[0].value


def _raw_value(value: Any) -> Any:
    return value.value if isinstance(value, LabeledValue) else value


def _result_labels(spec: PlacementSpec, value: Any) -> SecurityLabels:
    if isinstance(value, LabeledValue):
        return value.labels
    low_integrity = spec.trust is NodeTrust.UNTRUSTED or spec.kind in {
        NodeKind.MODEL,
        NodeKind.SUBGRAPH,
        NodeKind.SUBAGENT,
        NodeKind.NESTED_AGENT,
    }
    return SecurityLabels(integrity="low" if low_integrity else "trusted")


def _identity(value: Any) -> Any:
    return value
