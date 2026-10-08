"""Compile-time placement of framework operations on the HostRouter path."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Protocol, cast, runtime_checkable

from langchain_core.runnables import Runnable, RunnableConfig
from langgraph.types import Command, Send

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
    """Execution trust assigned to one graph node at compile time."""

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
    """Route dispatch, model context, and state writes around one graph node."""

    def __init__(
        self,
        runnable: Runnable[Any, Any],
        spec: PlacementSpec,
        router: HostRouter,
        *,
        untrusted_host: UntrustedNodeHost | None = None,
    ) -> None:
        self.runnable = runnable
        self.spec = spec
        self.router = router
        self.untrusted_host = untrusted_host

    def invoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
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
        if self.spec.kind is not NodeKind.MODEL or not isinstance(value, Mapping):
            return value
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
        return {item.name: item.value for item in effective}

    async def _amodel_input(
        self, principal: Principal, value: Any, config: RunnableConfig
    ) -> Any:
        if self.spec.kind is not NodeKind.MODEL or not isinstance(value, Mapping):
            return value
        context: list[LabeledValue] = []
        for name, item in value.items():
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
        return {item.name: item.value for item in effective}

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
    ) -> None:
        self.runnable = runnable
        self.name = name
        self.router = router
        self.trust = trust
        self.untrusted_host = untrusted_host

    def invoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        principal, bound_config = _principal(config)
        if self.trust is NodeTrust.UNTRUSTED:
            if self.untrusted_host is None:
                raise PermissionError("placement:untrusted_branch_has_no_host")
            result = self.untrusted_host.invoke(self.name, input, principal.user_id)
        else:
            result = self.runnable.invoke(input, bound_config, **kwargs)
        _route_sends(self.router, principal, result, bound_config, self.name)
        return result

    async def ainvoke(
        self,
        input: Any,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
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

    def __init__(
        self,
        router: HostRouter,
        host: ObjectManagerHost,
        *,
        destination: str,
        clearance: frozenset[str],
    ) -> None:
        self.router = router
        self.host = host
        self.destination = destination
        self.clearance = clearance

    def __call__(self, value: Any, config: RunnableConfig) -> Any:
        principal, bound_config = _principal(config)
        content, rebuild = _stream_payload(value)
        result = self.router.output_emit(
            principal,
            OutputRequest(
                self.destination,
                content,
                self.host.labels_for_output(content),
                self.clearance,
                _operation_id(bound_config, "__graph__", "output"),
            ),
        )
        if isinstance(result, ObjectAuthorization):
            raise self._approval_required(principal, result, rebuild)
        return rebuild(result)

    async def acall(self, value: Any, config: RunnableConfig) -> Any:
        principal, bound_config = _principal(config)
        content, rebuild = _stream_payload(value)
        result = await self.router.aoutput_emit(
            principal,
            OutputRequest(
                self.destination,
                content,
                self.host.labels_for_output(content),
                self.clearance,
                _operation_id(bound_config, "__graph__", "output"),
            ),
        )
        if isinstance(result, ObjectAuthorization):
            raise self._approval_required(principal, result, rebuild)
        return rebuild(result)

    def _approval_required(
        self,
        principal: Principal,
        authorization: ObjectAuthorization,
        rebuild: Callable[[Any], Any],
    ) -> OutputApprovalRequired:
        escalation = authorization.decision.escalation
        if escalation is None:
            raise PermissionError("output:invalid_escalation")

        def resume(response: Any) -> Any:
            approval = coerce_approval(response, escalation)
            return rebuild(
                self.router.resume(principal, authorization.request, approval)
            )

        async def aresume(response: Any) -> Any:
            approval = coerce_approval(response, escalation)
            return rebuild(
                await self.router.aresume(principal, authorization.request, approval)
            )

        return OutputApprovalRequired(
            escalation.to_payload(),
            resume,
            aresume,
        )


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
    bound: RunnableConfig = config or {}
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


def _stream_payload(value: Any):
    if isinstance(value, dict) and "type" in value and "data" in value:
        return value["data"], lambda content: {**value, "data": content}
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        return value[1], lambda content: (value[0], content)
    if (
        isinstance(value, tuple)
        and len(value) == 3
        and isinstance(value[0], tuple)
        and isinstance(value[1], str)
    ):
        return value[2], lambda content: (value[0], value[1], content)
    return value, lambda content: content
