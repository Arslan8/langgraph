"""Security mediation for tools and delegated graphs outside ToolNode."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any, overload

from langchain_core.runnables import Runnable, RunnableConfig
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.types import interrupt

from langgraph.prebuilt.security.binding import (
    _bind_principal,
    history_for,
    next_call_index,
    principal_from,
)
from langgraph.prebuilt.security.blobs import copy_blobs
from langgraph.prebuilt.security.config import SecurityConfig
from langgraph.prebuilt.security.descriptor import normalize_resource, security_for_tool
from langgraph.prebuilt.security.errors import (
    SecurityAuditError,
    SecurityConfigurationError,
    SecurityIndeterminateError,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
)
from langgraph.prebuilt.security.flow import ToolFlowRule
from langgraph.prebuilt.security.introspect import (
    ToolInventoryEntry,
    _register_guarded_tool,
)
from langgraph.prebuilt.security.stack import (
    SecurityStack,
    coerce_approval,
    record_approval,
)
from langgraph.prebuilt.security.types import (
    Decision,
    ExecutionOutcome,
    Principal,
    Tool,
    ToolCall,
    Verdict,
)


class SecurityDeniedError(PermissionError):
    """Raised when security mediation rejects direct execution or delegation."""


class _GuardedExecutor:
    def __init__(self, target: BaseTool, security: SecurityConfig) -> None:
        self.target = target
        self.security = security
        descriptor, author_dac = security_for_tool(target)
        overrides = security.dac_overrides
        if overrides is not None:
            unknown = set(overrides).difference({target.name})
            if unknown:
                names = ", ".join(sorted(unknown))
                raise ValueError(f"DAC overrides reference unknown tools: {names}")
        policy = overrides.get(target.name, author_dac) if overrides else author_dac
        self.tool = Tool(
            target.name,
            policy,
            descriptor.effects,
            descriptor.resources,
        )
        self.stack = SecurityStack(
            security.modules,
            policy_timeout_s=security.policy_timeout_s,
            observer=security.observer,
            audit_sink=security.audit_sink,
            approval_ttl_s=security.approval_ttl_s,
        )
        if security.flow_policy is not None:
            security.flow_policy.validate_tools((target.name,))
        if security.host_executor is not None:
            security.host_executor.validate_tools((target.name,))
        for module in self.stack.modules:
            slot = self.tool.security.allocate(module.name)
            module.tool_alloc_security(self.tool, slot)
        _register_guarded_tool(
            ToolInventoryEntry(
                name=target.name,
                descriptor=descriptor,
                dac=policy,
                path=(),
                source="guarded_tool",
                labels={
                    name: slot.snapshot() for name, slot in self.tool.security.items()
                },
            )
        )

    def invoke(self, args: Mapping[str, Any], config: RunnableConfig) -> Any:
        principal, call = self._prepare(args, config)
        decision, call = self.stack.prepare(principal, call)
        if decision.verdict is Verdict.ALLOW:
            decision = self.stack.permission(principal, call)
        if decision.verdict is Verdict.ESCALATE:
            decision = self._resume(principal, call, decision)
        if decision.verdict is not Verdict.ALLOW:
            raise SecurityDeniedError(decision.reason)
        policy_constraints = decision.constraints
        decision, flow_reservation = self._acquire_flow(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            raise SecurityDeniedError(decision.reason)
        try:
            self.stack.record_framework_event(
                principal,
                call,
                "dispatch",
                Decision(Verdict.ALLOW, "dispatch:reserved"),
            )
        except SecurityAuditError as exc:
            self._release_flow(principal, flow_reservation)
            raise SecurityDeniedError("audit_failure") from exc
        result: Any = None
        outcome = ExecutionOutcome.INDETERMINATE
        try:
            if self.security.host_executor is not None:
                host_result = self.security.host_executor.invoke(
                    principal, call, policy_constraints
                )
                self.stack.record_framework_event(
                    principal,
                    call,
                    "activation",
                    Decision(Verdict.ALLOW, host_result.receipt.audit_reason()),
                )
                result = host_result.value
            else:
                result = self.target.invoke(dict(call.args), config=config)
            outcome = ExecutionOutcome.SUCCEEDED
            return result
        except HostExecutionDenied as exc:
            outcome = ExecutionOutcome.DENIED_BEFORE_DISPATCH
            raise SecurityDeniedError(str(exc)) from exc
        except HostExecutionError as exc:
            outcome = exc.outcome
            try:
                self.stack.record_framework_event(
                    principal,
                    call,
                    "activation",
                    Decision(Verdict.ALLOW, exc.receipt.audit_reason()),
                )
            except SecurityAuditError as audit_exc:
                raise SecurityIndeterminateError(
                    "tool activation evidence could not be persisted"
                ) from audit_exc
            raise
        finally:
            try:
                self.stack.post(principal, call, result)
                self.stack.record_framework_event(
                    principal,
                    call,
                    "outcome",
                    Decision(Verdict.ALLOW, f"execution:{outcome.value}"),
                    outcome=outcome,
                )
            except SecurityAuditError as exc:
                raise SecurityIndeterminateError(
                    "tool outcome is indeterminate because completion audit failed"
                ) from exc
            finally:
                self._release_flow(principal, flow_reservation)

    async def ainvoke(self, args: Mapping[str, Any], config: RunnableConfig) -> Any:
        principal, call = self._prepare(args, config)
        decision, call = await self.stack.aprepare(principal, call)
        if decision.verdict is Verdict.ALLOW:
            decision = await self.stack.apermission(principal, call)
        if decision.verdict is Verdict.ESCALATE:
            decision = await self._aresume(principal, call, decision)
        if decision.verdict is not Verdict.ALLOW:
            raise SecurityDeniedError(decision.reason)
        policy_constraints = decision.constraints
        decision, flow_reservation = self._acquire_flow(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            raise SecurityDeniedError(decision.reason)
        try:
            self.stack.record_framework_event(
                principal,
                call,
                "dispatch",
                Decision(Verdict.ALLOW, "dispatch:reserved"),
            )
        except SecurityAuditError as exc:
            self._release_flow(principal, flow_reservation)
            raise SecurityDeniedError("audit_failure") from exc
        result: Any = None
        outcome = ExecutionOutcome.INDETERMINATE
        try:
            if self.security.host_executor is not None:
                host_result = await self.security.host_executor.ainvoke(
                    principal, call, policy_constraints
                )
                self.stack.record_framework_event(
                    principal,
                    call,
                    "activation",
                    Decision(Verdict.ALLOW, host_result.receipt.audit_reason()),
                )
                result = host_result.value
            else:
                result = await self.target.ainvoke(dict(call.args), config=config)
            outcome = ExecutionOutcome.SUCCEEDED
            return result
        except HostExecutionDenied as exc:
            outcome = ExecutionOutcome.DENIED_BEFORE_DISPATCH
            raise SecurityDeniedError(str(exc)) from exc
        except HostExecutionError as exc:
            outcome = exc.outcome
            try:
                self.stack.record_framework_event(
                    principal,
                    call,
                    "activation",
                    Decision(Verdict.ALLOW, exc.receipt.audit_reason()),
                )
            except SecurityAuditError as audit_exc:
                raise SecurityIndeterminateError(
                    "tool activation evidence could not be persisted"
                ) from audit_exc
            raise
        finally:
            try:
                await self.stack.apost(principal, call, result)
                self.stack.record_framework_event(
                    principal,
                    call,
                    "outcome",
                    Decision(Verdict.ALLOW, f"execution:{outcome.value}"),
                    outcome=outcome,
                )
            except SecurityAuditError as exc:
                raise SecurityIndeterminateError(
                    "tool outcome is indeterminate because completion audit failed"
                ) from exc
            finally:
                self._release_flow(principal, flow_reservation)

    def _prepare(
        self, args: Mapping[str, Any], config: RunnableConfig
    ) -> tuple[Principal, ToolCall]:
        principal = principal_from(config)
        if principal is None:
            if self.security.require_principal:
                raise SecurityDeniedError("no_principal")
            principal = Principal(
                "__anonymous__", frozenset(), frozenset(), "anonymous"
            )
        call_index = next_call_index(config)
        try:
            normalized = _normalize_args(self.tool, args)
        except Exception as exc:
            raise SecurityDeniedError("normalization_error") from exc
        history = history_for(self.security.audit_sink, principal)
        return principal, ToolCall(
            self.tool,
            args,
            normalized,
            f"guarded:{self.tool.name}:{call_index}",
            call_index,
            history,
        )

    def _acquire_flow(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolFlowRule | None]:
        policy = self.security.flow_policy
        if policy is None:
            return Decision(Verdict.ALLOW, "flow:disabled"), None
        try:
            decision, reservation = policy.acquire(principal, call.tool.name)
        except BaseException:
            decision, reservation = Decision(Verdict.DENY, "flow:store_error"), None
        try:
            self.stack.record_framework_event(principal, call, "flow", decision)
        except BaseException:
            policy.release(principal, reservation)
            raise
        return decision, reservation

    def _release_flow(
        self, principal: Principal, reservation: ToolFlowRule | None
    ) -> None:
        policy = self.security.flow_policy
        if policy is not None:
            policy.release(principal, reservation)

    def _resume(
        self, principal: Principal, call: ToolCall, decision: Decision
    ) -> Decision:
        escalation = decision.escalation
        if escalation is None:
            return Decision(Verdict.DENY, "invalid_escalation")
        response = interrupt(dict(escalation.to_payload()))
        approval = coerce_approval(response, escalation)
        if not record_approval(principal, approval):
            return Decision(Verdict.DENY, "approval_replay")
        resumed = self.stack.resume_permission(principal, approval)
        if resumed.verdict is not Verdict.ALLOW:
            return resumed
        return self.stack.permission(principal, call, approval=approval)

    async def _aresume(
        self, principal: Principal, call: ToolCall, decision: Decision
    ) -> Decision:
        escalation = decision.escalation
        if escalation is None:
            return Decision(Verdict.DENY, "invalid_escalation")
        response = interrupt(dict(escalation.to_payload()))
        approval = coerce_approval(response, escalation)
        if not record_approval(principal, approval):
            return Decision(Verdict.DENY, "approval_replay")
        resumed = await self.stack.aresume_permission(principal, approval)
        if resumed.verdict is not Verdict.ALLOW:
            return resumed
        return await self.stack.apermission(principal, call, approval=approval)


@overload
def guarded_tool(
    target: Callable[..., Any] | BaseTool, *, security: SecurityConfig
) -> StructuredTool: ...


@overload
def guarded_tool(
    target: None = None, *, security: SecurityConfig
) -> Callable[[Callable[..., Any] | BaseTool], StructuredTool]: ...


def guarded_tool(
    target: Callable[..., Any] | BaseTool | None = None, *, security: SecurityConfig
) -> StructuredTool | Callable[[Callable[..., Any] | BaseTool], StructuredTool]:
    """Create a tool whose direct sync and async invocations are mediated."""

    def decorate(function: Callable[..., Any] | BaseTool) -> StructuredTool:
        if isinstance(function, BaseTool):
            original = function
        else:
            original = StructuredTool.from_function(
                func=function if not inspect.iscoroutinefunction(function) else None,
                coroutine=function if inspect.iscoroutinefunction(function) else None,
                name=function.__name__,
                description=inspect.getdoc(function) or function.__name__,
            )
        executor = _GuardedExecutor(original, security)

        def guarded_sync(config: RunnableConfig, **kwargs: Any) -> Any:
            return executor.invoke(kwargs, config)

        async def guarded_async(config: RunnableConfig, **kwargs: Any) -> Any:
            return await executor.ainvoke(kwargs, config)

        guarded = StructuredTool.from_function(
            func=guarded_sync,
            coroutine=guarded_async,
            name=original.name,
            description=original.description,
            args_schema=original.args_schema,
            return_direct=original.return_direct,
        )
        guarded.metadata = {
            **(guarded.metadata or {}),
            "security": {
                "descriptor": security_for_tool(original)[0],
                "dac": executor.tool.dac,
            },
        }
        return guarded

    return decorate(target) if target is not None else decorate


class _DelegatedRunnable(Runnable[Any, Any]):
    def __init__(
        self,
        graph: Runnable[Any, Any],
        scopes: frozenset[str],
        security: SecurityConfig,
    ) -> None:
        self.graph = graph
        self.scopes = scopes
        self.security = security
        self.stack = SecurityStack(
            security.modules,
            policy_timeout_s=security.policy_timeout_s,
            observer=security.observer,
            audit_sink=security.audit_sink,
        )

    def invoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        child_config = self._child_config(config)
        return self.graph.invoke(input, config=child_config, **kwargs)

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        child_config = await self._achild_config(config)
        return await self.graph.ainvoke(input, config=child_config, **kwargs)

    def _child_config(self, config: RunnableConfig | None) -> RunnableConfig:
        parent, child = self._principals(config)
        decision = self.stack.cred_transfer(parent, child)
        if decision.verdict is not Verdict.ALLOW:
            raise SecurityDeniedError(decision.reason)
        return _bind_principal(config, child)

    async def _achild_config(self, config: RunnableConfig | None) -> RunnableConfig:
        parent, child = self._principals(config)
        decision = await self.stack.acred_transfer(parent, child)
        if decision.verdict is not Verdict.ALLOW:
            raise SecurityDeniedError(decision.reason)
        return _bind_principal(config, child)

    def _principals(self, config: RunnableConfig | None) -> tuple[Principal, Principal]:
        parent = principal_from(config)
        if parent is None:
            raise SecurityDeniedError("delegation requires a principal")
        child = Principal(
            user_id=parent.user_id,
            roles=parent.roles,
            scopes=self.scopes,
            session_id=parent.session_id,
            delegated_by=parent.user_id,
            security=copy_blobs(parent.security),
        )
        return parent, child


def delegate(
    graph: Runnable[Any, Any],
    *,
    scopes: Sequence[str],
    security: SecurityConfig | None = None,
) -> Runnable[Any, Any]:
    """Wrap a child graph with an explicitly reduced delegated principal."""
    inherited = getattr(graph, "_security_config", None)
    if inherited is None:
        inherited = getattr(getattr(graph, "builder", None), "_security_config", None)
    if security is not None and inherited is not None and security is not inherited:
        raise SecurityConfigurationError(
            "delegation cannot replace an inherited SecurityConfig"
        )
    configured = security if security is not None else inherited
    if not isinstance(configured, SecurityConfig):
        raise SecurityConfigurationError(
            "delegation requires an explicit or inherited SecurityConfig"
        )
    return _DelegatedRunnable(graph, frozenset(scopes), configured)


def _normalize_args(tool: Tool, args: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for resource in tool.resources:
        if resource.arg not in args:
            continue
        value = normalize_resource(resource, args[resource.arg])
        normalized[resource.arg] = value
        if resource.normalizer in {"domain", "email_domain"}:
            normalized[f"{resource.arg}_domain"] = value
        elif resource.normalizer == "sql_statement_kind":
            normalized[f"{resource.arg}_statement_kind"] = value
        elif resource.normalizer == "shell_argv0":
            normalized[f"{resource.arg}_argv0"] = value
    return normalized
