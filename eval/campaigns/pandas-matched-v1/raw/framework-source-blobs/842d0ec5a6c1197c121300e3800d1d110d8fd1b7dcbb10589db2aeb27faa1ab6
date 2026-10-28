"""Trusted policy/host contracts and construction for the host-only router."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionResult,
    HostToolExecutor,
)
from langgraph.prebuilt.security.objects import FrameworkRequest, ObjectAuthorization
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    PolicyConstraint,
    Principal,
    ToolCall,
    Verdict,
)

if TYPE_CHECKING:
    from langgraph.prebuilt.security.host_router import HostRouter


@dataclass(frozen=True, slots=True)
class ToolOrigin:
    """Untrusted origin description until the host authenticates its channel.

    The host must bind all fields to a live worker, its principal and parent
    call. These strings alone are not credentials and must never authenticate
    a caller. The channel handle is owned by the trusted host transport.
    """

    caller_tool: str
    parent_call_id: str
    channel: object


class BoundaryPolicy(Protocol):
    """Restrictive decisions; every non-ALLOW outcome prevents dispatch."""

    def permission(self, principal: Principal, call: ToolCall) -> Decision: ...
    async def apermission(self, principal: Principal, call: ToolCall) -> Decision: ...
    def delegation_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision: ...
    async def adelegation_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision: ...
    def transition_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision: ...
    async def atransition_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision: ...
    def object_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization: ...
    async def aobject_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization: ...
    def object_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> ObjectAuthorization: ...
    async def aobject_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> ObjectAuthorization: ...


class BoundaryHost(Protocol):
    """Trusted atomic activate-and-execute boundary, backed by host MAC.

    invoke/ainvoke must install the exact principal/request/constraints before
    tool imports or execution, and must not fall back to the control process.
    Cross-call methods additionally bind the live authenticated parent channel
    at dispatch, preserve every constraint sequence, and prevent access to a
    destination's execution authority except through this interface. Tools
    cannot enter the trusted root-call interface from their worker channels.
    """

    def origin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision: ...
    async def aorigin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision: ...
    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult: ...
    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult: ...
    def invoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: ToolCall,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult: ...
    async def ainvoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: ToolCall,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult: ...
    def dispatch(self, principal: Principal, request: FrameworkRequest) -> object: ...
    async def adispatch(
        self, principal: Principal, request: FrameworkRequest
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class HostExecutorBoundary:
    """Use an existing confined executor for root calls; deny cross-tool RPC.

    This adapter does not invent caller authentication for LinuxSandboxExecutor,
    which currently exposes no authenticated nested-tool transport. A host with
    such a transport must implement BoundaryHost instead.
    """

    executor: HostToolExecutor

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        return self.executor.invoke(principal, call, constraints)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        return await self.executor.ainvoke(principal, call, constraints)

    def origin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return Decision(Verdict.DENY, "host:cross_tool_transport_unavailable")

    async def aorigin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return self.origin_permission(origin, parent, child, call)

    def invoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: ToolCall,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:cross_tool_transport_unavailable")

    async def ainvoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: ToolCall,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:cross_tool_transport_unavailable")

    def dispatch(self, principal: Principal, request: FrameworkRequest) -> object:
        raise HostExecutionDenied("host:framework_dispatch_unavailable")

    async def adispatch(
        self, principal: Principal, request: FrameworkRequest
    ) -> object:
        raise HostExecutionDenied("host:framework_dispatch_unavailable")


@dataclass(frozen=True, slots=True)
class StackBoundaryPolicy:
    """Use existing DAC/MAC hooks and an explicit default-deny transition list.

    Policy implementations needing richer caller/callee rules can implement
    BoundaryPolicy. The caller retains ownership of the SecurityStack lifetime.
    """

    stack: SecurityStack
    transitions: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "transitions", frozenset(self.transitions))

    def permission(self, principal: Principal, call: ToolCall) -> Decision:
        decision, prepared = self.stack.prepare(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            return decision
        if prepared is not call:
            return Decision(Verdict.DENY, "router:transforms_require_new_request")
        return self.stack.permission(principal, call)

    async def apermission(self, principal: Principal, call: ToolCall) -> Decision:
        decision, prepared = await self.stack.aprepare(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            return decision
        if prepared is not call:
            return Decision(Verdict.DENY, "router:transforms_require_new_request")
        return await self.stack.apermission(principal, call)

    def delegation_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        if not _attenuated(parent, child):
            return Decision(Verdict.DENY, "router:authority_growth")
        return self.stack.cred_transfer(parent, child)

    async def adelegation_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        if not _attenuated(parent, child):
            return Decision(Verdict.DENY, "router:authority_growth")
        return await self.stack.acred_transfer(parent, child)

    def transition_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        if (origin.caller_tool, call.tool.name) not in self.transitions:
            return Decision(Verdict.DENY, "router:tool_transition_denied")
        return Decision(Verdict.ALLOW, "router:tool_transition_allowed")

    async def atransition_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return self.transition_permission(origin, parent, child, call)

    def object_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization:
        return self.stack.object_permission(principal, request)

    async def aobject_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization:
        return await self.stack.aobject_permission(principal, request)

    def object_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> ObjectAuthorization:
        return self.stack.object_resume_permission(principal, request, approval)

    async def aobject_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> ObjectAuthorization:
        return await self.stack.aobject_resume_permission(principal, request, approval)


class _AuthorizedCallPolicy:
    """Bind one caller-produced decision to the exact router invocation.

    This is the migration bridge for existing ToolNode and guarded_tool policy
    stacks. The trusted caller still owns preparation, approval, flow
    reservation, and post handling, but it can no longer dispatch a host call
    around HostRouter. Context-local binding prevents concurrent calls from
    exchanging decisions.
    """

    def __init__(self) -> None:
        self._authorization: ContextVar[tuple[Principal, ToolCall, Decision] | None] = (
            ContextVar("slanggraph_host_router_authorization", default=None)
        )

    @contextmanager
    def bind(
        self, principal: Principal, call: ToolCall, decision: Decision
    ) -> Iterator[None]:
        if decision.verdict is not Verdict.ALLOW:
            raise HostExecutionDenied("router:non_allow_authorization")
        token: Token[tuple[Principal, ToolCall, Decision] | None] = (
            self._authorization.set((principal, call, decision))
        )
        try:
            yield
        finally:
            self._authorization.reset(token)

    def permission(self, principal: Principal, call: ToolCall) -> Decision:
        authorization = self._authorization.get()
        if authorization is None:
            return Decision(Verdict.DENY, "router:missing_authorization")
        expected_principal, expected_call, decision = authorization
        if principal is not expected_principal or call is not expected_call:
            return Decision(Verdict.DENY, "router:authorization_identity_mismatch")
        return decision

    async def apermission(self, principal: Principal, call: ToolCall) -> Decision:
        return self.permission(principal, call)

    def delegation_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return Decision(Verdict.DENY, "router:root_bridge_cannot_delegate")

    async def adelegation_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return self.delegation_permission(origin, parent, child, call)

    def transition_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return Decision(Verdict.DENY, "router:root_bridge_cannot_transition")

    async def atransition_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> Decision:
        return self.transition_permission(origin, parent, child, call)

    def object_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization:
        return ObjectAuthorization(
            Decision(Verdict.DENY, "router:root_bridge_cannot_dispatch_framework"),
            request,
        )

    async def aobject_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization:
        return self.object_permission(principal, request)

    def object_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> ObjectAuthorization:
        return self.object_permission(principal, request)

    async def aobject_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> ObjectAuthorization:
        return self.object_permission(principal, request)


@dataclass(frozen=True, slots=True)
class AuthorizedHostRouter:
    """Route one already-decided root call through the verified HostRouter.

    This private-facing bridge is transitional: it removes direct host dispatch
    from the existing Tool APIs while preserving their current approval and
    lifecycle semantics. New object-manager entry points should call HostRouter
    with their policy implementation directly instead of using this adapter.
    """

    router: HostRouter
    policy: _AuthorizedCallPolicy

    def invoke(
        self, principal: Principal, call: ToolCall, decision: Decision
    ) -> HostExecutionResult:
        with self.policy.bind(principal, call, decision):
            return self.router.invoke(principal, call)

    async def ainvoke(
        self, principal: Principal, call: ToolCall, decision: Decision
    ) -> HostExecutionResult:
        with self.policy.bind(principal, call, decision):
            return await self.router.ainvoke(principal, call)


def _attenuated(parent: Principal, child: Principal) -> bool:
    return (
        parent.user_id == child.user_id
        and parent.session_id == child.session_id
        and child.roles.issubset(parent.roles)
        and child.scopes.issubset(parent.scopes)
        and child.delegated_by == parent.user_id
    )


def make_host_router(policy: BoundaryPolicy, host: BoundaryHost) -> HostRouter:
    """Admit the exact verified router implementation in a trusted controller.

    This verifies the router, not arbitrary supplied policy/host implementations.
    Host and policy contracts in the returned verification report remain explicit
    obligations for the embedding application. Never expose this object or the
    root principal-binding API inside a tool worker.
    """
    from langgraph.prebuilt.security.boundary_verification import verify_host_router
    from langgraph.prebuilt.security.host_router import HostRouter

    report = verify_host_router()
    if not report["complete"]:
        raise ValueError("host router has unresolved mediation obligations")
    # Construct only the exact class whose whole method surface was checked.
    router = HostRouter()
    router.policy = policy
    router.host = host
    return router


def make_authorized_host_router(executor: HostToolExecutor) -> AuthorizedHostRouter:
    """Build the migration bridge used by existing secured Tool APIs."""
    policy = _AuthorizedCallPolicy()
    return AuthorizedHostRouter(
        make_host_router(policy, HostExecutorBoundary(executor)), policy
    )
