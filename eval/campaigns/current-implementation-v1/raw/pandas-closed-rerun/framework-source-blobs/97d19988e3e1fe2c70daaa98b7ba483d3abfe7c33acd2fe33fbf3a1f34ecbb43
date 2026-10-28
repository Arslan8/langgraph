"""Host-only routing core whose complete method surface is source-verified.

Policy and host objects are installed by make_host_router in the trusted
control plane. Workers receive a host-authenticated RPC channel, never this
object, the policy object, or a raw tool callable.
"""

from __future__ import annotations

from langgraph.prebuilt.security.execution import HostExecutionResult
from langgraph.prebuilt.security.host_boundary import (
    BoundaryHost,
    BoundaryPolicy,
    ToolOrigin,
)
from langgraph.prebuilt.security.objects import (
    DispatchRequest,
    FrameworkRequest,
    ModelInvocationRequest,
    OutputRequest,
    StateRequest,
    ToolRegistryRequest,
)
from langgraph.prebuilt.security.types import Approval, Principal, ToolCall, Verdict


class HostRouter:
    """Mediate root and cross-tool calls without an in-process execution path."""

    __slots__ = ("policy", "host")

    policy: BoundaryPolicy
    host: BoundaryHost

    def invoke(self, principal: Principal, call: ToolCall) -> HostExecutionResult:
        decision = self.policy.permission(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError(decision.reason)
        return self.host.invoke(principal, call, decision.constraints)

    async def ainvoke(
        self, principal: Principal, call: ToolCall
    ) -> HostExecutionResult:
        decision = await self.policy.apermission(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError(decision.reason)
        return await self.host.ainvoke(principal, call, decision.constraints)

    def invoke_from(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> HostExecutionResult:
        identity = self.host.origin_permission(origin, parent, child, call)
        if identity.verdict is not Verdict.ALLOW:
            raise PermissionError(identity.reason)
        delegation = self.policy.delegation_permission(origin, parent, child, call)
        if delegation.verdict is not Verdict.ALLOW:
            raise PermissionError(delegation.reason)
        transition = self.policy.transition_permission(origin, parent, child, call)
        if transition.verdict is not Verdict.ALLOW:
            raise PermissionError(transition.reason)
        decision = self.policy.permission(child, call)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError(decision.reason)
        return self.host.invoke_from(
            origin,
            parent,
            child,
            call,
            decision.constraints,
            delegation.constraints,
            transition.constraints,
        )

    async def ainvoke_from(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: ToolCall
    ) -> HostExecutionResult:
        identity = await self.host.aorigin_permission(origin, parent, child, call)
        if identity.verdict is not Verdict.ALLOW:
            raise PermissionError(identity.reason)
        delegation = await self.policy.adelegation_permission(
            origin, parent, child, call
        )
        if delegation.verdict is not Verdict.ALLOW:
            raise PermissionError(delegation.reason)
        transition = await self.policy.atransition_permission(
            origin, parent, child, call
        )
        if transition.verdict is not Verdict.ALLOW:
            raise PermissionError(transition.reason)
        decision = await self.policy.apermission(child, call)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError(decision.reason)
        return await self.host.ainvoke_from(
            origin,
            parent,
            child,
            call,
            decision.constraints,
            delegation.constraints,
            transition.constraints,
        )

    def route(self, principal: Principal, request: FrameworkRequest) -> object:
        authorization = self.policy.object_permission(principal, request)
        if authorization.decision.verdict is Verdict.ESCALATE:
            return authorization
        if authorization.decision.verdict is not Verdict.ALLOW:
            raise PermissionError(authorization.decision.reason)
        return self.host.dispatch(principal, authorization.request)

    async def aroute(self, principal: Principal, request: FrameworkRequest) -> object:
        authorization = await self.policy.aobject_permission(principal, request)
        if authorization.decision.verdict is Verdict.ESCALATE:
            return authorization
        if authorization.decision.verdict is not Verdict.ALLOW:
            raise PermissionError(authorization.decision.reason)
        return await self.host.adispatch(principal, authorization.request)

    def resume(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> object:
        authorization = self.policy.object_resume_permission(
            principal, request, approval
        )
        if authorization.decision.verdict is not Verdict.ALLOW:
            raise PermissionError(authorization.decision.reason)
        return self.host.dispatch(principal, authorization.request)

    async def aresume(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ) -> object:
        authorization = await self.policy.aobject_resume_permission(
            principal, request, approval
        )
        if authorization.decision.verdict is not Verdict.ALLOW:
            raise PermissionError(authorization.decision.reason)
        return await self.host.adispatch(principal, authorization.request)

    def dispatch(self, principal: Principal, request: DispatchRequest) -> object:
        return self.route(principal, request)

    async def adispatch(self, principal: Principal, request: DispatchRequest) -> object:
        return await self.aroute(principal, request)

    def register(self, principal: Principal, request: ToolRegistryRequest) -> object:
        return self.route(principal, request)

    async def aregister(
        self, principal: Principal, request: ToolRegistryRequest
    ) -> object:
        return await self.aroute(principal, request)

    def state(self, principal: Principal, request: StateRequest) -> object:
        return self.route(principal, request)

    async def astate(self, principal: Principal, request: StateRequest) -> object:
        return await self.aroute(principal, request)

    def model_invoke(
        self, principal: Principal, request: ModelInvocationRequest
    ) -> object:
        return self.route(principal, request)

    async def amodel_invoke(
        self, principal: Principal, request: ModelInvocationRequest
    ) -> object:
        return await self.aroute(principal, request)

    def output_emit(self, principal: Principal, request: OutputRequest) -> object:
        return self.route(principal, request)

    async def aoutput_emit(
        self, principal: Principal, request: OutputRequest
    ) -> object:
        return await self.aroute(principal, request)

    def run(self, principal: Principal, call: ToolCall) -> HostExecutionResult:
        return self.invoke(principal, call)

    async def arun(self, principal: Principal, call: ToolCall) -> HostExecutionResult:
        return await self.ainvoke(principal, call)

    def __call__(self, principal: Principal, call: ToolCall) -> HostExecutionResult:
        return self.invoke(principal, call)
