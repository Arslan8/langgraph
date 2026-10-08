"""Runtime checks of the proved routing boundary with a protocol-level host."""

import asyncio
from dataclasses import replace
from unittest.mock import Mock

import pytest

from langgraph.prebuilt.security import (
    Decision,
    Effect,
    EscalationRequest,
    ForbidConstraint,
    Principal,
    RulePredicate,
    SecurityModule,
    SecurityStack,
    Tool,
    ToolCall,
    ToolDac,
    Verdict,
)
from langgraph.prebuilt.security.enforcement import ActivationReceipt
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionResult,
    HostToolExecutor,
)
from langgraph.prebuilt.security.host_boundary import (
    HostExecutorBoundary,
    StackBoundaryPolicy,
    ToolOrigin,
    make_authorized_host_router,
    make_host_router,
)


def _decision(verdict: Verdict, reason: str) -> Decision:
    if verdict is Verdict.TRANSFORM:
        return Decision(verdict, reason, new_args={"value": "changed"})
    if verdict is Verdict.ESCALATE:
        return Decision(
            verdict,
            reason,
            escalation=EscalationRequest("approval", reason, "tool_b", "call"),
        )
    return Decision(verdict, reason)


def _context():
    parent = Principal("alice", frozenset({"operator"}), frozenset({"read"}), "session")
    child = replace(parent, delegated_by="alice")
    tool = Tool(
        "tool_b",
        ToolDac("operator", {"operator": "x", "*": "-"}),
        frozenset({Effect.READ}),
        (),
    )
    call = ToolCall(tool, {"value": "data"}, {}, "call", 0)
    origin = ToolOrigin("tool_a", "parent", object())
    return origin, parent, child, call


class Policy:
    def __init__(self, events):
        self.events = events
        self.decisions = {
            name: Decision(
                Verdict.ALLOW,
                name,
                constraints=(
                    ForbidConstraint(name, RulePredicate(domain="network"), name),
                ),
            )
            for name in ("tool", "delegation", "transition")
        }

    def permission(self, principal, call):
        self.events.append("tool")
        return self.decisions["tool"]

    async def apermission(self, principal, call):
        return self.permission(principal, call)

    def delegation_permission(self, origin, parent, child, call):
        self.events.append("delegation")
        return self.decisions["delegation"]

    async def adelegation_permission(self, origin, parent, child, call):
        return self.delegation_permission(origin, parent, child, call)

    def transition_permission(self, origin, parent, child, call):
        self.events.append("transition")
        return self.decisions["transition"]

    async def atransition_permission(self, origin, parent, child, call):
        return self.transition_permission(origin, parent, child, call)


class Host:
    """In-memory protocol fixture; this does not supply kernel evidence."""

    def __init__(self, events, origin):
        self.events = events
        self.origin = origin
        self.identity = Decision(Verdict.ALLOW, "origin")
        self.executions = []
        self.fail_activation = False

    def origin_permission(self, origin, parent, child, call):
        self.events.append("origin")
        if origin != self.origin or origin.channel is not self.origin.channel:
            return Decision(Verdict.DENY, "untrusted_channel")
        return self.identity

    async def aorigin_permission(self, origin, parent, child, call):
        return self.origin_permission(origin, parent, child, call)

    def invoke(self, principal, call, constraints):
        self.events.append("activate")
        if self.fail_activation:
            raise HostExecutionDenied("activation_failed")
        self.events.append("execute")
        self.executions.append((principal, call, tuple(constraints)))
        return HostExecutionResult("result", Mock(spec=ActivationReceipt))

    async def ainvoke(self, principal, call, constraints):
        return self.invoke(principal, call, constraints)

    def invoke_from(
        self,
        origin,
        parent,
        child,
        call,
        tool_constraints,
        delegation_constraints,
        transition_constraints,
    ):
        if (
            self.origin_permission(origin, parent, child, call).verdict
            is not Verdict.ALLOW
        ):
            raise HostExecutionDenied("origin_expired")
        return self.invoke(
            child,
            call,
            (*tool_constraints, *delegation_constraints, *transition_constraints),
        )

    async def ainvoke_from(
        self,
        origin,
        parent,
        child,
        call,
        tool_constraints,
        delegation_constraints,
        transition_constraints,
    ):
        return self.invoke_from(
            origin,
            parent,
            child,
            call,
            tool_constraints,
            delegation_constraints,
            transition_constraints,
        )


@pytest.mark.parametrize("api", ["invoke", "ainvoke", "run", "arun", "__call__"])
def test_every_root_api_routes_through_permission_and_host(api):
    origin, parent, _, call = _context()
    events = []
    policy, host = Policy(events), Host(events, origin)
    router = make_host_router(policy, host)
    method = getattr(router, api)
    result = (
        asyncio.run(method(parent, call))
        if api in {"ainvoke", "arun"}
        else method(parent, call)
    )
    assert result.value == "result"
    assert events == ["tool", "activate", "execute"]
    assert host.executions == [(parent, call, policy.decisions["tool"].constraints)]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_cross_call_preserves_all_constraint_domains(asynchronous):
    origin, parent, child, call = _context()
    events = []
    policy, host = Policy(events), Host(events, origin)
    router = make_host_router(policy, host)
    if asynchronous:
        result = asyncio.run(router.ainvoke_from(origin, parent, child, call))
    else:
        result = router.invoke_from(origin, parent, child, call)
    assert result.value == "result"
    assert events == [
        "origin",
        "delegation",
        "transition",
        "tool",
        "origin",
        "activate",
        "execute",
    ]
    assert host.executions[0][:2] == (child, call)
    assert [item.constraint_id for item in host.executions[0][2]] == [
        "tool",
        "delegation",
        "transition",
    ]


@pytest.mark.parametrize("gate", ["origin", "delegation", "transition", "tool"])
@pytest.mark.parametrize("verdict", [Verdict.DENY, Verdict.ESCALATE, Verdict.TRANSFORM])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_every_non_allow_cross_call_gate_prevents_execution(
    gate, verdict, asynchronous
):
    origin, parent, child, call = _context()
    events = []
    policy, host = Policy(events), Host(events, origin)
    if gate == "origin":
        host.identity = _decision(verdict, "blocked")
    else:
        policy.decisions[gate] = _decision(verdict, "blocked")
    router = make_host_router(policy, host)
    with pytest.raises(PermissionError, match="blocked"):
        if asynchronous:
            asyncio.run(router.ainvoke_from(origin, parent, child, call))
        else:
            router.invoke_from(origin, parent, child, call)
    assert "activate" not in events and not host.executions


def test_untrusted_origin_strings_do_not_authenticate_a_channel():
    origin, parent, child, call = _context()
    host = Host([], origin)
    router = make_host_router(Policy(host.events), host)
    with pytest.raises(PermissionError, match="untrusted_channel"):
        router.invoke_from(replace(origin, channel=object()), parent, child, call)
    assert host.events == ["origin"] and not host.executions


@pytest.mark.parametrize("asynchronous", [False, True])
def test_host_failure_never_falls_back_or_retries(asynchronous):
    origin, parent, _, call = _context()
    events = []
    policy, host = Policy(events), Host(events, origin)
    host.fail_activation = True
    router = make_host_router(policy, host)
    with pytest.raises(HostExecutionDenied, match="activation_failed"):
        if asynchronous:
            asyncio.run(router.ainvoke(parent, call))
        else:
            router.invoke(parent, call)
    assert events == ["tool", "activate"] and not host.executions


def test_retry_reauthorizes_and_observes_new_denial():
    origin, parent, _, call = _context()
    events = []
    policy, host = Policy(events), Host(events, origin)
    router = make_host_router(policy, host)
    router.invoke(parent, call)
    policy.decisions["tool"] = Decision(Verdict.DENY, "revoked")
    with pytest.raises(PermissionError, match="revoked"):
        router.invoke(parent, call)
    assert len(host.executions) == 1 and events.count("tool") == 2


@pytest.mark.parametrize("asynchronous", [False, True])
def test_existing_tool_api_bridge_enters_router_with_exact_decision(asynchronous):
    _, parent, _, call = _context()
    receipt = Mock(spec=ActivationReceipt)
    executor = Mock(spec=HostToolExecutor)
    executor.invoke.return_value = HostExecutionResult("result", receipt)
    executor.ainvoke.return_value = HostExecutionResult("result", receipt)
    decision = Decision(
        Verdict.ALLOW,
        "existing_stack_allowed",
        constraints=(
            ForbidConstraint("existing", RulePredicate(domain="network"), "existing"),
        ),
    )
    bridge = make_authorized_host_router(executor)

    result = (
        asyncio.run(bridge.ainvoke(parent, call, decision))
        if asynchronous
        else bridge.invoke(parent, call, decision)
    )

    assert result.value == "result"
    expected = (parent, call, decision.constraints)
    if asynchronous:
        executor.ainvoke.assert_awaited_once_with(*expected)
        executor.invoke.assert_not_called()
    else:
        executor.invoke.assert_called_once_with(*expected)
        executor.ainvoke.assert_not_called()
    with pytest.raises(PermissionError, match="router:missing_authorization"):
        bridge.router.invoke(parent, call)


def test_existing_tool_api_bridge_rejects_non_allow_decision():
    _, parent, _, call = _context()
    bridge = make_authorized_host_router(Mock(spec=HostToolExecutor))
    with pytest.raises(HostExecutionDenied, match="router:non_allow_authorization"):
        bridge.invoke(parent, call, Decision(Verdict.DENY, "blocked"))


@pytest.mark.parametrize("asynchronous", [False, True])
def test_existing_host_adapter_denies_unsupported_cross_tool_transport(asynchronous):
    origin, parent, child, call = _context()
    executor = Mock()
    host = HostExecutorBoundary(executor)
    router = make_host_router(Policy([]), host)
    with pytest.raises(PermissionError, match="cross_tool_transport_unavailable"):
        if asynchronous:
            asyncio.run(router.ainvoke_from(origin, parent, child, call))
        else:
            router.invoke_from(origin, parent, child, call)
    executor.invoke.assert_not_called()
    executor.ainvoke.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("roles", frozenset({"admin"})),
        ("scopes", frozenset({"write"})),
        ("user_id", "bob"),
        ("session_id", "other"),
        ("delegated_by", None),
    ],
)
def test_stack_adapter_rejects_delegation_growth(field, value):
    origin, parent, child, call = _context()
    stack = SecurityStack(())
    try:
        policy = StackBoundaryPolicy(stack, frozenset({("tool_a", "tool_b")}))
        widened = replace(child, **{field: value})
        assert (
            policy.delegation_permission(origin, parent, widened, call).verdict
            is Verdict.DENY
        )
        assert (
            asyncio.run(
                policy.adelegation_permission(origin, parent, widened, call)
            ).verdict
            is Verdict.DENY
        )
    finally:
        stack.close()


def test_stack_adapter_uses_default_deny_transitions_and_actual_mac():
    origin, parent, child, call = _context()
    stack = SecurityStack(())
    try:
        policy = StackBoundaryPolicy(stack)
        assert (
            policy.transition_permission(origin, parent, child, call).verdict
            is Verdict.DENY
        )
        allowed = StackBoundaryPolicy(stack, frozenset({("tool_a", "tool_b")}))
        assert (
            allowed.delegation_permission(origin, parent, child, call).verdict
            is Verdict.ALLOW
        )
        assert (
            asyncio.run(
                allowed.adelegation_permission(origin, parent, child, call)
            ).verdict
            is Verdict.ALLOW
        )
        assert allowed.permission(child, call).verdict is Verdict.ALLOW
        assert asyncio.run(allowed.apermission(child, call)).verdict is Verdict.ALLOW
        assert (
            asyncio.run(
                allowed.atransition_permission(origin, parent, child, call)
            ).verdict
            is Verdict.ALLOW
        )
        assert (
            allowed.permission(replace(child, roles=frozenset()), call).verdict
            is Verdict.DENY
        )
    finally:
        stack.close()


def test_argument_transform_requires_a_new_request_and_decision():
    class Transform(SecurityModule):
        def tool_call_prepare(self, principal, call):
            return Decision(
                Verdict.TRANSFORM, "rewrite", new_args={"value": "different"}
            )

    _, parent, _, call = _context()
    stack = SecurityStack((Transform(),))
    try:
        policy = StackBoundaryPolicy(stack)
        assert (
            policy.permission(parent, call).reason
            == "router:transforms_require_new_request"
        )
        assert (
            asyncio.run(policy.apermission(parent, call)).reason
            == "router:transforms_require_new_request"
        )
    finally:
        stack.close()
