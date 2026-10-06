"""Tests for direct tool guards, delegation, and approval resumption."""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.types import Command

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Decision,
    Effect,
    EscalationRequest,
    Principal,
    SecurityConfig,
    SecurityDeniedError,
    SecurityModule,
    Verdict,
    dac,
    delegate,
    effects,
    guarded_tool,
    principal_from,
    with_principal,
)
from langgraph.prebuilt.security.introspect import _unregister_guarded_tool


def _principal(scopes: frozenset[str] = frozenset({"read", "write"})) -> Principal:
    return Principal("alice", frozenset({"user"}), scopes, "session")


@pytest.fixture(autouse=True)
def _clean_guarded_registry():
    yield
    for name in ("direct_read", "direct_approve", "direct_async_approve"):
        _unregister_guarded_tool(name)


def test_guarded_tool_mediates_direct_invocation() -> None:
    """Calling a guarded tool without ToolNode still enforces the stack."""
    executed = 0

    class Deny(SecurityModule):
        name = "deny"

        def tool_call_permission(self, principal, call):
            return Decision(Verdict.DENY, "blocked")

    security = SecurityConfig(modules=[Deny()])

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"}, required_scopes={"read"})
    @effects(Effect.READ)
    def direct_read(value: str) -> str:
        """Read a value."""
        nonlocal executed
        executed += 1
        return value

    config = with_principal({}, _principal(), modules=security.modules)
    with pytest.raises(SecurityDeniedError, match="blocked"):
        direct_read.invoke({"value": "secret"}, config=config)
    assert executed == 0


@pytest.mark.asyncio
async def test_guarded_tool_async_parity() -> None:
    """A guarded async tool uses the same DAC and module semantics."""
    security = SecurityConfig()

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"}, required_scopes={"read"})
    @effects(Effect.READ)
    async def direct_read(value: str) -> str:
        """Read a value."""
        return value

    config = with_principal({}, _principal(), modules=security.modules)
    assert await direct_read.ainvoke({"value": "safe"}, config=config) == "safe"


def test_guarded_tool_escalation_resumes_and_rechecks() -> None:
    """Direct guards use the same durable approval path as ToolNode mediation."""
    executed = 0

    class ApprovalModule(SecurityModule):
        name = "approval"
        can_escalate = True

        def tool_call_permission(self, principal, call):
            return Decision(
                Verdict.ESCALATE,
                "approval_required",
                escalation=EscalationRequest(
                    "guarded-request", "sensitive", call.tool.name, call.call_id
                ),
            )

    security = SecurityConfig(modules=[ApprovalModule()])

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"}, required_scopes={"write"})
    @effects(Effect.WRITE)
    def direct_approve(value: str) -> str:
        """Change a value after approval."""
        nonlocal executed
        executed += 1
        return value

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([direct_approve]))
    builder.add_edge(START, "tools")
    graph = builder.compile(checkpointer=InMemorySaver())
    config = with_principal(
        {"configurable": {"thread_id": "guarded-approval"}},
        _principal(),
        modules=security.modules,
    )
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "direct_approve",
                        "args": {"value": "updated"},
                        "id": "guarded-call",
                    }
                ],
            )
        ]
    }

    interrupted = graph.invoke(request, config=config)
    assert interrupted["__interrupt__"][0].value["request_id"] == "guarded-request"
    result = graph.invoke(Command(resume={"approved": True}), config=config)

    assert executed == 1
    assert result["messages"][-1].content == "updated"


@pytest.mark.asyncio
async def test_guarded_tool_async_escalation_resumes_and_rechecks() -> None:
    """Async direct guards preserve durable approval and recheck semantics."""
    executed = 0

    class ApprovalModule(SecurityModule):
        name = "approval"
        can_escalate = True

        def tool_call_permission(self, principal, call):
            return Decision(
                Verdict.ESCALATE,
                "approval_required",
                escalation=EscalationRequest(
                    "guarded-async", "sensitive", call.tool.name, call.call_id
                ),
            )

    security = SecurityConfig(modules=[ApprovalModule()])

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"}, required_scopes={"write"})
    @effects(Effect.WRITE)
    async def direct_async_approve(value: str) -> str:
        """Change a value asynchronously after approval."""
        nonlocal executed
        executed += 1
        return value

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([direct_async_approve]))
    builder.add_edge(START, "tools")
    graph = builder.compile(checkpointer=InMemorySaver())
    config = with_principal(
        {"configurable": {"thread_id": "guarded-async-approval"}},
        _principal(),
        modules=security.modules,
    )
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "direct_async_approve",
                        "args": {"value": "updated"},
                        "id": "guarded-async-call",
                    }
                ],
            )
        ]
    }

    interrupted = await graph.ainvoke(request, config=config)
    assert interrupted["__interrupt__"][0].value["request_id"] == "guarded-async"
    result = await graph.ainvoke(Command(resume=True), config=config)

    assert executed == 1
    assert result["messages"][-1].content == "updated"


def test_delegate_reduces_authority_and_copies_private_blobs() -> None:
    """A child receives only requested scopes and independent module slots."""

    def inspect_principal(_: Any, config: RunnableConfig) -> tuple:
        principal = principal_from(config)
        assert principal is not None
        principal.security.allocate("example")["child"] = True
        return principal.scopes, principal.delegated_by

    parent = _principal()
    parent.security.allocate("example")["parent"] = True
    delegated = delegate(
        RunnableLambda(inspect_principal),
        scopes=["read"],
        security=SecurityConfig(),
    )

    result = delegated.invoke(None, config=with_principal({}, parent))

    assert result == (frozenset({"read"}), "alice")
    assert "child" not in parent.security["example"]


def test_delegate_rejects_scope_growth() -> None:
    """The mandatory capability module rejects delegated scope growth."""
    delegated = delegate(
        RunnableLambda(lambda value: value),
        scopes=["admin"],
        security=SecurityConfig(),
    )
    with pytest.raises(SecurityDeniedError, match="scope_growth"):
        delegated.invoke(None, config=with_principal({}, _principal()))


def test_delegate_does_not_reprepare_attenuated_module_slot() -> None:
    """Credential preparation cannot regrow a slot after transfer restricts it."""

    class Attenuating(SecurityModule):
        name = "attenuating"

        def cred_prepare(self, principal, slot):
            slot["level"] = 10

        def cred_transfer(self, parent, child, slot):
            slot["level"] = 1
            return Decision(Verdict.ALLOW, "attenuated")

    module = Attenuating()
    security = SecurityConfig(modules=[module])
    delegated = delegate(
        RunnableLambda(
            lambda _, config: principal_from(config).security["attenuating"]["level"]
        ),
        scopes=["read"],
        security=security,
    )
    config = with_principal({}, _principal(), modules=[module])

    assert delegated.invoke(None, config=config) == 1


@pytest.mark.asyncio
async def test_async_delegate_preserves_attenuated_module_slot() -> None:
    """Async delegation awaits transfer hooks without rerunning preparation."""

    class Attenuating(SecurityModule):
        name = "async_attenuating"

        def cred_prepare(self, principal, slot):
            slot["level"] = 10

        async def cred_transfer(self, parent, child, slot):
            slot["level"] = 1
            return Decision(Verdict.ALLOW, "attenuated")

    module = Attenuating()
    security = SecurityConfig(modules=[module])
    delegated = delegate(
        RunnableLambda(
            lambda _, config: principal_from(config).security["async_attenuating"][
                "level"
            ]
        ),
        scopes=["read"],
        security=security,
    )
    config = with_principal({}, _principal(), modules=[module])

    assert await delegated.ainvoke(None, config=config) == 1


def test_escalation_uses_interrupt_and_rechecks_approval() -> None:
    """Approval is argument-free policy input and rejection remains restrictive."""
    executed = 0

    class ApprovalModule(SecurityModule):
        name = "approval"
        can_escalate = True

        def tool_call_permission(self, principal, call):
            return Decision(
                Verdict.ESCALATE,
                "approval_required",
                escalation=EscalationRequest(
                    "request-1", "sensitive", call.tool.name, call.call_id
                ),
            )

    @tool
    @dac(owner="user", grants={"user": "x"}, required_scopes={"write"})
    @effects(Effect.WRITE)
    def change_value(value: str) -> str:
        """Change a value."""
        nonlocal executed
        executed += 1
        return value

    security = SecurityConfig(modules=[ApprovalModule()])
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([change_value]))
    builder.add_edge(START, "tools")
    graph = builder.compile(checkpointer=InMemorySaver(), security=security)
    config = with_principal(
        {"configurable": {"thread_id": "approval-test"}},
        _principal(),
        modules=security.modules,
    )
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "change_value",
                        "args": {"value": "updated"},
                        "id": "call-1",
                    }
                ],
            )
        ]
    }

    interrupted = graph.invoke(request, config=config)
    assert interrupted["__interrupt__"][0].value["request_id"] == "request-1"
    assert "args" not in interrupted["__interrupt__"][0].value
    result = graph.invoke(Command(resume={"approved": True}), config=config)

    assert executed == 1
    assert result["messages"][-1].content == "updated"
    principal = principal_from(config)
    assert principal is not None
    approval = principal.security["cap"]["approval:request-1"]
    assert approval.approved is True


def test_approval_rechecks_modules_after_escalating_module() -> None:
    """Approval cannot skip a restrictive module later in stack order."""
    executed = 0

    class ApprovalModule(SecurityModule):
        name = "approval"
        can_escalate = True

        def tool_call_permission(self, principal, call):
            return Decision(
                Verdict.ESCALATE,
                "approval_required",
                escalation=EscalationRequest(
                    "request-2", "sensitive", call.tool.name, call.call_id
                ),
            )

    class DenyAfterApproval(SecurityModule):
        name = "deny_after"

        def tool_call_permission(self, principal, call):
            return Decision(Verdict.DENY, "still_blocked")

    @tool
    @dac(owner="user", grants={"user": "x"})
    @effects(Effect.WRITE)
    def restricted_change(value: str) -> str:
        """Change a restricted value."""
        nonlocal executed
        executed += 1
        return value

    security = SecurityConfig(modules=[ApprovalModule(), DenyAfterApproval()])
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([restricted_change]))
    builder.add_edge(START, "tools")
    graph = builder.compile(checkpointer=InMemorySaver(), security=security)
    config = with_principal(
        {"configurable": {"thread_id": "approval-recheck"}},
        _principal(),
        modules=security.modules,
    )
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "restricted_change",
                        "args": {"value": "blocked"},
                        "id": "call-2",
                    }
                ],
            )
        ]
    }

    graph.invoke(request, config=config)
    result = graph.invoke(Command(resume={"approved": True}), config=config)

    assert executed == 0
    assert result["messages"][-1].status == "error"
    assert "still_blocked" in result["messages"][-1].content
