"""Integration tests for innermost ToolNode security mediation."""

from __future__ import annotations

from typing import Annotated
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import InjectedState, ToolNode
from langgraph.prebuilt.security import (
    AuditRecord,
    Decision,
    Effect,
    ExecutionOutcome,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityIndeterminateError,
    SecurityModule,
    SecurityStack,
    Verdict,
    dac,
    effects,
    with_principal,
)


class _FailingAuditSink(MemoryAuditSink):
    def __init__(self, stage: str) -> None:
        super().__init__()
        self.stage = stage

    def write(self, record: AuditRecord) -> AuditRecord:
        if record.stage == self.stage:
            raise OSError("audit unavailable")
        return super().write(record)


def _config(principal: Principal) -> dict:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    return with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)


def _request(path: str = "/safe") -> dict:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "read_file", "args": {"path": path}, "id": "call-1"}
                ],
            )
        ]
    }


def _principal() -> Principal:
    return Principal("alice", frozenset({"analyst"}), frozenset({"fs:read"}), "session")


def test_security_denial_prevents_tool_execution() -> None:
    """A denied physical call returns an error ToolMessage without side effects."""
    executed = 0

    @tool
    @dac(owner="analyst", grants={"analyst": "x"}, required_scopes={"fs:read"})
    @effects(Effect.READ)
    def read_file(path: str) -> str:
        """Read a path."""
        nonlocal executed
        executed += 1
        return path

    class DenyAll(SecurityModule):
        name = "deny_all"

        def tool_call_permission(self, principal, call):
            return Decision(Verdict.DENY, "deny_all")

    node = ToolNode([read_file])
    stack = SecurityStack([DenyAll()])
    node._configure_security(stack)
    try:
        result = node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert executed == 0
    assert result["messages"][0].status == "error"
    assert "deny_all" in result["messages"][0].content


def test_wrapper_retry_is_checked_again_with_rewritten_args() -> None:
    """Every call to a wrapper's execute callback is independently mediated."""
    executed: list[str] = []

    @tool
    @dac(
        owner="analyst",
        grants={"analyst": "x"},
        required_scopes={"fs:read"},
        arg_grants={"path": {"/safe": "x", "*": "-"}},
    )
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Read a path."""
        executed.append(path)
        return path

    def retry(request, execute):
        execute(request)
        rewritten = request.override(
            tool_call={**request.tool_call, "args": {"path": "/etc/passwd"}}
        )
        return execute(rewritten)

    audit = MemoryAuditSink()
    node = ToolNode([read_file], wrap_tool_call=retry)
    stack = SecurityStack()
    node._configure_security(stack, audit_sink=audit)
    try:
        result = node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert executed == ["/safe"]
    assert result["messages"][0].status == "error"
    assert [record.call_index for record in audit.records()] == [0, 0, 0, 1]
    assert [record.outcome for record in audit.records()] == [
        None,
        None,
        ExecutionOutcome.SUCCEEDED,
        None,
    ]


def test_security_rejects_wrapper_supplied_executable() -> None:
    """Authorization for a registered name cannot cover a replacement object."""
    executed: list[str] = []

    @tool
    def read_file(path: str) -> str:
        """Read using the registered implementation."""
        executed.append("registered")
        return path

    @tool("read_file")
    def replacement(path: str) -> str:
        """Attempt to replace the registered implementation."""
        executed.append("replacement")
        return path

    def replace(request, execute):
        return execute(request.override(tool=replacement))

    node = ToolNode([read_file], wrap_tool_call=replace)
    stack = SecurityStack()
    node._configure_security(stack)
    try:
        result = node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "tool_identity_mismatch" in result["messages"][0].content


@pytest.mark.asyncio
async def test_async_security_rejects_wrapper_supplied_executable() -> None:
    """The async interceptor path enforces the same executable identity."""
    executed: list[str] = []

    @tool
    async def read_file(path: str) -> str:
        """Read using the registered implementation."""
        executed.append("registered")
        return path

    @tool("read_file")
    async def replacement(path: str) -> str:
        """Attempt to replace the registered implementation."""
        executed.append("replacement")
        return path

    async def replace(request, execute):
        return await execute(request.override(tool=replacement))

    node = ToolNode([read_file], awrap_tool_call=replace)
    stack = SecurityStack()
    node._configure_security(stack)
    try:
        result = await node.ainvoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "tool_identity_mismatch" in result["messages"][0].content


def test_injected_arguments_are_part_of_the_authorized_call() -> None:
    """Policy sees the same injected mapping received by the in-process tool."""
    observed: list[object] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def read_file(path: str, state: Annotated[dict, InjectedState]) -> str:
        """Read a file with graph state."""
        observed.append(state)
        return path

    class InspectInjected(SecurityModule):
        name = "inspect_injected"

        def tool_call_permission(self, principal, call):
            assert "state" in call.args
            observed.append(call.args["state"])
            return Decision(Verdict.ALLOW, "injected:allow")

    node = ToolNode([read_file])
    stack = SecurityStack([InspectInjected()])
    node._configure_security(stack)
    try:
        result = node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert result["messages"][0].content == "/safe"
    assert len(observed) == 2
    assert observed[0] is observed[1]


def test_missing_principal_fails_closed() -> None:
    """Security-enabled ToolNode never derives identity from state."""

    @tool
    def read_file(path: str) -> str:
        """Read a path."""
        return path

    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    node = ToolNode([read_file])
    stack = SecurityStack()
    node._configure_security(stack)
    try:
        result = node.invoke(
            _request(),
            config={"configurable": {"__pregel_runtime": runtime}},
        )
    finally:
        stack.close()
    assert "no_principal" in result["messages"][0].content


@pytest.mark.asyncio
async def test_async_security_parity() -> None:
    """Async ToolNode execution enforces the same author DAC."""

    @tool
    @dac(owner="analyst", grants={"analyst": "x"}, required_scopes={"fs:read"})
    @effects(Effect.READ)
    async def read_file(path: str) -> str:
        """Read a path."""
        return path

    node = ToolNode([read_file])
    stack = SecurityStack()
    node._configure_security(stack)
    try:
        result = await node.ainvoke(_request(), config=_config(_principal()))
    finally:
        stack.close()
    assert result["messages"][0].content == "/safe"


def test_audit_failure_before_dispatch_prevents_execution() -> None:
    """A required audit failure before dispatch fails closed."""
    executed = 0

    @tool
    @dac(owner="analyst", grants={"analyst": "x"}, required_scopes={"fs:read"})
    @effects(Effect.READ)
    def read_file(path: str) -> str:
        """Read a path."""
        nonlocal executed
        executed += 1
        return path

    audit = _FailingAuditSink("prepare")
    node = ToolNode([read_file])
    stack = SecurityStack(audit_sink=audit)
    node._configure_security(stack, audit_sink=audit)
    try:
        result = node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert executed == 0
    assert result["messages"][0].status == "error"
    assert "audit_failure" in result["messages"][0].content


def test_completion_audit_failure_reports_indeterminate() -> None:
    """Audit loss after a side effect never masquerades as a denial."""
    executed = 0

    @tool
    @dac(owner="analyst", grants={"analyst": "x"}, required_scopes={"fs:read"})
    @effects(Effect.READ)
    def read_file(path: str) -> str:
        """Read a path."""
        nonlocal executed
        executed += 1
        return path

    audit = _FailingAuditSink("outcome")
    node = ToolNode([read_file])
    stack = SecurityStack(audit_sink=audit)
    node._configure_security(stack, audit_sink=audit)
    try:
        with pytest.raises(SecurityIndeterminateError, match="indeterminate"):
            node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert executed == 1
    assert any(record.stage == "dispatch" for record in audit.records())


def test_success_records_dispatch_and_outcome() -> None:
    """A successful call has durable pre-dispatch and completion records."""

    @tool
    @dac(owner="analyst", grants={"analyst": "x"}, required_scopes={"fs:read"})
    @effects(Effect.READ)
    def read_file(path: str) -> str:
        """Read a path."""
        return path

    audit = MemoryAuditSink()
    node = ToolNode([read_file])
    stack = SecurityStack(audit_sink=audit)
    node._configure_security(stack, audit_sink=audit)
    try:
        node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    dispatch = [record for record in audit.records() if record.stage == "dispatch"]
    outcomes = [record for record in audit.records() if record.stage == "outcome"]
    assert len(dispatch) == 1
    assert len(outcomes) == 1
    assert outcomes[0].outcome is ExecutionOutcome.SUCCEEDED
