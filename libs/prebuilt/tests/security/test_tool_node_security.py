"""Integration tests for innermost ToolNode security mediation."""

from __future__ import annotations

from typing import Annotated
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.runtime import Runtime
from langgraph.store.memory import InMemoryStore

from langgraph.prebuilt import InjectedState, ToolNode, ToolRuntime
from langgraph.prebuilt.security import (
    AuditRecord,
    Decision,
    Effect,
    ExecutionOutcome,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityConfig,
    SecurityIndeterminateError,
    SecurityModule,
    SecurityStack,
    ToolObjectDac,
    Verdict,
    dac,
    effects,
    with_principal,
)
from langgraph.prebuilt.security.execution import HostToolExecutor


class _FailingAuditSink(MemoryAuditSink):
    def __init__(self, stage: str) -> None:
        super().__init__()
        self.stage = stage

    def write(self, record: AuditRecord) -> AuditRecord:
        if record.stage == self.stage:
            raise OSError("audit unavailable")
        return super().write(record)


def _config(principal: Principal, *, store=None) -> dict:
    runtime = Mock(store=store, context=None, stream_writer=lambda _: None)
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


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("missing", ["call", "principal", "both"])
async def test_host_execution_denies_lost_security_context(
    monkeypatch, asynchronous, missing
) -> None:
    """A damaged preparation result cannot select the in-process branch."""
    executed = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    @effects(Effect.READ)
    def read_file(path: str) -> str:
        """Return fixture data."""
        executed.append(path)
        return path

    host = Mock(spec=HostToolExecutor)
    node = ToolNode([read_file], security=SecurityConfig(host_executor=host))
    prepare = node._prepare_security_request

    def damaged_preparation(request):
        decision, prepared, call = prepare(request)
        assert decision.verdict is Verdict.ALLOW
        if missing in {"principal", "both"}:
            prepared = prepared.override(principal=None)
        if missing in {"call", "both"}:
            call = None
        return decision, prepared, call

    monkeypatch.setattr(node, "_prepare_security_request", damaged_preparation)
    try:
        result = (
            await node.ainvoke(_request(), config=_config(_principal()))
            if asynchronous
            else node.invoke(_request(), config=_config(_principal()))
        )
    finally:
        node._security_stack.close()
    assert executed == []
    host.invoke.assert_not_called()
    host.ainvoke.assert_not_called()
    assert result["messages"][0].status == "error"
    assert "host:missing_security_context" in result["messages"][0].content


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


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_parallel_tool_dispatch_records_one_identity_transfer_per_call(
    asynchronous: bool,
) -> None:
    transfers: list[str] = []
    executed: list[str] = []

    class RecordTransfer(SecurityModule):
        name = "record_transfer"

        def cred_transfer(self, parent, child, slot):
            assert child is parent
            transfers.append(parent.user_id)
            return Decision(Verdict.ALLOW, "identity_transfer")

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    @effects(Effect.READ)
    def read_file(path: str) -> str:
        """Read a path."""
        executed.append(path)
        return path

    node = ToolNode([read_file], security=SecurityConfig(modules=(RecordTransfer(),)))
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "read_file", "args": {"path": "/one"}, "id": "1"},
                    {"name": "read_file", "args": {"path": "/two"}, "id": "2"},
                ],
            )
        ]
    }
    try:
        result = (
            await node.ainvoke(request, config=_config(_principal()))
            if asynchronous
            else node.invoke(request, config=_config(_principal()))
        )
    finally:
        node._security_stack.close()

    assert sorted(executed) == ["/one", "/two"]
    assert transfers == ["alice", "alice"]
    assert all(message.status == "success" for message in result["messages"])


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

    node = ToolNode(
        [read_file],
        security=SecurityConfig(
            modules=(InspectInjected(),),
            object_dacs={
                "read_file": ToolObjectDac(readable_channels=frozenset({"messages"}))
            },
        ),
    )
    stack = node._security_stack
    assert stack is not None
    try:
        result = node.invoke(_request(), config=_config(_principal()))
    finally:
        stack.close()

    assert result["messages"][0].content == "/safe"
    assert len(observed) == 2
    assert observed[0] is observed[1]


def test_secured_tool_runtime_exposes_only_declared_objects() -> None:
    observed: list[ToolRuntime] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def read_file(path: str, runtime: ToolRuntime) -> str:
        """Inspect the capability-shaped runtime."""
        observed.append(runtime)
        return path

    node = ToolNode(
        [read_file],
        security=SecurityConfig(
            object_dacs={
                "read_file": ToolObjectDac(readable_channels=frozenset({"messages"}))
            }
        ),
    )
    result = node.invoke(
        {**_request(), "secret": "must-not-cross"}, config=_config(_principal())
    )

    assert result["messages"][0].content == "/safe"
    runtime = observed[0]
    assert set(runtime.state) == {"messages"}
    assert runtime.config == {}
    assert runtime.context is None
    assert runtime.store is None
    assert runtime.tools == []
    assert runtime.execution_info is None
    assert runtime.server_info is None
    assert runtime.principal_id == "alice"


def test_undeclared_injected_channel_is_denied() -> None:
    executed = False

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def read_file(path: str, secret: Annotated[str, InjectedState("secret")]) -> str:
        """Try to receive an undeclared channel."""
        nonlocal executed
        executed = True
        return secret

    node = ToolNode([read_file], security=SecurityConfig())
    result = node.invoke(
        {**_request(), "secret": "must-not-cross"}, config=_config(_principal())
    )

    assert not executed
    assert result["messages"][0].status == "error"
    assert "state:channel_not_granted:secret" in result["messages"][0].content


def test_injected_store_allows_only_exact_declared_keys() -> None:
    store = InMemoryStore()

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def read_file(path: str, runtime: ToolRuntime) -> str:
        """Use the mediated exact-key store facade."""
        assert runtime.store is not None
        runtime.store.put(("notes",), "item", {"value": path})
        item = runtime.store.get(("notes",), "item")
        assert item is not None
        with pytest.raises(PermissionError, match="dac:object_not_granted"):
            runtime.store.get(("notes",), "other")
        return item.value["value"]

    node = ToolNode(
        [read_file],
        security=SecurityConfig(
            object_dacs={
                "read_file": ToolObjectDac(
                    readable_store_keys=frozenset({"notes/item"}),
                    writable_store_keys=frozenset({"notes/item"}),
                )
            }
        ),
    )
    result = node.invoke(_request(), config=_config(_principal(), store=store))

    assert result["messages"][0].content == "/safe"


def test_dynamic_tool_without_profile_is_registered_but_default_denied() -> None:
    executed = False

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def registered(path: str) -> str:
        """A statically registered placeholder."""
        return path

    @tool("dynamic")
    def dynamic(path: str) -> str:
        """An undeclared runtime tool."""
        nonlocal executed
        executed = True
        return path

    def resolve(request, execute):
        return execute(request.override(tool=dynamic))

    node = ToolNode([registered], wrap_tool_call=resolve, security=SecurityConfig())
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "dynamic", "args": {"path": "/safe"}, "id": "d-1"}
                ],
            )
        ]
    }
    result = node.invoke(request, config=_config(_principal()))

    assert not executed
    assert result["messages"][0].status == "error"
    assert "dac:" in result["messages"][0].content


@pytest.mark.asyncio
async def test_declared_dynamic_tool_runs_after_async_allocation() -> None:
    executed = False

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    async def registered(path: str) -> str:
        """A statically registered placeholder."""
        return path

    @tool("dynamic")
    @dac(owner="analyst", grants={"analyst": "x"})
    async def dynamic(path: str) -> str:
        """A declared runtime tool."""
        nonlocal executed
        executed = True
        return path

    async def resolve(request, execute):
        return await execute(request.override(tool=dynamic))

    node = ToolNode([registered], awrap_tool_call=resolve, security=SecurityConfig())
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "dynamic", "args": {"path": "/safe"}, "id": "d-1"}
                ],
            )
        ]
    }
    result = await node.ainvoke(request, config=_config(_principal()))

    assert executed
    assert result["messages"][0].content == "/safe"


def test_missing_principal_fails_closed() -> None:
    """Security-enabled ToolNode never derives identity from state."""

    @tool
    def read_file(path: str) -> str:
        """Read a path."""
        return path

    runtime = Runtime(context=None)
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
