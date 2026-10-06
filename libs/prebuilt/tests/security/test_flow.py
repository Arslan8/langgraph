"""Session-wide information-flow enforcement tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Confidentiality,
    MemoryAuditSink,
    Principal,
    SecurityConfig,
    SessionFlowPolicy,
    SqliteFlowStateStore,
    ToolFlowRule,
    dac,
    guarded_tool,
    with_principal,
)
from langgraph.prebuilt.security.introspect import _unregister_guarded_tool


@pytest.fixture(autouse=True)
def _clean_guarded_inventory() -> None:
    """Keep guarded tools created by these tests out of global inventory."""
    yield
    _unregister_guarded_tool("read_secret")
    _unregister_guarded_tool("send_external")


def _config(principal: Principal) -> dict:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    return with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)


def _request(*names: str) -> dict:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": name, "args": {}, "id": f"call-{index}"}
                    for index, name in enumerate(names)
                ],
            )
        ]
    }


def _tools(executed: list[str]):
    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def read_secret() -> str:
        """Read operator-classified secret data."""
        executed.append("read")
        return "secret"

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def send_external() -> str:
        """Send data to an external sink."""
        executed.append("send")
        return "sent"

    return read_secret, send_external


def _policy(*, store=None) -> SessionFlowPolicy:
    return SessionFlowPolicy(
        {
            "read_secret": ToolFlowRule(Confidentiality.SECRET),
            "send_external": ToolFlowRule(
                Confidentiality.PUBLIC, Confidentiality.PUBLIC
            ),
        },
        store=store,
    )


def test_later_egress_is_denied_after_sensitive_read() -> None:
    """A result retained through model or graph state taints the whole session."""
    executed: list[str] = []
    node = ToolNode(_tools(executed), security=SecurityConfig(flow_policy=_policy()))
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    node.invoke(_request("read_secret"), config=_config(principal))
    result = node.invoke(_request("send_external"), config=_config(principal))

    assert executed == ["read"]
    assert result["messages"][0].status == "error"
    assert "flow:egress" in result["messages"][0].content


@pytest.mark.asyncio
async def test_async_later_egress_is_denied_after_sensitive_read() -> None:
    """Async calls share exactly the same durable session flow state."""
    executed: list[str] = []
    node = ToolNode(_tools(executed), security=SecurityConfig(flow_policy=_policy()))
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    await node.ainvoke(_request("read_secret"), config=_config(principal))
    result = await node.ainvoke(_request("send_external"), config=_config(principal))

    assert executed == ["read"]
    assert result["messages"][0].status == "error"
    assert "flow:egress" in result["messages"][0].content


def test_parallel_read_and_egress_cannot_race_flow_state() -> None:
    """Batch premarking prevents a concurrent sink from beating the source call."""
    executed: list[str] = []
    node = ToolNode(_tools(executed), security=SecurityConfig(flow_policy=_policy()))
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _request("send_external", "read_secret"), config=_config(principal)
    )

    assert executed == ["read"]
    by_name = {message.name: message for message in result["messages"]}
    assert by_name["send_external"].status == "error"
    assert by_name["read_secret"].status == "success"


def test_flow_policy_requires_operator_classification_for_every_tool() -> None:
    """Enabling flow enforcement fails closed on an unclassified tool."""
    executed: list[str] = []
    read_secret, send_external = _tools(executed)

    with pytest.raises(ValueError, match="flow policy missing tools: send_external"):
        ToolNode(
            (read_secret, send_external),
            security=SecurityConfig(
                flow_policy=SessionFlowPolicy(
                    {"read_secret": ToolFlowRule(Confidentiality.SECRET)}
                )
            ),
        )


def test_unknown_tool_call_does_not_break_batch_premarking() -> None:
    """A model-proposed unknown tool follows normal invalid-tool handling."""
    executed: list[str] = []
    node = ToolNode(_tools(executed), security=SecurityConfig(flow_policy=_policy()))
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(_request("not_registered"), config=_config(principal))

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "not a valid tool" in result["messages"][0].content


def test_flow_label_survives_new_principal_and_process_store(tmp_path) -> None:
    """Flow state is keyed outside messages and survives principal reconstruction."""
    store = SqliteFlowStateStore(tmp_path / "flow.db")
    executed: list[str] = []
    node = ToolNode(
        _tools(executed), security=SecurityConfig(flow_policy=_policy(store=store))
    )
    first = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    second = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    try:
        node.invoke(_request("read_secret"), config=_config(first))
        result = node.invoke(_request("send_external"), config=_config(second))
    finally:
        store.close()

    assert executed == ["read"]
    assert result["messages"][0].status == "error"


def test_separate_tool_nodes_share_one_session_policy() -> None:
    """Cross-call enforcement is not local to one ToolNode instance."""
    executed: list[str] = []
    read_secret, send_external = _tools(executed)
    security = SecurityConfig(flow_policy=_policy())
    read_node = ToolNode((read_secret,), security=security)
    send_node = ToolNode((send_external,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    read_node.invoke(_request("read_secret"), config=_config(principal))
    result = send_node.invoke(_request("send_external"), config=_config(principal))

    assert executed == ["read"]
    assert result["messages"][0].status == "error"


def test_sqlite_reservations_block_cross_worker_races(tmp_path) -> None:
    """Separate SQLite connections coordinate incompatible active calls."""
    first = SqliteFlowStateStore(tmp_path / "shared-flow.db")
    second = SqliteFlowStateStore(tmp_path / "shared-flow.db")
    try:
        assert (
            first.reserve(
                "alice",
                "session",
                Confidentiality.PUBLIC,
                Confidentiality.PUBLIC,
            )
            is None
        )
        assert (
            second.reserve("alice", "session", Confidentiality.SECRET, None)
            == "flow:concurrent_egress"
        )
        first.release("alice", "session", Confidentiality.PUBLIC)
        assert second.reserve("alice", "session", Confidentiality.SECRET, None) is None
    finally:
        first.close()
        second.close()


def test_guarded_tools_share_the_same_session_flow_state() -> None:
    """Direct guarded calls cannot bypass cross-call flow enforcement."""
    executed: list[str] = []
    read_secret, send_external = _tools(executed)
    security = SecurityConfig(flow_policy=_policy())
    guarded_read = guarded_tool(read_secret, security=security)
    guarded_send = guarded_tool(send_external, security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    config = _config(principal)

    guarded_read.invoke({}, config=config)
    try:
        guarded_send.invoke({}, config=config)
    except PermissionError as exc:
        assert "flow:egress" in str(exc)
    else:
        raise AssertionError("guarded sink executed after a secret read")

    assert executed == ["read"]


def test_concurrent_source_cannot_start_while_egress_is_active() -> None:
    """Atomic reservations close races across independent graph invocations."""
    entered = Event()
    finish = Event()
    executed: list[str] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def read_secret() -> str:
        """Read secret data."""
        executed.append("read")
        return "secret"

    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    def send_external() -> str:
        """Hold an external sink open for a concurrent source attempt."""
        entered.set()
        assert finish.wait(timeout=5)
        executed.append("send")
        return "sent"

    policy = _policy()
    security = SecurityConfig(flow_policy=policy)
    guarded_read = guarded_tool(read_secret, security=security)
    guarded_send = guarded_tool(send_external, security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    config = _config(principal)

    with ThreadPoolExecutor(max_workers=2) as executor:
        sink = executor.submit(guarded_send.invoke, {}, config)
        assert entered.wait(timeout=5)
        with pytest.raises(PermissionError, match="flow:concurrent_egress"):
            guarded_read.invoke({}, config=config)
        finish.set()
        assert sink.result(timeout=5) == "sent"

    assert executed == ["send"]


def test_flow_decisions_are_in_the_required_audit_chain() -> None:
    """Flow enforcement is evidence-bearing, including denial."""
    sink = MemoryAuditSink()
    executed: list[str] = []
    node = ToolNode(
        _tools(executed),
        security=SecurityConfig(flow_policy=_policy(), audit_sink=sink),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    node.invoke(_request("read_secret"), config=_config(principal))
    node.invoke(_request("send_external"), config=_config(principal))

    flow = [record for record in sink.records() if record.stage == "flow"]
    assert [record.verdict.value for record in flow] == ["allow", "deny"]
    assert flow[-1].reason == "flow:egress"
    assert sink.verify() == (True, None)
