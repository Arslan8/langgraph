"""Stored graph state must pass the same output policy as live publications."""

import json
from dataclasses import asdict, is_dataclass

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import StateSnapshot, interrupt

from langgraph.prebuilt.security import Decision, SecurityConfig, Verdict
from langgraph.prebuilt.security.placement import OutputApprovalRequired
from tests.security.test_placement import (
    ApproveOutput,
    PlacementState,
    RedactSecretOutput,
    _config,
    produce_secret,
    update_value,
)


def serialized(value):
    return json.dumps(
        value, default=lambda item: asdict(item) if is_dataclass(item) else repr(item)
    )


def graph_for(module, producer=produce_secret):
    builder = StateGraph(PlacementState)
    builder.add_node("produce", producer)
    builder.add_edge(START, "produce")
    builder.add_edge("produce", END)
    return builder.compile(
        checkpointer=InMemorySaver(), security=SecurityConfig(modules=(module,))
    )


async def read(graph, config, asynchronous, history):
    if history:
        return (
            [s async for s in graph.aget_state_history(config)]
            if asynchronous
            else list(graph.get_state_history(config))
        )
    return [await graph.aget_state(config) if asynchronous else graph.get_state(config)]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("history", [False, True])
async def test_state_publication_redacts_complete_snapshot(asynchronous, history):
    graph = graph_for(RedactSecretOutput())
    config = _config()
    await graph.ainvoke({}, config) if asynchronous else graph.invoke({}, config)
    states = await read(graph, config, asynchronous, history)
    assert '"token"' not in serialized(states)
    redacted = [state for state in states if state.values == "[redacted]"]
    assert redacted
    assert all(
        state == StateSnapshot("[redacted]", (), {}, None, None, None, (), ())
        for state in redacted
    )


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("history", [False, True])
async def test_allowed_state_retains_useful_values_and_checkpoint_identity(
    asynchronous, history
):
    graph = graph_for(RedactSecretOutput(), update_value)
    config = _config()
    initial = {"value": "public"}
    await graph.ainvoke(initial, config) if asynchronous else graph.invoke(
        initial, config
    )
    states = await read(graph, config, asynchronous, history)
    assert states[0].values["value"] == "public!"
    assert states[0].config["configurable"]["thread_id"] == "placement-thread"
    assert states[0].metadata is not None
    assert states[0].created_at


class DenySnapshots(RedactSecretOutput):
    def output_emit(self, principal, request):
        if isinstance(request.content, StateSnapshot):
            assert principal.user_id == "alice"
            return Decision(Verdict.DENY, "test:snapshot_denied")
        return super().output_emit(principal, request)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("history", [False, True])
async def test_state_denial_uses_caller_identity_and_publishes_nothing(
    asynchronous, history
):
    graph = graph_for(DenySnapshots(), update_value)
    config = _config()
    await graph.ainvoke({"value": "public"}, config)
    with pytest.raises(PermissionError, match="test:snapshot_denied"):
        await read(graph, config, asynchronous, history)


class ApproveSnapshots(ApproveOutput):
    def output_emit(self, principal, request):
        if isinstance(request.content, StateSnapshot):
            return super().output_emit(principal, request)
        return Decision(Verdict.ALLOW, "test:ordinary_output")


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("history", [False, True])
async def test_state_approval_resumes_to_authorized_snapshot(asynchronous, history):
    graph = graph_for(ApproveSnapshots(), update_value)
    config = _config()
    await graph.ainvoke({"value": "public"}, config)
    with pytest.raises(OutputApprovalRequired) as caught:
        await read(graph, config, asynchronous, history)
    approval = caught.value
    response = {
        "request_id": approval.payload["request_id"],
        "subject_digest": approval.payload["subject_digest"],
        "approved": True,
        "approver": "reviewer",
    }
    state = (
        await approval.aresume(response) if asynchronous else approval.resume(response)
    )
    assert isinstance(state, StateSnapshot)
    assert state.values["value"] == "public!"


def interrupt_secret(state):
    interrupt(produce_secret(state)["secret"])
    return {}


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("history", [False, True])
async def test_state_interrupt_payloads_are_mediated(asynchronous, history):
    graph = graph_for(RedactSecretOutput(), interrupt_secret)
    config = _config()
    await graph.ainvoke({}, config) if asynchronous else graph.invoke({}, config)
    states = await read(graph, config, asynchronous, history)
    assert '"token"' not in serialized(states)
    assert states[0].values == "[redacted]"
    assert states[0].interrupts == ()
    assert states[0].tasks == ()
