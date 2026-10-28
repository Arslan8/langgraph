"""Legacy event publication must consume effective output decisions."""

import json
from dataclasses import asdict, is_dataclass

import jsonpatch
import pytest
from langchain_core.tracers.log_stream import RunLogPatch
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from langgraph.prebuilt.security import (
    Decision,
    SecurityConfig,
    Verdict,
)
from langgraph.prebuilt.security.placement import OutputApprovalRequired
from tests.security.test_placement import (
    ApproveOutput,
    PlacementState,
    RedactCanaryOutput,
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


@pytest.mark.parametrize("version", ["v1", "v2"])
async def test_legacy_inner_node_events_apply_redaction(version):
    graph = graph_for(RedactSecretOutput())
    events = [
        event async for event in graph.astream_events({}, _config(), version=version)
    ]
    assert '"token"' not in serialized(events)
    redacted = [event for event in events if event["name"] == "security_output"]
    # A callback guard may redact before the event iterator sees the value.
    assert "[redacted]" in serialized(events)
    assert all(event["data"] == "[redacted]" for event in redacted)
    assert all(
        event["metadata"] == {} and event["tags"] == [] and event["parent_ids"] == []
        for event in redacted
    )


@pytest.mark.parametrize("version", ["v1", "v2"])
async def test_allowed_legacy_events_preserve_original_record(version):
    graph = graph_for(RedactSecretOutput(), update_value)
    events = [
        event
        async for event in graph.astream_events(
            {"value": "public"}, _config(), version=version
        )
    ]
    assert any(
        event["event"] == "on_chain_end" and event["name"] == "produce"
        for event in events
    )
    assert all(event["name"] != "security_output" for event in events)
    assert "public" in serialized(events)


@pytest.mark.parametrize("version", ["v1", "v2"])
async def test_legacy_event_redaction_does_not_retain_original_metadata(version):
    graph = graph_for(RedactCanaryOutput(), update_value)
    config = _config()
    config.update(
        run_name="tuple-canary",
        tags=["tuple-canary"],
        metadata={"note": "tuple-canary"},
    )
    events = [
        event
        async for event in graph.astream_events(
            {"value": "public"}, config, version=version
        )
    ]
    assert "tuple-canary" not in serialized(events)
    assert events
    assert all(event["name"] == "security_output" for event in events)


class DenyLegacyEvents(RedactSecretOutput):
    def output_emit(self, principal, request):
        if isinstance(request.content, dict) and "event" in request.content:
            return Decision(Verdict.DENY, "test:event_denied")
        return super().output_emit(principal, request)


@pytest.mark.parametrize("version", ["v1", "v2"])
async def test_legacy_event_denial_publishes_no_event(version):
    events = []
    with pytest.raises(PermissionError):
        async for event in graph_for(DenyLegacyEvents()).astream_events(
            {}, _config(), version=version
        ):
            events.append(event)
    assert events == []


class ApproveLegacyEvents(ApproveOutput):
    def output_emit(self, principal, request):
        if isinstance(request.content, dict) and "event" in request.content:
            return super().output_emit(principal, request)
        return Decision(Verdict.ALLOW, "test:ordinary_output")


@pytest.mark.parametrize("version", ["v1", "v2"])
async def test_legacy_event_approval_resumes_to_an_event_record(version):
    graph = graph_for(ApproveLegacyEvents(), update_value)
    with pytest.raises(OutputApprovalRequired) as caught:
        async for _ in graph.astream_events(
            {"value": "public"}, _config(), version=version
        ):
            pytest.fail("An escalation must withhold the first event")
    approval = caught.value
    released = await approval.aresume(
        {
            "request_id": approval.payload["request_id"],
            "subject_digest": approval.payload["subject_digest"],
            "approved": True,
            "approver": "reviewer",
        }
    )
    assert released["event"] == "on_chain_start"
    assert released["data"]["input"] == {"value": "public"}
    assert isinstance(released["run_id"], str)


@pytest.mark.parametrize("diff", [False, True])
@pytest.mark.parametrize("with_streamed_output_list", [False, True])
async def test_legacy_logs_redact_full_states_and_raw_patch_history(
    diff, with_streamed_output_list
):
    graph = graph_for(RedactSecretOutput())
    logs = [
        log
        async for log in graph.astream_log(
            {},
            _config(),
            diff=diff,
            with_streamed_output_list=with_streamed_output_list,
        )
    ]
    assert '"token"' not in serialized([log.ops for log in logs])
    assert "[redacted]" in serialized([log.ops for log in logs])
    if not diff:
        assert '"token"' not in serialized([log.state for log in logs])
        assert logs[-1].state["final_output"] == "[redacted]"


@pytest.mark.parametrize("diff", [False, True])
async def test_allowed_legacy_log_patches_reconstruct_useful_output(diff):
    graph = graph_for(RedactSecretOutput(), update_value)
    logs = [
        log
        async for log in graph.astream_log({"value": "public"}, _config(), diff=diff)
    ]
    state = None
    for log in logs:
        state = jsonpatch.apply_patch(state, log.ops)
        if not diff:
            assert state == log.state
    # The log API uses the graph's default updates stream, keyed by node.
    assert state["final_output"] == {"produce": {"value": "public!"}}
    assert state["logs"]["produce"]["final_output"] == {"value": "public!"}


class DenyLegacyLogs(RedactSecretOutput):
    def output_emit(self, principal, request):
        if (
            isinstance(request.content, dict)
            and "logs" in request.content
            and "streamed_output" in request.content
        ):
            return Decision(Verdict.DENY, "test:log_denied")
        return super().output_emit(principal, request)


@pytest.mark.parametrize("diff", [False, True])
async def test_legacy_log_denial_publishes_no_patch(diff):
    logs = []
    with pytest.raises(PermissionError):
        async for log in graph_for(DenyLegacyLogs()).astream_log(
            {}, _config(), diff=diff
        ):
            logs.append(log)
    assert logs == []


class ApproveLegacyLogs(ApproveOutput):
    def output_emit(self, principal, request):
        if (
            isinstance(request.content, dict)
            and "logs" in request.content
            and "streamed_output" in request.content
        ):
            return super().output_emit(principal, request)
        return Decision(Verdict.ALLOW, "test:ordinary_output")


@pytest.mark.parametrize("diff", [False, True])
async def test_legacy_log_approval_rebuilds_only_the_authorized_state(diff):
    graph = graph_for(ApproveLegacyLogs(), update_value)
    with pytest.raises(OutputApprovalRequired) as caught:
        async for _ in graph.astream_log({"value": "public"}, _config(), diff=diff):
            pytest.fail("An escalation must withhold the first log state")
    approval = caught.value
    released = await approval.aresume(
        {
            "request_id": approval.payload["request_id"],
            "subject_digest": approval.payload["subject_digest"],
            "approved": True,
            "approver": "reviewer",
        }
    )
    assert isinstance(released, RunLogPatch)
    state = jsonpatch.apply_patch(None, released.ops)
    assert state["logs"] == {}
    if not diff:
        assert released.state == state
