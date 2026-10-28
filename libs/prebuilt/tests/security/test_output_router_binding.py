"""Output publication captures an exact admitted router through approval."""

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from langgraph.prebuilt.security import SecurityConfig
from langgraph.prebuilt.security.host_router import HostRouter
from langgraph.prebuilt.security.placement import OutputApprovalRequired
from tests.security.test_placement import (
    ApproveOutput,
    PlacementState,
    _config,
    update_value,
)


class ReplacementRouter:
    def __init__(self):
        self.calls = 0

    def output_emit(self, *args):
        self.calls += 1
        return "unmediated"

    async def aoutput_emit(self, *args):
        return self.output_emit(*args)

    def resume(self, *args):
        self.calls += 1
        return "retargeted"

    async def aresume(self, *args):
        return self.resume(*args)


class RouterSubclass(HostRouter):
    def output_emit(self, *args):
        raise AssertionError("subclass method executed")

    async def aoutput_emit(self, *args):
        raise AssertionError("subclass method executed")


def mediator(*, approval=False):
    builder = StateGraph(PlacementState)
    builder.add_node("update", update_value)
    builder.add_edge(START, "update")
    builder.add_edge("update", END)
    builder.compile(
        checkpointer=InMemorySaver(),
        security=SecurityConfig(modules=(ApproveOutput(),) if approval else ()),
    )
    return builder._security_output_mediator


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("subclass", [False, True])
async def test_unsupported_router_is_rejected_before_any_candidate_method(
    asynchronous, subclass
):
    boundary = mediator()
    replacement = RouterSubclass() if subclass else ReplacementRouter()
    boundary.router = replacement
    with pytest.raises(PermissionError, match="output:unsupported_router"):
        if asynchronous:
            await boundary.acall("protected", _config())
        else:
            boundary("protected", _config())
    if not subclass:
        assert replacement.calls == 0


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_pending_approval_retains_the_original_router(asynchronous):
    boundary = mediator(approval=True)
    with pytest.raises(OutputApprovalRequired) as caught:
        if asynchronous:
            await boundary.acall("protected", _config())
        else:
            boundary("protected", _config())
    pending = caught.value
    replacement = ReplacementRouter()
    boundary.router = replacement
    response = {
        "request_id": pending.payload["request_id"],
        "subject_digest": pending.payload["subject_digest"],
        "approved": True,
        "approver": "reviewer",
    }
    result = (
        await pending.aresume(response) if asynchronous else pending.resume(response)
    )
    assert result == "protected"
    assert replacement.calls == 0
    with pytest.raises(PermissionError, match="approval_replay"):
        if asynchronous:
            await pending.aresume(response)
        else:
            pending.resume(response)
