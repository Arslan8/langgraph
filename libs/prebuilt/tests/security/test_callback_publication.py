"""Direct observers must receive only effective callback payloads."""

import json
from dataclasses import asdict, is_dataclass

import pytest
from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
from langgraph.callbacks import GraphCallbackHandler

from langgraph.prebuilt.security import Decision, Verdict
from langgraph.prebuilt.security.placement import OutputApprovalRequired
from tests.security.test_legacy_event_publication import graph_for
from tests.security.test_placement import (
    ApproveOutput,
    RedactSecretOutput,
    _config,
    interrupt_with_secret,
    update_value,
)


class Capture(BaseCallbackHandler):
    def __init__(self):
        self.ends = []
        self.parents = []
        self.errors = []

    def on_chain_end(self, outputs, **kwargs):
        self.ends.append(outputs)
        self.parents.append(kwargs.get("parent_run_id"))

    def on_chain_error(self, error, **kwargs):
        self.errors.append(error)


class AsyncCapture(AsyncCallbackHandler):
    def __init__(self):
        self.ends = []
        self.parents = []
        self.errors = []

    async def on_chain_end(self, outputs, **kwargs):
        self.ends.append(outputs)
        self.parents.append(kwargs.get("parent_run_id"))

    async def on_chain_error(self, error, **kwargs):
        self.errors.append(error)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("observer", [Capture, AsyncCapture])
async def test_direct_inner_callback_never_receives_the_secret(asynchronous, observer):
    capture = observer()
    config = _config()
    config["callbacks"] = [capture]
    graph = graph_for(RedactSecretOutput())
    result = (
        await graph.ainvoke({}, config) if asynchronous else graph.invoke({}, config)
    )
    assert result == "[redacted]"
    assert None in capture.parents and any(
        parent is not None for parent in capture.parents
    )
    assert capture.ends and all(value == "[redacted]" for value in capture.ends)
    assert '"token"' not in json.dumps(
        capture.ends, default=lambda x: asdict(x) if is_dataclass(x) else repr(x)
    )


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("observer", [Capture, AsyncCapture])
async def test_allowed_callbacks_retain_useful_results(asynchronous, observer):
    capture = observer()
    config = _config()
    config["callbacks"] = [capture]
    graph = graph_for(RedactSecretOutput(), update_value)
    result = (
        await graph.ainvoke({"value": "public"}, config)
        if asynchronous
        else graph.invoke({"value": "public"}, config)
    )
    assert result == {"value": "public!"}
    assert {"value": "public!"} in capture.ends
    assert None in capture.parents and any(
        parent is not None for parent in capture.parents
    )


class DenyCallbackEnds(RedactSecretOutput):
    def output_emit(self, principal, request):
        if (
            isinstance(request.content, dict)
            and request.content.get("callback") == "on_chain_end"
        ):
            return Decision(Verdict.DENY, "callback:denied")
        return super().output_emit(principal, request)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("observer", [Capture, AsyncCapture])
async def test_callback_denial_is_not_swallowed_by_default_handler_policy(
    asynchronous, observer
):
    capture = observer()
    config = _config()
    config["callbacks"] = [capture]
    graph = graph_for(DenyCallbackEnds(), update_value)
    with pytest.raises(PermissionError, match="callback:denied"):
        if asynchronous:
            await graph.ainvoke({"value": "public"}, config)
        else:
            graph.invoke({"value": "public"}, config)
    assert capture.ends == []
    assert all(
        error.__traceback__ is None and not hasattr(error, "_resume")
        for error in capture.errors
    )


class ApproveCallbackEnds(ApproveOutput):
    def output_emit(self, principal, request):
        if (
            isinstance(request.content, dict)
            and request.content.get("callback") == "on_chain_end"
        ):
            return super().output_emit(principal, request)
        return Decision(Verdict.ALLOW, "test:other_output")


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("observer", [Capture, AsyncCapture])
async def test_approval_performs_the_withheld_callback_delivery(asynchronous, observer):
    capture = observer()
    config = _config()
    config["callbacks"] = [capture]
    graph = graph_for(ApproveCallbackEnds(), update_value)
    with pytest.raises(OutputApprovalRequired) as caught:
        if asynchronous:
            await graph.ainvoke({"value": "public"}, config)
        else:
            graph.invoke({"value": "public"}, config)
    assert capture.ends == []
    approval = caught.value
    response = {
        "request_id": approval.payload["request_id"],
        "subject_digest": approval.payload["subject_digest"],
        "approved": True,
        "approver": "reviewer",
    }
    result = (
        await approval.aresume(response)
        if asynchronous or observer is AsyncCapture
        else approval.resume(response)
    )
    assert result is None
    assert capture.ends == [{"value": "public!"}]
    assert all(
        not hasattr(error, "_resume") and error.__traceback__ is None
        for error in capture.errors
    )


class GraphCapture(GraphCallbackHandler):
    def __init__(self):
        self.events = []

    def on_interrupt(self, event):
        self.events.append(event)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_interrupt_callback_payload_is_mediated(asynchronous):
    capture = GraphCapture()
    config = _config()
    config["callbacks"] = [capture]
    graph = graph_for(RedactSecretOutput(), interrupt_with_secret)
    if asynchronous:
        await graph.ainvoke({}, config)
    else:
        graph.invoke({}, config)
    assert capture.events
    assert all(event.interrupts[0].value == "[redacted]" for event in capture.events)
    assert "interrupt-canary" not in json.dumps(
        capture.events, default=lambda x: asdict(x) if is_dataclass(x) else repr(x)
    )
