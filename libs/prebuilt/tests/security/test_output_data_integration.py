"""Output admission precedes policy/analysis and binds approval content."""

from dataclasses import replace

import pytest
from langchain_core.messages import AIMessage

from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.objects import (
    LabeledValue,
    OutputRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.output_data import OutputDataError
from langgraph.prebuilt.security.placement import OutputApprovalRequired
from langgraph.prebuilt.security.types import Decision, Verdict
from tests.security.test_object_manager import _principal, _router
from tests.security.test_output_host_binding import output_boundary, response_for
from tests.security.test_placement import ApproveOutput, _config


def secret():
    return LabeledValue("private", "canary", SecurityLabels(frozenset({"secret"})))


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("kind", ["nested", "message"])
async def test_nested_labels_reach_the_real_output_clearance_check(asynchronous, kind):
    value = (
        LabeledValue("wrapper", secret(), SecurityLabels())
        if kind == "nested"
        else AIMessage(content="public", additional_kwargs={"private": secret()})
    )
    with output_boundary() as boundary:
        with pytest.raises(PermissionError, match="output:clearance"):
            if asynchronous:
                await boundary.acall(value, _config())
            else:
                boundary(value, _config())
        boundary.clearance = frozenset({"secret"})
        actual = (
            await boundary.acall(value, _config())
            if asynchronous
            else boundary(value, _config())
        )
        assert actual is value


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_approval_cannot_release_mutated_payload(asynchronous):
    with output_boundary(ApproveOutput()) as boundary:
        value = {"data": ["approved"]}
        with pytest.raises(OutputApprovalRequired) as caught:
            if asynchronous:
                await boundary.acall(value, _config())
            else:
                boundary(value, _config())
        pending = caught.value
        response = response_for(pending)
        value["data"].append("changed")
        with pytest.raises(PermissionError):
            if asynchronous:
                await pending.aresume(response)
            else:
                pending.resume(response)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_unknown_payload_never_runs_mapping_methods_or_policy(asynchronous):
    calls = []

    class Hostile(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("unadmitted mapping ran")

    class Policy(SecurityModule):
        name = "observe"

        def output_emit(self, principal, request):
            calls.append("policy")
            return Decision(Verdict.ALLOW, "allow")

    with output_boundary(Policy()) as boundary:
        with pytest.raises(OutputDataError):
            if asynchronous:
                await boundary.acall(Hostile(value="canary"), _config())
            else:
                boundary(Hostile(value="canary"), _config())
    assert calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("malformation", ["payload", "labels", "capability"])
async def test_transformed_output_is_readmitted_before_next_hook(
    asynchronous, malformation
):
    calls = []

    class BadLabels:
        def issubset(self, other):
            calls.append("subset")
            return True

    class Transform(SecurityModule):
        name = "transform"

        def output_emit(self, principal, request):
            if malformation == "payload":
                values = {"content": secret(), "labels": SecurityLabels()}
            elif malformation == "labels":
                labels = SecurityLabels()
                object.__setattr__(labels, "confidentiality", BadLabels())
                values = {"content": "safe", "labels": labels}
            else:
                values = {"content": lambda: "capability"}
            return Decision(Verdict.REDACT, "transform", new_args=values)

    class Later(SecurityModule):
        name = "later"

        def output_emit(self, principal, request):
            calls.append("later")
            return Decision(Verdict.ALLOW, "allow")

    with output_boundary(Transform(), Later()) as boundary:
        with pytest.raises(PermissionError, match="module_widened"):
            if asynchronous:
                await boundary.acall("original", _config())
            else:
                boundary("original", _config())
    assert calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_host_rejects_forged_native_label_fields_without_protocols(asynchronous):
    calls = []

    class Forged:
        def issubset(self, other):
            calls.append("subset")
            return True

    labels = SecurityLabels()
    object.__setattr__(labels, "confidentiality", Forged())
    stack, host, _ = _router()
    try:
        request = OutputRequest("test", "canary", labels, frozenset(), "output")
        with pytest.raises(OutputDataError):
            if asynchronous:
                await host.adispatch(_principal(), request)
            else:
                host.dispatch(_principal(), request)
    finally:
        stack.close()
    assert calls == []


def test_host_rejects_explicit_payload_labels_missing_from_request():
    stack, host, _ = _router()
    try:
        request = OutputRequest(
            "test", secret(), SecurityLabels(), frozenset({"secret"}), "output"
        )
        with pytest.raises(OutputDataError, match="payload_confidentiality"):
            host.dispatch(_principal(), request)
        assert (
            host.dispatch(_principal(), replace(request, labels=secret().labels))
            is request.content
        )
    finally:
        stack.close()
