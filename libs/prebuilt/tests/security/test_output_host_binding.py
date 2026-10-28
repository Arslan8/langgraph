"""Fixed output receivers reject substitution without removing useful output."""

from contextlib import contextmanager

import pytest

from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.object_manager import ObjectManagerHost
from langgraph.prebuilt.security.objects import LabeledValue
from langgraph.prebuilt.security.placement import OutputApprovalRequired, OutputMediator
from langgraph.prebuilt.security.types import Decision, Verdict
from tests.security.test_object_manager import _router
from tests.security.test_placement import ApproveOutput, _config


class ReplacementHost:
    def __init__(self):
        self.calls = []

    def labels_for_output(self, *args):
        self.calls.append("labels")
        raise AssertionError("replacement label collector ran")

    def dispatch(self, *args):
        self.calls.append("dispatch")
        return "unmediated"

    async def adispatch(self, *args):
        return self.dispatch(*args)


class HostSubclass(ObjectManagerHost):
    def labels_for_output(self, *args):
        raise AssertionError("subclass label collector ran")

    def dispatch(self, *args):
        raise AssertionError("subclass dispatcher ran")


class MediatorSubclass(OutputMediator):
    def _emit(self, *args, **kwargs):
        raise AssertionError("subclass emitter ran")

    async def _aemit(self, *args, **kwargs):
        raise AssertionError("subclass emitter ran")


class TransformOutput(SecurityModule):
    name = "transform_output"

    def output_emit(self, principal, request):
        return Decision(Verdict.REDACT, "test:redacted", new_args={"content": "safe"})


@contextmanager
def output_boundary(*modules):
    stack, host, router = _router(*modules)
    try:
        yield OutputMediator(router, host, destination="test", clearance=frozenset())
    finally:
        stack.close()


def response_for(pending):
    return {
        "request_id": pending.payload["request_id"],
        "subject_digest": pending.payload["subject_digest"],
        "approved": True,
        "approver": "reviewer",
    }


def assert_literal_refusal(error, code):
    assert error.args == (code,)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert not hasattr(error, "obj")


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "receiver,slot,code",
    [
        ("router", "host", "output:host_binding_changed"),
        ("router", "policy", "output:host_binding_changed"),
        ("host", "_lock", "output_data:state_shape"),
        ("host", "_state", "output_data:state_shape"),
        ("mediator", "router", "output:unsupported_mediator"),
        ("mediator", "host", "output:unsupported_mediator"),
        ("mediator", "destination", "output:unsupported_mediator"),
        ("mediator", "clearance", "output:unsupported_mediator"),
    ],
)
async def test_missing_output_slots_refuse_without_retaining_receivers(
    asynchronous, receiver, slot, code
):
    with output_boundary() as boundary:
        target = boundary if receiver == "mediator" else getattr(boundary, receiver)
        delattr(target, slot)
        with pytest.raises(PermissionError) as caught:
            if asynchronous:
                await boundary.acall("protected", _config())
            else:
                boundary("protected", _config())
        assert_literal_refusal(caught.value, code)


def test_missing_router_binding_refuses_during_mediator_construction():
    with output_boundary() as boundary:
        del boundary.router.host
        with pytest.raises(PermissionError) as caught:
            OutputMediator(
                boundary.router,
                boundary.host,
                destination="test",
                clearance=frozenset(),
            )
        assert_literal_refusal(caught.value, "output:host_binding_changed")


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_foreign_host_lock_is_refused_before_context_protocols(asynchronous):
    calls = []

    class ForeignLock:
        def __enter__(self):
            calls.append("enter")
            raise AssertionError("foreign lock executed")

        def __exit__(self, *args):
            calls.append("exit")
            return True

    with output_boundary() as boundary:
        boundary.host._lock = ForeignLock()
        with pytest.raises(PermissionError) as caught:
            if asynchronous:
                await boundary.acall("protected", _config())
            else:
                boundary("protected", _config())
        assert_literal_refusal(caught.value, "output_data:state_shape")
    assert calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_missing_stored_label_slot_does_not_retain_state_receiver(asynchronous):
    with output_boundary() as boundary:
        boundary.host._state[("alice", "session", "", "field")] = object.__new__(
            LabeledValue
        )
        with pytest.raises(PermissionError) as caught:
            if asynchronous:
                await boundary.acall({"field": "protected"}, _config())
            else:
                boundary({"field": "protected"}, _config())
        assert_literal_refusal(caught.value, "output_data:state_shape")


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("transformed", [False, True])
async def test_exact_host_retains_allowed_and_transformed_output(
    asynchronous, transformed
):
    modules = (TransformOutput(),) if transformed else ()
    with output_boundary(*modules) as boundary:
        value = {"value": "protected"}
        result = (
            await boundary.acall(value, _config())
            if asynchronous
            else boundary(value, _config())
        )
        if transformed:
            assert result == "safe"
        else:
            assert result is value


def test_fixed_layout_prevents_instance_method_shadowing():
    with output_boundary() as boundary:
        for receiver, name in (
            (boundary, "_emit"),
            (boundary, "_aemit"),
            (boundary, "_approval_required"),
            (boundary.host, "dispatch"),
            (boundary.host, "adispatch"),
            (boundary.host, "labels_for_output"),
        ):
            with pytest.raises(AttributeError):
                setattr(receiver, name, lambda *args: "unmediated")
            with pytest.raises(AttributeError):
                getattr(receiver, "__dict__")


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_base_entry_rejects_mediator_subclass_without_calling_override(
    asynchronous,
):
    candidate = object.__new__(MediatorSubclass)
    with pytest.raises(PermissionError, match="output:unsupported_mediator"):
        if asynchronous:
            await OutputMediator.acall(candidate, "protected", _config())
        else:
            OutputMediator.__call__(candidate, "protected", _config())


@pytest.mark.parametrize("subclass", [False, True])
def test_constructor_rejects_unsupported_host_without_methods(subclass):
    with output_boundary() as boundary:
        candidate = (
            HostSubclass(checkpoint_key=b"test") if subclass else ReplacementHost()
        )
        boundary.router.host = candidate
        with pytest.raises(PermissionError, match="output:unsupported_host"):
            OutputMediator(
                boundary.router, candidate, destination="test", clearance=frozenset()
            )
        if not subclass:
            assert candidate.calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("change", ["host", "router_host", "both", "exact_router_host"])
async def test_host_substitution_refuses_before_any_label_or_dispatch_call(
    asynchronous, change
):
    with output_boundary() as boundary:
        replacement = ReplacementHost()
        if change in {"host", "both"}:
            boundary.host = replacement
        if change in {"router_host", "both"}:
            boundary.router.host = replacement
        if change == "exact_router_host":
            boundary.router.host = ObjectManagerHost(checkpoint_key=b"different")
        with pytest.raises(
            PermissionError, match="output:(unsupported_host|host_binding_changed)"
        ):
            if asynchronous:
                await boundary.acall("protected", _config())
            else:
                boundary("protected", _config())
        assert replacement.calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_unmodeled_label_collection_cannot_replace_host(asynchronous):
    with output_boundary() as boundary:
        replacement = ReplacementHost()

        class MutatingContent(dict):
            def items(self):
                boundary.router.host = replacement
                return super().items()

        with pytest.raises(PermissionError, match="output_data:unsupported_type"):
            if asynchronous:
                await boundary.acall(MutatingContent(value="protected"), _config())
            else:
                boundary(MutatingContent(value="protected"), _config())
        assert replacement.calls == []
        assert boundary.router.host is boundary.host


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_pending_approval_keeps_original_host_when_mediator_host_changes(
    asynchronous,
):
    with output_boundary(ApproveOutput()) as boundary:
        with pytest.raises(OutputApprovalRequired) as caught:
            if asynchronous:
                await boundary.acall("protected", _config())
            else:
                boundary("protected", _config())
        pending = caught.value
        replacement = ReplacementHost()
        boundary.host = replacement
        response = response_for(pending)
        result = (
            await pending.aresume(response)
            if asynchronous
            else pending.resume(response)
        )
        assert result == "protected"
        assert replacement.calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_pending_approval_refuses_captured_router_host_substitution(asynchronous):
    with output_boundary(ApproveOutput()) as boundary:
        with pytest.raises(OutputApprovalRequired) as caught:
            if asynchronous:
                await boundary.acall("protected", _config())
            else:
                boundary("protected", _config())
        pending = caught.value
        router, host = boundary.router, boundary.host
        replacement = ReplacementHost()
        router.host = replacement
        response = response_for(pending)
        with pytest.raises(PermissionError, match="output:host_binding_changed"):
            if asynchronous:
                await pending.aresume(response)
            else:
                pending.resume(response)
        assert replacement.calls == []
        # Refusal happens before approval consumption; restoring the original
        # pair permits the same pending operation and preserves its content.
        router.host = host
        result = (
            await pending.aresume(response)
            if asynchronous
            else pending.resume(response)
        )
        assert result == "protected"


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_resume_rechecks_host_after_approval_response_conversion(asynchronous):
    with output_boundary(ApproveOutput()) as boundary:
        with pytest.raises(OutputApprovalRequired) as caught:
            if asynchronous:
                await boundary.acall("protected", _config())
            else:
                boundary("protected", _config())
        pending = caught.value
        replacement = ReplacementHost()

        class MutatingApproval(dict):
            def get(self, *args):
                boundary.router.host = replacement
                return super().get(*args)

        response = MutatingApproval(response_for(pending))
        with pytest.raises(PermissionError, match="output:host_binding_changed"):
            if asynchronous:
                await pending.aresume(response)
            else:
                pending.resume(response)
        assert replacement.calls == []
