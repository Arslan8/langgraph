from __future__ import annotations

from dataclasses import replace

import pytest

from langgraph.prebuilt.security.audit import MemoryAuditSink
from langgraph.prebuilt.security.descriptor import ToolDac
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.host_boundary import make_host_router
from langgraph.prebuilt.security.object_manager import (
    ObjectManagerHost,
    ObjectManagerPolicy,
    ToolObjectDac,
    seal_checkpoint,
)
from langgraph.prebuilt.security.objects import (
    DispatchKind,
    DispatchRequest,
    LabeledValue,
    ModelInvocationRequest,
    OutputRequest,
    SecurityLabels,
    StateOperation,
    StateRequest,
    ToolRegistryRequest,
)
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    EscalationRequest,
    ForbidConstraint,
    Principal,
    RulePredicate,
    Tool,
    Verdict,
)


def _principal(user: str = "alice") -> Principal:
    return Principal(user, frozenset({"user"}), frozenset({"tools"}), "session")


def _tool(name: str = "reader") -> Tool:
    return Tool(
        name,
        ToolDac(owner="operator", grants={"alice": "x"}),
        frozenset(),
        (),
    )


def _router(
    *modules: SecurityModule,
    dacs: dict[str, ToolObjectDac] | None = None,
    audit: MemoryAuditSink | None = None,
):
    stack = SecurityStack(modules, audit_sink=audit)
    host = ObjectManagerHost(checkpoint_key=b"checkpoint-key")
    router = make_host_router(ObjectManagerPolicy(stack, dacs), host)
    return stack, host, router


class DenyState(SecurityModule):
    name = "deny_state"

    def state_read(self, principal, request):
        return Decision(Verdict.DENY, "test:state_denied")


class StripSecret(SecurityModule):
    name = "strip_secret"

    def model_invoke(self, principal, request):
        context = tuple(
            item
            for item in request.context
            if "secret" not in item.labels.confidentiality
        )
        return Decision(Verdict.TRANSFORM, "test:strip", new_args={"context": context})


class RedactSecret(SecurityModule):
    name = "redact_secret"

    def output_emit(self, principal, request):
        if "secret" not in request.labels.confidentiality:
            return Decision(Verdict.ALLOW, "test:public")
        return Decision(
            Verdict.REDACT,
            "test:redact",
            new_args={"content": "[redacted]", "labels": SecurityLabels()},
        )


class BrokenAllocation(SecurityModule):
    name = "broken_allocation"

    def tool_alloc_security(self, tool, slot):
        raise RuntimeError("boom")


class EscalateOutput(SecurityModule):
    name = "escalate_output"
    can_escalate = True

    def output_emit(self, principal, request):
        return Decision(
            Verdict.ESCALATE,
            "test:approval_required",
            escalation=EscalationRequest(
                "approval-1",
                "review output",
                "output_emit",
                request.output_id,
            ),
        )


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_undeclared_tool_reads_no_state(asynchronous: bool) -> None:
    stack, host, router = _router()
    principal = _principal()
    host._state["messages"] = ["private"]
    request = StateRequest(
        StateOperation.TOOL_READ,
        "messages",
        principal.user_id,
        tool_name="undeclared",
    )
    try:
        with pytest.raises(PermissionError, match="dac:object_not_granted"):
            if asynchronous:
                await router.aroute(principal, request)
            else:
                router.route(principal, request)
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_declared_channel_read_runs_module_stack(asynchronous: bool) -> None:
    stack, host, router = _router(
        DenyState(),
        dacs={"reader": ToolObjectDac(readable_channels=frozenset({"messages"}))},
    )
    principal = _principal()
    host._state["messages"] = ["private"]
    request = StateRequest(
        StateOperation.TOOL_READ,
        "messages",
        principal.user_id,
        tool_name="reader",
    )
    try:
        with pytest.raises(PermissionError, match="test:state_denied"):
            if asynchronous:
                await router.aroute(principal, request)
            else:
                router.route(principal, request)
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_model_context_is_stripped_before_dispatch(asynchronous: bool) -> None:
    stack, _, router = _router(StripSecret())
    principal = _principal()
    public = LabeledValue("public", "hello")
    secret = LabeledValue(
        "secret", "token", SecurityLabels(confidentiality=frozenset({"secret"}))
    )
    request = ModelInvocationRequest("local", (public, secret), "model-1")
    try:
        result = (
            await router.aroute(principal, request)
            if asynchronous
            else router.route(principal, request)
        )
        assert result == (public,)
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_output_redaction_precedes_clearance_check(asynchronous: bool) -> None:
    stack, _, router = _router(RedactSecret())
    request = OutputRequest(
        "public",
        "token",
        SecurityLabels(confidentiality=frozenset({"secret"})),
        frozenset(),
        "output-1",
    )
    try:
        result = (
            await router.aroute(_principal(), request)
            if asynchronous
            else router.route(_principal(), request)
        )
        assert result == "[redacted]"
    finally:
        stack.close()


def test_output_without_redaction_cannot_cross_clearance() -> None:
    stack, _, router = _router()
    request = OutputRequest(
        "public",
        "token",
        SecurityLabels(confidentiality=frozenset({"secret"})),
        frozenset(),
        "output-1",
    )
    try:
        with pytest.raises(PermissionError, match="output:clearance"):
            router.route(_principal(), request)
    finally:
        stack.close()


def test_store_keys_are_owner_bound_and_dac_mediated() -> None:
    dacs = {
        "store_tool": ToolObjectDac(
            readable_store_keys=frozenset({"notes"}),
            writable_store_keys=frozenset({"notes"}),
        )
    }
    stack, _, router = _router(dacs=dacs)
    alice = _principal()
    bob = _principal("bob")
    write = StateRequest(
        StateOperation.STORE_WRITE,
        "notes",
        alice.user_id,
        tool_name="store_tool",
        value="alice-data",
    )
    read = replace(write, operation=StateOperation.STORE_READ, value=None)
    try:
        assert router.route(alice, write) == "alice-data"
        assert router.route(alice, read) == "alice-data"
        with pytest.raises(PermissionError, match="store:owner_mismatch"):
            router.route(bob, replace(read, owner_id=bob.user_id))
    finally:
        stack.close()


def test_checkpoint_restore_is_bound_chained_and_replay_safe() -> None:
    stack, _, router = _router()
    alice = _principal()
    first = seal_checkpoint(
        b"checkpoint-key",
        checkpoint_id="one",
        principal=alice,
        sequence=0,
        previous_hash="",
        payload={"count": 1},
    )
    request = StateRequest(
        StateOperation.RESTORE, "checkpoint", alice.user_id, value=first
    )
    try:
        assert router.route(alice, request) == {"count": 1}
        with pytest.raises(PermissionError, match="checkpoint:replay"):
            router.route(alice, request)
        with pytest.raises(PermissionError, match="checkpoint:principal_mismatch"):
            router.route(_principal("bob"), replace(request, owner_id="bob"))
        tampered = replace(first, payload={"count": 999})
        with pytest.raises(PermissionError, match="checkpoint:invalid_hash"):
            fresh_stack, _, fresh_router = _router()
            try:
                fresh_router.route(alice, replace(request, value=tampered))
            finally:
                fresh_stack.close()
    finally:
        stack.close()


@pytest.mark.parametrize("kind", list(DispatchKind))
def test_every_dispatch_form_checks_child_subset_and_transfer_hook(kind) -> None:
    transfers: list[tuple[Principal, Principal]] = []

    class RecordTransfer(SecurityModule):
        name = "record_transfer"

        def cred_transfer(self, parent, child, slot):
            transfers.append((parent, child))
            return Decision(Verdict.ALLOW, "recorded")

    stack, _, router = _router(RecordTransfer())
    parent = _principal()
    child = replace(parent, scopes=frozenset(), delegated_by=parent.user_id)
    wider = replace(parent, scopes=frozenset({"tools", "admin"}))
    try:
        assert (
            router.route(
                parent,
                DispatchRequest(kind, parent, child, "d-1"),
            )
            is child
        )
        assert transfers == [(parent, child)]
        with pytest.raises(PermissionError, match="dispatch:authority_growth"):
            router.route(parent, DispatchRequest(kind, parent, wider, "d-2"))
        assert transfers == [(parent, child)]
    finally:
        stack.close()


def test_same_principal_dispatch_has_redacted_identity_transfer_audit() -> None:
    audit = MemoryAuditSink()
    stack, _, router = _router(audit=audit)
    principal = _principal()
    try:
        request = DispatchRequest(
            DispatchKind.PARALLEL_BRANCH,
            principal,
            principal,
            "parallel-1",
        )
        assert router.dispatch(principal, request) is principal
        record = audit.records()[-1]
        assert (record.stage, record.module, record.verdict) == (
            "dispatch",
            "object_manager",
            Verdict.ALLOW,
        )
        assert record.tool_name == "__framework__"
        assert record.args_hash
        assert "parallel-1" not in repr(record)
        assert audit.verify() == (True, None)
    finally:
        stack.close()


def test_dynamic_registration_fails_closed_on_alloc_error() -> None:
    stack, host, router = _router(BrokenAllocation())
    tool = _tool()
    try:
        with pytest.raises(PermissionError, match="module_error:broken_allocation"):
            router.route(_principal(), ToolRegistryRequest(tool, dynamic=True))
        assert tool.name not in host._tools
    finally:
        stack.close()


def test_framework_constraint_is_denied_until_it_has_an_enforcer() -> None:
    class ConstraintModule(SecurityModule):
        name = "constraint"

        def state_read(self, principal, request):
            return Decision(
                Verdict.ALLOW,
                "constraint:allow",
                constraints=(
                    ForbidConstraint("unattributed", "block-state", RulePredicate()),
                ),
            )

    principal = _principal()
    stack = SecurityStack((ConstraintModule(),))
    policy = ObjectManagerPolicy(
        stack,
        {"reader": ToolObjectDac(readable_channels=frozenset({"messages"}))},
    )
    try:
        authorization = policy.object_permission(
            principal,
            StateRequest(
                StateOperation.TOOL_READ,
                "messages",
                principal.user_id,
                tool_name="reader",
            ),
        )
    finally:
        stack.close()

    assert authorization.decision == Decision(
        Verdict.DENY, "object_constraints_unsupported:constraint"
    )


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_output_escalation_rechecks_complete_chain(asynchronous: bool) -> None:
    stack, _, router = _router(EscalateOutput())
    principal = _principal()
    request = OutputRequest("console", "reviewed", output_id="output-1")
    try:
        authorization = (
            await router.aoutput_emit(principal, request)
            if asynchronous
            else router.output_emit(principal, request)
        )
        escalation = authorization.decision.escalation
        assert escalation is not None
        approval = Approval(
            escalation.request_id,
            True,
            "operator",
            subject_digest=escalation.subject_digest,
        )
        result = (
            await router.aresume(principal, request, approval)
            if asynchronous
            else router.resume(principal, request, approval)
        )
        assert result == "reviewed"
        with pytest.raises(PermissionError, match="approval_replay"):
            if asynchronous:
                await router.aresume(principal, request, approval)
            else:
                router.resume(principal, request, approval)
    finally:
        stack.close()
