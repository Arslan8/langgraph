from __future__ import annotations

from dataclasses import replace

import pytest
from langgraph.store.memory import InMemoryStore

from langgraph.prebuilt.security.audit import MemoryAuditSink
from langgraph.prebuilt.security.descriptor import ToolDac
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.host_boundary import make_host_router
from langgraph.prebuilt.security.object_manager import (
    MediatedStore,
    ObjectManagerHost,
    ObjectManagerPolicy,
    StoreResource,
    ToolObjectDac,
    authenticate_store_resource,
    seal_checkpoint,
    seal_store_resource,
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


class EscalateStateRead(SecurityModule):
    name = "escalate_state_read"
    can_escalate = True

    def state_read(self, principal, request):
        return Decision(
            Verdict.ESCALATE,
            "test:approval_required",
            escalation=EscalationRequest(
                "state-approval-1",
                "review state read",
                "state_read",
                request.resource,
            ),
        )


class RewriteStoreValue(SecurityModule):
    name = "rewrite_store_value"

    def state_write(self, principal, request):
        if request.operation is StateOperation.STORE_WRITE:
            return Decision(
                Verdict.TRANSFORM,
                "test:rewrite_store_value",
                new_args={"value": {"authorized": True}},
            )
        return Decision(Verdict.ALLOW, "test:allow")


class RewriteStoreRead(SecurityModule):
    name = "rewrite_store_read"

    def state_read(self, principal, request):
        if (
            request.operation is StateOperation.STORE_READ
            and request.metadata.get("store_envelope") is not None
        ):
            return Decision(
                Verdict.TRANSFORM,
                "test:rewrite_store_read",
                new_args={"value": {"authorized": True}},
            )
        return Decision(Verdict.ALLOW, "test:allow")


class DenyStoreRead(SecurityModule):
    name = "deny_store_read"

    def state_read(self, principal, request):
        if request.operation is StateOperation.STORE_READ:
            return Decision(Verdict.DENY, "test:store_read_denied")
        return Decision(Verdict.ALLOW, "test:allow")


class DenySecretStoreRead(SecurityModule):
    name = "deny_secret_store_read"

    def state_read(self, principal, request):
        if "secret" in request.labels.confidentiality:
            return Decision(Verdict.DENY, "test:secret_store_read_denied")
        return Decision(Verdict.ALLOW, "test:allow")


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


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_mediated_store_applies_effective_authorized_write(
    asynchronous: bool,
) -> None:
    stack, _, router = _router(
        RewriteStoreValue(),
        dacs={"writer": ToolObjectDac(writable_store_keys=frozenset({"notes/item"}))},
    )
    backing = InMemoryStore()
    store = MediatedStore(
        backing,
        router=router,
        principal=_principal(),
        tool_name="writer",
        store_key=b"checkpoint-key",
    )
    try:
        if asynchronous:
            await store.aput(("notes",), "item", {"authorized": False})
        else:
            store.put(("notes",), "item", {"authorized": False})
        saved = backing.get(("notes",), "item")
        assert saved is not None
        resource = authenticate_store_resource(
            b"checkpoint-key", "notes/item", saved.value
        )
        assert resource.value == {"authorized": True}
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_mediated_store_publishes_only_effective_authorized_read(
    asynchronous: bool,
) -> None:
    dacs = {
        "reader": ToolObjectDac(
            readable_store_keys=frozenset({"notes/item"}),
            writable_store_keys=frozenset({"notes/item"}),
        )
    }
    stack, _, router = _router(RewriteStoreRead(), dacs=dacs)
    backing = InMemoryStore()
    store = MediatedStore(
        backing,
        router=router,
        principal=_principal(),
        tool_name="reader",
        store_key=b"checkpoint-key",
    )
    try:
        if asynchronous:
            await store.aput(("notes",), "item", {"secret": "raw"})
            result = await store.aget(("notes",), "item")
        else:
            store.put(("notes",), "item", {"secret": "raw"})
            result = store.get(("notes",), "item")
        assert result is not None
        assert result.value == {"authorized": True}
        raw = backing.get(("notes",), "item")
        assert raw is not None
        resource = authenticate_store_resource(
            b"checkpoint-key", "notes/item", raw.value
        )
        assert resource.value == {"secret": "raw"}
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_mediated_store_rejects_denied_and_wrong_owner_reads(
    asynchronous: bool,
) -> None:
    dacs = {
        "reader": ToolObjectDac(
            readable_store_keys=frozenset({"notes/item"}),
            writable_store_keys=frozenset({"notes/item"}),
        )
    }
    backing = InMemoryStore()
    deny_stack, _, deny_router = _router(DenyStoreRead(), dacs=dacs)
    denied = MediatedStore(
        backing,
        router=deny_router,
        principal=_principal(),
        tool_name="reader",
        store_key=b"checkpoint-key",
    )
    owner_stack, _, owner_router = _router(dacs=dacs)
    bob_stack, _, bob_router = _router(dacs=dacs)
    alice = MediatedStore(
        backing,
        router=bob_router,
        principal=_principal(),
        tool_name="reader",
        store_key=b"checkpoint-key",
    )
    bob = MediatedStore(
        backing,
        router=owner_router,
        principal=_principal("bob"),
        tool_name="reader",
        store_key=b"checkpoint-key",
    )
    try:
        if asynchronous:
            await denied.aput(("notes",), "item", {"secret": "raw"})
            with pytest.raises(PermissionError, match="test:store_read_denied"):
                await denied.aget(("notes",), "item")
            await alice.aput(("notes",), "item", {"secret": "raw"})
            with pytest.raises(PermissionError, match="store:owner_mismatch"):
                await bob.aget(("notes",), "item")
        else:
            denied.put(("notes",), "item", {"secret": "raw"})
            with pytest.raises(PermissionError, match="test:store_read_denied"):
                denied.get(("notes",), "item")
            alice.put(("notes",), "item", {"secret": "raw"})
            with pytest.raises(PermissionError, match="store:owner_mismatch"):
                bob.get(("notes",), "item")
    finally:
        deny_stack.close()
        owner_stack.close()
        bob_stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_mediated_store_rejects_unregistered_or_changed_backing_data(
    asynchronous: bool,
) -> None:
    dacs = {
        "reader": ToolObjectDac(
            readable_store_keys=frozenset({"notes/item"}),
            writable_store_keys=frozenset({"notes/item"}),
        )
    }
    stack, _, router = _router(dacs=dacs)
    backing = InMemoryStore()
    store = MediatedStore(
        backing,
        router=router,
        principal=_principal(),
        tool_name="reader",
        store_key=b"checkpoint-key",
    )
    try:
        backing.put(("notes",), "item", {"secret": "unregistered"})
        with pytest.raises(PermissionError, match="store:unverifiable_resource"):
            if asynchronous:
                await store.aget(("notes",), "item")
            else:
                store.get(("notes",), "item")

        if asynchronous:
            await store.aput(("notes",), "item", {"secret": "registered"})
        else:
            store.put(("notes",), "item", {"secret": "registered"})
        raw = backing.get(("notes",), "item")
        assert raw is not None
        changed = dict(raw.value)
        changed["__slanggraph_value__"] = {"secret": "changed"}
        backing.put(("notes",), "item", changed)
        with pytest.raises(
            PermissionError, match="store:invalid_resource_authentication"
        ):
            if asynchronous:
                await store.aget(("notes",), "item")
            else:
                store.get(("notes",), "item")
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_mediated_store_authorizes_authenticated_backing_labels(
    asynchronous: bool,
) -> None:
    dacs = {"reader": ToolObjectDac(readable_store_keys=frozenset({"notes/item"}))}
    stack, _, router = _router(DenySecretStoreRead(), dacs=dacs)
    backing = InMemoryStore()
    backing.put(
        ("notes",),
        "item",
        seal_store_resource(
            b"checkpoint-key",
            "notes/item",
            StoreResource(
                "alice",
                {"secret": "protected"},
                SecurityLabels(confidentiality=frozenset({"secret"})),
            ),
        ),
    )
    store = MediatedStore(
        backing,
        router=router,
        principal=_principal(),
        tool_name="reader",
        store_key=b"checkpoint-key",
    )
    try:
        with pytest.raises(PermissionError, match="test:secret_store_read_denied"):
            if asynchronous:
                await store.aget(("notes",), "item")
            else:
                store.get(("notes",), "item")
    finally:
        stack.close()


def test_state_channels_are_isolated_by_principal_session() -> None:
    stack, _, router = _router()
    first = _principal()
    second = replace(first, session_id="other-session")

    def request(principal: Principal, operation: StateOperation, value=None):
        return StateRequest(
            operation,
            "messages",
            principal.user_id,
            value=value,
        )

    try:
        assert router.state(first, request(first, StateOperation.WRITE, "first")) == (
            "first"
        )
        assert (
            router.state(second, request(second, StateOperation.WRITE, "second"))
            == "second"
        )
        assert (
            router.state(first, request(first, StateOperation.MODEL_READ)).value
            == "first"
        )
        assert (
            router.state(second, request(second, StateOperation.MODEL_READ)).value
            == "second"
        )
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_resume_rechecks_object_dac_before_dispatch(asynchronous: bool) -> None:
    stack, _, router = _router(
        EscalateStateRead(),
        dacs={"reader": ToolObjectDac(readable_channels=frozenset({"allowed"}))},
    )
    principal = _principal()
    request = StateRequest(
        StateOperation.TOOL_READ,
        "allowed",
        principal.user_id,
        tool_name="reader",
    )
    try:
        authorization = (
            await router.astate(principal, request)
            if asynchronous
            else router.state(principal, request)
        )
        escalation = authorization.decision.escalation
        assert escalation is not None
        approval = Approval(
            escalation.request_id,
            True,
            "operator",
            subject_digest=escalation.subject_digest,
        )
        forbidden = replace(request, resource="forbidden")
        with pytest.raises(PermissionError, match="dac:object_not_granted"):
            if asynchronous:
                await router.aresume(principal, forbidden, approval)
            else:
                router.resume(principal, forbidden, approval)
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
