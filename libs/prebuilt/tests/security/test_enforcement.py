"""Contract tests for exact grant lowering and worker activation evidence."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    AdapterPlan,
    AuthorityDomain,
    EnforcementAdapter,
    EnforcementCoordinator,
    EnforcementMode,
    EnforcementObligation,
    ExecutionContext,
    Grant,
    GrantRule,
    HostAttestation,
    ObligationKind,
    RequirementEntry,
    RequirementLedger,
    SupportAssessment,
    SupportLevel,
    compile_grant,
    compile_obligations,
)
from langgraph.prebuilt.security.profile import (
    FsRule,
    PathTemplate,
    PrincipalProfile,
    Requirement,
    ToolProfile,
    evaluate_dac,
)


class _Verifier:
    def __init__(self, trusted: bool = True) -> None:
        self.trusted = trusted

    def verify(self, attestation: HostAttestation) -> bool:
        return self.trusted and attestation.signature == "trusted"


class _Adapter(EnforcementAdapter):
    def __init__(
        self,
        adapter_id: str,
        supported: set[str],
        *,
        wrong_context: bool = False,
    ) -> None:
        self._adapter_id = adapter_id
        self.supported = supported
        self.wrong_context = wrong_context

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        support = (
            SupportLevel.EXACT
            if obligation.obligation_id in self.supported
            else SupportLevel.UNSUPPORTED
        )
        return SupportAssessment(
            self.adapter_id, obligation.obligation_id, support, support.value
        )

    def lower(
        self,
        grant: Grant,
        obligations: tuple[EnforcementObligation, ...],
        host: HostAttestation,
    ) -> AdapterPlan:
        obligation_ids = frozenset(item.obligation_id for item in obligations)
        return AdapterPlan(
            self.adapter_id,
            obligation_ids,
            f"plan:{self.adapter_id}:{','.join(sorted(obligation_ids))}",
        )

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        return ActivationEvidence(
            self.adapter_id,
            plan.native_plan_digest,
            "wrong" if self.wrong_context else context.digest,
            nonce,
            plan.obligation_ids,
            10.0,
            100.0,
            "adapter-signed",
        )

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        return evidence.signature == "adapter-signed"


def _grant(requirement: Requirement = Requirement.NEED) -> Grant:
    return Grant(
        "alice",
        "session",
        "send_email",
        "artifact-sha256",
        "call-1",
        "intent-sha256",
        "policy-sha256",
        (
            GrantRule(
                "mail-rule",
                AuthorityDomain.SERVICE,
                "mail.send",
                "mail-service",
                {"recipient": "alice@example.com"},
                requirement,
                ("tool-profile:12", "operator-policy:7"),
            ),
        ),
    )


def _ledger(requirement: Requirement = Requirement.NEED) -> RequirementLedger:
    return RequirementLedger(
        (RequirementEntry("profile:mail", requirement, frozenset({"mail-rule"})),)
    )


def _obligations(
    *, recipient_waivable: bool = False
) -> tuple[EnforcementObligation, ...]:
    return (
        EnforcementObligation(
            "mail.recipient",
            "mail-rule",
            ObligationKind.OPERATE,
            AuthorityDomain.SERVICE,
            "mail.send",
            "mail-service",
            {"recipient": "alice@example.com"},
            frozenset({"mail.channel", "mail.credential"}),
            recipient_waivable,
        ),
        EnforcementObligation(
            "mail.channel",
            "mail-rule",
            ObligationKind.AUTHENTICATED_CHANNEL,
            AuthorityDomain.SERVICE,
            "broker.request",
            "mail-broker",
        ),
        EnforcementObligation(
            "mail.credential",
            "mail-rule",
            ObligationKind.CREDENTIAL_CUSTODY,
            AuthorityDomain.SERVICE,
            "credential.hold",
            "mail-credential",
        ),
        EnforcementObligation(
            "mail.default_deny",
            "mail-rule",
            ObligationKind.DENY_COMPLEMENT,
            AuthorityDomain.SERVICE,
            "service.deny_unlisted",
            "*",
        ),
        *(
            EnforcementObligation(
                f"domain.{domain.value}.default_deny",
                f"domain:{domain.value}",
                ObligationKind.DENY_COMPLEMENT,
                domain,
                "deny_unlisted",
                "*",
            )
            for domain in AuthorityDomain
            if domain is not AuthorityDomain.SERVICE
        ),
    )


def _complement_ids() -> set[str]:
    return {
        item.obligation_id
        for item in _obligations()
        if item.kind is ObligationKind.DENY_COMPLEMENT
    }


def test_compile_grant_preserves_requirements_and_baseline() -> None:
    """Every final rule is attributable to its need/want or runtime source."""
    evaluation = evaluate_dac(
        ToolProfile(
            "reader",
            owner="alice",
            call_grants={"alice"},
            fs=(
                FsRule(
                    {"read", "write"},
                    PathTemplate("/workspace/report"),
                    Requirement.WANT,
                ),
            ),
        ),
        PrincipalProfile(
            "alice",
            fs=(FsRule({"read", "write"}, PathTemplate("/workspace", True)),),
        ),
        {},
    )
    baseline = GrantRule(
        "runtime:python",
        AuthorityDomain.RUNTIME,
        "read",
        "/usr/lib/python",
        {"subtree": True},
        baseline=True,
    )

    compiled = compile_grant(
        evaluation,
        principal_id="alice",
        session_id="session",
        artifact_digest="artifact-sha256",
        call_id="call-1",
        normalized_intent_digest="intent-sha256",
        policy_digest="policy-sha256",
        baseline_rules=(baseline,),
    )

    want_rules = {
        rule.rule_id
        for rule in compiled.grant.rules
        if rule.domain is AuthorityDomain.FILESYSTEM
    }
    assert len(want_rules) == 2
    assert all(
        rule.requirement is Requirement.WANT
        for rule in compiled.grant.rules
        if rule.rule_id in want_rules
    )
    assert compiled.ledger.recheck(frozenset({"runtime:python"})).removed_wants == (
        "fs:0",
    )
    assert compiled.ledger.recheck(frozenset(want_rules)).missing_needs == (
        "baseline:runtime:python",
        "syscall:minimal",
    )


def test_compile_grant_rejects_denial_and_unmarked_baseline() -> None:
    """Denied DAC results and hidden ambient authority never become grants."""
    denied = evaluate_dac(
        ToolProfile("reader", owner="alice", call_grants={"bob"}),
        PrincipalProfile("alice"),
        {},
    )
    arguments = {
        "principal_id": "alice",
        "session_id": "session",
        "artifact_digest": "artifact",
        "call_id": "call",
        "normalized_intent_digest": "intent",
        "policy_digest": "policy",
    }
    with pytest.raises(ValueError, match="denied DAC"):
        compile_grant(denied, **arguments)

    allowed = evaluate_dac(
        ToolProfile("reader", owner="alice", call_grants={"alice"}),
        PrincipalProfile("alice"),
        {},
    )
    hidden = GrantRule(
        "runtime:hidden",
        AuthorityDomain.RUNTIME,
        "read",
        "/usr/lib",
    )
    with pytest.raises(ValueError, match="baseline=True"):
        compile_grant(allowed, baseline_rules=(hidden,), **arguments)


def test_compile_obligations_denies_complement_of_every_domain() -> None:
    """Omitted domains still require proof that their ambient authority is denied."""
    obligations = compile_obligations(_grant())

    complements = {
        item.domain
        for item in obligations
        if item.kind is ObligationKind.DENY_COMPLEMENT
    }
    assert complements == set(AuthorityDomain)
    assert any(item.obligation_id == "rule:mail-rule:operate" for item in obligations)


def _host(*, nonce: str = "challenge", signature: str = "trusted") -> HostAttestation:
    return HostAttestation(
        "supervisor",
        nonce,
        "boot-1",
        "linux",
        1.0,
        100.0,
        frozenset({"service"}),
        {"mount_ns": "mnt:1", "cgroup": "/slanggraph/1"},
        {"probe_digest": "probe-sha256"},
        signature,
    )


def _context(*, worker_id: str = "worker-1") -> ExecutionContext:
    return ExecutionContext(
        worker_id,
        "pidfd:42",
        "boot-1",
        {"mount": "mnt:1", "network": "net:1"},
        "credential-context-sha256",
        "/slanggraph/1",
        "broker-epoch-1",
    )


def test_grant_digest_is_canonical_and_conditions_are_frozen() -> None:
    """Ordering and caller mutation cannot change the authority identity."""
    conditions: dict[str, Any] = {"method": "POST", "headers": {"x": "1"}}
    rule = GrantRule(
        "http-rule",
        AuthorityDomain.NETWORK,
        "http.request",
        "https://example.com/reports",
        conditions,
    )
    conditions["method"] = "DELETE"
    first = replace(_grant(), rules=(rule,))
    second = replace(
        _grant(),
        rules=(
            GrantRule(
                "http-rule",
                AuthorityDomain.NETWORK,
                "http.request",
                "https://example.com/reports",
                {"headers": {"x": "1"}, "method": "POST"},
            ),
        ),
    )
    assert first.digest == second.digest
    assert rule.conditions["method"] == "POST"


def test_capability_class_does_not_substitute_for_exact_rule_support() -> None:
    """A host capability cannot make an adapter's unsupported rule executable."""
    adapter = _Adapter("service", _complement_ids())
    result = EnforcementCoordinator([adapter], _Verifier()).negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert not result.allowed
    assert result.reason == "adapter_rule_unsupported:mail.channel"


def test_closed_world_complement_is_required_and_nonwaivable() -> None:
    """Listed permissions never run without denial of unlisted authority."""
    obligations = tuple(
        item
        for item in _obligations()
        if item.kind is not ObligationKind.DENY_COMPLEMENT
    )
    adapter = _Adapter("service", {item.obligation_id for item in obligations})
    result = EnforcementCoordinator([adapter], _Verifier()).negotiate(
        _grant(),
        _ledger(),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.default_deny"}),
        now=50.0,
    )
    assert not result.allowed
    assert result.reason.startswith("default_deny_missing:")
    assert "service" in result.reason


def test_multi_component_rule_requires_every_dependency() -> None:
    """Recipient validation alone is insufficient without channel and custody."""
    supported = {"mail.recipient", *_complement_ids()}
    adapter = _Adapter("service", supported)
    result = EnforcementCoordinator([adapter], _Verifier()).negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert not result.allowed
    assert result.reason == "adapter_rule_unsupported:mail.channel"


def test_one_primary_owner_is_selected_per_obligation() -> None:
    """Overlapping adapters require an explicit primary obligation owner."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    first = _Adapter("first", obligation_ids)
    second = _Adapter("second", obligation_ids)
    coordinator = EnforcementCoordinator([first, second], _Verifier())
    conflict = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    owners = {item: "first" for item in obligation_ids}
    selected = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        owners=owners,
        now=50.0,
    )
    assert conflict.reason.startswith("adapter_ownership_conflict:")
    assert selected.allowed
    assert selected.plan is not None
    assert {item.adapter_id for item in selected.plan.assignments} == {"first"}


def test_waiver_cannot_remove_need_but_can_remove_want_as_degraded() -> None:
    """Later lowering rechecks source requirements instead of widening access."""
    supported = {
        "mail.channel",
        "mail.credential",
        *_complement_ids(),
    }
    adapter = _Adapter("service", supported)
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    obligations = _obligations(recipient_waivable=True)
    need = coordinator.negotiate(
        _grant(Requirement.NEED),
        _ledger(Requirement.NEED),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.recipient"}),
        now=50.0,
    )
    want = coordinator.negotiate(
        _grant(Requirement.WANT),
        _ledger(Requirement.WANT),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.recipient"}),
        now=50.0,
    )
    assert need.reason == "required_authority_removed:profile:mail"
    assert want.allowed
    assert want.plan is not None
    assert want.plan.mode is EnforcementMode.DEGRADED
    assert want.plan.removed_wants == ("profile:mail",)


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        (_host(nonce="other"), "host_attestation_failed:nonce"),
        (_host(signature="untrusted"), "host_attestation_failed:trust"),
    ],
)
def test_host_evidence_is_verified_and_nonce_bound(
    host: HostAttestation, reason: str
) -> None:
    """A digest without fresh trust-anchored evidence cannot negotiate a plan."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    result = EnforcementCoordinator(
        [_Adapter("service", obligation_ids)], _Verifier()
    ).negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        host,
        expected_nonce="challenge",
        now=50.0,
    )
    assert result.reason == reason


def test_activation_receipt_binds_plan_and_worker_context() -> None:
    """Only worker-specific activation evidence releases an enforced plan."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    adapter = _Adapter("service", obligation_ids)
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    result = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert result.plan is not None
    receipt = coordinator.activate(
        _grant(), result.plan, _host(), _context(), nonce="activation", now=50.0
    )
    assert receipt.context_digest == _context().digest
    assert receipt.activated_obligations == frozenset(obligation_ids)
    assert receipt.mode is EnforcementMode.ENFORCED
    assert coordinator.validate_receipt(
        receipt,
        _grant(),
        result.plan,
        _host(),
        _context(),
        now=50.0,
    )
    changed_broker = replace(_context(), broker_epoch="broker-2")
    assert not coordinator.validate_receipt(
        receipt,
        _grant(),
        result.plan,
        _host(),
        changed_broker,
        now=50.0,
    )
    assert not coordinator.validate_receipt(
        receipt,
        _grant(),
        result.plan,
        _host(),
        _context(),
        now=101.0,
    )


def test_activation_rejects_evidence_from_another_worker() -> None:
    """Adapter evidence for a different execution context fails closed."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    adapter = _Adapter("service", obligation_ids, wrong_context=True)
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    result = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert result.plan is not None
    with pytest.raises(ValueError, match="worker binding"):
        coordinator.activate(
            _grant(), result.plan, _host(), _context(), nonce="activation", now=50.0
        )
