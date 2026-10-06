"""Tests for typed, forbid-only mandatory-policy filtering."""

from __future__ import annotations

from dataclasses import replace

from langgraph.prebuilt.security import (
    AuthorityDomain,
    ForbidCombination,
    ForbidConstraint,
    Grant,
    GrantRule,
    Requirement,
    RequirementEntry,
    RequirementLedger,
    RulePredicate,
    SelectorMatch,
    TypedPolicyBackend,
)


def _grant(*rules: GrantRule) -> Grant:
    return Grant(
        "alice",
        "session",
        "research",
        "artifact",
        "call",
        "intent",
        "policy",
        rules,
    )


def _ledger(*rules: GrantRule) -> RequirementLedger:
    return RequirementLedger(
        tuple(
            RequirementEntry(
                f"source:{rule.rule_id}", rule.requirement, frozenset({rule.rule_id})
            )
            for rule in rules
        )
    )


def test_broad_filesystem_forbid_is_soundly_subtracted() -> None:
    """A forbidden child subtree becomes an exact adapter-visible exclusion."""
    broad = GrantRule(
        "workspace",
        AuthorityDomain.FILESYSTEM,
        "read",
        "/workspace",
        {"subtree": True},
    )
    constraint = ForbidConstraint(
        "no-secrets",
        RulePredicate(
            AuthorityDomain.FILESYSTEM.value,
            {"read"},
            "/workspace/secrets",
            SelectorMatch.SUBTREE,
        ),
        "secrets_are_isolated",
        "paths",
    )

    result = TypedPolicyBackend().filter(_grant(broad), _ledger(broad), (constraint,))

    assert result.allowed
    assert result.grant is not None
    assert result.grant.rules[0].conditions["exclude_subtrees"] == (
        "/workspace/secrets",
    )
    assert result.grant.rules[0].rule_id != broad.rule_id
    assert result.ledger.recheck(frozenset({result.grant.rules[0].rule_id})).allowed


def test_broad_nonrepresentable_forbid_removes_rule_and_rechecks_need() -> None:
    """A conditional service subset is never approximated as broadly allowed."""
    broad = GrantRule(
        "mail",
        AuthorityDomain.SERVICE,
        "send",
        "mail",
        requirement=Requirement.NEED,
    )
    constraint = ForbidConstraint(
        "no-competitor",
        RulePredicate(
            AuthorityDomain.SERVICE.value,
            {"send"},
            "mail",
            SelectorMatch.EXACT,
            {"recipient_domain": "competitor.example"},
        ),
        "external_recipient",
        "mail",
    )

    result = TypedPolicyBackend().filter(_grant(broad), _ledger(broad), (constraint,))

    assert not result.allowed
    assert result.reason.startswith("required_authority_removed")


def test_want_can_be_removed_without_broadening() -> None:
    """Removing advisory authority produces a narrower valid grant."""
    optional = GrantRule(
        "optional-net",
        AuthorityDomain.NETWORK,
        "connect",
        "443",
        requirement=Requirement.WANT,
    )
    constraint = ForbidConstraint(
        "offline",
        RulePredicate(domain=AuthorityDomain.NETWORK.value),
        "offline_execution",
        "network",
    )

    result = TypedPolicyBackend().filter(
        _grant(optional), _ledger(optional), (constraint,)
    )

    assert result.allowed
    assert result.grant is not None and result.grant.rules == ()


def test_aggregate_constraint_rejects_sensitive_read_plus_egress() -> None:
    """Combinations can be forbidden even when individual lines survive."""
    sensitive = GrantRule(
        "secrets",
        AuthorityDomain.FILESYSTEM,
        "read",
        "/workspace/secrets",
        {"subtree": True},
    )
    egress = GrantRule(
        "egress",
        AuthorityDomain.NETWORK,
        "connect",
        "443",
    )
    combination = ForbidCombination(
        "no-read-exfiltrate",
        (
            RulePredicate(
                AuthorityDomain.FILESYSTEM.value,
                {"read"},
                "/workspace/secrets",
                SelectorMatch.SUBTREE,
            ),
            RulePredicate(AuthorityDomain.NETWORK.value, {"connect"}),
        ),
        "sensitive_plus_egress",
        "flow",
    )

    result = TypedPolicyBackend().filter(
        _grant(sensitive, egress),
        _ledger(sensitive, egress),
        (combination,),
    )

    assert not result.allowed
    assert result.reason == "forbidden_combination:flow:no-read-exfiltrate"


def test_policy_diagnostics_fail_closed() -> None:
    """Unknown domains and malformed backend input cannot be silently skipped."""
    rule = GrantRule("file", AuthorityDomain.FILESYSTEM, "read", "/safe")
    invalid = ForbidConstraint(
        "bad",
        RulePredicate(domain="not-a-domain"),
        "bad_policy",
        "module",
    )

    result = TypedPolicyBackend().filter(_grant(rule), _ledger(rule), (invalid,))

    assert not result.allowed
    assert result.reason == "policy_error"
    assert result.diagnostics


def test_policy_digest_binds_typed_constraints() -> None:
    """Changing one constraint changes the policy and grant digests."""
    optional = GrantRule(
        "optional-net",
        AuthorityDomain.NETWORK,
        "connect",
        "443",
        requirement=Requirement.WANT,
    )
    first = ForbidConstraint(
        "offline",
        RulePredicate(domain=AuthorityDomain.NETWORK.value),
        "offline",
        "network",
    )
    second = replace(first, reason="different")
    backend = TypedPolicyBackend()

    one = backend.filter(_grant(optional), _ledger(optional), (first,))
    two = backend.filter(_grant(optional), _ledger(optional), (second,))

    assert one.grant is not None and two.grant is not None
    assert one.grant.policy_digest != two.grant.policy_digest
    assert one.grant.digest != two.grant.digest
