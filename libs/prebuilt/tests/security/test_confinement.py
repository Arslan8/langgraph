"""Tests for AppArmor-style mandatory confinement profiles."""

from __future__ import annotations

from pathlib import Path

import pytest

from langgraph.prebuilt.security import (
    AuthorityDomain,
    ConfinementDeny,
    ConfinementPolicy,
    ConfinementProfile,
    Grant,
    GrantRule,
    Principal,
    Requirement,
    RequirementEntry,
    RequirementLedger,
    ResourceAllowance,
    RulePredicate,
    SecurityStack,
    Tool,
    ToolCall,
    ToolDac,
    TypedPolicyBackend,
    Verdict,
    resource_path,
)


def _principal() -> Principal:
    return Principal("alice", frozenset({"user"}), frozenset(), "session")


def _call(name: str) -> ToolCall:
    tool = Tool(name, ToolDac("user", {"user": "x"}), frozenset(), ())
    return ToolCall(tool, {}, {}, "call", 0)


def _grant(*rules: GrantRule) -> Grant:
    return Grant(
        "alice", "session", "tool", "artifact", "call", "intent", "policy", rules
    )


def _ledger(*rules: GrantRule) -> RequirementLedger:
    return RequirementLedger(
        tuple(
            RequirementEntry(rule.rule_id, rule.requirement, frozenset({rule.rule_id}))
            for rule in rules
        )
    )


def _decision(policy: ConfinementPolicy, tool_name: str = "report"):
    stack = SecurityStack([policy])
    try:
        return stack.permission(_principal(), _call(tool_name))
    finally:
        stack.close()


def test_profile_default_denies_unlisted_paths_and_explicit_domains(
    tmp_path: Path,
) -> None:
    root = resource_path(f"{tmp_path}/workspace/**")
    source = resource_path(f"{tmp_path}/workspace/source/**")
    profile = ConfinementProfile(
        "reporter",
        "1",
        frozenset({"report"}),
        root,
        (ResourceAllowance(source, frozenset({"read"})),),
        deny=(
            ConfinementDeny(
                "offline",
                RulePredicate(domain=AuthorityDomain.NETWORK.value),
                "network_disabled",
            ),
        ),
    )
    decision = _decision(ConfinementPolicy([profile]))
    assert decision.verdict is Verdict.ALLOW

    read = GrantRule(
        "read",
        AuthorityDomain.FILESYSTEM,
        "read",
        source.value,
        {"subtree": True},
        Requirement.WANT,
    )
    write = GrantRule(
        "write",
        AuthorityDomain.FILESYSTEM,
        "write",
        source.value,
        {"subtree": True},
        Requirement.WANT,
    )
    unlisted = GrantRule(
        "secret",
        AuthorityDomain.FILESYSTEM,
        "read",
        f"{tmp_path}/workspace/secrets",
        {"subtree": True},
        Requirement.WANT,
    )
    network = GrantRule(
        "network",
        AuthorityDomain.NETWORK,
        "connect",
        "443",
        requirement=Requirement.WANT,
    )
    result = TypedPolicyBackend().filter(
        _grant(read, write, unlisted, network),
        _ledger(read, write, unlisted, network),
        decision.constraints,
    )

    assert result.allowed
    assert result.grant is not None
    assert {(rule.operation, rule.selector) for rule in result.grant.rules} == {
        ("read", source.value)
    }


def test_required_authority_removed_by_profile_denies_call(tmp_path: Path) -> None:
    root = resource_path(f"{tmp_path}/workspace/**")
    profile = ConfinementProfile(
        "read-only",
        "1",
        frozenset({"report"}),
        root,
        (
            ResourceAllowance(
                resource_path(f"{tmp_path}/workspace/**"), frozenset({"read"})
            ),
        ),
    )
    decision = _decision(ConfinementPolicy([profile]))
    required_write = GrantRule(
        "write",
        AuthorityDomain.FILESYSTEM,
        "write",
        f"{tmp_path}/workspace/output",
        requirement=Requirement.NEED,
    )

    result = TypedPolicyBackend().filter(
        _grant(required_write), _ledger(required_write), decision.constraints
    )

    assert not result.allowed
    assert result.reason == "required_authority_removed:write"


def test_missing_profile_fails_closed_by_default() -> None:
    profile = ConfinementProfile("known", "1", frozenset({"known"}))

    decision = _decision(ConfinementPolicy([profile]), "unknown")

    assert decision.verdict is Verdict.DENY
    assert decision.reason == "confinement:profile_missing:unknown"


def test_wildcard_and_tool_profile_both_apply() -> None:
    baseline = ConfinementProfile(
        "baseline",
        "1",
        frozenset({"*"}),
        deny=(
            ConfinementDeny(
                "no-delegation",
                RulePredicate(domain=AuthorityDomain.DELEGATION.value),
                "delegation_disabled",
            ),
        ),
    )
    offline = ConfinementProfile(
        "offline",
        "1",
        frozenset({"report"}),
        deny=(
            ConfinementDeny(
                "no-network",
                RulePredicate(domain=AuthorityDomain.NETWORK.value),
                "network_disabled",
            ),
        ),
    )

    decision = _decision(ConfinementPolicy([baseline, offline]))

    assert decision.verdict is Verdict.ALLOW
    assert len(decision.constraints) == 2
    assert {constraint.module for constraint in decision.constraints} == {"confinement"}


def test_profile_rejects_path_rules_without_scope(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="path rules require a path_scope"):
        ConfinementProfile(
            "invalid",
            "1",
            frozenset({"tool"}),
            path_allow=(
                ResourceAllowance(resource_path(str(tmp_path)), frozenset({"read"})),
            ),
        )
