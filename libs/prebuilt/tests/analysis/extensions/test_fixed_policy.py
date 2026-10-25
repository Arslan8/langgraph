"""Progent-inspired fixed predicates; no inference, DSL or policy updates."""

from typing import Literal

import pytest
from pydantic import Field, ValidationError

from langgraph.prebuilt.analysis.contracts import Record
from langgraph.prebuilt.security import (
    Decision,
    SecurityConfig,
    SecurityDeniedError,
    SecurityModule,
    Verdict,
    dac,
    guarded_tool,
)
from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate
from tests.analysis.test_policy_bridge import principal_config
from tests.analysis.test_runtime_access import setup_runtime


class Predicate(Record):
    kind: Literal["membership", "numeric_bounds"]
    argument: str
    members: frozenset[str] = frozenset()
    minimum: float = Field(default=0, allow_inf_nan=False)
    maximum: float = Field(default=100, allow_inf_nan=False)

    def matches(self, arguments):
        value = arguments.get(self.argument)
        if self.kind == "membership":
            return isinstance(value, str) and value in self.members
        return type(value) in (int, float) and self.minimum <= value <= self.maximum


class Rule(Record):
    tool_id: str
    effect: Literal["permit", "deny"]
    predicates: tuple[Predicate, ...]


class FixedPrivilegePolicy(SecurityModule):
    name = "fixed_privilege"

    def __init__(self, rules: tuple[Rule, ...]):
        self._rules = tuple(rules)

    def tool_call_permission(self, principal, call):
        # This fixture has scalar args with identity normalization and no resources.
        arguments = {**call.args, **call.normalized}
        matched = [
            r
            for r in self._rules
            if r.tool_id == call.tool.name
            and all(p.matches(arguments) for p in r.predicates)
        ]
        if any(r.effect == "deny" for r in matched) or not any(
            r.effect == "permit" for r in matched
        ):
            return Decision(Verdict.DENY, "fixed:denied")
        return Decision(Verdict.ALLOW, "fixed:no_objection")


def test_fixed_predicates_default_deny_and_deny_precedence():
    runtime, _, _, _ = setup_runtime()
    rules = (
        Rule(
            tool_id="fixed_test",
            effect="permit",
            predicates=(
                Predicate(
                    kind="numeric_bounds", argument="amount", minimum=0, maximum=10
                ),
            ),
        ),
        Rule(
            tool_id="fixed_test",
            effect="deny",
            predicates=(
                Predicate(
                    kind="numeric_bounds", argument="amount", minimum=5, maximum=6
                ),
            ),
        ),
    )
    policy = FixedPrivilegePolicy(rules)
    security = SecurityConfig(
        modules=(AnalysisGate(runtime.config.policy_version), policy), analysis=runtime
    )
    effects = []

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"})
    def fixed_test(amount: int) -> str:
        """Record a bounded fixture amount."""
        effects.append(amount)
        return "recorded"

    fixed_test.invoke({"amount": 2}, principal_config())
    for amount in (5, 12):
        with pytest.raises(SecurityDeniedError):
            fixed_test.invoke({"amount": amount}, principal_config())
    assert effects == [2]
    assert policy._rules == rules
    with pytest.raises(ValidationError):
        Predicate(kind="python", argument="amount")
    runtime.close()
