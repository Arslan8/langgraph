"""Typed, forbid-only mandatory-policy filtering for final grants."""

from __future__ import annotations

import hashlib
import json
import posixpath
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    Grant,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
)
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.types import (
    ForbidCombination,
    ForbidConstraint,
    PolicyConstraint,
    RulePredicate,
    SelectorMatch,
)


@dataclass(frozen=True, slots=True)
class PolicyFilterResult:
    """Result of mandatory filtering, including diagnostics and reductions."""

    grant: Grant | None
    ledger: RequirementLedger
    reason: str
    removed_rule_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        """Whether a complete post-policy grant remains."""
        return self.grant is not None and not self.diagnostics


@runtime_checkable
class MandatoryPolicyBackend(Protocol):
    """Replaceable backend for filtering exact authority with typed constraints."""

    def filter(
        self,
        grant: Grant,
        ledger: RequirementLedger,
        constraints: Sequence[PolicyConstraint],
    ) -> PolicyFilterResult:
        """Return a no-broader grant or a fail-closed result."""
        ...


class TypedPolicyBackend:
    """Reference backend with sound path subtraction and aggregate checks."""

    def filter(
        self,
        grant: Grant,
        ledger: RequirementLedger,
        constraints: Sequence[PolicyConstraint],
    ) -> PolicyFilterResult:
        """Apply attributed forbid-only constraints without evaluating code."""
        try:
            return _filter_grant(grant, ledger, constraints)
        except (TypeError, ValueError) as exc:
            modules = sorted(
                {
                    str(getattr(constraint, "module", "unknown")) or "unknown"
                    for constraint in constraints
                }
            )
            diagnostic = (
                f"policy_error:{type(exc).__name__}:{exc}:modules={','.join(modules)}"
            )
            return PolicyFilterResult(
                None, ledger, "policy_error", diagnostics=(diagnostic,)
            )


_PATH_DOMAINS = frozenset(
    {AuthorityDomain.FILESYSTEM.value, AuthorityDomain.RUNTIME.value}
)


class _Relation(str, Enum):
    NONE = "none"
    FULL = "full"
    PARTIAL = "partial"


def _filter_grant(
    grant: Grant,
    ledger: RequirementLedger,
    constraints: Sequence[PolicyConstraint],
) -> PolicyFilterResult:
    _validate_constraints(constraints)
    # Forbids are monotone, so application order cannot change effective
    # authority. A canonical order also makes derived rule IDs, provenance,
    # and the policy digest independent of module registration order.
    constraints = sorted(
        constraints, key=lambda item: (item.module, item.constraint_id)
    )
    active = {rule.rule_id: rule for rule in grant.rules}
    origins = {rule.rule_id: frozenset({rule.rule_id}) for rule in grant.rules}
    removed: set[str] = set()

    for constraint in constraints:
        if not isinstance(constraint, ForbidConstraint):
            continue
        for rule in tuple(active.values()):
            relation = _relation(constraint.predicate, rule)
            if relation is _Relation.NONE:
                continue
            if relation is _Relation.FULL:
                _remove(rule.rule_id, active, origins, removed)
                continue
            narrowed = _subtract(rule, constraint)
            if narrowed is None:
                _remove(rule.rule_id, active, origins, removed)
            else:
                rule_origins = origins.pop(rule.rule_id)
                del active[rule.rule_id]
                active[narrowed.rule_id] = narrowed
                origins[narrowed.rule_id] = rule_origins
                removed.add(rule.rule_id)

    for combination in (
        item for item in constraints if isinstance(item, ForbidCombination)
    ):
        matches = [
            tuple(rule for rule in active.values() if _matches(term, rule))
            for term in combination.terms
        ]
        if any(not term_matches for term_matches in matches):
            continue
        removable = {
            rule.rule_id
            for term_matches in matches
            for rule in term_matches
            if rule.requirement is Requirement.WANT and not rule.baseline
        }
        if not removable:
            return PolicyFilterResult(
                None,
                _remap_ledger(ledger, origins),
                f"forbidden_combination:{combination.module}:{combination.constraint_id}",
                tuple(sorted(removed)),
            )
        for rule_id in removable:
            _remove(rule_id, active, origins, removed)

    filtered_ledger = _remap_ledger(ledger, origins)
    active_ids = frozenset(active)
    check = filtered_ledger.recheck(active_ids)
    if not check.allowed:
        return PolicyFilterResult(
            None,
            filtered_ledger,
            f"required_authority_removed:{','.join(check.missing_needs)}",
            tuple(sorted(removed)),
        )
    policy_digest = _digest(
        {
            "constraints": [_constraint_payload(item) for item in constraints],
            "prior_policy_digest": grant.policy_digest,
        }
    )
    filtered = replace(
        grant,
        policy_digest=policy_digest,
        rules=tuple(sorted(active.values(), key=lambda item: item.rule_id)),
    )
    return PolicyFilterResult(
        filtered,
        filtered_ledger,
        "allow",
        tuple(sorted(removed)),
    )


def _validate_constraints(constraints: Sequence[PolicyConstraint]) -> None:
    identities: set[tuple[str, str]] = set()
    if len(constraints) > 256:
        raise ValueError("constraint count exceeds the bounded complexity limit")
    for constraint in constraints:
        if not isinstance(constraint, ForbidConstraint | ForbidCombination):
            raise TypeError("module returned an unknown policy constraint")
        if not constraint.module:
            raise ValueError("policy constraints must be attributed to a module")
        identity = (constraint.module, constraint.constraint_id)
        if identity in identities:
            raise ValueError("module constraint IDs must be unique")
        identities.add(identity)
        predicates = (
            (constraint.predicate,)
            if isinstance(constraint, ForbidConstraint)
            else constraint.terms
        )
        for predicate in predicates:
            if predicate.domain is not None:
                try:
                    AuthorityDomain(predicate.domain)
                except ValueError as exc:
                    raise ValueError(
                        f"unknown authority domain:{predicate.domain}"
                    ) from exc
            if (
                predicate.selector_match is SelectorMatch.SUBTREE
                and predicate.domain not in _PATH_DOMAINS
            ):
                raise ValueError("subtree matching is valid only for path rules")
            if predicate.exempt_subtrees or predicate.exempt_paths:
                selector = predicate.selector or ""
                for exempt in (*predicate.exempt_subtrees, *predicate.exempt_paths):
                    if not _canonical_absolute(exempt) or not _path_contains(
                        selector, exempt
                    ):
                        raise ValueError(
                            "exemptions must be canonical paths inside the selector"
                        )


def _matches(predicate: RulePredicate, rule: GrantRule) -> bool:
    return _relation(predicate, rule) is not _Relation.NONE


def _relation(predicate: RulePredicate, rule: GrantRule) -> _Relation:
    if predicate.domain is not None and predicate.domain != rule.domain.value:
        return _Relation.NONE
    if predicate.operations and rule.operation not in predicate.operations:
        return _Relation.NONE
    selector_relation = _selector_relation(predicate, rule)
    if selector_relation is _Relation.NONE:
        return _Relation.NONE
    for key, value in predicate.conditions.items():
        if key not in rule.conditions:
            return _Relation.PARTIAL
        if rule.conditions[key] != value:
            return _Relation.NONE
    return selector_relation


def _selector_relation(predicate: RulePredicate, rule: GrantRule) -> _Relation:
    if predicate.selector_match is SelectorMatch.ANY:
        return _Relation.FULL
    selector = predicate.selector
    if selector is None:
        raise ValueError("selector is required")
    if predicate.selector_match is SelectorMatch.EXACT:
        if rule.selector == selector and not bool(rule.conditions.get("subtree")):
            return _Relation.FULL
        if _rule_contains_path(rule, selector):
            return _Relation.PARTIAL
        return _Relation.NONE
    if not _canonical_absolute(selector):
        raise ValueError("subtree predicate selector must be canonical and absolute")
    rule_subtree = bool(rule.conditions.get("subtree"))
    if _path_contains(selector, rule.selector):
        relation = _Relation.FULL
    elif rule_subtree and _path_contains(rule.selector, selector):
        relation = _Relation.PARTIAL
    else:
        return _Relation.NONE
    return _apply_exemptions(predicate, rule, rule_subtree, relation)


def _apply_exemptions(
    predicate: RulePredicate,
    rule: GrantRule,
    rule_subtree: bool,
    relation: _Relation,
) -> _Relation:
    """Narrow a subtree relation to the selector minus its exemptions.

    Existing rule exclusions are ignored, which can only over-approximate the
    rule and therefore never turns a real overlap into `NONE`.
    """
    if not predicate.exempt_subtrees and not predicate.exempt_paths:
        return relation
    if any(_path_contains(item, rule.selector) for item in predicate.exempt_subtrees):
        return _Relation.NONE
    if not rule_subtree and rule.selector in predicate.exempt_paths:
        return _Relation.NONE
    if rule_subtree and any(
        _path_contains(rule.selector, item)
        for item in (*predicate.exempt_subtrees, *predicate.exempt_paths)
    ):
        return _Relation.PARTIAL
    return relation


def _rule_contains_path(rule: GrantRule, path: str) -> bool:
    return (
        rule.domain.value in _PATH_DOMAINS
        and bool(rule.conditions.get("subtree"))
        and _path_contains(rule.selector, path)
    )


def _canonical_absolute(path: str) -> bool:
    return path.startswith("/") and posixpath.normpath(path) == path


def _path_contains(parent: str, child: str) -> bool:
    return parent == "/" or child == parent or child.startswith(parent + "/")


def _subtract(rule: GrantRule, constraint: ForbidConstraint) -> GrantRule | None:
    predicate = constraint.predicate
    if (
        rule.domain is not AuthorityDomain.FILESYSTEM
        or predicate.selector is None
        or predicate.conditions
        # The partial difference keeps exempt pieces inside the forbidden
        # region, which one exclusion list cannot represent.
        or predicate.exempt_subtrees
        or predicate.exempt_paths
    ):
        return None
    conditions = dict(rule.conditions)
    key = (
        "exclude_subtrees"
        if predicate.selector_match is SelectorMatch.SUBTREE
        else "exclude_paths"
    )
    excluded = set(conditions.get(key, ()))
    excluded.add(predicate.selector)
    conditions[key] = tuple(sorted(excluded))
    suffix = _digest(
        {
            "constraint": constraint.constraint_id,
            "conditions": conditions,
            "module": constraint.module,
        }
    )[:16]
    return replace(
        rule,
        rule_id=f"{rule.rule_id}:restricted:{suffix}",
        conditions=conditions,
        provenance=(
            *rule.provenance,
            f"{constraint.module}:{constraint.constraint_id}",
        ),
    )


def _remove(
    rule_id: str,
    active: dict[str, GrantRule],
    origins: dict[str, frozenset[str]],
    removed: set[str],
) -> None:
    active.pop(rule_id, None)
    origins.pop(rule_id, None)
    removed.add(rule_id)


def _remap_ledger(
    ledger: RequirementLedger,
    origins: Mapping[str, frozenset[str]],
) -> RequirementLedger:
    entries: list[RequirementEntry] = []
    for entry in ledger.entries:
        descendants = frozenset(
            current_id
            for current_id, source_ids in origins.items()
            if not source_ids.isdisjoint(entry.rule_ids)
        )
        if descendants:
            entries.append(
                RequirementEntry(entry.source_id, entry.requirement, descendants)
            )
        else:
            entries.append(
                RequirementEntry(entry.source_id, entry.requirement, frozenset())
            )
    return RequirementLedger(tuple(entries))


def _constraint_payload(constraint: PolicyConstraint) -> Mapping[str, Any]:
    predicates = (
        (constraint.predicate,)
        if isinstance(constraint, ForbidConstraint)
        else constraint.terms
    )
    return {
        "constraint_id": constraint.constraint_id,
        "kind": "forbid" if isinstance(constraint, ForbidConstraint) else "combination",
        "module": constraint.module,
        "predicates": [
            {
                "conditions": dict(predicate.conditions),
                "domain": predicate.domain,
                "exempt_paths": sorted(predicate.exempt_paths),
                "exempt_subtrees": sorted(predicate.exempt_subtrees),
                "operations": sorted(predicate.operations),
                "selector": predicate.selector,
                "selector_match": predicate.selector_match.value,
            }
            for predicate in predicates
        ],
        "reason": constraint.reason,
    }


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=repr
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
