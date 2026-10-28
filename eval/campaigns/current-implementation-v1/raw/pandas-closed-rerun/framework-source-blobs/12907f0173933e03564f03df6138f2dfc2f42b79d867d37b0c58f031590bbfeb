"""Reference mandatory module that bounds filesystem authority by resource.

`ResourceBoundary` is an ordinary `SecurityModule`. It never sees or builds a
grant, mount, seccomp rule, or executor plan. It translates an operator policy
into attributed, forbid-only `ForbidConstraint` values; the framework's policy
backend applies them to the candidate grant, rechecks `need` lines, and the
configured host executor negotiates and activates whatever remains.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from langgraph.prebuilt.security.descriptor import NORMALIZERS
from langgraph.prebuilt.security.enforcement import AuthorityDomain
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.profile import BoundPath, PathTemplate
from langgraph.prebuilt.security.types import (
    Decision,
    ForbidConstraint,
    Principal,
    RulePredicate,
    SelectorMatch,
    ToolCall,
    Verdict,
)

FILESYSTEM_OPERATIONS = frozenset(
    {"read", "write", "create", "delete", "exec", "truncate"}
)
"""Operation vocabulary shared with `.slp` filesystem lines."""

# Requested files and the runtime baseline are both path authority. Applying
# the same predicates to both domains means the module cannot exempt resources
# merely because the interpreter needs them.
_PATH_DOMAINS = (AuthorityDomain.FILESYSTEM.value, AuthorityDomain.RUNTIME.value)
_MAX_RESOURCES = 32


def resource_path(value: str | os.PathLike[str] | BoundPath) -> BoundPath:
    """Normalize one policy selector with the framework's path rules.

    Strings use the `.slp` path grammar: an exact absolute path, or a terminal
    `/**` for a subtree. The base path is then canonicalized with the same
    `realpath` normalizer used for tool path arguments, so policy selectors and
    grant selectors name resources in one namespace.
    """
    if isinstance(value, BoundPath):
        raw, subtree = value.value, value.subtree
    else:
        template = PathTemplate(os.fspath(value))
        raw, subtree = template.value, template.subtree
    if "${" in raw:
        raise ValueError("resource selectors cannot contain variables")
    return BoundPath(NORMALIZERS["realpath"](raw), subtree)


@dataclass(frozen=True, slots=True)
class ResourceAllowance:
    """Maximum filesystem operations permitted on one resource in the scope."""

    path: BoundPath
    operations: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", resource_path(self.path))
        operations = frozenset(self.operations)
        unknown = operations.difference(FILESYSTEM_OPERATIONS)
        if not operations or unknown:
            raise ValueError(
                f"allowance operations must be a non-empty subset of "
                f"{sorted(FILESYSTEM_OPERATIONS)}: {sorted(unknown)!r}"
            )
        object.__setattr__(self, "operations", operations)


@dataclass(frozen=True, slots=True)
class ResourceBoundaryPolicy:
    """Operator-owned resource restrictions with an audit identity.

    Within `scope`, a path may receive at most the operations of every
    allowance covering it (intersection), no operation if a forbidden selector
    covers it, and no operation if no allowance covers it. Outside `scope` the
    policy abstains. Neither entry order nor duplicate entries change the result.
    """

    policy_id: str
    version: str
    scope: BoundPath
    allow: tuple[ResourceAllowance, ...] = ()
    forbid: tuple[BoundPath, ...] = ()

    def __post_init__(self) -> None:
        for label, value in (("policy_id", self.policy_id), ("version", self.version)):
            if not value or any(
                character.isspace() or character in "@:" for character in value
            ):
                raise ValueError(f"{label} must be a non-empty atom without '@' or ':'")
        scope = resource_path(self.scope)
        if not scope.subtree:
            raise ValueError("resource boundary scope must be a '/**' subtree")
        allow = tuple(self.allow)
        if any(not isinstance(item, ResourceAllowance) for item in allow):
            raise TypeError("allow entries must be ResourceAllowance values")
        forbid = tuple(resource_path(item) for item in self.forbid)
        selectors = [item.path for item in allow] + list(forbid)
        outside = [item for item in selectors if not scope.contains(item)]
        if outside:
            raise ValueError(
                "resource boundary entries must lie inside the scope: "
                + ", ".join(_display(item) for item in outside)
            )
        if len(set(selectors)) > _MAX_RESOURCES:
            raise ValueError(
                f"resource boundary supports at most {_MAX_RESOURCES} resources"
            )
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "allow", allow)
        object.__setattr__(self, "forbid", forbid)

    @property
    def ceilings(self) -> Mapping[BoundPath, frozenset[str]]:
        """Return the per-selector operation ceiling after combining duplicates."""
        ceilings: dict[BoundPath, frozenset[str]] = {}
        for allowance in self.allow:
            prior = ceilings.get(allowance.path, FILESYSTEM_OPERATIONS)
            ceilings[allowance.path] = prior & allowance.operations
        for path in self.forbid:
            ceilings[path] = frozenset()
        return MappingProxyType(dict(sorted(ceilings.items())))

    @property
    def attribution(self) -> str:
        """Return the policy identity recorded in constraint IDs and reasons."""
        return f"{self.policy_id}@{self.version}"


class ResourceBoundary(SecurityModule):
    """Restrict filesystem and runtime path authority to an operator policy.

    The module supplies restrictions only. A resource it permits remains
    inaccessible unless author DAC and every other module also permit it. It
    never changes arguments or the principal and never escalates.
    """

    can_escalate = False

    def __init__(
        self, policy: ResourceBoundaryPolicy, *, name: str = "resource_boundary"
    ) -> None:
        if not isinstance(policy, ResourceBoundaryPolicy):
            raise TypeError("ResourceBoundary requires a ResourceBoundaryPolicy")
        self.name = name
        self.policy = policy
        self.constraints = _compile_constraints(policy)

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Return the policy's restrictions for the framework to apply.

        The framework evaluates these predicates against the call's candidate
        grant, including runtime baseline lines, so the module needs no
        tool-specific knowledge.
        """
        del principal, call
        return Decision(
            Verdict.ALLOW,
            f"{self.name}:{self.policy.attribution}",
            constraints=self.constraints,
        )


def _compile_constraints(
    policy: ResourceBoundaryPolicy,
) -> tuple[ForbidConstraint, ...]:
    ceilings = policy.ceilings
    constraints: list[ForbidConstraint] = []
    for domain in _PATH_DOMAINS:
        for path, permitted in ceilings.items():
            excess = FILESYSTEM_OPERATIONS - permitted
            if not excess:
                continue
            constraints.append(
                ForbidConstraint(
                    f"{policy.attribution}:{domain}:ceiling:{_display(path)}",
                    RulePredicate(
                        domain,
                        # An empty operation set matches every operation,
                        # including any outside the filesystem vocabulary.
                        excess if permitted else frozenset(),
                        path.value,
                        SelectorMatch.SUBTREE if path.subtree else SelectorMatch.EXACT,
                    ),
                    "resource_forbidden"
                    if not permitted
                    else "operation_not_permitted",
                )
            )
        permitted_paths = [path for path, ops in ceilings.items() if ops]
        constraints.append(
            ForbidConstraint(
                f"{policy.attribution}:{domain}:scope:{_display(policy.scope)}",
                RulePredicate(
                    domain,
                    frozenset(),
                    policy.scope.value,
                    SelectorMatch.SUBTREE,
                    exempt_subtrees=_values(p for p in permitted_paths if p.subtree),
                    exempt_paths=_values(p for p in permitted_paths if not p.subtree),
                ),
                "resource_not_listed",
            )
        )
    return tuple(constraints)


def _values(paths: Iterable[BoundPath]) -> frozenset[str]:
    return frozenset(path.value for path in paths)


def _display(path: BoundPath) -> str:
    if not path.subtree:
        return path.value
    return "/**" if path.value == "/" else f"{path.value}/**"
