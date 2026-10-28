"""AppArmor-style confinement profiles built on mandatory grant filtering.

The profiles in this module are framework policy, not Linux AppArmor profiles.
They attach restrictive, typed constraints to named tools; the configured host
executor remains responsible for lowering and enforcing the filtered grant.
"""

from __future__ import annotations

from dataclasses import dataclass

from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.profile import BoundPath
from langgraph.prebuilt.security.resource_boundary import (
    ResourceAllowance,
    ResourceBoundary,
    ResourceBoundaryPolicy,
    resource_path,
)
from langgraph.prebuilt.security.types import (
    Decision,
    ForbidConstraint,
    Principal,
    RulePredicate,
    ToolCall,
    Verdict,
)

_MAX_PROFILES = 64
_MAX_DENIES = 64


@dataclass(frozen=True, slots=True)
class ConfinementDeny:
    """One explicitly denied class of authority in a confinement profile."""

    rule_id: str
    predicate: RulePredicate
    reason: str

    def __post_init__(self) -> None:
        if not self.rule_id or not self.reason:
            raise ValueError("deny rule identity and reason must be non-empty")
        if any(character.isspace() or character in "@:" for character in self.rule_id):
            raise ValueError("deny rule ID must be an atom without '@' or ':'")


@dataclass(frozen=True, slots=True)
class ConfinementProfile:
    """A restrictive profile attached to one or more tool names.

    `path_scope` enables default-deny path policy inside that subtree. Listed
    `path_allow` entries are permission ceilings, and `path_forbid` entries win
    over allowances. Explicit `deny` rules cover non-path domains or additional
    path restrictions. A tool may match multiple profiles; all of them apply.
    The special tool name `*` matches every tool.
    """

    profile_id: str
    version: str
    tools: frozenset[str]
    path_scope: BoundPath | None = None
    path_allow: tuple[ResourceAllowance, ...] = ()
    path_forbid: tuple[BoundPath, ...] = ()
    deny: tuple[ConfinementDeny, ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("profile_id", self.profile_id),
            ("version", self.version),
        ):
            if not value or any(
                character.isspace() or character in "@:" for character in value
            ):
                raise ValueError(f"{label} must be a non-empty atom without '@' or ':'")
        tools = frozenset(self.tools)
        if not tools or any(not tool or tool != tool.strip() for tool in tools):
            raise ValueError("confinement profiles require non-empty tool names")
        if "*" in tools and len(tools) != 1:
            raise ValueError("the wildcard tool must be the profile's only tool")
        path_allow = tuple(self.path_allow)
        path_forbid = tuple(resource_path(path) for path in self.path_forbid)
        deny = tuple(self.deny)
        if len(deny) > _MAX_DENIES:
            raise ValueError(f"profiles support at most {_MAX_DENIES} deny rules")
        if any(not isinstance(item, ConfinementDeny) for item in deny):
            raise TypeError("deny entries must be ConfinementDeny values")
        rule_ids = [item.rule_id for item in deny]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("deny rule IDs must be unique within a profile")
        if self.path_scope is None and (path_allow or path_forbid):
            raise ValueError("path rules require a path_scope")
        scope = resource_path(self.path_scope) if self.path_scope is not None else None
        # Reuse the boundary policy's canonical containment and complexity checks.
        if scope is not None:
            ResourceBoundaryPolicy(
                self.profile_id,
                self.version,
                scope,
                path_allow,
                path_forbid,
            )
        object.__setattr__(self, "tools", tools)
        object.__setattr__(self, "path_scope", scope)
        object.__setattr__(self, "path_allow", path_allow)
        object.__setattr__(self, "path_forbid", path_forbid)
        object.__setattr__(self, "deny", deny)

    @property
    def attribution(self) -> str:
        """Return the stable identity included in decisions and constraints."""
        return f"{self.profile_id}@{self.version}"


class ConfinementPolicy(SecurityModule):
    """Attach AppArmor-style, forbid-only confinement profiles to tools."""

    can_escalate = False

    def __init__(
        self,
        profiles: tuple[ConfinementProfile, ...] | list[ConfinementProfile],
        *,
        require_profile: bool = True,
        name: str = "confinement",
    ) -> None:
        profiles = tuple(profiles)
        if not name:
            raise ValueError("confinement module name must be non-empty")
        if not profiles or len(profiles) > _MAX_PROFILES:
            raise ValueError(
                f"confinement policy requires between one and {_MAX_PROFILES} profiles"
            )
        if any(not isinstance(profile, ConfinementProfile) for profile in profiles):
            raise TypeError("profiles must be ConfinementProfile values")
        identities = [profile.attribution for profile in profiles]
        if len(identities) != len(set(identities)):
            raise ValueError("confinement profile identities must be unique")
        self.name = name
        self.profiles = profiles
        self.require_profile = require_profile
        self._constraints = {
            profile.attribution: _compile_profile(profile) for profile in profiles
        }

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Return every matching profile's restrictions or fail closed."""
        del principal
        matched = tuple(
            profile
            for profile in self.profiles
            if "*" in profile.tools or call.tool.name in profile.tools
        )
        if not matched:
            verdict = Verdict.DENY if self.require_profile else Verdict.ALLOW
            return Decision(verdict, f"{self.name}:profile_missing:{call.tool.name}")
        constraints = tuple(
            constraint
            for profile in matched
            for constraint in self._constraints[profile.attribution]
        )
        identities = ",".join(profile.attribution for profile in matched)
        return Decision(
            Verdict.ALLOW,
            f"{self.name}:profiles:{identities}",
            constraints=constraints,
        )


def _compile_profile(profile: ConfinementProfile) -> tuple[ForbidConstraint, ...]:
    constraints: list[ForbidConstraint] = []
    if profile.path_scope is not None:
        boundary = ResourceBoundary(
            ResourceBoundaryPolicy(
                profile.profile_id,
                profile.version,
                profile.path_scope,
                profile.path_allow,
                profile.path_forbid,
            )
        )
        constraints.extend(boundary.constraints)
    constraints.extend(
        ForbidConstraint(
            f"{profile.attribution}:deny:{deny.rule_id}",
            deny.predicate,
            deny.reason,
        )
        for deny in profile.deny
    )
    return tuple(constraints)
