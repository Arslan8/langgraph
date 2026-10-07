"""Policy and composition tests for the `ResourceBoundary` reference module.

These tests exercise the semantic path only: module constraints, the reference
policy backend, and requirement revalidation. Real worker enforcement is covered
by `test_resource_boundary_linux.py`.
"""

from __future__ import annotations

import itertools
import random
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import Mock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Approval,
    AuthorityDomain,
    CapModule,
    Decision,
    Effect,
    EscalationRequest,
    ForbidConstraint,
    Grant,
    GrantRule,
    PolicyConstraint,
    PolicyFilterResult,
    Principal,
    Requirement,
    RequirementEntry,
    RequirementLedger,
    ResourceAllowance,
    ResourceArg,
    ResourceBoundary,
    ResourceBoundaryPolicy,
    RulePredicate,
    SecurityConfig,
    SecurityDeniedError,
    SecurityModule,
    SecurityStack,
    SelectorMatch,
    Tool,
    ToolCall,
    ToolDac,
    TypedPolicyBackend,
    Verdict,
    compile_grant,
    dac,
    effects,
    guarded_tool,
    parse_profiles,
    resource_path,
    with_principal,
)

_ALL = frozenset({"read", "write", "create", "delete", "exec", "truncate"})
_MUTATE = frozenset({"read", "write", "create", "delete", "truncate"})


class _Layout:
    """Temporary fixture tree; never real credentials or personal files."""

    def __init__(self, root: Path) -> None:
        self.root = root / "project"
        self.src = self.root / "src"
        self.artifacts = self.root / "artifacts"
        self.credentials = self.root / "credentials"
        self.config = self.root / "project.toml"
        for directory in (self.src, self.artifacts, self.credentials):
            directory.mkdir(parents=True)
        (self.src / "main.py").write_text("print('fixture')\n")
        (self.credentials / "token.txt").write_text("fixture-not-a-secret\n")
        self.config.write_text("name = 'fixture'\n")


def _policy(
    layout: _Layout, *, version: str = "1", reverse: bool = False
) -> ResourceBoundaryPolicy:
    allow = [
        ResourceAllowance(resource_path(f"{layout.src}/**"), frozenset({"read"})),
        ResourceAllowance(resource_path(f"{layout.artifacts}/**"), _MUTATE),
        ResourceAllowance(resource_path(str(layout.config)), frozenset({"read"})),
    ]
    forbid = [resource_path(f"{layout.credentials}/**")]
    if reverse:
        allow.reverse()
    return ResourceBoundaryPolicy(
        "project-boundary",
        version,
        resource_path(f"{layout.root}/**"),
        tuple(allow),
        tuple(forbid),
    )


@pytest.fixture
def layout(tmp_path: Path) -> _Layout:
    return _Layout(tmp_path)


def _profiles(layout: _Layout, tool_lines: str, *, principal_fs: str = "") -> str:
    return f"""
tool probe {{
  owner analyst
  grant analyst: call
  {tool_lines}
}}
principal alice {{
  roles analyst
  {principal_fs or f"fs {layout.root}/**"}
}}
"""


def _principal(scopes: Sequence[str] = ()) -> Principal:
    return Principal("alice", frozenset({"analyst"}), frozenset(scopes), "session")


def _call(name: str = "probe", required_scopes: Sequence[str] = ()) -> ToolCall:
    tool_ = Tool(
        name,
        ToolDac("analyst", {"analyst": "x"}, frozenset(required_scopes)),
        frozenset({Effect.READ}),
        (),
    )
    return ToolCall(tool_, {}, {}, "call", 0)


def _candidate(
    profile_text: str,
    args: dict[str, object],
    *,
    tool_name: str = "probe",
    baseline: Sequence[GrantRule] = (),
):
    evaluation = parse_profiles(profile_text).evaluate(tool_name, "alice", args)
    assert not evaluation.denied, evaluation.reason
    return compile_grant(
        evaluation,
        principal_id="alice",
        session_id="session",
        artifact_digest="artifact",
        call_id="call",
        normalized_intent_digest="intent",
        policy_digest="pre-mac",
        baseline_rules=baseline,
    )


def _module_constraints(
    modules: Sequence[SecurityModule],
    *,
    principal: Principal | None = None,
    call: ToolCall | None = None,
    approval: Approval | None = None,
) -> Decision:
    stack = SecurityStack(modules)
    try:
        return stack.permission(
            principal or _principal(), call or _call(), approval=approval
        )
    finally:
        stack.close()


def _filter(compiled, constraints: Sequence[PolicyConstraint]) -> PolicyFilterResult:
    return TypedPolicyBackend().filter(compiled.grant, compiled.ledger, constraints)


def _authority(grant: Grant | None) -> set[tuple[str, str, str, tuple]]:
    """Effective authority with identities and provenance erased."""
    assert grant is not None
    return {
        (
            rule.domain.value,
            rule.operation,
            rule.selector,
            tuple(sorted((key, str(value)) for key, value in rule.conditions.items())),
        )
        for rule in grant.rules
        if rule.domain.value in {"filesystem", "runtime"}
    }


def _restrict(layout: _Layout, compiled) -> PolicyFilterResult:
    decision = _module_constraints([ResourceBoundary(_policy(layout))])
    assert decision.verdict is Verdict.ALLOW
    return _filter(compiled, decision.constraints)


# Policy configuration


def test_policy_combines_overlaps_by_intersection_and_forbids_override(
    tmp_path: Path,
) -> None:
    """Duplicate and nested entries narrow; a forbid empties the ceiling."""
    scope = resource_path(f"{tmp_path}/**")
    shared = resource_path(f"{tmp_path}/shared/**")
    policy = ResourceBoundaryPolicy(
        "p",
        "1",
        scope,
        (
            ResourceAllowance(shared, frozenset({"read", "write"})),
            ResourceAllowance(shared, frozenset({"read", "create"})),
            ResourceAllowance(resource_path(f"{tmp_path}/x/**"), _MUTATE),
        ),
        (resource_path(f"{tmp_path}/x/**"),),
    )

    assert policy.ceilings[shared] == frozenset({"read"})
    assert policy.ceilings[resource_path(f"{tmp_path}/x/**")] == frozenset()
    assert policy.attribution == "p@1"


@pytest.mark.parametrize(
    "selector",
    ["relative/**", "/a/*.txt", "/a/${user}/**", "/a/[ab]"],
)
def test_policy_selectors_use_profile_path_grammar(selector: str) -> None:
    """Selectors are parsed by the `.slp` grammar, not a second parser."""
    with pytest.raises(ValueError):
        resource_path(selector)


def test_policy_selectors_use_realpath_normalization(tmp_path: Path) -> None:
    """A symlinked selector names the same resource as a normalized argument."""
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "alias").symlink_to(real)

    assert resource_path(f"{tmp_path}/alias/**") == resource_path(f"{real}/**")
    assert resource_path(f"{tmp_path}/real/../real/**").value == str(real)


def test_policy_rejects_entries_outside_scope_and_bad_operations(
    tmp_path: Path,
) -> None:
    """Entries outside the controlled scope would be silently inert."""
    scope = resource_path(f"{tmp_path}/scope/**")
    with pytest.raises(ValueError, match="inside the scope"):
        ResourceBoundaryPolicy(
            "p",
            "1",
            scope,
            (ResourceAllowance(resource_path(f"{tmp_path}/scoped/**"), {"read"}),),
        )
    with pytest.raises(ValueError, match="subset"):
        ResourceAllowance(resource_path(f"{tmp_path}/scope/**"), {"read", "chmod"})
    with pytest.raises(ValueError, match="subset"):
        ResourceAllowance(resource_path(f"{tmp_path}/scope/**"), set())
    with pytest.raises(ValueError, match="subtree"):
        ResourceBoundaryPolicy("p", "1", resource_path(str(tmp_path)))
    with pytest.raises(ValueError, match="atom"):
        ResourceBoundaryPolicy("p@x", "1", scope)


def test_constraints_are_independent_of_entry_order(layout: _Layout) -> None:
    """Reordering operator entries yields identical typed constraints."""
    forward = ResourceBoundary(_policy(layout)).constraints
    backward = ResourceBoundary(_policy(layout, reverse=True)).constraints

    assert forward == backward
    assert all(item.constraint_id.startswith("project-boundary@1:") for item in forward)


def test_module_only_restricts(layout: _Layout) -> None:
    """The module returns ALLOW with forbids; it cannot transform or escalate."""
    module = ResourceBoundary(_policy(layout))
    call = _call()
    principal = _principal()

    decision = module.tool_call_permission(principal, call)

    assert decision.verdict is Verdict.ALLOW
    assert decision.new_args is None and decision.escalation is None
    assert all(isinstance(item, ForbidConstraint) for item in decision.constraints)
    assert type(module).tool_call_prepare is SecurityModule.tool_call_prepare
    assert not module.can_escalate


# Partial authorization


def test_optional_write_to_source_is_removed(layout: _Layout) -> None:
    """Optional read/write on source keeps read and loses mutation authority."""
    target = layout.src / "main.py"
    compiled = _candidate(
        _profiles(layout, "fs read+write+truncate ${path} want"), {"path": target}
    )

    result = _restrict(layout, compiled)

    assert result.allowed
    assert _authority(result.grant) == {
        ("filesystem", "read", str(target), (("subtree", "False"),))
    }


def test_required_write_to_source_is_denied(layout: _Layout) -> None:
    """A `need` line whose authority is write is removed, so the call denies.

    `need` is evaluated per source line, as in DAC: a line keeps its status if
    any operation survives. Required mutation is therefore its own line.
    """
    compiled = _candidate(
        _profiles(layout, "fs read ${path} need, write+truncate ${path} need"),
        {"path": layout.src / "main.py"},
    )

    result = _restrict(layout, compiled)

    assert not result.allowed
    assert result.reason.startswith("required_authority_removed:")


@pytest.mark.parametrize(
    ("requirement", "allowed"), [(Requirement.WANT, True), (Requirement.NEED, False)]
)
def test_credentials_access_is_removed_or_denied(
    layout: _Layout, requirement: Requirement, allowed: bool
) -> None:
    """Optional credential access disappears; required access denies."""
    compiled = _candidate(
        _profiles(
            layout,
            f"fs read {layout.src}/** need, read ${{path}} {requirement.value}",
        ),
        {"path": layout.credentials / "token.txt"},
    )

    result = _restrict(layout, compiled)

    assert result.allowed is allowed
    if allowed:
        assert _authority(result.grant) == {
            ("filesystem", "read", str(layout.src), (("subtree", "True"),))
        }


def test_broad_read_with_forbidden_subtree_is_restricted(layout: _Layout) -> None:
    """A representable difference produces an explicit subtree exclusion."""
    policy = ResourceBoundaryPolicy(
        "readable-project",
        "1",
        resource_path(f"{layout.root}/**"),
        (ResourceAllowance(resource_path(f"{layout.root}/**"), {"read"}),),
        (resource_path(f"{layout.credentials}/**"),),
    )
    compiled = _candidate(_profiles(layout, f"fs read {layout.root}/** need"), {})
    decision = _module_constraints([ResourceBoundary(policy)])

    result = _filter(compiled, decision.constraints)

    assert result.allowed
    assert result.grant is not None
    (rule,) = (item for item in result.grant.rules if item.domain.value == "filesystem")
    assert rule.selector == str(layout.root)
    assert rule.conditions["exclude_subtrees"] == (str(layout.credentials),)
    assert any(item.startswith("resource_boundary:") for item in rule.provenance)


@pytest.mark.parametrize(
    ("requirement", "allowed"), [(Requirement.WANT, True), (Requirement.NEED, False)]
)
def test_unrepresentable_broad_read_is_removed_not_retained(
    layout: _Layout, requirement: Requirement, allowed: bool
) -> None:
    """Reading the whole scope cannot be one rule minus exclusions, so it goes."""
    compiled = _candidate(
        _profiles(
            layout,
            f"fs read {layout.src}/** need, read {layout.root}/** {requirement.value}",
        ),
        {},
    )

    result = _restrict(layout, compiled)

    assert result.allowed is allowed
    if allowed:
        assert all(rule.selector != str(layout.root) for rule in result.grant.rules)


def test_policy_permission_never_adds_missing_dac_authority(layout: _Layout) -> None:
    """The module permits artifact writes, but DAC never granted them."""
    compiled = _candidate(
        _profiles(
            layout,
            "fs read+write+create+delete+truncate ${path} want",
            principal_fs=f"fs read {layout.root}/**",
        ),
        {"path": layout.artifacts / "out.txt"},
    )

    result = _restrict(layout, compiled)

    assert result.allowed
    assert {rule[1] for rule in _authority(result.grant)} == {"read"}


def test_read_only_configuration_file(layout: _Layout) -> None:
    """The exact configuration file keeps read and loses mutation."""
    compiled = _candidate(
        _profiles(layout, "fs read+write+truncate ${path} want"),
        {"path": layout.config},
    )

    result = _restrict(layout, compiled)

    assert _authority(result.grant) == {
        ("filesystem", "read", str(layout.config), (("subtree", "False"),))
    }


def test_module_abstains_outside_scope(layout: _Layout, tmp_path: Path) -> None:
    """Authority outside the controlled scope is untouched."""
    outside = tmp_path / "outside"
    outside.mkdir()
    compiled = _candidate(
        _profiles(
            layout,
            "fs read+write+create+delete+truncate ${path} need",
            principal_fs=f"fs {tmp_path}/**",
        ),
        {"path": outside},
    )

    result = _restrict(layout, compiled)

    assert result.allowed
    assert result.grant is not None
    assert sorted(rule.rule_id for rule in result.grant.rules) == sorted(
        rule.rule_id for rule in compiled.grant.rules
    )
    assert result.removed_rule_ids == ()


# Runtime baseline


def _baseline(selector: Path, *, subtree: bool = True) -> GrantRule:
    return GrantRule(
        "runtime:root:0",
        AuthorityDomain.RUNTIME,
        "read",
        str(selector),
        {"subtree": subtree},
        baseline=True,
    )


@pytest.mark.parametrize(
    "selector", ["credentials", "", "artifacts/../credentials/token.txt"]
)
def test_conflicting_runtime_baseline_fails_compilation(
    layout: _Layout, selector: str
) -> None:
    """A runtime root is restricted like requested authority, never exempted."""
    root = (layout.root / selector).resolve()
    compiled = _candidate(
        _profiles(layout, f"fs read {layout.src}/** need"),
        {},
        baseline=(_baseline(root, subtree=root.is_dir()),),
    )

    result = _restrict(layout, compiled)

    assert not result.allowed
    assert result.reason == "required_authority_removed:baseline:runtime:root:0"


def test_permitted_runtime_baseline_survives(layout: _Layout, tmp_path: Path) -> None:
    """Baseline lines permitted by the policy or outside scope are retained."""
    compiled = _candidate(
        _profiles(layout, f"fs read {layout.src}/** need"),
        {},
        baseline=(_baseline(layout.src),),
    )

    result = _restrict(layout, compiled)

    assert result.allowed
    assert any(rule.baseline for rule in result.grant.rules)


# Tool independence


def test_equivalent_tools_receive_identical_effective_authority(
    layout: _Layout,
) -> None:
    """Different tool names and argument shapes reduce to the same authority."""
    text = f"""
tool summarize_source {{
  owner analyst
  grant analyst: call
  fs read+write+truncate ${{path}} want, read+write+create+delete+truncate ${{out}}/** want
}}
tool count_lines {{
  owner analyst
  grant analyst: call
  fs read+write+create+delete+truncate {layout.artifacts}/** want, read+write+truncate ${{file}} want
}}
principal alice {{
  roles analyst
  fs {layout.root}/**
}}
"""
    source = layout.src / "main.py"
    first = _filter(
        _candidate(
            text,
            {"path": source, "out": layout.artifacts},
            tool_name="summarize_source",
        ),
        _module_constraints([ResourceBoundary(_policy(layout))]).constraints,
    )
    second = _filter(
        _candidate(text, {"file": source}, tool_name="count_lines"),
        _module_constraints(
            [ResourceBoundary(_policy(layout))], call=_call("count_lines")
        ).constraints,
    )

    assert first.allowed and second.allowed
    assert _authority(first.grant) == _authority(second.grant)
    assert ("filesystem", "write", str(source), (("subtree", "False"),)) not in (
        _authority(first.grant)
    )


# Composition


class _ForbidArtifactDelete(SecurityModule):
    """Independent stateless restriction from another policy author."""

    name = "retention"

    def __init__(self, artifacts: Path) -> None:
        self.artifacts = str(artifacts)

    def tool_call_permission(self, principal, call):
        return Decision(
            Verdict.ALLOW,
            "retention",
            constraints=(
                ForbidConstraint(
                    "no-delete",
                    RulePredicate(
                        "filesystem",
                        frozenset({"delete"}),
                        self.artifacts,
                        SelectorMatch.SUBTREE,
                    ),
                    "artifacts_are_retained",
                ),
            ),
        )


class _Deny(SecurityModule):
    name = "deny"

    def tool_call_permission(self, principal, call):
        return Decision(Verdict.DENY, "independent_deny")


class _Approval(SecurityModule):
    name = "approval"
    can_escalate = True

    def tool_call_permission(self, principal, call):
        return Decision(
            Verdict.ESCALATE,
            "approval_required",
            escalation=EscalationRequest(
                "request", "review", call.tool.name, call.call_id
            ),
        )


def _mutating_candidate(layout: _Layout):
    return _candidate(
        _profiles(
            layout,
            "fs read+write+truncate ${src} want, "
            "read+write+create+delete+truncate ${out}/** want",
        ),
        {"src": layout.src / "main.py", "out": layout.artifacts},
    )


def test_reordering_restrictive_modules_preserves_authority(layout: _Layout) -> None:
    """Independent stateless restrictions commute; `CapModule` stays first."""
    compiled = _mutating_candidate(layout)
    modules = (
        ResourceBoundary(_policy(layout)),
        _ForbidArtifactDelete(layout.artifacts),
        ResourceBoundary(_policy(layout, version="2"), name="second_boundary"),
    )
    digests = set()
    authorities = []
    for order in itertools.permutations(modules):
        stack = SecurityStack(order)
        assert isinstance(stack.modules[0], CapModule)
        stack.close()
        result = _filter(compiled, _module_constraints(order).constraints)
        assert result.allowed
        digests.add(result.grant.digest)
        authorities.append(_authority(result.grant))

    assert len(digests) == 1
    assert all(item == authorities[0] for item in authorities)
    operations = {(rule[1], rule[2]) for rule in authorities[0]}
    assert ("delete", str(layout.artifacts)) not in operations
    assert ("write", str(layout.artifacts)) in operations
    assert ("write", str(layout.src / "main.py")) not in operations


def test_scope_possession_does_not_bypass_restriction(layout: _Layout) -> None:
    """Holding the tool's required scope satisfies `CapModule` only."""
    compiled = _mutating_candidate(layout)
    decision = _module_constraints(
        [ResourceBoundary(_policy(layout))],
        principal=_principal(["src:write", "admin"]),
        call=_call(required_scopes=["src:write"]),
    )

    result = _filter(compiled, decision.constraints)

    assert decision.verdict is Verdict.ALLOW
    assert ("write", str(layout.src / "main.py")) not in {
        (rule[1], rule[2]) for rule in _authority(result.grant)
    }


def _approved(modules: Sequence[SecurityModule]) -> Decision:
    """Escalate once, then resume with a matching one-time approval."""
    stack = SecurityStack(modules)
    try:
        pending = stack.permission(_principal(), _call())
        assert pending.verdict is Verdict.ESCALATE
        assert pending.escalation is not None
        return stack.permission(
            _principal(),
            _call(),
            approval=Approval(
                "request",
                True,
                "reviewer",
                subject_digest=pending.escalation.subject_digest,
            ),
        )
    finally:
        stack.close()


@pytest.mark.parametrize("approval_first", [True, False])
def test_approval_cannot_override_resource_restriction(
    layout: _Layout, approval_first: bool
) -> None:
    """A matching approval clears the escalation, not another module's forbids."""
    modules = [_Approval(), ResourceBoundary(_policy(layout))]
    if not approval_first:
        modules.reverse()

    approved = _approved(modules)

    assert approved.verdict is Verdict.ALLOW
    assert approved.constraints
    result = _filter(_mutating_candidate(layout), approved.constraints)
    assert ("write", str(layout.src / "main.py")) not in {
        (rule[1], rule[2]) for rule in _authority(result.grant)
    }


def test_required_restriction_still_denies_after_approval(layout: _Layout) -> None:
    """Approval never turns a removed `need` into an allowed grant."""
    approved = _approved([_Approval(), ResourceBoundary(_policy(layout))])
    compiled = _candidate(
        _profiles(layout, "fs write+truncate ${path} need"),
        {"path": layout.src / "main.py"},
    )

    assert approved.verdict is Verdict.ALLOW
    assert not _filter(compiled, approved.constraints).allowed


@pytest.mark.parametrize("deny_first", [True, False])
def test_other_module_denial_remains_denial(layout: _Layout, deny_first: bool) -> None:
    """A permitted resource cannot convert another module's denial."""
    modules = [_Deny(), ResourceBoundary(_policy(layout))]
    if not deny_first:
        modules.reverse()

    decision = _module_constraints(modules)

    assert decision.verdict is Verdict.DENY
    assert decision.reason == "independent_deny"
    assert decision.constraints == ()


# Mediation without a host grant


def _read_tool():
    @tool
    @dac(owner="analyst", grants={"analyst": "x"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Read one file in-process."""
        executed.append(path)
        return Path(path).read_text()

    executed: list[str] = []
    return read_file, executed


def test_tool_node_denies_constraints_without_host_executor(layout: _Layout) -> None:
    """Restrictions are never silently dropped by in-process execution."""
    read_file, executed = _read_tool()
    security = SecurityConfig(modules=[ResourceBoundary(_policy(layout))])
    node = ToolNode([read_file], security=security)
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    config = with_principal(
        {"configurable": {"__pregel_runtime": runtime}}, _principal()
    )
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "read_file",
                "args": {"path": str(layout.src / "main.py")},
                "id": "call-1",
            }
        ],
    )

    result = node.invoke({"messages": [message]}, config=config)

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "policy:constraints_require_host_executor" in result["messages"][0].content


def test_guarded_tool_denies_constraints_without_host_executor(
    layout: _Layout,
) -> None:
    """Direct mediation applies the same fail-closed rule."""
    read_file, executed = _read_tool()
    security = SecurityConfig(modules=[ResourceBoundary(_policy(layout))])
    guarded = guarded_tool(read_file, security=security)
    config = with_principal({}, _principal(), modules=security.modules)

    with pytest.raises(SecurityDeniedError, match="constraints_require_host"):
        guarded.invoke({"path": str(layout.src / "main.py")}, config=config)
    assert executed == []


@pytest.mark.asyncio
async def test_async_tool_node_denies_constraints_without_host_executor(
    layout: _Layout,
) -> None:
    """Async ToolNode mediation never drops restrictions in-process."""
    read_file, executed = _read_tool()
    security = SecurityConfig(modules=[ResourceBoundary(_policy(layout))])
    node = ToolNode([read_file], security=security)
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    config = with_principal(
        {"configurable": {"__pregel_runtime": runtime}}, _principal()
    )
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "read_file",
                "args": {"path": str(layout.src / "main.py")},
                "id": "call-1",
            }
        ],
    )

    result = await node.ainvoke({"messages": [message]}, config=config)

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "policy:constraints_require_host_executor" in result["messages"][0].content


@pytest.mark.asyncio
async def test_async_guarded_tool_denies_constraints_without_host_executor(
    layout: _Layout,
) -> None:
    """Async direct mediation applies the same fail-closed rule."""
    read_file, executed = _read_tool()
    security = SecurityConfig(modules=[ResourceBoundary(_policy(layout))])
    guarded = guarded_tool(read_file, security=security)
    config = with_principal({}, _principal(), modules=security.modules)

    with pytest.raises(SecurityDeniedError, match="constraints_require_host"):
        await guarded.ainvoke({"path": str(layout.src / "main.py")}, config=config)
    assert executed == []


# Soundness property over a finite path universe

_UNIVERSE = ("/p", "/p/a", "/p/a/x", "/p/a/x/y", "/p/b", "/p/b/z", "/p/c", "/q")
_SELECTORS = st.sampled_from(_UNIVERSE).flatmap(
    lambda path: st.sampled_from((resource_path(path), resource_path(f"{path}/**")))
)


def _covers(selector: str, subtree: bool, path: str) -> bool:
    if not subtree:
        return path == selector
    return path == selector or path.startswith(selector + "/")


def _ceiling(policy: ResourceBoundaryPolicy, path: str) -> frozenset[str]:
    if not _covers(policy.scope.value, True, path):
        return _ALL
    covering = [
        operations
        for selector, operations in policy.ceilings.items()
        if _covers(selector.value, selector.subtree, path)
    ]
    if not covering:
        return frozenset()
    return frozenset.intersection(*covering)


def _concrete(rule: GrantRule) -> set[str]:
    subtree = bool(rule.conditions.get("subtree"))
    excluded_subtrees = rule.conditions.get("exclude_subtrees", ())
    excluded_paths = rule.conditions.get("exclude_paths", ())
    return {
        path
        for path in _UNIVERSE
        if _covers(rule.selector, subtree, path)
        and path not in excluded_paths
        and not any(_covers(item, True, path) for item in excluded_subtrees)
    }


@settings(max_examples=300, deadline=None)
@given(
    allow=st.lists(
        st.tuples(_SELECTORS, st.sets(st.sampled_from(sorted(_ALL)), min_size=1)),
        max_size=4,
    ),
    forbid=st.lists(_SELECTORS, max_size=2),
    rules=st.lists(
        st.tuples(
            _SELECTORS,
            st.sampled_from(sorted(_ALL)),
            st.sampled_from(("filesystem", "runtime")),
        ),
        min_size=1,
        max_size=5,
    ),
    seed=st.integers(0, 1000),
)
def test_filtered_grant_never_exceeds_policy_ceiling(
    allow, forbid, rules, seed
) -> None:
    """Every concrete path/operation left in the grant is within the policy."""
    scope = resource_path("/p/**")
    allow = [
        ResourceAllowance(path, frozenset(ops))
        for path, ops in allow
        if _covers("/p", True, path.value)
    ]
    forbid = [path for path in forbid if _covers("/p", True, path.value)]
    policy = ResourceBoundaryPolicy("prop", "1", scope, tuple(allow), tuple(forbid))
    grant_rules = tuple(
        GrantRule(
            f"rule:{index}",
            AuthorityDomain(domain),
            operation,
            selector.value,
            {"subtree": selector.subtree},
            Requirement.WANT,
        )
        for index, (selector, operation, domain) in enumerate(rules)
    )
    grant = Grant("alice", "s", "t", "a", "c", "i", "p", grant_rules)
    constraints = [
        ForbidConstraint(item.constraint_id, item.predicate, item.reason, "boundary")
        for item in ResourceBoundary(policy).constraints
    ]
    random.Random(seed).shuffle(constraints)
    ledger = RequirementLedger(
        tuple(
            RequirementEntry(
                f"source:{rule.rule_id}", rule.requirement, frozenset({rule.rule_id})
            )
            for rule in grant_rules
        )
    )

    result = TypedPolicyBackend().filter(grant, ledger, constraints)
    baseline = TypedPolicyBackend().filter(
        grant, ledger, sorted(constraints, key=lambda item: item.constraint_id)
    )

    assert result.allowed
    assert result.grant == baseline.grant
    for rule in result.grant.rules:
        for path in _concrete(rule):
            assert rule.operation in _ceiling(policy, path), (rule, path)
