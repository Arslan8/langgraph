"""`ResourceBoundary` restrictions reaching actual Linux worker authority.

Every call here crosses `ToolNode` into `LinuxSandboxExecutor`: a bubblewrap
worker is activated only after the module's constraints filter the grant, so
outcomes are kernel results, not mocked executor responses.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Decision,
    Effect,
    ForbidConstraint,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    Principal,
    ResourceAllowance,
    ResourceArg,
    ResourceBoundary,
    ResourceBoundaryPolicy,
    RulePredicate,
    SecurityConfig,
    SecurityModule,
    SelectorMatch,
    Verdict,
    effects,
    parse_profiles,
    resource_path,
    with_principal,
)

_FIXTURES = Path(__file__).with_name("fixtures").resolve()
_ARTIFACT = _FIXTURES / "resource_boundary_tools.py"
_MUTATE = frozenset({"read", "write", "create", "delete", "truncate"})


class _Layout:
    def __init__(self, root: Path) -> None:
        self.root = root / "project"
        self.src = self.root / "src"
        self.artifacts = self.root / "artifacts"
        self.credentials = self.root / "credentials"
        self.config = self.root / "project.toml"
        for directory in (self.src, self.artifacts, self.credentials):
            directory.mkdir(parents=True)
        self.source = self.src / "main.py"
        self.source.write_text("print('fixture')\n")
        self.token = self.credentials / "token.txt"
        self.token.write_text("fixture-not-a-secret\n")
        self.config.write_text("name = 'fixture'\n")


@pytest.fixture
def layout() -> Iterator[_Layout]:
    # The worker's private `/tmp` is a runtime-baseline subtree. A scope under
    # host `/tmp` intersects it and correctly denies every call, so the
    # fixture tree lives in `/var/tmp`.
    root = Path(tempfile.mkdtemp(prefix="resource-boundary-", dir="/var/tmp"))
    try:
        yield _Layout(root.resolve())
    finally:
        shutil.rmtree(root)


def _policy(
    layout: _Layout, *, artifact_operations: frozenset[str] = _MUTATE
) -> ResourceBoundaryPolicy:
    return ResourceBoundaryPolicy(
        "project-boundary",
        "1",
        resource_path(f"{layout.root}/**"),
        (
            ResourceAllowance(resource_path(f"{layout.src}/**"), {"read"}),
            ResourceAllowance(
                resource_path(f"{layout.artifacts}/**"), artifact_operations
            ),
            ResourceAllowance(resource_path(str(layout.config)), {"read"}),
        ),
        (resource_path(f"{layout.credentials}/**"),),
    )


# Parent-side schema stubs. Only the pinned worker artifact may execute.
def read_source(path: str) -> str:
    """Parent callback that must never execute."""
    raise AssertionError("parent callback executed")


def annotate_pathlib(path: str) -> str:
    """Parent callback that must never execute."""
    raise AssertionError("parent callback executed")


def annotate_descriptor(file: str) -> str:
    """Parent callback that must never execute."""
    raise AssertionError("parent callback executed")


def build_artifacts(directory: str) -> str:
    """Parent callback that must never execute."""
    raise AssertionError("parent callback executed")


def probe_read(path: str, target: str) -> str:
    """Parent callback that must never execute."""
    raise AssertionError("parent callback executed")


def mark_executed(path: str) -> str:
    """Parent callback that must never execute."""
    raise AssertionError("parent callback executed")


_STUBS: dict[str, tuple[Callable[..., str], str]] = {
    "read_source": (read_source, "path"),
    "annotate_pathlib": (annotate_pathlib, "path"),
    "annotate_descriptor": (annotate_descriptor, "file"),
    "build_artifacts": (build_artifacts, "directory"),
    "probe_read": (probe_read, "path"),
    "mark_executed": (mark_executed, "path"),
}


def _tool(name: str) -> StructuredTool:
    function, argument = _STUBS[name]
    adapted = StructuredTool.from_function(function)
    return effects(Effect.READ, resources=[ResourceArg(argument, "path", "realpath")])(
        adapted
    )


def _node(
    layout: _Layout,
    tool_fs: dict[str, str],
    *,
    modules: Sequence[SecurityModule] | None = None,
    runtime_roots: Sequence[Path] = (),
) -> tuple[ToolNode, LinuxSandboxExecutor]:
    blocks = "".join(
        f"""
tool {name} {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs {lines}
}}"""
        for name, lines in tool_fs.items()
    )
    profiles = parse_profiles(
        f"""{blocks}
principal alice {{
  roles analyst
  fs {layout.root}/**
}}
""",
        source="boundary.slp",
    )
    digest = hashlib.sha256(_ARTIFACT.read_bytes()).hexdigest()
    executor = LinuxSandboxExecutor(
        profiles,
        {
            name: LinuxToolSpec(f"resource_boundary_tools:{name}", _ARTIFACT, digest)
            for name in tool_fs
        },
        runtime_roots=(_FIXTURES, *runtime_roots),
    )
    security = SecurityConfig(
        modules=([ResourceBoundary(_policy(layout))] if modules is None else modules),
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )
    tools = [_tool(name) for name in tool_fs]
    return ToolNode(tools, security=security, handle_tool_errors=True), executor


def _call(node: ToolNode, name: str, args: dict[str, object]) -> Any:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    config = with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)
    message = AIMessage(
        content="", tool_calls=[{"name": name, "args": args, "id": "call-1"}]
    )
    return node.invoke({"messages": [message]}, config=config)["messages"][0]


def _denied_before_release(
    message: Any, executor: LinuxSandboxExecutor, reason: str
) -> None:
    assert message.status == "error"
    assert reason in message.content
    assert "tool-code-ran" not in message.content
    assert executor.activation_receipts() == ()


def test_authorized_source_read_succeeds(layout: _Layout) -> None:
    """A permitted read crosses the boundary and runs in a worker."""
    node, executor = _node(layout, {"read_source": "read ${path} need"})

    message = _call(node, "read_source", {"path": str(layout.source)})

    assert message.status == "success"
    assert message.content == "print('fixture')\n"
    assert len(executor.activation_receipts()) == 1


@pytest.mark.parametrize(
    ("tool_name", "argument"),
    [("annotate_pathlib", "path"), ("annotate_descriptor", "file")],
)
def test_optional_source_write_is_blocked_by_the_kernel(
    layout: _Layout, tool_name: str, argument: str
) -> None:
    """Removed write authority becomes a read-only mount, not a mere verdict."""
    node, _ = _node(layout, {tool_name: f"read+write+truncate ${{{argument}}} want"})

    message = _call(node, tool_name, {argument: str(layout.source)})

    assert message.status == "success"
    assert json.loads(message.content)["write"] == "blocked:EROFS"
    assert layout.source.read_text() == "print('fixture')\n"


def test_equivalent_tools_activate_identical_worker_authority(
    layout: _Layout,
) -> None:
    """Differently implemented tools with equal requests get the same plan."""
    node, executor = _node(
        layout,
        {
            "annotate_pathlib": "read+write+truncate ${path} want",
            "annotate_descriptor": "read+write+truncate ${file} want",
        },
    )

    first = _call(node, "annotate_pathlib", {"path": str(layout.source)})
    second = _call(node, "annotate_descriptor", {"file": str(layout.source)})

    assert first.content == second.content
    plans = {
        evidence.native_plan_digest
        for receipt in executor.activation_receipts()
        for evidence in receipt.evidence
    }
    assert len(executor.activation_receipts()) == 2
    assert len(plans) == 1


def test_required_source_write_denies_before_tool_code(layout: _Layout) -> None:
    """A required write line removed by policy denies before release."""
    node, executor = _node(
        layout, {"mark_executed": "read ${path} need, write+truncate ${path} need"}
    )

    message = _call(node, "mark_executed", {"path": str(layout.source)})

    _denied_before_release(
        message, executor, "required_authority_removed:fs:boundary.slp:7:3:1"
    )


def test_artifact_directory_supports_permitted_operations(layout: _Layout) -> None:
    """Create, write, truncate, read, and delete succeed where permitted."""
    node, _ = _node(
        layout,
        {"build_artifacts": "read+write+create+delete+truncate ${directory}/** need"},
    )

    message = _call(node, "build_artifacts", {"directory": str(layout.artifacts)})

    assert message.status == "success"
    assert json.loads(message.content) == {
        "create": "ok",
        "delete": "ok",
        "read": "draft",
        "truncate": "ok",
        "write": "ok",
    }
    assert (layout.artifacts / "report.txt").read_text() == "draft"
    assert not (layout.artifacts / "scratch.txt").exists()


def test_protected_directory_is_inaccessible(layout: _Layout) -> None:
    """Required credential access denies; a hostile probe sees nothing."""
    node, executor = _node(
        layout,
        {
            "mark_executed": "read ${path} need",
            "probe_read": "read ${path} need",
        },
    )

    required = _call(node, "mark_executed", {"path": str(layout.token)})
    _denied_before_release(required, executor, "required_authority_removed")

    probe = _call(
        node, "probe_read", {"path": str(layout.source), "target": str(layout.token)}
    )
    assert probe.status == "success"
    assert probe.content == "blocked:ENOENT"


def test_optional_credentials_are_removed_from_the_worker(layout: _Layout) -> None:
    """An optional credential line disappears; the worker still runs."""
    node, _ = _node(
        layout,
        {"probe_read": f"read ${{path}} need, read {layout.credentials}/** want"},
    )

    message = _call(
        node, "probe_read", {"path": str(layout.source), "target": str(layout.token)}
    )

    assert message.status == "success"
    assert message.content == "blocked:ENOENT"


def test_read_only_configuration_cannot_be_updated(layout: _Layout) -> None:
    """The configuration file is mounted read-only; required update denies."""
    node, executor = _node(
        layout,
        {
            "annotate_pathlib": "read+write+truncate ${path} want",
            "mark_executed": "read ${path} need, write ${path} need",
        },
    )

    optional = _call(node, "annotate_pathlib", {"path": str(layout.config)})
    assert optional.status == "success"
    assert json.loads(optional.content)["write"] == "blocked:EROFS"
    assert layout.config.read_text() == "name = 'fixture'\n"

    receipts = executor.activation_receipts()
    required = _call(node, "mark_executed", {"path": str(layout.config)})
    assert required.status == "error"
    assert "required_authority_removed" in required.content
    assert executor.activation_receipts() == receipts


def test_representable_subtree_exclusion_is_not_lowered(layout: _Layout) -> None:
    """A restricted semantic result the adapter cannot enforce never runs."""
    readable = ResourceBoundaryPolicy(
        "readable-project",
        "1",
        resource_path(f"{layout.root}/**"),
        (ResourceAllowance(resource_path(f"{layout.root}/**"), {"read"}),),
        (resource_path(f"{layout.credentials}/**"),),
    )
    node, executor = _node(
        layout,
        {"mark_executed": f"read {layout.root}/** need"},
        modules=[ResourceBoundary(readable)],
    )

    message = _call(node, "mark_executed", {"path": str(layout.source)})

    # Policy filtering succeeded with an excluded subtree; negotiation refused
    # to enforce the restricted rule rather than mounting the broad subtree.
    _denied_before_release(message, executor, "host:adapter_rule_unsupported:")
    assert ":restricted:" in message.content


def test_unlowerable_operation_combination_is_rejected(layout: _Layout) -> None:
    """A writable directory without delete/truncate has no exact mount."""
    narrowed = _policy(
        layout, artifact_operations=frozenset({"read", "write", "create"})
    )
    node, executor = _node(
        layout,
        {"mark_executed": "read+write+create+delete+truncate ${path}/** want"},
        modules=[ResourceBoundary(narrowed)],
    )

    message = _call(node, "mark_executed", {"path": str(layout.artifacts)})

    _denied_before_release(message, executor, "host:adapter_lowering_failed")


def test_conflicting_runtime_baseline_fails_compilation(layout: _Layout) -> None:
    """A runtime root inside the protected directory is not exempted."""
    site = layout.credentials / "site-packages"
    site.mkdir()
    node, executor = _node(
        layout, {"read_source": "read ${path} need"}, runtime_roots=(site,)
    )

    message = _call(node, "read_source", {"path": str(layout.source)})

    _denied_before_release(
        message,
        executor,
        "required_authority_removed:baseline:runtime:root:1",
    )


class _Retention(SecurityModule):
    """Independent forbid on artifact deletion from another policy author."""

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


@pytest.mark.parametrize("boundary_first", [True, False])
def test_composed_restriction_reaches_lowering(
    layout: _Layout, boundary_first: bool
) -> None:
    """Another author's forbid composes with the boundary in either order.

    Removing delete from the artifact directory leaves no exact writable mount,
    so the combined restriction is rejected rather than approximated.
    """
    modules: list[SecurityModule] = [
        ResourceBoundary(_policy(layout)),
        _Retention(layout.artifacts),
    ]
    if not boundary_first:
        modules.reverse()
    node, executor = _node(
        layout,
        {"build_artifacts": "read+write+create+delete+truncate ${directory}/** want"},
        modules=modules,
    )

    message = _call(node, "build_artifacts", {"directory": str(layout.artifacts)})

    _denied_before_release(message, executor, "host:adapter_lowering_failed")
