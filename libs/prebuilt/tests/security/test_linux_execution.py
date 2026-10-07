"""End-to-end Linux host-enforcement integration tests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    Principal,
    ResourceArg,
    SecurityConfig,
    dac,
    effects,
    guarded_tool,
    parse_profiles,
    with_principal,
)

_FIXTURES = Path(__file__).with_name("fixtures").resolve()


def _input(name: str, args: dict[str, object]) -> dict[str, object]:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[{"name": name, "args": args, "id": "call-1"}],
            )
        ]
    }


def _config(principal: Principal) -> dict[str, object]:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    return with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)


def _security(profile_text: str, entrypoint: str) -> SecurityConfig:
    profiles = parse_profiles(profile_text, source="linux-test.slp")
    artifact = _FIXTURES / "linux_tools.py"
    executor = LinuxSandboxExecutor(
        profiles,
        {
            "read_file": LinuxToolSpec(
                entrypoint,
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(_FIXTURES,),
    )
    return SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )


def _profile(root: Path, *, network: bool = False) -> str:
    resource = "net connect 443 need" if network else "fs read ${path} need"
    principal_resource = "net connect 443" if network else f"fs read {root}/**"
    return f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  {resource}
}}
principal alice {{
  roles analyst
  {principal_resource}
}}
"""


def test_tool_node_executes_only_inside_activated_linux_worker(tmp_path: Path) -> None:
    """The registered in-process callback is never used when Linux is enabled."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("sandbox-result")
    parent_executed: list[str] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent-process callback that must not execute."""
        parent_executed.append(path)
        return "parent-result"

    security = _security(_profile(tmp_path), "linux_tools:read_file")
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert parent_executed == []
    assert result["messages"][0].content == "sandbox-result"
    assert result["messages"][0].status == "success"
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    receipts = security.host_executor.activation_receipts()
    assert len(receipts) == 1
    assert receipts[0].grant_digest
    assert receipts[0].evidence


def test_hostile_tool_cannot_read_undeclared_file(tmp_path: Path) -> None:
    """A hostile entry point cannot exceed the final filesystem grant."""
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    allowed = allowed_root / "visible.txt"
    allowed.write_text("visible")
    forbidden = tmp_path / "secret.txt"
    forbidden.write_text("secret")

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str, forbidden_path: str) -> str:
        """Local callback with the worker's public schema."""
        raise AssertionError("parent callback executed")

    security = _security(
        _profile(allowed_root),
        "linux_tools:hostile_probe",
    )
    node = ToolNode((read_file,), security=security, handle_tool_errors=True)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input(
            "read_file",
            {"path": str(allowed), "forbidden_path": str(forbidden)},
        ),
        config=_config(principal),
    )

    assert result["messages"][0].status == "error"
    assert "sandboxed tool failed" in str(result["messages"][0].content)


def test_unsupported_network_grant_denies_before_tool_code(tmp_path: Path) -> None:
    """The Linux filesystem backend never claims unsupported network authority."""
    executed: list[bool] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Tool that must be rejected during exact obligation negotiation."""
        executed.append(True)
        return "unexpected"

    node = ToolNode(
        (read_file,),
        security=_security(_profile(tmp_path, network=True), "linux_tools:read_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {}),
        config=_config(principal),
    )

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "adapter_rule_unsupported" in str(result["messages"][0].content)


@pytest.mark.asyncio
async def test_async_tool_node_uses_same_linux_activation_path(tmp_path: Path) -> None:
    """Async execution waits for the same verified worker startup barrier."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("async-sandbox-result")

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    async def read_file(path: str) -> str:
        """Parent coroutine that must not execute."""
        raise AssertionError(path)

    node = ToolNode(
        (read_file,),
        security=_security(_profile(tmp_path), "linux_tools:async_read_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = await node.ainvoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "async-sandbox-result"


def test_linux_worker_enforces_authorized_write(tmp_path: Path) -> None:
    """Read-plus-write authority lowers to a writable stable bind mount."""
    target = tmp_path / "target.txt"
    target.write_text("before")
    profiles = f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read+write+truncate ${{path}} need
}}
principal alice {{
  roles analyst
  fs read+write+truncate {tmp_path}/**
}}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(
        Effect.READ,
        Effect.WRITE,
        resources=[ResourceArg("path", "path", "realpath")],
    )
    def read_file(path: str, content: str) -> str:
        """Parent writer that must not execute."""
        raise AssertionError(path, content)

    node = ToolNode(
        (read_file,),
        security=_security(profiles, "linux_tools:write_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(target), "content": "after"}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "written"
    assert target.read_text() == "after"


@pytest.mark.parametrize(
    ("entrypoint", "expected_type"),
    [
        ("linux_tools:network_probe", "PermissionError"),
        ("linux_tools:exec_probe", "PermissionError"),
    ],
)
def test_linux_worker_blocks_ambient_network_and_exec(
    tmp_path: Path, entrypoint: str, expected_type: str
) -> None:
    """Namespace and seccomp controls deny authority omitted from the grant."""
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Parent callback that must not execute."""
        raise AssertionError

    node = ToolNode(
        (read_file,),
        security=_security(profiles, entrypoint),
        handle_tool_errors=True,
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(_input("read_file", {}), config=_config(principal))

    assert result["messages"][0].status == "error"
    assert expected_type in str(result["messages"][0].content)


def test_guarded_tool_uses_linux_host_executor(tmp_path: Path) -> None:
    """Direct guarded calls share the activated host execution path."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("guarded-sandbox-result")
    executed: list[str] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        executed.append(path)
        return "parent"

    guarded = guarded_tool(
        read_file,
        security=_security(_profile(tmp_path), "linux_tools:read_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = guarded.invoke({"path": str(allowed)}, config=_config(principal))

    assert result == "guarded-sandbox-result"
    assert executed == []


def test_linux_tool_spec_rejects_unverified_artifact() -> None:
    """A manifest cannot bind an entry point to unverified executable bytes."""
    artifact = _FIXTURES / "linux_tools.py"

    with pytest.raises(ValueError, match="digest does not match"):
        LinuxToolSpec("linux_tools:read_file", artifact, "0" * 64)


def test_linux_executor_rechecks_artifact_at_dispatch(tmp_path: Path) -> None:
    """Changing an artifact after configuration denies before worker release."""
    artifact = tmp_path / "linux_tools.py"
    artifact.write_bytes((_FIXTURES / "linux_tools.py").read_bytes())
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    profiles = parse_profiles(_profile(tmp_path), source="linux-test.slp")
    executor = LinuxSandboxExecutor(
        profiles,
        {"read_file": LinuxToolSpec("linux_tools:read_file", artifact, digest)},
        runtime_roots=(tmp_path,),
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    artifact.write_text(artifact.read_text() + "\n# changed after manifest creation\n")
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("value")
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].status == "error"
    assert "host:artifact_changed" in str(result["messages"][0].content)


def test_linux_executor_loads_pinned_path_not_shadow_module(tmp_path: Path) -> None:
    """A same-named module in an earlier runtime root cannot replace the artifact."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("pinned-result")
    shadow_root = tmp_path / "shadow"
    shadow_root.mkdir()
    (shadow_root / "linux_tools.py").write_text(
        "def read_file(path):\n    return 'shadow-result'\n"
    )
    profiles = parse_profiles(_profile(tmp_path), source="linux-test.slp")
    artifact = _FIXTURES / "linux_tools.py"
    executor = LinuxSandboxExecutor(
        profiles,
        {
            "read_file": LinuxToolSpec(
                "linux_tools:read_file",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(shadow_root, _FIXTURES),
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "pinned-result"


def test_linux_executor_rejects_inexact_writable_mount(tmp_path: Path) -> None:
    """A coarse writable bind is not used for a narrower write-only grant."""
    target = tmp_path / "target.txt"
    target.write_text("before")
    profiles = f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs write ${{path}} need
}}
principal alice {{
  roles analyst
  fs write {tmp_path}/**
}}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.WRITE, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str, content: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path, content)

    node = ToolNode(
        (read_file,),
        security=_security(profiles, "linux_tools:write_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(target), "content": "after"}),
        config=_config(principal),
    )

    assert result["messages"][0].status == "error"
    assert "adapter_lowering_failed" in str(result["messages"][0].content)
    assert target.read_text() == "before"
