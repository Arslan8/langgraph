from __future__ import annotations

import errno
from pathlib import Path

import pytest

from langgraph.prebuilt.security import cgroup as cgroup_module
from langgraph.prebuilt.security.cgroup import (
    CgroupV2Scope,
    delegated_controllers,
)


def test_delegated_controllers_requires_available_and_enabled(tmp_path: Path) -> None:
    (tmp_path / "cgroup.controllers").write_text("cpu io memory pids\n")
    (tmp_path / "cgroup.subtree_control").write_text("cpu memory\n")

    assert delegated_controllers(tmp_path) == frozenset({"cpu", "memory"})


def test_create_writes_conservative_per_call_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "cgroup.controllers").write_text("cpu memory pids\n")
    (tmp_path / "cgroup.subtree_control").write_text("cpu memory pids\n")
    writes: list[tuple[str, str]] = []

    def record(path: Path, value: str) -> None:
        writes.append((path.name, value))

    monkeypatch.setattr(cgroup_module, "_write_control", record)
    scope = CgroupV2Scope.create(
        tmp_path,
        {"address_space_bytes": 4096, "cpu_ms": 2000, "pids": 1},
        nonce="fixed",
    )
    try:
        assert writes == [
            ("memory.max", "4096"),
            ("pids.max", "1"),
            ("cpu.max", "100000 100000"),
        ]
    finally:
        scope.close()


def test_assign_verifies_kernel_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "call"
    path.mkdir()
    scope = CgroupV2Scope(path, False)
    monkeypatch.setattr(cgroup_module, "_write_control", lambda path, value: None)

    with pytest.raises(OSError) as raised:
        scope.assign(1234)

    assert raised.value.errno == errno.EIO


def test_kill_uses_cgroup_kill_control(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes: list[tuple[Path, str]] = []
    scope = CgroupV2Scope(tmp_path, True)
    monkeypatch.setattr(
        cgroup_module,
        "_write_control",
        lambda path, value: writes.append((path, value)),
    )

    assert scope.kill()
    assert writes == [(tmp_path / "cgroup.kill", "1")]


def test_invalid_limit_fails_before_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "cgroup.controllers").write_text("cpu memory pids\n")
    (tmp_path / "cgroup.subtree_control").write_text("cpu memory pids\n")
    monkeypatch.setattr(cgroup_module, "_write_control", lambda path, value: None)

    with pytest.raises(ValueError, match="address_space_bytes"):
        CgroupV2Scope.create(
            tmp_path,
            {"address_space_bytes": 0, "cpu_ms": 1000, "pids": 1},
            nonce="invalid",
        )
