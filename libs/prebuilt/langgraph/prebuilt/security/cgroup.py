"""Per-call cgroup v2 lifecycle for the Linux security backend."""

from __future__ import annotations

import errno
import os
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})


@dataclass(slots=True)
class CgroupV2Scope:
    """One trusted-parent-owned cgroup containing exactly one tool call."""

    path: Path
    has_kill: bool
    _closed: bool = False

    @classmethod
    def create(
        cls,
        root: Path,
        limits: Mapping[str, int],
        *,
        nonce: str | None = None,
    ) -> CgroupV2Scope:
        """Create and configure a fresh leaf below an attested delegation root."""
        root = root.resolve(strict=True)
        _require_delegated_controllers(root)
        name = f"slanggraph-{os.getpid()}-{nonce or secrets.token_hex(8)}"
        path = root / name
        path.mkdir(mode=0o700)
        scope = cls(path, (path / "cgroup.kill").exists())
        try:
            memory = _positive_limit(limits, "address_space_bytes")
            pids = _positive_limit(limits, "pids")
            _write_control(path / "memory.max", str(memory))
            _write_control(path / "pids.max", str(pids))
            # cpu.max controls CPU bandwidth, while RLIMIT_CPU in the worker
            # independently enforces the grant's cumulative CPU-time ceiling.
            # One full CPU is a conservative phase-one bandwidth ceiling.
            _positive_limit(limits, "cpu_ms")
            _write_control(path / "cpu.max", "100000 100000")
            return scope
        except BaseException:
            try:
                scope.close(timeout_s=0)
            except OSError:
                pass
            raise

    def assign(self, pid: int) -> None:
        """Move a fresh worker into the cgroup and verify membership."""
        if self._closed or pid <= 0:
            raise ValueError("cgroup assignment requires an open scope and valid pid")
        _write_control(self.path / "cgroup.procs", str(pid))
        members = _read_pids(self.path / "cgroup.procs")
        if pid not in members:
            raise OSError(errno.EIO, "worker cgroup membership was not established")

    def kill(self) -> bool:
        """Kill all descendants atomically when the kernel exposes cgroup.kill."""
        if self._closed or not self.has_kill:
            return False
        _write_control(self.path / "cgroup.kill", "1")
        return True

    def close(self, *, timeout_s: float = 2.0) -> None:
        """Wait for an empty cgroup and remove the per-call leaf."""
        if self._closed:
            return
        deadline = time.monotonic() + max(0.0, timeout_s)
        while _populated(self.path) and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            self.path.rmdir()
        except FileNotFoundError:
            pass
        self._closed = True


def delegated_controllers(root: Path) -> frozenset[str]:
    """Return required controllers delegated to children of `root`."""
    available = _read_words(root / "cgroup.controllers")
    enabled = frozenset(
        item.removeprefix("+") for item in _read_words(root / "cgroup.subtree_control")
    )
    return _REQUIRED_CONTROLLERS.intersection(available, enabled)


def _require_delegated_controllers(root: Path) -> None:
    missing = _REQUIRED_CONTROLLERS.difference(delegated_controllers(root))
    if missing:
        raise OSError(
            errno.EOPNOTSUPP,
            "cgroup controllers are not delegated: " + ",".join(sorted(missing)),
        )
    if not os.access(root, os.W_OK):
        raise PermissionError(errno.EACCES, "cgroup delegation root is not writable")


def _positive_limit(limits: Mapping[str, int], name: str) -> int:
    value = limits.get(name)
    if type(value) is not int or value <= 0:
        raise ValueError(f"invalid cgroup limit:{name}")
    return value


def _write_control(path: Path, value: str) -> None:
    with path.open("w", encoding="ascii") as stream:
        stream.write(value)


def _read_words(path: Path) -> frozenset[str]:
    try:
        return frozenset(path.read_text(encoding="ascii").split())
    except OSError:
        return frozenset()


def _read_pids(path: Path) -> frozenset[int]:
    try:
        return frozenset(int(item) for item in path.read_text(encoding="ascii").split())
    except (OSError, ValueError):
        return frozenset()


def _populated(path: Path) -> bool:
    try:
        events = (path / "cgroup.events").read_text(encoding="ascii").splitlines()
    except OSError:
        return False
    for line in events:
        key, separator, value = line.partition(" ")
        if key == "populated" and separator:
            return value.strip() == "1"
    return False
