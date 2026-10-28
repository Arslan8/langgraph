"""Direct Linux capability probes used by backend compilation and attestation."""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.cgroup import delegated_controllers

_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_CREATE_RULESET_NR = 444


@dataclass(frozen=True, slots=True)
class LinuxCapabilities:
    """Boot-specific facts established without kernel-version inference."""

    boot_id: str
    landlock_abi: int
    cgroup_v2: bool
    cgroup_delegated: bool
    cgroup_kill: bool
    unprivileged_userns: bool
    bpf_lsm: bool
    landlock_audit: bool
    pidfd: bool
    evidence: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))

    @property
    def capabilities(self) -> frozenset[str]:
        """Return stable capability names suitable for host attestation."""
        values = {
            f"landlock:abi:{self.landlock_abi}",
            "cgroup:v2" if self.cgroup_v2 else "cgroup:v2:unavailable",
            "cgroup:delegated"
            if self.cgroup_delegated
            else "cgroup:delegated:unavailable",
            "cgroup:kill" if self.cgroup_kill else "cgroup:kill:unavailable",
            "userns:unprivileged"
            if self.unprivileged_userns
            else "userns:unprivileged:unavailable",
            "lsm:bpf" if self.bpf_lsm else "lsm:bpf:unavailable",
            "landlock:audit" if self.landlock_audit else "landlock:audit:unavailable",
            "pidfd" if self.pidfd else "pidfd:unavailable",
        }
        return frozenset(values)


def probe_landlock_abi() -> int:
    """Return the Landlock ABI from the version-query syscall, or zero."""
    if os.name != "posix":
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = syscall(
        ctypes.c_long(_LANDLOCK_CREATE_RULESET_NR),
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result >= 0:
        return int(result)
    error = ctypes.get_errno()
    if error in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
        return 0
    return 0


def probe_linux_capabilities() -> LinuxCapabilities:
    """Probe the current boot's Linux enforcement facilities directly."""
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    boot_id = _read_text(boot_path) or "unavailable"
    cgroup_path = _current_cgroup_path()
    cgroup_v2 = _filesystem_type(Path("/sys/fs/cgroup")) == "cgroup2fs"
    controllers = (
        delegated_controllers(cgroup_path)
        if cgroup_v2 and cgroup_path is not None
        else frozenset()
    )
    cgroup_delegated = bool(
        cgroup_v2
        and cgroup_path is not None
        and controllers == frozenset({"cpu", "memory", "pids"})
        and os.access(cgroup_path, os.W_OK)
        and os.access(cgroup_path / "cgroup.procs", os.W_OK)
    )
    cgroup_kill_path = cgroup_path / "cgroup.kill" if cgroup_path else None
    cgroup_kill = bool(cgroup_kill_path and cgroup_kill_path.exists())
    userns, userns_reason = _probe_userns()
    lsm_text = _read_text(Path("/sys/kernel/security/lsm")) or ""
    active_lsms = frozenset(item.strip() for item in lsm_text.split(",") if item)
    audit_probe_paths = (
        Path("/sys/kernel/tracing/events/landlock"),
        Path("/sys/kernel/debug/tracing/events/landlock"),
    )
    landlock_audit = any(_is_readable_directory(path) for path in audit_probe_paths)
    return LinuxCapabilities(
        boot_id=boot_id,
        landlock_abi=probe_landlock_abi(),
        cgroup_v2=cgroup_v2,
        cgroup_delegated=cgroup_delegated,
        cgroup_kill=cgroup_kill,
        unprivileged_userns=userns,
        bpf_lsm="bpf" in active_lsms,
        landlock_audit=landlock_audit,
        pidfd=hasattr(os, "pidfd_open"),
        evidence={
            "bpf_lsm_source": "/sys/kernel/security/lsm",
            "cgroup_path": os.fspath(cgroup_path) if cgroup_path else "unavailable",
            "cgroup_controllers": sorted(controllers),
            "landlock_abi_probe": (
                "landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)"
            ),
            "landlock_audit_probe": [os.fspath(path) for path in audit_probe_paths],
            "userns_probe": userns_reason,
        },
    )


def _current_cgroup_path() -> Path | None:
    text = _read_text(Path("/proc/self/cgroup"))
    if text is None:
        return None
    for line in text.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            relative = fields[2].lstrip("/")
            return Path("/sys/fs/cgroup") / relative
    return None


def _filesystem_type(path: Path) -> str:
    stat = shutil.which("stat")
    if stat is None:
        return "unavailable"
    try:
        result = subprocess.run(
            (stat, "-fc", "%T", os.fspath(path)),
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _probe_userns() -> tuple[bool, str]:
    unshare = shutil.which("unshare")
    if unshare is None:
        return False, "unshare executable unavailable"
    try:
        result = subprocess.run(
            (unshare, "--user", "--map-root-user", "true"),
            check=False,
            capture_output=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, type(exc).__name__
    return result.returncode == 0, f"unshare exit {result.returncode}"


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _is_readable_directory(path: Path) -> bool:
    try:
        return path.is_dir() and os.access(path, os.R_OK)
    except OSError:
        return False
