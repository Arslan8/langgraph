"""Process-wide execution policy owned by the trusted runtime bootstrap."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from threading import RLock
from typing import Any, Protocol


class RuntimePolicy(Protocol):
    def check(self, target: Any) -> None: ...


_lock = RLock()
_policy: RuntimePolicy | None = None
_started = False
_system_loaded = False
_SYSTEM_POLICY_PATH = Path("/etc/langgraph/mac.cedar")


def _load_system_policy() -> None:
    """Load operator policy from the deployment directory.

    Called under `_lock`. Existing interpreters retain their boot policy;
    deployment policy changes require restarting controllers.
    """
    global _policy, _system_loaded
    if _system_loaded:
        return
    configured_directory = os.environ.get("LANGGRAPH_MAC_DIR")
    if configured_directory is not None and not configured_directory.strip():
        raise RuntimeError("LANGGRAPH_MAC_DIR must name a directory")
    policy_path = (
        Path(configured_directory).expanduser().absolute() / "mac.cedar"
        if configured_directory is not None
        else _SYSTEM_POLICY_PATH
    )
    if os.name != "posix":
        if configured_directory is not None:
            raise RuntimeError("directory-based MAC policy requires POSIX")
        _system_loaded = True
        return
    trusted_owners = {0, os.geteuid()} if configured_directory is not None else {0}
    ownership = (
        "root or deployment-user-owned"
        if configured_directory is not None
        else "root-owned"
    )
    try:
        directory = os.open(
            policy_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
    except FileNotFoundError:
        if configured_directory is not None:
            raise RuntimeError(
                f"configured MAC directory is missing: {policy_path.parent}"
            ) from None
        _system_loaded = True
        return
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid not in trusted_owners or metadata.st_mode & 0o022:
            raise RuntimeError(
                f"MAC directory must be {ownership} and not group/world writable"
            )
        try:
            descriptor = os.open(
                policy_path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
        except FileNotFoundError:
            if configured_directory is not None:
                raise RuntimeError(
                    f"configured MAC policy is missing: {policy_path}"
                ) from None
            _system_loaded = True
            return
    finally:
        os.close(directory)
    with os.fdopen(descriptor, encoding="utf-8") as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in trusted_owners
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError(
                f"MAC policy must be {ownership}, regular, and not group/world writable"
            )
        forbids = source.read(1_048_577)
        if len(forbids) > 1_048_576:
            raise RuntimeError("system MAC policy exceeds size limit")
    from langgraph.prebuilt.security.mac import RuntimeMAC

    _policy = RuntimeMAC(forbids)
    _system_loaded = True


def install_runtime_policy(policy: RuntimePolicy) -> None:
    """Seal the runtime policy before the first graph or tool execution.

    There is deliberately no replacement or uninstall API. Each independent
    interpreter must install its operator policy during trusted bootstrap.
    """
    global _policy
    with _lock:
        _load_system_policy()
        if _policy is not None:
            raise RuntimeError("runtime policy is already installed")
        if _started:
            raise RuntimeError("runtime policy must be installed before execution")
        _policy = policy


def runtime_policy() -> RuntimePolicy | None:
    with _lock:
        _load_system_policy()
        return _policy


def check_runtime_policy(target: Any) -> None:
    """Gate all executions, including graphs compiled before installation."""
    global _started
    with _lock:
        _load_system_policy()
        _started = True
        policy = _policy
    if policy is not None:
        policy.check(target)
