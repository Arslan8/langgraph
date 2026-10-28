"""Internal lifecycle primitive for a persistent container executor.

This module owns reuse and confirmed destruction, not policy authorization or
confinement activation. It is not a HostToolExecutor and is not exported as one.
A caller must derive the identity from the authorized effective plan, hold the
lease through execution, and invalidate it after uncertain execution outcomes.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import subprocess
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ContainerIdentity:
    """All authority and runtime inputs that permit same-container reuse.

    Digests cover canonical principal (including session and roles), mandatory
    policy, effective grants, runtime/code, and the native confinement plan.
    No call id is included: an otherwise identical invocation may reuse state.
    """

    principal_digest: str
    policy_digest: str
    grant_digest: str
    runtime_digest: str
    native_plan_digest: str

    def __post_init__(self) -> None:
        for value in self.canonical().values():
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Container identity fields must be SHA-256 digests")

    def canonical(self) -> dict[str, str]:
        return {
            "principal": self.principal_digest,
            "policy": self.policy_digest,
            "grant": self.grant_digest,
            "runtime": self.runtime_digest,
            "native_plan": self.native_plan_digest,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class ContainerRuntime(Protocol):
    """Trusted runtime operations; removal must cover the whole container."""

    def create(self, name: str, identity: ContainerIdentity) -> str: ...

    def matches(self, container_id: str, identity: ContainerIdentity) -> bool: ...

    def destroy(self, name: str) -> bool:
        """Return true only after confirming the named container is absent."""
        ...


class ContainerCleanupError(RuntimeError):
    """Old container state remains quarantined until destruction is confirmed."""


@dataclass(frozen=True, slots=True)
class ContainerLease:
    name: str
    container_id: str
    identity: ContainerIdentity
    reused: bool


class ContainerLifecycle:
    """Serialize use and refuse reuse across authority or runtime changes."""

    def __init__(self, runtime: ContainerRuntime) -> None:
        self._runtime = runtime
        self._lock = RLock()
        self._lease: ContainerLease | None = None
        self._pending_name: str | None = None
        self._in_use = False

    def _destroy(self) -> None:
        name = self._pending_name
        if name is None:
            return
        # Do not clear the handle on failure: subsequent calls must retry cleanup,
        # never create a replacement while the old authority can still execute.
        self._lease = None
        try:
            destroyed = self._runtime.destroy(name)
        except Exception as exc:
            raise ContainerCleanupError(
                "Container destruction is not confirmed"
            ) from exc
        if not destroyed:
            raise ContainerCleanupError("Container destruction is not confirmed")
        self._pending_name = None
        self._lease = None

    @contextmanager
    def lease(self, identity: ContainerIdentity) -> Iterator[ContainerLease]:
        with self._lock:
            if self._in_use:
                raise RuntimeError("Nested container leases are unsupported")
            if self._pending_name is not None and (
                self._lease is None
                or self._lease.identity != identity
                or not self._runtime.matches(self._lease.container_id, identity)
            ):
                self._destroy()
            reused = self._lease is not None
            if self._lease is None:
                name = "slg-session-" + secrets.token_hex(16)
                self._pending_name = name
                try:
                    container_id = self._runtime.create(name, identity)
                    if not self._runtime.matches(container_id, identity):
                        raise RuntimeError("New container identity verification failed")
                    self._lease = ContainerLease(name, container_id, identity, False)
                except BaseException:
                    self._destroy()
                    raise
            lease = ContainerLease(
                self._lease.name, self._lease.container_id, identity, reused
            )
            self._in_use = True
            try:
                yield lease
            except BaseException:
                self._destroy()
                raise
            finally:
                self._in_use = False

    def close(self) -> None:
        with self._lock:
            if self._in_use:
                raise RuntimeError("Cannot close an active container lease")
            self._destroy()


class DockerContainerRuntime:
    """Docker lifecycle backend with identity labels and confirmed whole removal.

    The executor supplies the complete fixed launch arguments for the effective
    native plan. This backend does not certify that those arguments enforce it.
    The Docker daemon and the argument builder are trusted configuration.
    """

    def __init__(
        self,
        arguments: Callable[[ContainerIdentity], Sequence[str]],
        *,
        timeout_s: float = 30.0,
        run: Callable[..., Any] = subprocess.run,
        client: Sequence[str] = ("docker",),
    ) -> None:
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("timeout_s must be finite and positive")
        if not client or any(not isinstance(part, str) or not part for part in client):
            raise ValueError("Container client command must be nonempty")
        self._client = tuple(client)
        self._arguments = arguments
        self._timeout = timeout_s
        self._run = run
        self._owner = secrets.token_hex(32)

    def _command(self, *arguments: str) -> Any:
        return self._run(
            [*self._client, *arguments],
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )

    def create(self, name: str, identity: ContainerIdentity) -> str:
        result = self._command(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            f"slg.lifecycle.owner={self._owner}",
            "--label",
            f"slg.lifecycle.identity={identity.digest}",
            *self._arguments(identity),
        )
        container_id = result.stdout.strip()
        if result.returncode or not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("Container creation did not return an exact identity")
        return container_id

    def matches(self, container_id: str, identity: ContainerIdentity) -> bool:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            return False
        result = self._command("inspect", "--type", "container", container_id)
        if result.returncode:
            return False
        try:
            entries = json.loads(result.stdout)
            if not isinstance(entries, list) or len(entries) != 1:
                return False
            entry = entries[0]
            if not isinstance(entry, Mapping):
                return False
            labels = entry["Config"]["Labels"]
            return bool(
                entry["Id"] == container_id
                and entry["State"]["Running"] is True
                and labels.get("slg.lifecycle.owner") == self._owner
                and labels.get("slg.lifecycle.identity") == identity.digest
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            return False

    def destroy(self, name: str) -> bool:
        if not re.fullmatch(r"slg-session-[0-9a-f]{32}", name):
            raise ValueError("Unrecognized owned container name")
        try:
            self._command("rm", "-f", "--volumes", name)
        except (OSError, subprocess.SubprocessError):
            pass  # An uncertain response may still have removed the container.
        try:
            result = self._command(
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.ID}}",
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0 and not result.stdout.strip()
