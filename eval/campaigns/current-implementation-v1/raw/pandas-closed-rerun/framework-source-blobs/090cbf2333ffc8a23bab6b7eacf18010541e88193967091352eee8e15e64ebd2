"""Persistent Docker execution for exact read-only object grants.

The Docker daemon, pinned image and private host input directories are trusted.
The image must contain Python at `/usr/bin/python3` and libseccomp, and must not
contain secrets. Image content and private container `/tmp` are runtime baseline
access. Host input namespaces must not be mutated by untrusted host processes.
This is a read-only filesystem adapter, not a broker or metadata-secrecy adapter.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections import deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security._container_guardian_client import (
    DockerGuardian,
    _write_frame,
)
from langgraph.prebuilt.security._container_lifecycle import (
    ContainerCleanupError,
    ContainerIdentity,
    ContainerLifecycle,
    DockerContainerRuntime,
)
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    EnforcementMode,
    RuleEnforcement,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.linux import LinuxToolSpec, _readline_json
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectClass,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.types import ExecutionOutcome, Principal, ToolCall


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class DockerObjectDispatcher:
    """Activate native read grants before releasing the standard Linux worker.

    Use as `cedar_security(..., dispatcher=...)`. Reuse includes principal roles,
    scopes and session, current mandatory policy, effective authority, pinned
    tool/runtime identity and mount identities. Call ids are bound to individual
    activation receipts rather than to reuse. Close the dispatcher explicitly.

    Each invocation receives a fresh Python worker inside the container. Only
    whole-container destruction clears persistent state across identity changes.
    Cancellation waits for bounded execution and destroys the container before
    returning. An unconfirmed deletion quarantines it and prevents further use.
    """

    enforcer_id = "docker-readonly-v1"

    def __init__(
        self,
        tools: Mapping[str, LinuxToolSpec],
        *,
        image: str,
        private_roots: Sequence[str | Path],
        wall_timeout_s: float = 30.0,
    ) -> None:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("image must be an exact local Docker image id")
        if not math.isfinite(wall_timeout_s) or wall_timeout_s <= 0:
            raise ValueError("wall_timeout_s must be finite and positive")
        if not tools or any(spec.deployment is not None for spec in tools.values()):
            raise ValueError(
                "Pinned file tools are required; deployment bindings are unsupported"
            )
        binary = shutil.which("docker")
        if binary is None:
            raise ValueError("Docker client is unavailable")
        self._client = [binary]
        self.tools = MappingProxyType(dict(tools))
        self.image = image
        self.wall_timeout_s = wall_timeout_s
        roots = tuple(Path(path).absolute() for path in private_roots)
        if not roots:
            raise ValueError(
                "At least one operator-owned private input directory is required"
            )
        for root in roots:
            info = root.stat()
            if (
                root.resolve() != root
                or not root.is_dir()
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError(
                    "Input roots must be canonical, owned private directories"
                )
        self.private_roots = roots
        self._lock = RLock()
        self._record_lock = RLock()
        self._key = secrets.token_bytes(32)
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)
        self._events: deque[dict[str, Any]] = deque(maxlen=1024)
        self._plan: dict[str, Any] = {}
        self._closed = False
        self._directory = Path(tempfile.mkdtemp(prefix="slg-container-artifacts-"))
        worker = Path(__file__).with_name("_linux_worker.py").read_bytes()
        (self._directory / "worker.py").write_bytes(worker)
        self._worker_digest = hashlib.sha256(worker).hexdigest()
        try:
            for name, spec in self.tools.items():
                if not name.isidentifier():
                    raise ValueError("Tool names must be identifiers")
                source = spec.artifact_path.read_bytes()
                if hashlib.sha256(source).hexdigest() != spec.artifact_digest:
                    raise ValueError("Tool artifact changed")
                (self._directory / f"{name}.py").write_bytes(source)
            endpoint = (
                os.environ.get("DOCKER_HOST")
                if not os.environ.get("DOCKER_CONTEXT")
                else None
            ) or self._docker(
                "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
            )
            if not endpoint.strip().startswith("unix://"):
                raise ValueError("Only a local Unix-socket Docker daemon is supported")
            self._client = [binary, "--host", endpoint.strip()]
            if (
                self._docker("image", "inspect", image, "--format", "{{.Id}}").strip()
                != image
            ):
                raise ValueError("Pinned image identity is unavailable")
        except BaseException:
            shutil.rmtree(self._directory)
            raise
        try:
            self._guardian = DockerGuardian(self._client)
        except BaseException:
            shutil.rmtree(self._directory)
            raise
        self._runtime = DockerContainerRuntime(
            self._arguments, client=self._client, run=self._guardian.run
        )
        self._lifecycle = ContainerLifecycle(self._runtime)

    def _docker(self, *arguments: str) -> str:
        result = subprocess.run(
            [*self._client, *arguments], capture_output=True, text=True, timeout=30
        )
        if result.returncode:
            raise RuntimeError("Docker operation failed: " + result.stderr[:256])
        return result.stdout

    def _input(self, selector: str) -> Path:
        for root in self.private_roots:
            info = root.stat()
            if (
                root.resolve() != root
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError(
                    "Private input directory ownership or permissions changed"
                )
        path = Path(selector)
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError("File selector must be canonical")
        if not any(root in path.parents for root in self.private_roots):
            raise ValueError("File selector is outside private input roots")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Only regular files without linked aliases are supported")
        return path

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        if (
            object_class.name != "fs"
            or line.class_name != "fs"
            or line.operation != "read"
            or line.enforcer is not EnforcementKind.KERNEL
        ):
            return False
        try:
            self._input(line.selector)
        except (OSError, ValueError):
            return False
        return True

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        if set(tool_names) - self.tools.keys():
            raise ValueError("Container tool artifact is missing")

    def _arguments(self, identity: ContainerIdentity) -> Sequence[str]:
        if identity.native_plan_digest != _digest(self._plan):
            raise HostExecutionDenied("container:native_plan_binding")
        args = [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=1g",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--user=0:0",
        ]
        for source, destination in self._plan["mounts"]:
            if "," in source or "," in destination:
                raise HostExecutionDenied("container:mount_path_syntax")
            args += ["--mount", f"type=bind,src={source},dst={destination},readonly"]
        return [*args, "--entrypoint", "/bin/sleep", self.image, "infinity"]

    def _inspect(self, container_id: str) -> Mapping[str, Any]:
        values = json.loads(
            self._docker("inspect", "--type", "container", container_id)
        )
        if len(values) != 1:
            raise HostExecutionDenied("container:inspection_identity")
        value = values[0]
        host = value["HostConfig"]
        mounts = {
            (m["Source"], m["Destination"], m["RW"])
            for m in value["Mounts"]
            if m["Type"] == "bind"
        }
        expected = {(a, b, False) for a, b in self._plan["mounts"]}
        if (
            value["Id"] != container_id
            or value["Image"] != self.image
            or value["State"]["Running"] is not True
            or value["Config"]["User"] != "0:0"
            or host["NetworkMode"] != "none"
            or host["ReadonlyRootfs"] is not True
            or set(value["NetworkSettings"]["Networks"]) != {"none"}
            or any(m["Type"] not in {"bind", "tmpfs"} for m in value["Mounts"])
            or any(
                m["Type"] == "tmpfs" and m["Destination"] != "/tmp"
                for m in value["Mounts"]
            )
            or host.get("CapAdd")
            or host.get("Devices")
            or host["Privileged"]
            or host["PidsLimit"] != 32
            or host["Memory"] != 1073741824
            or "ALL" not in host["CapDrop"]
            or "no-new-privileges" not in host["SecurityOpt"]
            or mounts != expected
        ):
            raise HostExecutionDenied("container:confinement_inspection_failed")
        return value

    def invoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        return self._invoke(principal, call, grant, asynchronous=False)

    def _invoke(
        self,
        principal: Principal,
        call: ToolCall,
        grant: ObjectGrant,
        *,
        asynchronous: bool,
    ) -> HostExecutionResult:
        with self._lock:
            if self._closed:
                raise HostExecutionDenied("container:closed")
            if (
                grant.principal_id != principal.user_id
                or grant.tool_name != call.tool.name
                or grant.call_id != call.call_id
                or grant.enforcement_waivers
            ):
                raise HostExecutionDenied("container:grant_binding")
            if call.tool.name not in self.tools:
                raise HostExecutionDenied("container:tool_missing")
            spec = self.tools[call.tool.name]
            files = []
            for line in grant.lines:
                if (
                    line.class_name != "fs"
                    or line.operation != "read"
                    or line.enforcer is not EnforcementKind.KERNEL
                ):
                    raise HostExecutionDenied("container:unsupported_authority")
                try:
                    path = self._input(line.selector)
                    info = path.stat()
                except (OSError, ValueError) as exc:
                    raise HostExecutionDenied("container:invalid_input") from exc
                files.append((str(path), info.st_dev, info.st_ino))
            if len({line.line_id for line in grant.lines}) != len(grant.lines):
                raise HostExecutionDenied("container:duplicate_grant_line")
            tool = self._directory / f"{call.tool.name}.py"
            worker = self._directory / "worker.py"
            if (
                hashlib.sha256(tool.read_bytes()).hexdigest() != spec.artifact_digest
                or hashlib.sha256(worker.read_bytes()).hexdigest()
                != self._worker_digest
            ):
                raise HostExecutionDenied("container:artifact_changed")
            self._plan = {
                "image": self.image,
                "files": sorted(set(files)),
                "mounts": sorted(
                    {
                        (str(tool), "/opt/slg/tool.py"),
                        (str(worker), "/opt/slg/worker.py"),
                        *((path, path) for path, _, _ in files),
                    }
                ),
                "worker": self._worker_digest,
                "guardian": self._guardian.code_digest,
                "artifact": spec.artifact_digest,
                "seccomp": "linux-worker-minimal",
                "pids": 32,
                "memory": 1073741824,
            }
            identity = ContainerIdentity(
                _digest(
                    {
                        "user": principal.user_id,
                        "roles": sorted(principal.roles),
                        "scopes": sorted(principal.scopes),
                        "session": principal.session_id,
                        "delegated_by": principal.delegated_by,
                        "security": {
                            name: dict(slot)
                            for name, slot in principal.security.items()
                        },
                    }
                ),
                grant.policy_digest,
                _digest([line.canonical() for line in grant.lines]),
                _digest(
                    {
                        "image": self.image,
                        "worker": self._worker_digest,
                        "guardian": self._guardian.code_digest,
                        "artifact": spec.artifact_digest,
                        "entrypoint": spec.entrypoint,
                    }
                ),
                _digest(self._plan),
            )
            receipt = None
            try:
                with self._lifecycle.lease(identity) as lease:
                    inspected = self._inspect(lease.container_id)
                    nonce = secrets.token_hex(32)
                    request = {
                        "args": {**call.args, **call.normalized},
                        "artifact_path": "/opt/slg/tool.py",
                        "call_id": call.call_id,
                        "entrypoint": spec.entrypoint,
                        "plan_digest": identity.digest,
                        "runtime_roots": [],
                        "startup_challenge": nonce,
                        "tool_name": call.tool.name,
                        "asynchronous": asynchronous,
                        "limits": {
                            "cpu_ms": 30000,
                            "file_size_bytes": 67108864,
                            "nofile": 64,
                            "address_space_bytes": 536870912,
                        },
                    }
                    encoded = (json.dumps(request, allow_nan=False) + "\n").encode()
                    if len(encoded) > 1048576:
                        raise HostExecutionDenied("container:request_too_large")
                    process = subprocess.Popen(
                        [
                            *self._client,
                            "exec",
                            "-i",
                            lease.container_id,
                            "/usr/bin/python3",
                            "-I",
                            "-S",
                            "/opt/slg/worker.py",
                        ],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        bufsize=0,
                    )
                    try:
                        assert process.stdin is not None
                        _write_frame(process.stdin, encoded, 10.0)
                        ready = _readline_json(process, 10.0)
                        if ready != {
                            "status": "ready",
                            "plan_digest": identity.digest,
                            "startup_challenge": nonce,
                        }:
                            raise HostExecutionDenied("container:startup_protocol")
                        # The pinned shim installed limits and seccomp before this frame.
                        # No tool code has been imported. The private Docker exec pipe,
                        # container identity and nonce bind this blocked worker to the call.
                        context = _digest(
                            {
                                "container": lease.container_id,
                                "nonce": nonce,
                                "grant": grant.digest,
                            }
                        )
                        now = time.time()
                        evidence_payload = {
                            "context": context,
                            "plan": identity.digest,
                            "nonce": nonce,
                            "time": now,
                        }
                        signature = hmac.new(
                            self._key,
                            json.dumps(evidence_payload, sort_keys=True).encode(),
                            hashlib.sha256,
                        ).hexdigest()
                        obligations = frozenset(line.line_id for line in grant.lines)
                        receipt = ActivationReceipt(
                            grant.digest,
                            identity.digest,
                            _digest(
                                {
                                    "id": inspected["Id"],
                                    "image": inspected["Image"],
                                    "host_config": inspected["HostConfig"],
                                }
                            ),
                            context,
                            nonce,
                            EnforcementMode.ENFORCED,
                            (
                                ActivationEvidence(
                                    self.enforcer_id,
                                    identity.digest,
                                    context,
                                    nonce,
                                    obligations,
                                    now,
                                    now + self.wall_timeout_s + 10,
                                    signature,
                                ),
                            ),
                            obligations,
                            now + self.wall_timeout_s + 10,
                            tuple(
                                RuleEnforcement(
                                    line.line_id,
                                    SupportLevel.EXACT,
                                    "docker-readonly-bind",
                                )
                                for line in grant.lines
                            ),
                            artifact_digest=spec.artifact_digest,
                            runtime_digest=identity.runtime_digest,
                        )
                        with self._record_lock:
                            self._receipts.append(receipt)
                            self._events.append(
                                {
                                    "container_id": lease.container_id,
                                    "reused": lease.reused,
                                    "identity_digest": identity.digest,
                                    "grant_digest": grant.digest,
                                    "context_digest": context,
                                    "call_id": call.call_id,
                                    "activated_at": now,
                                }
                            )
                        _write_frame(process.stdin, b"GO\n", 10.0)
                        response = _readline_json(process, self.wall_timeout_s)
                        status = process.wait(timeout=2)
                        if (
                            status != 0
                            or response.get("status") != "ok"
                            or "result" not in response
                        ):
                            raise RuntimeError(
                                "Worker failed or returned an invalid result"
                            )
                        return HostExecutionResult(response["result"], receipt)
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=5)
                        if process.stdin:
                            process.stdin.close()
                        if process.stdout:
                            process.stdout.close()
            except ContainerCleanupError as exc:
                if receipt is not None:
                    raise HostExecutionError(
                        "container:cleanup_unconfirmed",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                    ) from exc
                raise HostExecutionDenied("container:cleanup_unconfirmed") from exc
            except HostExecutionDenied:
                raise
            except Exception as exc:
                if receipt is not None:
                    raise HostExecutionError(
                        "container:execution_failed",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                        termination_confirmed=True,
                    ) from exc
                raise HostExecutionDenied("container:activation_failed") from exc

    async def ainvoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        execution = asyncio.create_task(
            asyncio.to_thread(self._invoke, principal, call, grant, asynchronous=True)
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            while not execution.done():
                try:
                    await asyncio.shield(execution)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            failure = None
            try:
                execution.result()
            except BaseException as exc:
                failure = exc
            cleanup = asyncio.create_task(asyncio.to_thread(self._invalidate))
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            try:
                cleanup.result()
            except Exception as exc:
                if isinstance(failure, HostExecutionError):
                    raise failure from exc
                raise HostExecutionDenied(
                    "container:cancellation_cleanup_unconfirmed"
                ) from exc
            raise

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        with self._record_lock:
            return tuple(self._receipts)

    def execution_records(self) -> tuple[Mapping[str, Any], ...]:
        with self._record_lock:
            return tuple(dict(record) for record in self._events)

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        return False

    def _invalidate(self) -> None:
        with self._lock:
            self._lifecycle.close()

    def close(self) -> None:
        with self._lock:
            self._lifecycle.close()
            self._guardian.close()
            self._closed = True
            shutil.rmtree(self._directory, ignore_errors=True)
