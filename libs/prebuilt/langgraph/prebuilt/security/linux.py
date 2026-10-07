"""Linux bubblewrap executor for host-confined tool entry points."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import hmac
import json
import os
import platform
import secrets
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AdapterPlan,
    AuthorityDomain,
    EnforcementCoordinator,
    EnforcementObligation,
    EnforcementPlan,
    ExecutionContext,
    Grant,
    GrantRule,
    HostAttestation,
    ObligationKind,
    SupportAssessment,
    SupportLevel,
    compile_grant,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.policy import (
    MandatoryPolicyBackend,
    TypedPolicyBackend,
)
from langgraph.prebuilt.security.profile import ProfileDocument
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
)

_ADAPTER_ID = "linux-bubblewrap-v1"
_MAX_FRAME = 1_048_576
_MAX_PROTOCOL_DEPTH = 64
_MAX_PROTOCOL_NODES = 100_000
_SUPPORTED_LIMITS = frozenset(
    {
        "address_space_bytes",
        "cpu_ms",
        "file_size_bytes",
        "nofile",
        "pids",
        "tmpfs_bytes",
        "wall_ms",
    }
)
_WRITE_OPERATIONS = frozenset({"write", "create", "delete", "truncate"})
_DEFAULT_LIMITS = MappingProxyType(
    {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 30_000,
        "file_size_bytes": 67_108_864,
        "nofile": 64,
        "pids": 1,
        "tmpfs_bytes": 67_108_864,
        "wall_ms": 30_000,
    }
)


@dataclass(frozen=True, slots=True)
class LinuxToolSpec:
    """Trusted manifest entry for one tool imported inside the sandbox.

    `entrypoint` has the form `package.module:attribute`. `artifact_path` and
    `artifact_digest` identify the exact operator-verified module file bound
    into the per-call grant. Every other module needed to import the entry
    point must live under an explicit runtime root.
    """

    entrypoint: str
    artifact_path: Path
    artifact_digest: str

    def __post_init__(self) -> None:
        module, separator, attribute = self.entrypoint.partition(":")
        if (
            not separator
            or not module
            or not attribute
            or "<locals>" in attribute
            or any(not part.isidentifier() for part in module.split("."))
            or any(not part.isidentifier() for part in attribute.split("."))
        ):
            raise ValueError(
                "Linux tool entrypoint must be importable module:attribute"
            )
        artifact = _canonical_existing_path(self.artifact_path)
        if not artifact.is_file():
            raise ValueError("Linux tool artifact_path must name a file")
        if (
            len(self.artifact_digest) != 64
            or _file_digest(artifact) != self.artifact_digest
        ):
            raise ValueError("Linux tool artifact digest does not match artifact_path")
        object.__setattr__(self, "artifact_path", artifact)


class LinuxSandboxExecutor:
    """Execute manifest tools in a fresh, fail-closed bubblewrap worker.

    The backend currently enforces filesystem grants, an isolated no-network
    namespace, a default-deny seccomp allowlist, and resource ceilings. Network,
    service, credential, delegation, and executable grants are rejected until a
    broker or a more capable Linux adapter owns their exact obligations.
    """

    def __init__(
        self,
        profiles: ProfileDocument,
        tools: Mapping[str, LinuxToolSpec],
        *,
        runtime_roots: Sequence[str | Path],
        principal_bindings: Mapping[str, Mapping[str, object]] | None = None,
        policy_backend: MandatoryPolicyBackend | None = None,
        bubblewrap_path: str | Path = "bwrap",
        python_executable: str | Path | None = None,
        startup_timeout_s: float = 5.0,
        default_wall_timeout_s: float = 30.0,
        default_limits: Mapping[str, int] | None = None,
        attestation_key: bytes | None = None,
    ) -> None:
        if platform.system() != "Linux":
            raise RuntimeError("LinuxSandboxExecutor requires Linux")
        try:
            ctypes.CDLL("libseccomp.so.2")
        except OSError as exc:
            raise RuntimeError(
                "libseccomp.so.2 is required for Linux host execution"
            ) from exc
        bwrap = shutil.which(os.fspath(bubblewrap_path))
        if bwrap is None:
            raise RuntimeError("bubblewrap is required for Linux host execution")
        python = Path(python_executable or os.sys.executable).resolve()
        if not python.is_file():
            raise ValueError("python_executable must resolve to an existing file")
        roots = tuple(_canonical_existing_path(item) for item in runtime_roots)
        if not roots:
            raise ValueError("at least one explicit runtime root is required")
        if any(not _is_supported_mount_type(root) for root in roots):
            raise ValueError("runtime roots must be regular files or directories")
        if startup_timeout_s <= 0 or default_wall_timeout_s <= 0:
            raise ValueError("Linux sandbox timeouts must be positive")
        _verify_bubblewrap_host(bwrap, startup_timeout_s)
        limits = dict(_DEFAULT_LIMITS if default_limits is None else default_limits)
        if (
            set(limits) != _SUPPORTED_LIMITS
            or any(type(value) is not int or value <= 0 for value in limits.values())
            or limits["cpu_ms"] % 1000
            or limits["pids"] != 1
        ):
            raise ValueError(
                "default_limits must provide positive address_space_bytes, "
                "cpu_ms, file_size_bytes, nofile, pids, tmpfs_bytes, and "
                "wall_ms values; cpu_ms must use whole-second RLIMIT_CPU granularity"
                " and pids must be 1 for the no-process-creation profile"
            )
        copied_tools = dict(tools)
        if not copied_tools:
            raise ValueError("Linux sandbox requires at least one tool manifest")
        unknown = set(copied_tools).difference(profiles.tools)
        if unknown:
            raise ValueError(
                "Linux tool manifests lack profiles: " + ", ".join(sorted(unknown))
            )
        wrong_locus = {
            name for name in copied_tools if profiles.tools[name].runs != "linux"
        }
        if wrong_locus:
            raise ValueError(
                "Linux tool profiles must declare 'runs linux': "
                + ", ".join(sorted(wrong_locus))
            )
        wrong_syscalls = {
            name
            for name in copied_tools
            if profiles.tools[name].syscall_sets != frozenset({"minimal"})
        }
        if wrong_syscalls:
            raise ValueError(
                "Linux tool profiles require exactly 'syscalls @minimal': "
                + ", ".join(sorted(wrong_syscalls))
            )
        self.profiles = profiles
        self.tools = MappingProxyType(copied_tools)
        self.runtime_roots = roots
        self.principal_bindings = MappingProxyType(
            {
                name: MappingProxyType(dict(values))
                for name, values in (principal_bindings or {}).items()
            }
        )
        self.policy_backend = policy_backend or TypedPolicyBackend()
        self.bubblewrap_path = bwrap
        self.python_executable = python
        self._worker_script = Path(__file__).with_name("_linux_worker.py").resolve()
        self._python_digest = _file_digest(self.python_executable)
        self._worker_digest = _file_digest(self._worker_script)
        self.startup_timeout_s = startup_timeout_s
        self.default_wall_timeout_s = default_wall_timeout_s
        self.default_limits = MappingProxyType(limits)
        self._adapter = _LinuxBubblewrapAdapter(
            bwrap,
            attestation_key or secrets.token_bytes(32),
            self.python_executable,
            self._worker_script,
            startup_timeout_s
            + max(default_wall_timeout_s, limits["wall_ms"] / 1000)
            + 5.0,
        )
        self._coordinator = EnforcementCoordinator([self._adapter], self._adapter)
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)
        self._receipt_lock = RLock()
        self._unresolved: dict[str, TerminationRecovery] = {}
        self._termination_lock = RLock()

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require a closed manifest and Linux profile for every reachable tool."""
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "Linux execution missing tool manifests: " + ", ".join(sorted(missing))
            )

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        """Return a bounded snapshot of worker-specific activation evidence."""
        with self._receipt_lock:
            return tuple(self._receipts)

    def unresolved_terminations(self) -> tuple[TerminationRecovery, ...]:
        """Return workers still awaiting reliable termination evidence."""
        with self._termination_lock:
            return tuple(self._unresolved.values())

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Compile, activate, and execute one call in a fresh Linux worker."""
        return self._invoke(principal, call, constraints, asynchronous=False)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Compile, activate, and execute one async call off the event loop."""
        execution = asyncio.create_task(
            asyncio.to_thread(
                self._invoke,
                principal,
                call,
                constraints,
                asynchronous=True,
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            try:
                await execution
            except HostExecutionError as exc:
                if not exc.termination_confirmed:
                    raise exc
            except Exception:
                pass
            raise

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        """Confirm or force termination for one retained Linux worker identity."""
        with self._termination_lock:
            retained = self._unresolved.get(recovery.recovery_id)
            if retained is not None and retained != recovery:
                return False
        current_boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        confirmed = recovery.boot_id != current_boot or _confirm_worker_terminated(
            recovery.pid, recovery.start_time, timeout_s=2.0
        )
        if confirmed:
            with self._termination_lock:
                self._unresolved.pop(recovery.recovery_id, None)
        return confirmed

    def _invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        asynchronous: bool,
    ) -> Any:
        spec = self.tools.get(call.tool.name)
        if spec is None:
            raise HostExecutionDenied("host:tool_manifest_missing")
        grant, ledger = self._compile_grant(principal, call, spec)
        filtered = self.policy_backend.filter(grant, ledger, constraints)
        if not filtered.allowed or filtered.grant is None:
            raise HostExecutionDenied(f"host:{filtered.reason}")
        grant = filtered.grant
        obligations = compile_obligations(grant)
        challenge = secrets.token_hex(16)
        host = self._adapter.attest(challenge)
        negotiation = self._coordinator.negotiate(
            grant,
            filtered.ledger,
            obligations,
            host,
            expected_nonce=challenge,
        )
        if not negotiation.allowed or negotiation.plan is None:
            raise HostExecutionDenied(f"host:{negotiation.reason}")
        return self._run_worker(
            principal,
            call,
            spec,
            grant,
            host,
            negotiation.plan,
            asynchronous=asynchronous,
        )

    def _compile_grant(
        self, principal: Principal, call: ToolCall, spec: LinuxToolSpec
    ) -> tuple[Grant, Any]:
        profile = self.profiles.principals.get(principal.user_id)
        if profile is None:
            raise HostExecutionDenied("host:principal_profile_missing")
        if profile.roles != principal.roles or profile.scopes != principal.scopes:
            raise HostExecutionDenied("host:principal_profile_mismatch")
        bindings: dict[str, object] = dict(call.args)
        bindings.update(call.normalized)
        try:
            evaluation = self.profiles.evaluate(
                call.tool.name,
                principal.user_id,
                bindings,
                principal_bindings=self.principal_bindings,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("host:profile_evaluation_failed") from exc
        if evaluation.denied:
            raise HostExecutionDenied(f"host:dac:{evaluation.reason or 'deny'}")
        compiled = compile_grant(
            evaluation,
            principal_id=principal.user_id,
            session_id=principal.session_id,
            artifact_digest=spec.artifact_digest,
            call_id=call.call_id,
            normalized_intent_digest=_digest(
                {
                    "args": _json_value(call.args),
                    "normalized": _json_value(call.normalized),
                    "tool": call.tool.name,
                }
            ),
            policy_digest=_digest({"stage": "pre-mac"}),
            baseline_rules=self._baseline_rules(spec),
        )
        return compiled.grant, compiled.ledger

    def _baseline_rules(self, spec: LinuxToolSpec) -> tuple[GrantRule, ...]:
        rules = [
            GrantRule(
                "runtime:usr",
                AuthorityDomain.RUNTIME,
                "read",
                "/usr",
                {"subtree": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:read",
                AuthorityDomain.RUNTIME,
                "read",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:write",
                AuthorityDomain.RUNTIME,
                "write",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:create",
                AuthorityDomain.RUNTIME,
                "create",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:delete",
                AuthorityDomain.RUNTIME,
                "delete",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:truncate",
                AuthorityDomain.RUNTIME,
                "truncate",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:worker",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(self._worker_script),
                {"sha256": self._worker_digest},
                baseline=True,
            ),
            GrantRule(
                "runtime:artifact",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(spec.artifact_path),
                {"sha256": spec.artifact_digest},
                baseline=True,
            ),
            GrantRule(
                "runtime:interpreter",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(self.python_executable),
                {"sha256": self._python_digest},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:path",
                AuthorityDomain.RUNTIME,
                "environment",
                "PATH",
                {"value": "/usr/bin"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:no-bytecode",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONDONTWRITEBYTECODE",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:no-locale-coercion",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONCOERCECLOCALE",
                {"value": "0"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:no-user-site",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONNOUSERSITE",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:safe-path",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONSAFEPATH",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:unbuffered",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONUNBUFFERED",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:utf8",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONUTF8",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:protocol:request",
                AuthorityDomain.IPC,
                "read",
                "parent-request-pipe",
                {"descriptor": 0},
                baseline=True,
            ),
            GrantRule(
                "runtime:protocol:response",
                AuthorityDomain.IPC,
                "write",
                "parent-response-pipe",
                {"descriptor": 1},
                baseline=True,
            ),
            GrantRule(
                "runtime:protocol:diagnostic",
                AuthorityDomain.IPC,
                "write",
                "parent-diagnostic-pipe",
                {"descriptor": 2},
                baseline=True,
            ),
        ]
        for index, root in enumerate(self.runtime_roots):
            if root == Path("/usr") or Path("/usr") in root.parents:
                continue
            rules.append(
                GrantRule(
                    f"runtime:root:{index}",
                    AuthorityDomain.RUNTIME,
                    "read",
                    os.fspath(root),
                    {"subtree": root.is_dir()},
                    baseline=True,
                )
            )
        for name, maximum in self.default_limits.items():
            rules.append(
                GrantRule(
                    f"runtime:limit:{name}",
                    AuthorityDomain.RESOURCE_LIMIT,
                    "limit",
                    name,
                    {"maximum": maximum},
                    baseline=True,
                )
            )
        return tuple(rules)

    def _run_worker(
        self,
        principal: Principal,
        call: ToolCall,
        spec: LinuxToolSpec,
        grant: Grant,
        host: HostAttestation,
        plan: EnforcementPlan,
        *,
        asynchronous: bool,
    ) -> HostExecutionResult:
        adapter_plan = next(
            item for item in plan.adapter_plans if item.adapter_id == _ADAPTER_ID
        )
        if _file_digest(self.python_executable) != self._python_digest:
            raise HostExecutionDenied("host:interpreter_changed")
        if _file_digest(self._worker_script) != self._worker_digest:
            raise HostExecutionDenied("host:worker_shim_changed")
        startup_challenge = secrets.token_hex(16)
        try:
            request = {
                "args": _json_value(call.args),
                "artifact_path": os.fspath(spec.artifact_path),
                "asynchronous": asynchronous,
                "call_id": call.call_id,
                "entrypoint": spec.entrypoint,
                "limits": _plain_mapping(adapter_plan.payload.get("limits", {})),
                "plan_digest": adapter_plan.native_plan_digest,
                "runtime_roots": [os.fspath(item) for item in self.runtime_roots],
                "startup_challenge": startup_challenge,
                "tool_name": call.tool.name,
            }
            encoded_request = _encode_worker_request(request)
        except (RecursionError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("host:request_not_serializable") from exc
        command, inherited_fds, status_read, status_write, artifact_directory = (
            self._worker_command(adapter_plan, spec)
        )
        process: subprocess.Popen[bytes] | None = None
        receipt: ActivationReceipt | None = None
        released = False
        child_pid: int | None = None
        child_start_time: str | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                pass_fds=(*inherited_fds, status_write),
            )
            os.close(status_write)
            status_write = -1
            for descriptor in inherited_fds:
                os.close(descriptor)
            inherited_fds = ()
            if process.stdin is None or process.stdout is None:
                raise HostExecutionDenied("host:worker_pipe_failed")
            process.stdin.write(encoded_request)
            process.stdin.flush()
            status = _read_fd_json(status_read, self.startup_timeout_s)
            sandbox_init_pid = int(status["child-pid"])
            ready = _readline_json(process, self.startup_timeout_s)
            _remove_private_artifact(artifact_directory)
            artifact_directory = None
            if ready != {
                "plan_digest": adapter_plan.native_plan_digest,
                "startup_challenge": startup_challenge,
                "status": "ready",
            }:
                raise HostExecutionDenied("host:worker_startup_protocol")
            child_pid = _sandbox_payload_pid(
                sandbox_init_pid, timeout_s=self.startup_timeout_s
            )
            context = _execution_context(child_pid)
            child_start_time = context.process_identity.rpartition(":")[2]
            self._adapter.register_pending(adapter_plan, context)
            activation_nonce = secrets.token_hex(16)
            receipt = self._coordinator.activate(
                grant,
                plan,
                host,
                context,
                nonce=activation_nonce,
            )
            if not self._coordinator.validate_receipt(
                receipt, grant, plan, host, context
            ):
                raise HostExecutionDenied("host:activation_receipt_invalid")
            with self._receipt_lock:
                self._receipts.append(receipt)
            process.stdin.write(b"GO\n")
            process.stdin.flush()
            released = True
            wall_timeout = _wall_timeout(
                adapter_plan.payload, self.default_wall_timeout_s
            )
            response = _readline_json(process, wall_timeout)
            return_code = process.wait(timeout=1.0)
            if response.get("status") == "ok" and "result" in response:
                if return_code != 0:
                    raise HostExecutionError(
                        "sandboxed tool outcome is indeterminate",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                    )
                return HostExecutionResult(response["result"], receipt)
            error_type = str(response.get("error_type", "Exception"))
            raise HostExecutionError(
                f"sandboxed tool failed:{error_type}",
                receipt,
                ExecutionOutcome.FAILED,
            )
        except HostExecutionError:
            raise
        except HostExecutionDenied:
            raise
        except TimeoutError as exc:
            reason = "host:worker_startup_timeout" if not released else "tool_timeout"
            if released and receipt is not None:
                raise HostExecutionError(
                    reason, receipt, ExecutionOutcome.INDETERMINATE
                ) from exc
            raise HostExecutionDenied(reason) from exc
        except (
            KeyError,
            OSError,
            RecursionError,
            ValueError,
            subprocess.SubprocessError,
        ) as exc:
            if receipt is not None:
                raise HostExecutionError(
                    "sandboxed tool outcome is indeterminate",
                    receipt,
                    ExecutionOutcome.INDETERMINATE,
                ) from exc
            raise HostExecutionDenied("host:worker_activation_failed") from exc
        finally:
            if status_read >= 0:
                os.close(status_read)
            if status_write >= 0:
                os.close(status_write)
            for descriptor in inherited_fds:
                os.close(descriptor)
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2.0)
            termination_confirmed = not (
                child_pid is not None and child_start_time is not None
            ) or _confirm_worker_terminated(child_pid, child_start_time, timeout_s=2.0)
            if artifact_directory is not None:
                _remove_private_artifact(artifact_directory)
            if not termination_confirmed:
                recovery = TerminationRecovery(
                    secrets.token_hex(16),
                    child_pid,
                    child_start_time,
                    host.boot_id,
                )
                with self._termination_lock:
                    self._unresolved[recovery.recovery_id] = recovery
                active_error = sys.exception()
                if isinstance(active_error, HostExecutionError):
                    active_error.recovery = recovery
                if receipt is not None:
                    raise HostExecutionError(
                        f"host:worker_termination_unconfirmed:{recovery.recovery_id}",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                        recovery=recovery,
                    )
                raise HostExecutionDenied("host:worker_termination_unconfirmed")
            active_error = sys.exception()
            if isinstance(active_error, HostExecutionError):
                active_error.termination_confirmed = True

    def _worker_command(
        self, plan: AdapterPlan, spec: LinuxToolSpec
    ) -> tuple[list[str], tuple[int, ...], int, int, Path]:
        mounts = tuple(plan.payload.get("mounts", ()))
        environment = _plain_mapping(plan.payload.get("environment", {}))
        expected_environment = {
            "PATH": "/usr/bin",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
        }
        protocol = set(plan.payload.get("protocol", ()))
        limits = _plain_mapping(plan.payload.get("limits", {}))
        if environment != expected_environment or protocol != {
            "parent-request-pipe",
            "parent-response-pipe",
            "parent-diagnostic-pipe",
        }:
            raise HostExecutionDenied("host:invalid_runtime_baseline")
        if set(limits) != _SUPPORTED_LIMITS or any(
            type(value) is not int or value <= 0 for value in limits.values()
        ):
            raise HostExecutionDenied("host:invalid_resource_limits")
        descriptors: list[int] = []
        mount_args: list[str] = []
        destinations: set[str] = set()
        artifact_descriptor, artifact_directory = _verified_artifact_fd(spec)
        ordered_mounts = sorted(
            mounts,
            key=lambda item: (
                os.fspath(item.get("path", "")).count("/")
                if isinstance(item, Mapping)
                else 0,
                os.fspath(item.get("path", "")) if isinstance(item, Mapping) else "",
            ),
        )
        for raw in ordered_mounts:
            if not isinstance(raw, Mapping):
                raise HostExecutionDenied("host:invalid_native_plan")
            path = os.fspath(raw.get("path", ""))
            mode = str(raw.get("mode", ""))
            if mode not in {"ro", "rw"}:
                raise HostExecutionDenied("host:invalid_native_plan")
            if path == "/tmp":
                continue
            canonical = _canonical_existing_path(path)
            if os.fspath(canonical) != path:
                raise HostExecutionDenied("host:noncanonical_mount")
            if canonical.is_dir() and _nested_mount_points(canonical):
                raise HostExecutionDenied("host:nested_mount_changed")
            descriptor = (
                artifact_descriptor
                if canonical == spec.artifact_path
                else _verified_resource_fd(canonical)
            )
            descriptors.append(descriptor)
            destinations.add(path)
            mount_args.extend(
                ["--bind-fd" if mode == "rw" else "--ro-bind-fd", str(descriptor), path]
            )
        directories = sorted(
            {
                parent
                for destination in destinations
                for parent in _missing_parent_directories(destination)
            },
            key=lambda value: (value.count("/"), value),
        )
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        command = [
            self.bubblewrap_path,
            "--unshare-all",
            "--unshare-user",
            "--die-with-parent",
            "--new-session",
            "--disable-userns",
            "--assert-userns-disabled",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--size",
            str(limits["tmpfs_bytes"]),
            "--tmpfs",
            "/tmp",
        ]
        for directory in directories:
            command.extend(["--dir", directory])
        command.extend(mount_args)
        for name, value in sorted(environment.items()):
            command.extend(["--setenv", name, str(value)])
        command.extend(
            [
                "--chdir",
                "/tmp",
                "--json-status-fd",
                str(status_write),
                "--",
                os.fspath(self.python_executable),
                "-I",
                "-S",
                "-B",
                "-u",
                "-X",
                "utf8",
                os.fspath(self._worker_script),
            ]
        )
        return (
            command,
            tuple(descriptors),
            status_read,
            status_write,
            artifact_directory,
        )


class _LinuxBubblewrapAdapter:
    """Exact-obligation adapter used by `LinuxSandboxExecutor`."""

    def __init__(
        self,
        bwrap_path: str,
        key: bytes,
        python_executable: Path,
        worker_script: Path,
        lease_s: float,
    ) -> None:
        self.bwrap_path = bwrap_path
        self._key = key
        self._pending: dict[str, str] = {}
        self._lock = RLock()
        self._boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self._binary_digest = _file_digest(Path(bwrap_path))
        self._python_executable = python_executable
        self._python_digest = _file_digest(python_executable)
        self._worker_script = worker_script
        self._worker_digest = _file_digest(worker_script)
        self._lease_s = lease_s

    @property
    def adapter_id(self) -> str:
        """Return the versioned Linux adapter identity."""
        return _ADAPTER_ID

    def attest(self, nonce: str) -> HostAttestation:
        """Return fresh locally authenticated host evidence."""
        if _file_digest(Path(self.bwrap_path)) != self._binary_digest:
            raise HostExecutionDenied("host:bubblewrap_changed")
        if _file_digest(self._python_executable) != self._python_digest:
            raise HostExecutionDenied("host:interpreter_changed")
        if _file_digest(self._worker_script) != self._worker_digest:
            raise HostExecutionDenied("host:worker_shim_changed")
        now = time.time()
        attestation = HostAttestation(
            "slanggraph-local-linux",
            nonce,
            self._boot_id,
            "linux",
            now,
            now + self._lease_s,
            frozenset(
                {
                    "bubblewrap",
                    "filesystem",
                    "namespace:no-network",
                    "resource-limits",
                    "seccomp:minimal",
                }
            ),
            _namespace_links(os.getpid()),
            {
                "adapter": self.adapter_id,
                "bubblewrap_digest": self._binary_digest,
                "kernel": platform.release(),
                "python_digest": self._python_digest,
                "worker_digest": self._worker_digest,
            },
            "pending",
        )
        return replace(attestation, signature=self._sign(attestation.digest))

    def verify(self, attestation: HostAttestation) -> bool:
        """Verify local host evidence against this executor's trust key."""
        return (
            attestation.issuer == "slanggraph-local-linux"
            and attestation.boot_id == self._boot_id
            and hmac.compare_digest(
                attestation.signature, self._sign(attestation.digest)
            )
        )

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        """Report support only for guarantees this backend actually activates."""
        support = SupportLevel.UNSUPPORTED
        reason = "linux_adapter_unsupported"
        if obligation.kind is ObligationKind.DENY_COMPLEMENT:
            support = SupportLevel.EXACT
            reason = "isolated_empty_authority_domain"
        elif obligation.domain in {AuthorityDomain.FILESYSTEM, AuthorityDomain.RUNTIME}:
            if obligation.operation == "environment":
                support = SupportLevel.EXACT
                reason = "clearenv_explicit_value"
            else:
                support, reason = _assess_path_obligation(obligation)
        elif (
            obligation.domain is AuthorityDomain.IPC
            and obligation.operation in {"read", "write"}
            and obligation.selector
            in {
                "parent-request-pipe",
                "parent-response-pipe",
                "parent-diagnostic-pipe",
            }
        ):
            support = SupportLevel.EXACT
            reason = "explicit_protocol_descriptor"
        elif (
            obligation.domain is AuthorityDomain.PROCESS
            and obligation.operation == "syscall_set"
            and obligation.selector == "minimal"
        ):
            support = SupportLevel.EXACT
            reason = "seccomp_minimal"
        elif (
            obligation.domain is AuthorityDomain.RESOURCE_LIMIT
            and obligation.kind is ObligationKind.RESOURCE_LIMIT
        ):
            support, reason = _assess_limit_obligation(obligation)
        return SupportAssessment(
            self.adapter_id,
            obligation.obligation_id,
            support,
            reason,
            ("worker_namespace", "activation_receipt")
            if support is not SupportLevel.UNSUPPORTED
            else (),
        )

    def lower(
        self,
        grant: Grant,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
    ) -> AdapterPlan:
        """Compile assigned obligations into stable mounts and resource limits."""
        del host
        rules = {rule.rule_id: rule for rule in grant.rules}
        path_rules = [
            rules[item.rule_id]
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and (
                item.domain is AuthorityDomain.FILESYSTEM
                or (
                    item.domain is AuthorityDomain.RUNTIME
                    and item.operation in {"read", *_WRITE_OPERATIONS}
                )
            )
        ]
        operations: dict[tuple[AuthorityDomain, str], set[str]] = {}
        for rule in path_rules:
            operations.setdefault((rule.domain, rule.selector), set()).add(
                rule.operation
            )
        for (domain, selector), granted in operations.items():
            if domain is AuthorityDomain.RUNTIME:
                continue
            required = {"read", "write", "truncate"}
            path = _canonical_existing_path(selector)
            if path.is_dir():
                required.update({"create", "delete"})
            if granted.intersection(_WRITE_OPERATIONS) and not required.issubset(
                granted
            ):
                raise ValueError(f"inexact_writable_mount:{selector}")
        mounts: dict[str, str] = {}
        subtrees: dict[str, bool] = {}
        for rule in path_rules:
            mode = "rw" if rule.operation in _WRITE_OPERATIONS | {"write"} else "ro"
            prior = mounts.get(rule.selector)
            mounts[rule.selector] = "rw" if "rw" in {prior, mode} else "ro"
            subtrees[rule.selector] = bool(rule.conditions.get("subtree"))
        limits: dict[str, int] = {}
        for item in obligations:
            if item.kind is ObligationKind.RESOURCE_LIMIT:
                maximum = item.conditions.get("maximum")
                if not isinstance(maximum, int) or maximum <= 0:
                    raise ValueError(f"invalid_resource_limit:{item.obligation_id}")
                prior = limits.get(item.selector)
                limits[item.selector] = (
                    maximum if prior is None else min(prior, maximum)
                )
        environment = {
            rules[item.rule_id].selector: str(
                rules[item.rule_id].conditions.get("value", "")
            )
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and item.domain is AuthorityDomain.RUNTIME
            and item.operation == "environment"
        }
        protocol = sorted(
            rules[item.rule_id].selector
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and item.domain is AuthorityDomain.IPC
        )
        payload = {
            "environment": environment,
            "limits": limits,
            "mounts": [
                {"mode": mounts[path], "path": path, "subtree": subtrees[path]}
                for path in sorted(mounts)
            ],
            "network": "isolated",
            "protocol": protocol,
            "seccomp": "minimal",
        }
        native_digest = _digest(payload)
        return AdapterPlan(
            self.adapter_id,
            frozenset(item.obligation_id for item in obligations),
            native_digest,
            payload,
        )

    def register_pending(self, plan: AdapterPlan, context: ExecutionContext) -> None:
        """Bind one started-but-blocked worker to its native plan."""
        with self._lock:
            self._pending[context.digest] = plan.native_plan_digest

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        """Consume a blocked worker registration and sign activation evidence."""
        with self._lock:
            pending = self._pending.pop(context.digest, None)
        if pending != plan.native_plan_digest:
            raise ValueError("Linux worker was not started with this native plan")
        now = time.time()
        evidence = ActivationEvidence(
            self.adapter_id,
            plan.native_plan_digest,
            context.digest,
            nonce,
            plan.obligation_ids,
            now,
            now + self._lease_s,
            "pending",
        )
        return replace(evidence, signature=self._sign(_activation_payload(evidence)))

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        """Verify worker-bound activation evidence."""
        return hmac.compare_digest(
            evidence.signature, self._sign(_activation_payload(evidence))
        )

    def _sign(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()


def _assess_path_obligation(
    obligation: EnforcementObligation,
) -> tuple[SupportLevel, str]:
    if obligation.kind is not ObligationKind.OPERATE:
        return SupportLevel.UNSUPPORTED, "path_obligation_kind_unsupported"
    if obligation.operation not in {"read", *_WRITE_OPERATIONS}:
        return SupportLevel.UNSUPPORTED, "path_operation_unsupported"
    if obligation.conditions.get("exclude_paths") or obligation.conditions.get(
        "exclude_subtrees"
    ):
        return SupportLevel.UNSUPPORTED, "path_exclusion_requires_broker"
    try:
        path = _canonical_existing_path(obligation.selector)
    except (OSError, ValueError):
        return SupportLevel.UNSUPPORTED, "path_missing_or_noncanonical"
    if not _is_supported_mount_type(path):
        return SupportLevel.UNSUPPORTED, "special_file_requires_broker"
    if path.is_dir() and not bool(obligation.conditions.get("subtree")):
        return SupportLevel.UNSUPPORTED, "exact_directory_requires_broker"
    if path.is_dir() and _nested_mount_points(path):
        return SupportLevel.UNSUPPORTED, "nested_mount_requires_separate_grants"
    return SupportLevel.EXACT, "stable_bind_mount"


def _assess_limit_obligation(
    obligation: EnforcementObligation,
) -> tuple[SupportLevel, str]:
    maximum = obligation.conditions.get("maximum")
    if type(maximum) is not int or maximum <= 0:
        return SupportLevel.UNSUPPORTED, "invalid_resource_limit"
    if obligation.selector not in _SUPPORTED_LIMITS:
        return SupportLevel.UNSUPPORTED, "resource_limit_mechanism_unsupported"
    if obligation.selector == "cpu_ms" and maximum % 1000:
        return SupportLevel.UNSUPPORTED, "rlimit_cpu_requires_whole_seconds"
    if obligation.selector == "pids" and maximum != 1:
        return SupportLevel.UNSUPPORTED, "minimal_seccomp_supports_pids_one_only"
    mechanism = {
        "address_space_bytes": "rlimit_as",
        "cpu_ms": "rlimit_cpu",
        "file_size_bytes": "rlimit_fsize_per_file",
        "nofile": "rlimit_nofile",
        "pids": "seccomp_no_process_creation",
        "tmpfs_bytes": "private_tmpfs_aggregate_size",
        "wall_ms": "supervisor_deadline_and_termination",
    }[obligation.selector]
    return SupportLevel.EXACT, mechanism


def _verified_artifact_fd(spec: LinuxToolSpec) -> tuple[int, Path]:
    """Copy verified artifact bytes into a sealed, worker-bound file."""
    directory = Path(tempfile.mkdtemp(prefix="slanggraph-artifact-"))
    directory.chmod(0o700)
    artifact = directory / "artifact.py"
    digest = hashlib.sha256()
    try:
        with spec.artifact_path.open("rb") as source, artifact.open("xb") as target:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if digest.hexdigest() != spec.artifact_digest:
            raise HostExecutionDenied("host:artifact_changed")
        artifact.chmod(0o400)
        return (
            os.open(artifact, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW),
            directory,
        )
    except BaseException:
        _remove_private_artifact(directory)
        raise


def _verified_resource_fd(path: Path) -> int:
    """Open and identity-bind one canonical host resource for a worker mount."""
    descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
        ) != (
            current.st_dev,
            current.st_ino,
            stat.S_IFMT(current.st_mode),
        ):
            raise HostExecutionDenied("host:resource_identity_changed")
        if not (stat.S_ISREG(opened.st_mode) or stat.S_ISDIR(opened.st_mode)):
            raise HostExecutionDenied("host:special_resource_unsupported")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _remove_private_artifact(directory: Path) -> None:
    artifact = directory / "artifact.py"
    if artifact.exists():
        artifact.unlink()
    directory.rmdir()


def _wall_timeout(payload: Mapping[str, Any], default: float) -> float:
    limits = payload.get("limits", {})
    if isinstance(limits, Mapping):
        value = limits.get("wall_ms")
        if isinstance(value, int) and value > 0:
            return value / 1000
    return default


def _execution_context(pid: int) -> ExecutionContext:
    status = Path(f"/proc/{pid}/status").read_text()
    fields = {
        name: value.strip()
        for line in status.splitlines()
        if ":" in line
        for name, value in (line.split(":", 1),)
    }
    if (
        fields.get("NoNewPrivs") != "1"
        or fields.get("Seccomp") != "2"
        or fields.get("Threads") != "1"
        or any(
            fields.get(name) != "0000000000000000"
            for name in ("CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm")
        )
    ):
        raise HostExecutionDenied("host:kernel_activation_state_invalid")
    credential_lines = [
        line
        for line in status.splitlines()
        if line.startswith(
            ("Uid:", "Gid:", "Cap", "NoNewPrivs:", "Seccomp:", "Threads:")
        )
    ]
    stat = Path(f"/proc/{pid}/stat").read_text().split()
    cgroup = Path(f"/proc/{pid}/cgroup").read_text().strip() or "isolated"
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    namespaces = _namespace_links(pid)
    parent_namespaces = _namespace_links(os.getpid())
    if any(namespaces[name] == parent_namespaces[name] for name in namespaces):
        raise HostExecutionDenied("host:namespace_activation_state_invalid")
    mountinfo_digest = hashlib.sha256(
        Path(f"/proc/{pid}/mountinfo").read_bytes()
    ).hexdigest()
    return ExecutionContext(
        worker_id=f"linux-worker:{pid}:{stat[21]}",
        process_identity=f"pid:{pid}:start:{stat[21]}",
        boot_id=boot_id,
        namespaces=namespaces,
        credential_digest=_digest(
            {"mountinfo_digest": mountinfo_digest, "status": credential_lines}
        ),
        cgroup_id=cgroup,
        broker_epoch="no-broker",
    )


def _namespace_links(pid: int) -> Mapping[str, str]:
    namespace_root = Path(f"/proc/{pid}/ns")
    names = ("cgroup", "ipc", "mnt", "net", "pid", "user", "uts")
    return {name: os.readlink(namespace_root / name) for name in names}


def _activation_payload(evidence: ActivationEvidence) -> str:
    return _digest(
        {
            "activated_at": evidence.activated_at,
            "adapter_id": evidence.adapter_id,
            "context_digest": evidence.context_digest,
            "expires_at": evidence.expires_at,
            "native_plan_digest": evidence.native_plan_digest,
            "nonce": evidence.nonce,
            "obligation_ids": sorted(evidence.obligation_ids),
        }
    )


def _read_fd_json(descriptor: int, timeout: float) -> Mapping[str, Any]:
    ready, _, _ = select.select([descriptor], [], [], timeout)
    if not ready:
        raise TimeoutError
    payload = os.read(descriptor, 16_384)
    if not payload or len(payload) >= 16_384:
        raise ValueError("invalid bubblewrap status")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("invalid bubblewrap status")
    return value


def _readline_json(
    process: subprocess.Popen[bytes], timeout: float
) -> Mapping[str, Any]:
    if process.stdout is None:
        raise ValueError("worker stdout is unavailable")
    ready, _, _ = select.select([process.stdout.fileno()], [], [], timeout)
    if not ready:
        raise TimeoutError
    line = process.stdout.readline(_MAX_FRAME + 1)
    if not line or len(line) > _MAX_FRAME or not line.endswith(b"\n"):
        raise ValueError("invalid worker protocol frame")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("invalid worker protocol frame")
    _validate_protocol_shape(value)
    return value


def _encode_worker_request(request: Mapping[str, Any]) -> bytes:
    encoded = (
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    if len(encoded) > _MAX_FRAME:
        raise ValueError("worker request exceeds protocol limit")
    return encoded


def _validate_protocol_shape(value: object) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > _MAX_PROTOCOL_DEPTH or nodes > _MAX_PROTOCOL_NODES:
            raise ValueError("worker response exceeds structural limits")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _confirm_worker_terminated(pid: int, start_time: str, *, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stat_path = Path(f"/proc/{pid}/stat")
        try:
            current = stat_path.read_text().split()[21]
        except (FileNotFoundError, ProcessLookupError):
            return True
        if current != start_time:
            return True
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            return True
        time.sleep(0.01)
    return False


def _sandbox_payload_pid(init_pid: int, *, timeout_s: float) -> int:
    children_path = Path(f"/proc/{init_pid}/task/{init_pid}/children")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            children = children_path.read_text().split()
        except FileNotFoundError as exc:
            raise HostExecutionDenied("host:sandbox_init_exited") from exc
        if len(children) == 1:
            return int(children[0])
        if len(children) > 1:
            raise HostExecutionDenied("host:ambiguous_worker_identity")
        time.sleep(0.01)
    raise HostExecutionDenied("host:worker_identity_timeout")


def _canonical_existing_path(value: str | Path) -> Path:
    raw = Path(value)
    if not raw.is_absolute():
        raise ValueError("sandbox paths must be absolute")
    resolved = raw.resolve(strict=True)
    if raw != resolved:
        raise ValueError("sandbox paths must be canonical and symlink-free")
    return resolved


def _is_supported_mount_type(path: Path) -> bool:
    mode = path.stat(follow_symlinks=False).st_mode
    return stat.S_ISREG(mode) or stat.S_ISDIR(mode)


def _nested_mount_points(path: Path) -> tuple[Path, ...]:
    nested: list[Path] = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise HostExecutionDenied("host:mountinfo_invalid")
        value = fields[4]
        for encoded, decoded in (
            ("\\040", " "),
            ("\\011", "\t"),
            ("\\012", "\n"),
            ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        mount = Path(value)
        if mount != path and path in mount.parents:
            nested.append(mount)
    return tuple(sorted(nested))


def _verify_bubblewrap_host(bwrap_path: str, timeout: float) -> None:
    """Fail configuration unless the installed host can create our boundary."""
    try:
        help_result = subprocess.run(
            (bwrap_path, "--help"),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        help_text = help_result.stdout + help_result.stderr
        required = {
            "--assert-userns-disabled",
            "--bind-fd",
            "--disable-userns",
            "--json-status-fd",
            "--ro-bind-fd",
        }
        if not required.issubset(help_text.split()):
            raise RuntimeError("bubblewrap lacks required file-descriptor features")
        probe = subprocess.run(
            (
                bwrap_path,
                "--unshare-all",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--disable-userns",
                "--assert-userns-disabled",
                "--clearenv",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                "/",
                "/",
                "--",
                "/usr/bin/true",
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("bubblewrap host preflight failed") from exc
    if probe.returncode != 0:
        raise RuntimeError("bubblewrap isolation is unavailable on this host")


def _missing_parent_directories(value: str) -> tuple[str, ...]:
    path = Path(value)
    parents: list[str] = []
    for parent in reversed(path.parents):
        text = os.fspath(parent)
        if text in {"/", "/usr"} or text.startswith("/usr/"):
            continue
        parents.append(text)
    if path.is_dir():
        parents.append(value)
    return tuple(dict.fromkeys(parents))


def _plain_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("expected mapping")
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: object) -> Any:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, list | tuple) and type(value) in {list, tuple}:
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping) and type(value) in {dict, MappingProxyType}:
        if any(type(key) is not str for key in value):
            raise ValueError("sandbox mappings require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    raise ValueError(f"sandbox protocol cannot encode {type(value).__name__}")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=repr
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
