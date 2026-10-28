"""Capability-minimal WASI backend for pure WebAssembly tools."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.cedar import CedarPolicyBackend
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AuthorityDomain,
    EnforcementMode,
    GrantRule,
    RuleEnforcement,
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
from langgraph.prebuilt.security.policy import MandatoryPolicyBackend
from langgraph.prebuilt.security.profile import ProfileDocument
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
)

_MAX_FRAME = 1_048_576


@dataclass(frozen=True, slots=True)
class WasiToolSpec:
    """Pinned WASI module for one tool name."""

    module_path: Path
    module_digest: str

    def __post_init__(self) -> None:
        path = self.module_path.resolve(strict=True)
        if not path.is_file() or path.suffix != ".wasm":
            raise ValueError("WASI module_path must name a .wasm file")
        if _file_digest(path) != self.module_digest:
            raise ValueError("WASI module digest does not match")
        object.__setattr__(self, "module_path", path)


class WasiSandboxExecutor:
    """Run pure WASI modules with no preopens, network, processes, or credentials.

    Modules exchange one JSON value on stdin/stdout. This deliberately small
    backend supports computation-only grants; any resource authority it cannot
    express is denied instead of being approximated by a broader preopen.
    """

    def __init__(
        self,
        profiles: ProfileDocument,
        tools: Mapping[str, WasiToolSpec],
        *,
        principal_bindings: Mapping[str, Mapping[str, object]] | None = None,
        policy_backend: MandatoryPolicyBackend | None = None,
        wasmtime_path: str | Path = "wasmtime",
        wall_timeout_s: float = 30.0,
        attestation_key: bytes | None = None,
    ) -> None:
        runtime = shutil.which(os.fspath(wasmtime_path))
        if runtime is None:
            raise RuntimeError("wasmtime is required for WASI execution")
        if wall_timeout_s <= 0:
            raise ValueError("WASI wall timeout must be positive")
        copied = dict(tools)
        if not copied:
            raise ValueError("WASI backend requires tool manifests")
        if set(copied).difference(profiles.tools):
            raise ValueError("WASI tool manifests lack profiles")
        if any(profiles.tools[name].runs != "wasi" for name in copied):
            raise ValueError("WASI tool profiles must declare 'runs wasi'")
        self.profiles = profiles
        self.tools = MappingProxyType(copied)
        self.principal_bindings = MappingProxyType(
            {
                name: MappingProxyType(dict(values))
                for name, values in (principal_bindings or {}).items()
            }
        )
        self.policy_backend = policy_backend or CedarPolicyBackend()
        self.wasmtime_path = runtime
        self.wasmtime_digest = _file_digest(Path(runtime))
        self.wall_timeout_s = wall_timeout_s
        self._key = attestation_key or secrets.token_bytes(32)
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require a pinned module for every reachable tool."""
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "WASI execution missing manifests: " + ", ".join(sorted(missing))
            )

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        """Return bounded WASI activation evidence."""
        return tuple(self._receipts)

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Execute one module after exact grant filtering and lowering."""
        spec = self.tools.get(call.tool.name)
        if spec is None:
            raise HostExecutionDenied("wasi:tool_manifest_missing")
        if _file_digest(spec.module_path) != spec.module_digest:
            raise HostExecutionDenied("wasi:module_changed")
        profile = self.profiles.principals.get(principal.user_id)
        if (
            profile is None
            or profile.roles != principal.roles
            or profile.scopes != principal.scopes
        ):
            raise HostExecutionDenied("wasi:principal_profile_mismatch")
        try:
            evaluation = self.profiles.evaluate(
                call.tool.name,
                principal.user_id,
                {**dict(call.args), **dict(call.normalized)},
                principal_bindings=self.principal_bindings,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("wasi:profile_evaluation_failed") from exc
        if evaluation.denied:
            raise HostExecutionDenied(f"wasi:dac:{evaluation.reason or 'deny'}")
        compiled = compile_grant(
            evaluation,
            principal_id=principal.user_id,
            session_id=principal.session_id,
            artifact_digest=spec.module_digest,
            call_id=call.call_id,
            normalized_intent_digest=_digest(
                {"args": call.args, "normalized": call.normalized}
            ),
            policy_digest=_digest({"stage": "pre-mac"}),
        )
        filtered = self.policy_backend.filter(
            compiled.grant, compiled.ledger, constraints
        )
        if not filtered.allowed or filtered.grant is None:
            raise HostExecutionDenied(f"wasi:{filtered.reason}")
        grant = filtered.grant
        enforcement = tuple(self._lower(rule) for rule in grant.rules)
        request = json.dumps(
            {"args": dict(call.args), "call_id": call.call_id},
            sort_keys=True,
            separators=(",", ":"),
            default=repr,
        ).encode()
        if len(request) + 1 > _MAX_FRAME:
            raise HostExecutionDenied("wasi:request_too_large")
        timeout = self._wall_timeout(grant)
        started = time.time()
        process = subprocess.Popen(
            (self.wasmtime_path, "run", os.fspath(spec.module_path)),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env={},
        )
        receipt = self._receipt(grant, process.pid, enforcement, started)
        self._receipts.append(receipt)
        try:
            stdout, _ = process.communicate(request + b"\n", timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise HostExecutionError(
                "wasi:tool_timeout",
                receipt,
                ExecutionOutcome.FAILED,
                termination_confirmed=True,
            ) from exc
        if process.returncode != 0:
            raise HostExecutionError(
                "wasi:module_failed",
                receipt,
                ExecutionOutcome.FAILED,
                termination_confirmed=True,
            )
        if len(stdout) > _MAX_FRAME or not stdout.endswith(b"\n"):
            raise HostExecutionError(
                "wasi:invalid_response",
                receipt,
                ExecutionOutcome.FAILED,
                termination_confirmed=True,
            )
        try:
            response = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HostExecutionError(
                "wasi:invalid_response",
                receipt,
                ExecutionOutcome.FAILED,
                termination_confirmed=True,
            ) from exc
        return HostExecutionResult(response, receipt)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Execute one module without blocking the event loop."""
        return await asyncio.to_thread(self.invoke, principal, call, constraints)

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        """WASI calls are synchronously reaped before any result is returned."""
        del recovery
        return True

    def _lower(self, rule: GrantRule) -> RuleEnforcement:
        if (
            rule.domain is AuthorityDomain.PROCESS
            and rule.operation == "syscall_set"
            and rule.selector == "minimal"
        ):
            return RuleEnforcement(
                rule.rule_id, SupportLevel.TIGHTENED, "wasi:no-host-syscalls"
            )
        if rule.domain is AuthorityDomain.RESOURCE_LIMIT and rule.selector == "wall_ms":
            return RuleEnforcement(
                rule.rule_id, SupportLevel.EXACT, "supervisor:timer+kill"
            )
        raise HostExecutionDenied(f"wasi:unsupported_rule:{rule.rule_id}")

    def _wall_timeout(self, grant: Any) -> float:
        timeout = self.wall_timeout_s
        for rule in grant.rules:
            if (
                rule.domain is AuthorityDomain.RESOURCE_LIMIT
                and rule.selector == "wall_ms"
            ):
                maximum = rule.conditions.get("maximum")
                if type(maximum) is not int:
                    raise HostExecutionDenied("wasi:invalid_wall_limit")
                timeout = min(timeout, maximum / 1000)
        return timeout

    def _receipt(
        self,
        grant: Any,
        pid: int,
        enforcement: tuple[RuleEnforcement, ...],
        activated_at: float,
    ) -> ActivationReceipt:
        obligations = frozenset(
            item.obligation_id for item in compile_obligations(grant)
        )
        plan_digest = _digest(
            [(item.rule_id, item.support.value, item.mechanism) for item in enforcement]
        )
        context_digest = _digest(
            {
                "module": grant.artifact_digest,
                "pid": pid,
                "runtime": self.wasmtime_digest,
            }
        )
        nonce = secrets.token_hex(16)
        signature = hmac.new(
            self._key,
            f"{plan_digest}:{context_digest}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()
        valid_until = activated_at + self.wall_timeout_s + 5
        evidence = ActivationEvidence(
            "wasi-wasmtime-v1",
            plan_digest,
            context_digest,
            nonce,
            obligations,
            activated_at,
            valid_until,
            signature,
        )
        return ActivationReceipt(
            grant.digest,
            plan_digest,
            _digest({"runtime": self.wasmtime_digest}),
            context_digest,
            nonce,
            EnforcementMode.ENFORCED,
            (evidence,),
            obligations,
            valid_until,
            enforcement,
        )


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=repr, separators=(",", ":")).encode()
    ).hexdigest()
