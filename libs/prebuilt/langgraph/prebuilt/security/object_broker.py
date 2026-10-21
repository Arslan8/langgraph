"""Open-class capabilities brokered outside a Landlock/seccomp worker.

Adapters are trusted semantic implementations. Workers receive only a channel
bound to their invocation, never adapters or resource credentials.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.broker import (
    BrokerAuditRecord,
    CredentialBroker,
    SpawnRecord,
    broker_request,
)
from langgraph.prebuilt.security.enforcement import (
    ActivationReceipt,
    AuthorityDomain,
    Grant,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.landlock import LandlockSandboxExecutor
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectClass,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.types import Principal, ToolCall

Handler = Callable[[ObjectGrantLine, Mapping[str, Any]], Any]


def _service(class_name: str, selector: str) -> str:
    return json.dumps([class_name, selector], separators=(",", ":"))


def object_request(
    class_name: str,
    operation: str,
    selector: str,
    payload: Mapping[str, Any] | None = None,
) -> Any:
    """Request an exact capability over the inherited worker channel."""
    return broker_request(_service(class_name, selector), operation, payload)


class _ObjectBroker(CredentialBroker):
    """Reuse bounded spawn-bound transport without credential issuance."""

    def __init__(
        self, grant: ObjectGrant, handlers: Mapping[tuple[str, str], Handler]
    ) -> None:
        self.grant = grant
        self.handlers = handlers
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()

    def _handle_frame(
        self, frame: bytes, spawn: SpawnRecord, grant: Grant
    ) -> Mapping[str, Any]:
        if len(frame) > 1_048_576 or not frame.endswith(b"\n"):
            return {"status": "denied", "error": "broker:invalid_frame"}
        try:
            request = json.loads(frame)
            if not isinstance(request, dict) or set(request) != {
                "service",
                "operation",
                "payload",
            }:
                raise ValueError("invalid request")
            service, operation, payload = (
                request["service"],
                request["operation"],
                request["payload"],
            )
            if (
                not isinstance(service, str)
                or not isinstance(operation, str)
                or not isinstance(payload, dict)
            ):
                raise ValueError("invalid fields")
        except (ValueError, UnicodeError, RecursionError):
            return {"status": "denied", "error": "broker:invalid_request"}
        active = {
            rule.rule_id
            for rule in grant.rules
            if rule.domain is AuthorityDomain.SERVICE
            and rule.selector == service
            and rule.operation == operation
        }
        lines = [
            line
            for line in self.grant.lines
            if line.line_id in active
            and _service(line.class_name, line.selector) == service
            and line.operation == operation
        ]
        if not lines:
            self._record(spawn, service, operation, "", False, "not_granted")
            return {"status": "denied", "error": "broker:not_granted"}
        line = lines[0]
        try:
            result = self.handlers[(line.class_name, line.operation)](
                line, MappingProxyType(payload)
            )
        except Exception:
            self._record(
                spawn, service, operation, line.line_id, False, "adapter_failure"
            )
            return {"status": "denied", "error": "broker:adapter_failure"}
        self._record(
            spawn, service, operation, line.line_id, True, "exact_object_grant"
        )
        return {"status": "ok", "result": result}


class _ObjectWorker(LandlockSandboxExecutor):
    def __init__(self, object_grant: ObjectGrant, *args: Any, **kwargs: Any) -> None:
        self.object_grant = object_grant
        super().__init__(*args, **kwargs)

    def _compile_grant(
        self, principal: Principal, call: ToolCall, spec: Any, private_tmp: Path
    ) -> tuple[Grant, RequirementLedger]:
        obj = self.object_grant
        rules = tuple(
            GrantRule(
                line.line_id,
                AuthorityDomain.SERVICE,
                line.operation,
                _service(line.class_name, line.selector),
                requirement=line.requirement,
            )
            for line in obj.lines
        )
        rules += self._baseline_rules(spec, private_tmp, enable_broker=bool(obj.lines))
        rules += (
            GrantRule(
                "runtime:syscalls",
                AuthorityDomain.PROCESS,
                "syscall_set",
                "minimal",
                baseline=True,
            ),
        )
        grant = Grant(
            principal.user_id,
            principal.session_id,
            call.tool.name,
            spec.artifact_digest,
            call.call_id,
            hashlib.sha256(
                json.dumps(dict(call.args), sort_keys=True).encode()
            ).hexdigest(),
            obj.digest,
            rules,
        )
        ledger = RequirementLedger(
            tuple(
                RequirementEntry(
                    rule.rule_id, rule.requirement, frozenset({rule.rule_id})
                )
                for rule in rules
            )
        )
        return grant, ledger


class ObjectBrokerDispatcher:
    """Execute object grants in Linux workers with operator-owned adapters.

    Adapters must use the supplied line's selector and operation, validate
    payloads, and bound their I/O. Runtime roots are readable trusted code;
    they must not contain secrets. Only broker classes are supported; waivers
    are refused. Kernel confinement must activate before any tool import.
    """

    enforcer_id = "object-broker-landlock-v1"

    def __init__(
        self,
        tools: Mapping[str, LinuxToolSpec],
        handlers: Mapping[tuple[str, str], Handler],
        *,
        runtime_roots: Sequence[str | Path],
        wall_timeout_s: float = 30.0,
    ) -> None:
        self.tools = MappingProxyType(dict(tools))
        self.handlers = MappingProxyType(dict(handlers))
        self.runtime_roots = tuple(runtime_roots)
        self.wall_timeout_s = wall_timeout_s
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()

    def audit_records(self) -> tuple[BrokerAuditRecord, ...]:
        """Return bounded broker decisions bound to worker/grant identities."""
        with self._lock:
            return tuple(self._audit)

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        return (
            object_class.enforced_by is EnforcementKind.BROKER
            and line.enforcer is EnforcementKind.BROKER
            and (line.class_name, line.operation) in self.handlers
        )

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
        if (
            grant.principal_id != principal.user_id
            or grant.tool_name != call.tool.name
            or grant.call_id != call.call_id
            or grant.enforcement_waivers
        ):
            raise HostExecutionDenied("object_broker:grant_binding")
        if call.tool.name not in self.tools or any(
            line.enforcer is not EnforcementKind.BROKER
            or (line.class_name, line.operation) not in self.handlers
            for line in grant.lines
        ):
            raise HostExecutionDenied("object_broker:unsupported")
        profiles = parse_profiles(
            f"tool {call.tool.name} {{\n owner broker\n runs linux\n syscalls @minimal\n}}"
        )
        broker = _ObjectBroker(grant, self.handlers)
        worker = _ObjectWorker(
            grant,
            profiles,
            {call.tool.name: self.tools[call.tool.name]},
            runtime_roots=self.runtime_roots,
            policy_backend=TypedPolicyBackend(),
            credential_broker=broker,
            default_wall_timeout_s=self.wall_timeout_s,
        )
        try:
            result = worker._invoke(principal, call, (), asynchronous=asynchronous)
        except HostExecutionError as exc:
            exc.receipt = self._object_receipt(exc.receipt, grant)
            raise
        finally:
            with self._lock:
                self._audit.extend(broker.audit_records())
        return HostExecutionResult(
            result.value, self._object_receipt(result.receipt, grant)
        )

    @staticmethod
    def _object_receipt(
        receipt: ActivationReceipt, grant: ObjectGrant
    ) -> ActivationReceipt:
        ids = {line.line_id for line in grant.lines}
        # Kernel evidence remains bound to the lower plan, whose policy digest
        # includes the exact object grant. Expose only object lines to the host.
        return replace(
            receipt,
            grant_digest=grant.digest,
            rule_enforcement=tuple(
                item for item in receipt.rule_enforcement if item.rule_id in ids
            ),
        )

    async def ainvoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        return await asyncio.to_thread(
            self._invoke, principal, call, grant, asynchronous=True
        )

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        return False
