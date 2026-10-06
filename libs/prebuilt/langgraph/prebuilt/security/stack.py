"""Restrictive security-module composition for tool calls."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import replace
from functools import partial
from time import perf_counter
from typing import Any, cast

from langgraph.prebuilt.security.dac import dac_check
from langgraph.prebuilt.security.descriptor import normalize_resource
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.observability import (
    SecurityEvent,
    SecurityObserver,
    compose_observer,
    hash_args,
)
from langgraph.prebuilt.security.types import (
    Approval,
    AuditSink,
    Decision,
    EscalationRequest,
    ExecutionOutcome,
    ForbidCombination,
    ForbidConstraint,
    PolicyConstraint,
    Principal,
    Slot,
    ToolCall,
    Verdict,
)


class CapModule(SecurityModule):
    """Mandatory capability module that prevents scope growth."""

    name = "cap"

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Require the tool's declared scopes as a defense-in-depth check."""
        if not call.tool.dac.required_scopes.issubset(principal.scopes):
            return Decision(Verdict.DENY, "cap:scope")
        return Decision(Verdict.ALLOW, "cap:allow")

    def cred_transfer(
        self, parent: Principal, child: Principal, slot: Slot
    ) -> Decision:
        """Reject delegation that adds authority absent from the parent."""
        if not child.scopes.issubset(parent.scopes):
            return Decision(Verdict.DENY, "cap:scope_growth")
        return Decision(Verdict.ALLOW, "cap:allow")

    def resume_permission(self, principal: Principal, approval: Approval) -> Decision:
        """Treat human rejection as restrictive policy input."""
        if not approval.approved:
            return Decision(Verdict.DENY, "cap:approval_rejected")
        return Decision(Verdict.ALLOW, "cap:approval")


class SecurityStack:
    """Run DAC and independent security modules with restrictive semantics."""

    def __init__(
        self,
        modules: Sequence[SecurityModule] = (),
        *,
        policy_timeout_s: float = 2.0,
        observer: SecurityObserver | None = None,
        audit_sink: AuditSink | None = None,
        approval_ttl_s: float = 300.0,
    ) -> None:
        if policy_timeout_s <= 0:
            raise ValueError("policy_timeout_s must be positive")
        if approval_ttl_s <= 0:
            raise ValueError("approval_ttl_s must be positive")
        if any(module.name == "cap" for module in modules):
            raise ValueError("cap is framework-managed and cannot be registered")
        names = [module.name for module in modules]
        if any(not name for name in names) or len(names) != len(set(names)):
            raise ValueError("security module names must be unique and non-empty")
        self.modules = (CapModule(), *modules)
        self.policy_timeout_s = policy_timeout_s
        self.approval_ttl_s = approval_ttl_s
        self.observer = compose_observer(observer, audit_sink)
        self.audit_events = audit_sink is not None
        self._executor = ThreadPoolExecutor(
            max_workers=max(4, len(self.modules)),
            thread_name_prefix="slanggraph-policy",
        )

    def close(self) -> None:
        """Cancel queued policy work and release executor resources."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    def permission(
        self,
        principal: Principal,
        call: ToolCall,
        *,
        approval: Approval | None = None,
    ) -> Decision:
        """Run DAC first, then stop on the first module objection."""
        started = self._started()
        author = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "permission", "dac", author, started)
        if author.verdict is not Verdict.ALLOW:
            return author
        constraints: list[PolicyConstraint] = []
        for module in self.modules:
            started = self._started()
            decision = self._sync_decision(
                module, partial(module.tool_call_permission, principal, call)
            )
            decision = self._bind_escalation(module, principal, call, decision)
            decision = self._attribute_constraints(module, decision)
            if _matches_approval(decision, call, approval):
                decision = Decision(Verdict.ALLOW, f"approval:{module.name}")
            self._observe(principal, call, "permission", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
            constraints.extend(decision.constraints)
        return Decision(Verdict.ALLOW, "stack:allow", constraints=tuple(constraints))

    async def apermission(
        self,
        principal: Principal,
        call: ToolCall,
        *,
        approval: Approval | None = None,
    ) -> Decision:
        """Asynchronously run DAC and module permission hooks."""
        started = self._started()
        author = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "permission", "dac", author, started)
        if author.verdict is not Verdict.ALLOW:
            return author
        constraints: list[PolicyConstraint] = []
        for module in self.modules:
            started = self._started()
            decision = await self._async_decision(
                module, partial(module.tool_call_permission, principal, call)
            )
            decision = self._bind_escalation(module, principal, call, decision)
            decision = self._attribute_constraints(module, decision)
            if _matches_approval(decision, call, approval):
                decision = Decision(Verdict.ALLOW, f"approval:{module.name}")
            self._observe(principal, call, "permission", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
            constraints.extend(decision.constraints)
        return Decision(Verdict.ALLOW, "stack:allow", constraints=tuple(constraints))

    def prepare(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolCall]:
        """Apply ordered argument narrowing and re-run DAC on the final call."""
        started = self._started()
        initial = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "prepare", "dac_initial", initial, started)
        if initial.verdict is not Verdict.ALLOW:
            return initial, call
        current = call
        for module in self.modules:
            if type(module).tool_call_prepare is SecurityModule.tool_call_prepare:
                continue
            started = self._started()
            decision = self._sync_decision(
                module,
                partial(module.tool_call_prepare, principal, current),
            )
            self._observe(principal, current, "prepare", module.name, decision, started)
            if decision.verdict is Verdict.TRANSFORM:
                transformed = _replace_call_args(current, decision.new_args or {})
                if not _normalized_no_broader(
                    current.normalized, transformed.normalized
                ):
                    return (
                        Decision(Verdict.DENY, f"prepare:widened:{module.name}"),
                        current,
                    )
                current = transformed
                continue
            if decision.verdict is not Verdict.ALLOW:
                return decision, current
        started = self._started()
        final = dac_check(principal, current.tool, current.normalized)
        self._observe(principal, current, "prepare", "dac_final", final, started)
        if final.verdict is not Verdict.ALLOW:
            return Decision(Verdict.DENY, f"prepare:{final.reason}"), current
        return Decision(Verdict.ALLOW, "prepare:allow"), current

    async def aprepare(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolCall]:
        """Asynchronously apply ordered narrowing and final DAC validation."""
        started = self._started()
        initial = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "prepare", "dac_initial", initial, started)
        if initial.verdict is not Verdict.ALLOW:
            return initial, call
        current = call
        for module in self.modules:
            if type(module).tool_call_prepare is SecurityModule.tool_call_prepare:
                continue
            started = self._started()
            decision = await self._async_decision(
                module,
                partial(module.tool_call_prepare, principal, current),
            )
            self._observe(principal, current, "prepare", module.name, decision, started)
            if decision.verdict is Verdict.TRANSFORM:
                transformed = _replace_call_args(current, decision.new_args or {})
                if not _normalized_no_broader(
                    current.normalized, transformed.normalized
                ):
                    return (
                        Decision(Verdict.DENY, f"prepare:widened:{module.name}"),
                        current,
                    )
                current = transformed
                continue
            if decision.verdict is not Verdict.ALLOW:
                return decision, current
        started = self._started()
        final = dac_check(principal, current.tool, current.normalized)
        self._observe(principal, current, "prepare", "dac_final", final, started)
        if final.verdict is not Verdict.ALLOW:
            return Decision(Verdict.DENY, f"prepare:{final.reason}"), current
        return Decision(Verdict.ALLOW, "prepare:allow"), current

    def cred_transfer(self, parent: Principal, child: Principal) -> Decision:
        """Run every module's restrictive delegation hook."""
        return self._restrictive_sync(
            lambda module: module.cred_transfer(
                parent, child, child.security.allocate(module.name)
            ),
            principal=child,
            stage="cred_transfer",
        )

    async def acred_transfer(self, parent: Principal, child: Principal) -> Decision:
        """Asynchronously run restrictive delegation hooks."""
        return await self._restrictive_async(
            lambda module: module.cred_transfer(
                parent, child, child.security.allocate(module.name)
            ),
            principal=child,
            stage="cred_transfer",
        )

    def resume_permission(self, principal: Principal, approval: Approval) -> Decision:
        """Run every module after a human approval response."""
        return self._restrictive_sync(
            lambda module: module.resume_permission(principal, approval),
            principal=principal,
            stage="resume",
        )

    async def aresume_permission(
        self, principal: Principal, approval: Approval
    ) -> Decision:
        """Asynchronously run every post-approval hook."""
        return await self._restrictive_async(
            lambda module: module.resume_permission(principal, approval),
            principal=principal,
            stage="resume",
        )

    def post(self, principal: Principal, call: ToolCall, result: Any) -> Decision:
        """Run every post hook; failures are reported but cannot alter the result."""
        for module in self.modules:
            if type(module).tool_call_post is SecurityModule.tool_call_post:
                continue
            started = self._started()
            future = self._executor.submit(
                module.tool_call_post,
                principal,
                call,
                result,
                call.tool.security.allocate(module.name),
            )
            try:
                hook_result = future.result(timeout=self.policy_timeout_s)
            except FutureTimeoutError:
                future.cancel()
                decision = Decision(Verdict.DENY, f"module_timeout:{module.name}")
            except BaseException:
                decision = Decision(Verdict.DENY, f"module_error:{module.name}")
            else:
                decision = (
                    Decision(Verdict.ALLOW, f"{module.name}:complete")
                    if hook_result is None
                    else Decision(Verdict.DENY, f"module_error:{module.name}")
                )
            self._observe(principal, call, "post", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "post:complete")

    async def apost(
        self, principal: Principal, call: ToolCall, result: Any
    ) -> Decision:
        """Asynchronously run every post-execution hook."""
        for module in self.modules:
            if type(module).tool_call_post is SecurityModule.tool_call_post:
                continue
            started = self._started()
            loop = asyncio.get_running_loop()
            hook = cast(
                Callable[[], Any],
                partial(
                    module.tool_call_post,
                    principal,
                    call,
                    result,
                    call.tool.security.allocate(module.name),
                ),
            )
            try:
                hook_result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, hook), self.policy_timeout_s
                )
                if inspect.isawaitable(hook_result):
                    hook_result = await asyncio.wait_for(
                        hook_result, self.policy_timeout_s
                    )
            except TimeoutError:
                decision = Decision(Verdict.DENY, f"module_timeout:{module.name}")
            except BaseException:
                decision = Decision(Verdict.DENY, f"module_error:{module.name}")
            else:
                decision = (
                    Decision(Verdict.ALLOW, f"{module.name}:complete")
                    if hook_result is None
                    else Decision(Verdict.DENY, f"module_error:{module.name}")
                )
            self._observe(principal, call, "post", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "post:complete")

    def record_framework_event(
        self,
        principal: Principal,
        call: ToolCall,
        stage: str,
        decision: Decision,
        *,
        outcome: ExecutionOutcome | None = None,
    ) -> None:
        """Persist a framework execution-boundary event through the audit path."""
        self._observe(
            principal,
            call,
            stage,
            "framework",
            decision,
            self._started(),
            outcome=outcome,
        )

    def _restrictive_sync(
        self,
        hook: Callable[[SecurityModule], Any],
        *,
        principal: Principal,
        stage: str,
    ) -> Decision:
        for module in self.modules:
            started = self._started()
            decision = self._sync_decision(module, partial(hook, module))
            self._observe(principal, None, stage, module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    async def _restrictive_async(
        self,
        hook: Callable[[SecurityModule], Any],
        *,
        principal: Principal,
        stage: str,
    ) -> Decision:
        for module in self.modules:
            started = self._started()
            decision = await self._async_decision(module, partial(hook, module))
            self._observe(principal, None, stage, module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    def _started(self) -> float | None:
        return perf_counter() if self.observer is not None else None

    def _observe(
        self,
        principal: Principal,
        call: ToolCall | None,
        stage: str,
        module: str,
        decision: Decision,
        started: float | None,
        *,
        outcome: ExecutionOutcome | None = None,
    ) -> None:
        if self.observer is None or started is None:
            return
        self.observer.record(
            SecurityEvent(
                stage=stage,
                module=module,
                verdict=decision.verdict,
                reason=decision.reason,
                latency_ms=(perf_counter() - started) * 1000,
                user_id=principal.user_id,
                session_id=principal.session_id,
                tool_name=call.tool.name if call is not None else None,
                call_index=call.call_index if call is not None else None,
                args_hash=hash_args(call.args) if call is not None else "",
                outcome=outcome,
            )
        )

    def _sync_decision(
        self, module: SecurityModule, hook: Callable[[], Any]
    ) -> Decision:
        if isinstance(module, CapModule):
            result = hook()
            if not isinstance(result, Decision):
                return Decision(Verdict.DENY, "module_error:cap")
            return result
        future = self._executor.submit(hook)
        try:
            result = future.result(timeout=self.policy_timeout_s)
        except FutureTimeoutError:
            future.cancel()
            return Decision(Verdict.DENY, f"module_timeout:{module.name}")
        except BaseException:
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        if not isinstance(result, Decision):
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        return result

    def _bind_escalation(
        self,
        module: SecurityModule,
        principal: Principal,
        call: ToolCall,
        decision: Decision,
    ) -> Decision:
        escalation = decision.escalation
        if decision.verdict is not Verdict.ESCALATE or escalation is None:
            return decision
        payload = {
            "args": dict(call.args),
            "call_id": call.call_id,
            "delegated_by": principal.delegated_by,
            "module": module.name,
            "normalized": dict(call.normalized),
            "roles": sorted(principal.roles),
            "scopes": sorted(principal.scopes),
            "session_id": principal.session_id,
            "tool": call.tool.name,
            "user_id": principal.user_id,
        }
        encoded = json.dumps(
            payload, sort_keys=True, default=repr, separators=(",", ":")
        ).encode()
        bound = replace(
            escalation,
            subject_digest=hashlib.sha256(encoded).hexdigest(),
            expires_at=time.time() + self.approval_ttl_s,
        )
        return replace(decision, escalation=bound)

    def _attribute_constraints(
        self, module: SecurityModule, decision: Decision
    ) -> Decision:
        """Bind typed restrictions to their TCB module and reject spoofing."""
        if not decision.constraints:
            return decision
        attributed: list[PolicyConstraint] = []
        for constraint in decision.constraints:
            if not isinstance(constraint, ForbidConstraint | ForbidCombination):
                return Decision(Verdict.DENY, f"module_error:{module.name}")
            if constraint.module:
                return Decision(Verdict.DENY, f"module_error:{module.name}")
            attributed.append(replace(constraint, module=module.name))
        return replace(decision, constraints=tuple(attributed))

    async def _async_decision(
        self, module: SecurityModule, hook: Callable[[], Any]
    ) -> Decision:
        if isinstance(module, CapModule):
            result = hook()
            if not isinstance(result, Decision):
                return Decision(Verdict.DENY, "module_error:cap")
            return result
        try:
            if inspect.iscoroutinefunction(hook):
                result = await asyncio.wait_for(hook(), self.policy_timeout_s)
            else:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, hook), self.policy_timeout_s
                )
                if inspect.isawaitable(result):
                    result = await asyncio.wait_for(result, self.policy_timeout_s)
        except TimeoutError:
            return Decision(Verdict.DENY, f"module_timeout:{module.name}")
        except BaseException:
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        if not isinstance(result, Decision):
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        return result


def record_approval(principal: Principal, approval: Approval) -> bool:
    """Atomically record one approval and reject reuse of its request ID."""
    slot = principal.security.allocate("cap")
    return slot.put_if_absent(f"approval:{approval.request_id}", approval)


def _normalized_no_broader(
    original: Mapping[str, Any], transformed: Mapping[str, Any]
) -> bool:
    """Conservatively require transformed security resources to be subsets."""
    if not transformed.keys() <= original.keys():
        return False
    return all(
        _value_no_broader(original[key], value) for key, value in transformed.items()
    )


def _value_no_broader(original: Any, transformed: Any) -> bool:
    if isinstance(original, Mapping) and isinstance(transformed, Mapping):
        return _normalized_no_broader(original, transformed)
    if isinstance(original, set | frozenset) and isinstance(
        transformed, set | frozenset
    ):
        return transformed <= original
    return bool(transformed == original)


def coerce_approval(response: Any, escalation: EscalationRequest) -> Approval:
    """Bind an interrupt response to the framework-generated approval subject."""
    request_id = escalation.request_id
    subject_digest = escalation.subject_digest
    if isinstance(response, Approval):
        if response.request_id != request_id:
            return Approval(
                request_id,
                False,
                "framework",
                "request_id_mismatch",
                subject_digest,
            )
        if response.subject_digest not in ("", subject_digest):
            return Approval(
                request_id,
                False,
                "framework",
                "subject_digest_mismatch",
                subject_digest,
            )
        return replace(response, subject_digest=subject_digest)
    if isinstance(response, bool):
        return Approval(request_id, response, "human", subject_digest=subject_digest)
    if isinstance(response, Mapping):
        response_id = str(response.get("request_id", request_id))
        if response_id != request_id:
            return Approval(
                request_id,
                False,
                "framework",
                "request_id_mismatch",
                subject_digest,
            )
        response_digest = str(response.get("subject_digest", subject_digest))
        if response_digest != subject_digest:
            return Approval(
                request_id,
                False,
                "framework",
                "subject_digest_mismatch",
                subject_digest,
            )
        return Approval(
            request_id,
            response.get("approved") is True,
            str(response.get("approver", "human")),
            str(response.get("reason", "")),
            subject_digest,
        )
    return Approval(
        request_id,
        False,
        "framework",
        "invalid_response",
        subject_digest,
    )


def _matches_approval(
    decision: Decision, call: ToolCall, approval: Approval | None
) -> bool:
    escalation = decision.escalation
    return bool(
        approval is not None
        and approval.approved
        and decision.verdict is Verdict.ESCALATE
        and escalation is not None
        and escalation.request_id == approval.request_id
        and escalation.call_id == call.call_id
        and escalation.tool_name == call.tool.name
        and bool(escalation.subject_digest)
        and approval.subject_digest == escalation.subject_digest
        and (escalation.expires_at is None or time.time() <= escalation.expires_at)
    )


def _replace_call_args(call: ToolCall, args: Mapping[str, Any]) -> ToolCall:
    normalized: dict[str, Any] = {}
    for resource in call.tool.resources:
        if resource.arg not in args:
            continue
        value = normalize_resource(resource, args[resource.arg])
        normalized[resource.arg] = value
        if resource.normalizer in {"domain", "email_domain"}:
            normalized[f"{resource.arg}_domain"] = value
        elif resource.normalizer == "sql_statement_kind":
            normalized[f"{resource.arg}_statement_kind"] = value
        elif resource.normalizer == "shell_argv0":
            normalized[f"{resource.arg}_argv0"] = value
    return replace(call, args=args, normalized=normalized)
