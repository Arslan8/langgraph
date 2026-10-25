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
from langgraph.prebuilt.security.objects import (
    DispatchRequest,
    FrameworkRequest,
    ModelInvocationRequest,
    ObjectAuthorization,
    OutputRequest,
    StateOperation,
    StateRequest,
    ToolRegistryRequest,
)
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
        analysis: Any = None,
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
        self.analysis = analysis
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
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.enforcement import (
                EnforcementAdapter,
            )

            try:
                snapshot = EnforcementAdapter(self.analysis).snapshot(principal, call)
                call = replace(call, analysis_snapshot=snapshot)
            except Exception:
                return Decision(Verdict.DENY, "analysis:unavailable")
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
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.enforcement import (
                EnforcementAdapter,
            )

            try:
                snapshot = await EnforcementAdapter(self.analysis).asnapshot(
                    principal, call
                )
                call = replace(call, analysis_snapshot=snapshot)
            except Exception:
                return Decision(Verdict.DENY, "analysis:unavailable")
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
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.enforcement import (
                EnforcementAdapter,
            )

            try:
                call = EnforcementAdapter(self.analysis).prepare(principal, call)
            except Exception:
                return Decision(Verdict.DENY, "analysis:unavailable"), call
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
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.serialization import freeze

            try:
                current = replace(
                    current,
                    args=freeze(current.args),
                    normalized=freeze(current.normalized),
                )
            except Exception:
                return Decision(Verdict.DENY, "analysis:unavailable"), current
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
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.enforcement import (
                EnforcementAdapter,
            )

            try:
                call = await EnforcementAdapter(self.analysis).aprepare(principal, call)
            except Exception:
                return Decision(Verdict.DENY, "analysis:unavailable"), call
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
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.serialization import freeze

            try:
                current = replace(
                    current,
                    args=freeze(current.args),
                    normalized=freeze(current.normalized),
                )
            except Exception:
                return Decision(Verdict.DENY, "analysis:unavailable"), current
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

    def record_object_decision(
        self,
        principal: Principal,
        request: FrameworkRequest,
        authorization: ObjectAuthorization,
    ) -> None:
        """Persist one redacted aggregate decision for a framework operation."""
        if self.observer is None:
            return
        stage, tool_name, identity = _object_audit_identity(request)
        self.observer.record(
            SecurityEvent(
                stage=stage,
                module="object_manager",
                verdict=authorization.decision.verdict,
                reason=authorization.decision.reason,
                latency_ms=0.0,
                user_id=principal.user_id,
                session_id=principal.session_id,
                tool_name=tool_name,
                call_index=0,
                args_hash=hashlib.sha256(identity).hexdigest(),
            )
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

    def object_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization:
        """Authorize and monotonically narrow one framework-object operation."""
        if isinstance(request, DispatchRequest):
            if principal is not request.parent:
                return ObjectAuthorization(
                    Decision(Verdict.DENY, "dispatch:parent_identity_mismatch"),
                    request,
                )
            if not _principal_subset(request.parent, request.child):
                return ObjectAuthorization(
                    Decision(Verdict.DENY, "dispatch:authority_growth"), request
                )
            return ObjectAuthorization(
                self.cred_transfer(request.parent, request.child), request
            )
        if isinstance(request, ToolRegistryRequest):
            return ObjectAuthorization(self._allocate_tool(request), request)
        return self._object_modules(principal, request)

    async def aobject_permission(
        self, principal: Principal, request: FrameworkRequest
    ) -> ObjectAuthorization:
        """Asynchronously authorize one framework-object operation."""
        if isinstance(request, DispatchRequest):
            if principal is not request.parent:
                return ObjectAuthorization(
                    Decision(Verdict.DENY, "dispatch:parent_identity_mismatch"),
                    request,
                )
            if not _principal_subset(request.parent, request.child):
                return ObjectAuthorization(
                    Decision(Verdict.DENY, "dispatch:authority_growth"), request
                )
            return ObjectAuthorization(
                await self.acred_transfer(request.parent, request.child), request
            )
        if isinstance(request, ToolRegistryRequest):
            return ObjectAuthorization(await self._aallocate_tool(request), request)
        return await self._aobject_modules(principal, request)

    def object_resume_permission(
        self,
        principal: Principal,
        request: FrameworkRequest,
        approval: Approval,
    ) -> ObjectAuthorization:
        """Consume one approval and run the complete object hook chain again."""
        if not record_approval(principal, approval):
            return ObjectAuthorization(
                Decision(Verdict.DENY, "approval_replay"), request
            )
        resumed = self.resume_permission(principal, approval)
        if resumed.verdict is not Verdict.ALLOW:
            return ObjectAuthorization(resumed, request)
        if isinstance(request, DispatchRequest | ToolRegistryRequest):
            return self.object_permission(principal, request)
        return self._object_modules(principal, request, approval=approval)

    async def aobject_resume_permission(
        self,
        principal: Principal,
        request: FrameworkRequest,
        approval: Approval,
    ) -> ObjectAuthorization:
        """Asynchronously consume approval and rerun the object hook chain."""
        if not record_approval(principal, approval):
            return ObjectAuthorization(
                Decision(Verdict.DENY, "approval_replay"), request
            )
        resumed = await self.aresume_permission(principal, approval)
        if resumed.verdict is not Verdict.ALLOW:
            return ObjectAuthorization(resumed, request)
        if isinstance(request, DispatchRequest | ToolRegistryRequest):
            return await self.aobject_permission(principal, request)
        return await self._aobject_modules(principal, request, approval=approval)

    def _object_modules(
        self,
        principal: Principal,
        request: StateRequest | ModelInvocationRequest | OutputRequest,
        *,
        approval: Approval | None = None,
    ) -> ObjectAuthorization:
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.objects import ObjectAdapter

            try:
                snapshot = ObjectAdapter(self.analysis).snapshot(principal, request)
                request = replace(request, analysis_snapshot=snapshot)
            except Exception:
                return ObjectAuthorization(
                    Decision(Verdict.DENY, "analysis:unavailable"), request
                )
        current: StateRequest | ModelInvocationRequest | OutputRequest = request
        constraints: list[PolicyConstraint] = []
        for module in self.modules:
            started = self._started()
            decision = self._sync_decision(
                module, partial(_object_hook, module, principal, current)
            )
            decision = self._attribute_constraints(module, decision)
            if decision.constraints:
                decision = Decision(
                    Verdict.DENY, f"object_constraints_unsupported:{module.name}"
                )
            decision = self._bind_object_escalation(
                module, principal, current, decision
            )
            if _matches_object_approval(decision, approval):
                decision = Decision(Verdict.ALLOW, f"approval:{module.name}")
            self._observe(
                principal,
                None,
                _object_stage(current),
                module.name,
                decision,
                started,
            )
            if decision.verdict in (Verdict.TRANSFORM, Verdict.REDACT):
                narrowed = _narrow_object_request(current, decision)
                if narrowed is None:
                    return ObjectAuthorization(
                        Decision(Verdict.DENY, f"module_widened:{module.name}"),
                        current,
                    )
                current = narrowed
                continue
            if decision.verdict is not Verdict.ALLOW:
                return ObjectAuthorization(decision, current)
            constraints.extend(decision.constraints)
        return ObjectAuthorization(
            Decision(Verdict.ALLOW, "stack:allow", constraints=tuple(constraints)),
            current,
        )

    async def _aobject_modules(
        self,
        principal: Principal,
        request: StateRequest | ModelInvocationRequest | OutputRequest,
        *,
        approval: Approval | None = None,
    ) -> ObjectAuthorization:
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.objects import ObjectAdapter

            try:
                snapshot = await ObjectAdapter(self.analysis).asnapshot(
                    principal, request
                )
                request = replace(request, analysis_snapshot=snapshot)
            except Exception:
                return ObjectAuthorization(
                    Decision(Verdict.DENY, "analysis:unavailable"), request
                )
        current: StateRequest | ModelInvocationRequest | OutputRequest = request
        constraints: list[PolicyConstraint] = []
        for module in self.modules:
            started = self._started()
            decision = await self._async_decision(
                module, partial(_object_hook, module, principal, current)
            )
            decision = self._attribute_constraints(module, decision)
            if decision.constraints:
                decision = Decision(
                    Verdict.DENY, f"object_constraints_unsupported:{module.name}"
                )
            decision = self._bind_object_escalation(
                module, principal, current, decision
            )
            if _matches_object_approval(decision, approval):
                decision = Decision(Verdict.ALLOW, f"approval:{module.name}")
            self._observe(
                principal,
                None,
                _object_stage(current),
                module.name,
                decision,
                started,
            )
            if decision.verdict in (Verdict.TRANSFORM, Verdict.REDACT):
                narrowed = _narrow_object_request(current, decision)
                if narrowed is None:
                    return ObjectAuthorization(
                        Decision(Verdict.DENY, f"module_widened:{module.name}"),
                        current,
                    )
                current = narrowed
                continue
            if decision.verdict is not Verdict.ALLOW:
                return ObjectAuthorization(decision, current)
            constraints.extend(decision.constraints)
        return ObjectAuthorization(
            Decision(Verdict.ALLOW, "stack:allow", constraints=tuple(constraints)),
            current,
        )

    def _allocate_tool(self, request: ToolRegistryRequest) -> Decision:
        for module in self.modules:
            started = self._started()
            future = self._executor.submit(
                module.tool_alloc_security,
                request.tool,
                request.tool.security.allocate(module.name),
            )
            try:
                result = future.result(timeout=self.policy_timeout_s)
            except FutureTimeoutError:
                future.cancel()
                decision = Decision(Verdict.DENY, f"module_timeout:{module.name}")
            except BaseException:
                decision = Decision(Verdict.DENY, f"module_error:{module.name}")
            else:
                decision = (
                    Decision(Verdict.ALLOW, f"{module.name}:allocated")
                    if result is None
                    else Decision(Verdict.DENY, f"module_error:{module.name}")
                )
            self._observe(
                Principal("__registry__", frozenset(), frozenset(), "registry"),
                None,
                "tool_registry",
                module.name,
                decision,
                started,
            )
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "registry:allocated")

    async def _aallocate_tool(self, request: ToolRegistryRequest) -> Decision:
        for module in self.modules:
            started = self._started()
            loop = asyncio.get_running_loop()
            hook = partial(
                module.tool_alloc_security,
                request.tool,
                request.tool.security.allocate(module.name),
            )
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, hook), self.policy_timeout_s
                )
                if inspect.isawaitable(result):
                    result = await asyncio.wait_for(result, self.policy_timeout_s)
            except TimeoutError:
                decision = Decision(Verdict.DENY, f"module_timeout:{module.name}")
            except BaseException:
                decision = Decision(Verdict.DENY, f"module_error:{module.name}")
            else:
                decision = (
                    Decision(Verdict.ALLOW, f"{module.name}:allocated")
                    if result is None
                    else Decision(Verdict.DENY, f"module_error:{module.name}")
                )
            self._observe(
                Principal("__registry__", frozenset(), frozenset(), "registry"),
                None,
                "tool_registry",
                module.name,
                decision,
                started,
            )
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "registry:allocated")

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
        failures: list[Decision] = []
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
                failures.append(decision)
        return failures[0] if failures else Decision(Verdict.ALLOW, "post:complete")

    async def apost(
        self, principal: Principal, call: ToolCall, result: Any
    ) -> Decision:
        """Asynchronously run every post-execution hook."""
        failures: list[Decision] = []
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
                failures.append(decision)
        return failures[0] if failures else Decision(Verdict.ALLOW, "post:complete")

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
            "execution_binding": dict(call.execution_binding),
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

    def _bind_object_escalation(
        self,
        module: SecurityModule,
        principal: Principal,
        request: StateRequest | ModelInvocationRequest | OutputRequest,
        decision: Decision,
    ) -> Decision:
        escalation = decision.escalation
        if decision.verdict is not Verdict.ESCALATE or escalation is None:
            return decision
        encoded = json.dumps(
            {
                "module": module.name,
                "principal": principal.user_id,
                "request": repr(request),
                "session": principal.session_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return replace(
            decision,
            escalation=replace(
                escalation,
                subject_digest=hashlib.sha256(encoded).hexdigest(),
                expires_at=time.time() + self.approval_ttl_s,
            ),
        )

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


def _object_audit_identity(
    request: FrameworkRequest,
) -> tuple[str, str, bytes]:
    """Return a content-free audit identity for one framework request."""
    if isinstance(request, DispatchRequest):
        payload = {
            "child": (request.child.user_id, request.child.session_id),
            "dispatch_id": request.dispatch_id,
            "identity_transfer": request.parent is request.child,
            "kind": request.kind.value,
            "parent": (request.parent.user_id, request.parent.session_id),
        }
        stage = "dispatch"
        tool_name = "__framework__"
    elif isinstance(request, ToolRegistryRequest):
        payload = {
            "dynamic": request.dynamic,
            "override": request.override,
            "tool": request.tool.name,
        }
        stage = "tool_registry"
        tool_name = request.tool.name
    elif isinstance(request, StateRequest):
        payload = {
            "operation": request.operation.value,
            "owner": request.owner_id,
            "resource": request.resource,
            "tool": request.tool_name,
        }
        stage = "state"
        tool_name = request.tool_name or "__framework__"
    elif isinstance(request, ModelInvocationRequest):
        payload = {
            "context": [item.name for item in request.context],
            "invocation_id": request.invocation_id,
            "model": request.model,
        }
        stage = "model_invoke"
        tool_name = "__model__"
    else:
        payload = {
            "destination": request.destination,
            "output_id": request.output_id,
        }
        stage = "output_emit"
        tool_name = "__output__"
    return (
        stage,
        tool_name,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )


def _normalized_no_broader(
    original: Mapping[str, Any], transformed: Mapping[str, Any]
) -> bool:
    """Require identical normalized authority absent a semantic attenuator.

    Collection or string structure does not define an authority ordering. A
    module may rewrite non-resource arguments, but changing a normalized
    resource requires a framework-owned semantic grant transformation instead.
    """
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


def _matches_object_approval(decision: Decision, approval: Approval | None) -> bool:
    escalation = decision.escalation
    return bool(
        approval is not None
        and approval.approved
        and decision.verdict is Verdict.ESCALATE
        and escalation is not None
        and escalation.request_id == approval.request_id
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


def _principal_subset(parent: Principal, child: Principal) -> bool:
    return (
        parent.user_id == child.user_id
        and parent.session_id == child.session_id
        and child.roles.issubset(parent.roles)
        and child.scopes.issubset(parent.scopes)
        and child.delegated_by in (None, parent.user_id)
    )


def _object_hook(
    module: SecurityModule,
    principal: Principal,
    request: StateRequest | ModelInvocationRequest | OutputRequest,
) -> Decision:
    if isinstance(request, StateRequest):
        if request.operation is StateOperation.RESTORE:
            return module.state_restore(principal, request)
        if request.operation in (
            StateOperation.WRITE,
            StateOperation.STORE_WRITE,
            StateOperation.CHECKPOINT_WRITE,
        ):
            return module.state_write(principal, request)
        return module.state_read(principal, request)
    if isinstance(request, ModelInvocationRequest):
        return module.model_invoke(principal, request)
    return module.output_emit(principal, request)


def _object_stage(
    request: StateRequest | ModelInvocationRequest | OutputRequest,
) -> str:
    if isinstance(request, StateRequest):
        return f"state_{request.operation.value}"
    if isinstance(request, ModelInvocationRequest):
        return "model_invoke"
    return "output_emit"


def _narrow_object_request(
    request: StateRequest | ModelInvocationRequest | OutputRequest,
    decision: Decision,
) -> StateRequest | ModelInvocationRequest | OutputRequest | None:
    values = decision.new_args
    if values is None:
        return None
    if isinstance(request, StateRequest):
        if set(values) != {"value"}:
            return None
        return request.replace_value(values["value"])
    if isinstance(request, ModelInvocationRequest):
        if set(values) != {"context"}:
            return None
        proposed = values["context"]
        if not isinstance(proposed, (tuple, list)) or not all(
            item in request.context for item in proposed
        ):
            return None
        return replace(request, context=tuple(proposed))
    if set(values) not in ({"content"}, {"content", "labels"}):
        return None
    labels = values.get("labels", request.labels)
    if (
        not isinstance(labels, type(request.labels))
        or not labels.confidentiality.issubset(request.labels.confidentiality)
        or labels.integrity != request.labels.integrity
    ):
        return None
    return replace(request, content=values["content"], labels=labels)
