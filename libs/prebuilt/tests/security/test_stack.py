"""Tests for restrictive security-stack composition."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

import pytest
from hypothesis import given
from hypothesis import strategies as st

from langgraph.prebuilt.security import (
    Approval,
    Decision,
    Effect,
    EscalationRequest,
    ForbidConstraint,
    MemorySecurityObserver,
    Principal,
    ResourceArg,
    RulePredicate,
    SecurityModule,
    SecurityStack,
    Tool,
    ToolCall,
    ToolDac,
    Verdict,
)
from langgraph.prebuilt.security.stack import _matches_approval, _replace_call_args


def _principal(scopes: Sequence[str] = ("fs:read",)) -> Principal:
    return Principal("alice", frozenset({"analyst"}), frozenset(scopes), "session")


def _call(*, allowed_path: str = "/safe") -> ToolCall:
    tool = Tool(
        "read_file",
        ToolDac(
            "analyst",
            {"analyst": "x", "*": "-"},
            frozenset({"fs:read"}),
            {"path": {allowed_path: "x", "*": "-"}},
        ),
        frozenset({Effect.READ}),
        (ResourceArg("path", "path", "realpath"),),
    )
    return ToolCall(tool, {"path": allowed_path}, {"path": allowed_path}, "call", 0)


class FixedModule(SecurityModule):
    """Test module returning a configured permission verdict."""

    def __init__(self, name: str, decision: Decision) -> None:
        self.name = name
        self.decision = decision
        self.calls = 0

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        self.calls += 1
        return self.decision


def test_dac_denial_short_circuits_modules() -> None:
    """MAC hooks cannot observe or override an author-DAC denial."""
    module = FixedModule("allow_all", Decision(Verdict.ALLOW, "allow"))
    stack = SecurityStack([module])
    try:
        decision = stack.permission(_principal(scopes=()), _call())
    finally:
        stack.close()

    assert decision.reason == "dac:scope"
    assert module.calls == 0


@pytest.mark.parametrize("reverse", [False, True])
def test_module_order_cannot_turn_deny_into_allow(reverse: bool) -> None:
    """A permissive module cannot override a strict module in either order."""
    modules = [
        FixedModule("permissive", Decision(Verdict.ALLOW, "allow")),
        FixedModule("strict", Decision(Verdict.DENY, "strict")),
    ]
    stack = SecurityStack(list(reversed(modules)) if reverse else modules)
    try:
        decision = stack.permission(_principal(), _call())
    finally:
        stack.close()
    assert decision == Decision(Verdict.DENY, "strict")


def test_permission_attributes_and_accumulates_typed_constraints() -> None:
    """Allow means no objection while retaining every module restriction."""
    first = ForbidConstraint("one", RulePredicate(domain="network"), "offline")
    second = ForbidConstraint("two", RulePredicate(domain="process"), "no_exec")
    stack = SecurityStack(
        [
            FixedModule("network", Decision(Verdict.ALLOW, "ok", constraints=(first,))),
            FixedModule(
                "process", Decision(Verdict.ALLOW, "ok", constraints=(second,))
            ),
        ]
    )
    try:
        decision = stack.permission(_principal(), _call())
    finally:
        stack.close()

    assert decision.verdict is Verdict.ALLOW
    assert [(item.module, item.constraint_id) for item in decision.constraints] == [
        ("network", "one"),
        ("process", "two"),
    ]


def test_module_cannot_spoof_constraint_attribution() -> None:
    """The framework, not module output, owns TCB attribution."""
    spoofed = ForbidConstraint(
        "one", RulePredicate(domain="network"), "offline", module="other"
    )
    stack = SecurityStack(
        [FixedModule("network", Decision(Verdict.ALLOW, "ok", constraints=(spoofed,)))]
    )
    try:
        decision = stack.permission(_principal(), _call())
    finally:
        stack.close()

    assert decision == Decision(Verdict.DENY, "module_error:network")


def test_transform_is_rechecked_by_dac() -> None:
    """A prepare hook cannot widen arguments beyond author grants."""

    class WidenPath(SecurityModule):
        name = "widen"

        def tool_call_prepare(self, principal: Principal, call: ToolCall) -> Decision:
            return Decision(
                Verdict.TRANSFORM, "rewrite", new_args={"path": "/etc/passwd"}
            )

    stack = SecurityStack([WidenPath()])
    try:
        decision, transformed = stack.prepare(_principal(), _call())
    finally:
        stack.close()

    assert decision == Decision(Verdict.DENY, "prepare:widened:widen")
    assert transformed.normalized["path"] == "/safe"


@pytest.mark.parametrize(
    ("module", "reason"),
    [
        (
            type(
                "Raises",
                (SecurityModule,),
                {
                    "name": "raises",
                    "tool_call_permission": lambda self, principal, call: (
                        _ for _ in ()
                    ).throw(RuntimeError()),
                },
            )(),
            "module_error:raises",
        ),
        (
            type(
                "Malformed",
                (SecurityModule,),
                {
                    "name": "malformed",
                    "tool_call_permission": lambda self, principal, call: None,
                },
            )(),
            "module_error:malformed",
        ),
    ],
)
def test_module_failure_is_fail_closed(module: SecurityModule, reason: str) -> None:
    """Exceptions and malformed hook results become explicit denies."""
    stack = SecurityStack([module])
    try:
        assert stack.permission(_principal(), _call()).reason == reason
    finally:
        stack.close()


def test_sync_timeout_returns_without_waiting_for_hook() -> None:
    """A slow sync policy is cancelled from the enforcement path."""

    class Slow(SecurityModule):
        name = "slow"

        def tool_call_permission(
            self, principal: Principal, call: ToolCall
        ) -> Decision:
            time.sleep(0.5)
            return Decision(Verdict.ALLOW, "late")

    stack = SecurityStack([Slow()], policy_timeout_s=0.02)
    started = time.monotonic()
    try:
        decision = stack.permission(_principal(), _call())
    finally:
        stack.close()

    assert decision.reason == "module_timeout:slow"
    assert time.monotonic() - started < 0.2


@pytest.mark.asyncio
async def test_async_parity() -> None:
    """Async enforcement preserves restrictive sync semantics."""
    strict = FixedModule("strict", Decision(Verdict.DENY, "strict"))
    stack = SecurityStack([strict])
    try:
        decision = await stack.apermission(_principal(), _call())
        resume = await stack.aresume_permission(
            _principal(), Approval("approval", False, "reviewer")
        )
    finally:
        stack.close()
    assert decision.verdict is Verdict.DENY
    assert resume.reason == "cap:approval_rejected"


@given(dac_allows=st.booleans(), module_allows=st.lists(st.booleans(), max_size=8))
def test_no_module_sequence_allows_after_dac_denial(
    dac_allows: bool, module_allows: list[bool]
) -> None:
    """Property: final allow requires DAC and every module to allow."""
    modules = [
        FixedModule(
            f"m{index}",
            Decision(Verdict.ALLOW if allows else Verdict.DENY, "policy"),
        )
        for index, allows in enumerate(module_allows)
    ]
    principal = _principal() if dac_allows else _principal(scopes=())
    stack = SecurityStack(modules)
    try:
        decision = stack.permission(principal, _call())
    finally:
        stack.close()
    assert (decision.verdict is Verdict.ALLOW) is (dac_allows and all(module_allows))


@pytest.mark.parametrize(
    ("modules", "timeout", "message"),
    [
        ([], 0, "positive"),
        ([FixedModule("cap", Decision(Verdict.ALLOW, "allow"))], 1, "framework"),
        (
            [
                FixedModule("duplicate", Decision(Verdict.ALLOW, "allow")),
                FixedModule("duplicate", Decision(Verdict.ALLOW, "allow")),
            ],
            1,
            "unique",
        ),
        ([FixedModule("", Decision(Verdict.ALLOW, "allow"))], 1, "unique"),
    ],
)
def test_stack_rejects_invalid_configuration(
    modules: list[SecurityModule], timeout: float, message: str
) -> None:
    """Invalid timeout and module identities fail before an executor is exposed."""
    with pytest.raises(ValueError, match=message):
        SecurityStack(modules, policy_timeout_s=timeout)


class PostModule(SecurityModule):
    """Configurable post hook used to exercise failure conversion."""

    name = "post"

    def __init__(self, behavior: str) -> None:
        self.behavior = behavior

    def tool_call_post(self, principal, call, result, slot):
        slot["result"] = result
        if self.behavior == "raise":
            raise RuntimeError("broken")
        if self.behavior == "malformed":
            return "unexpected"
        if self.behavior == "slow":
            time.sleep(0.05)
        if self.behavior == "awaitable":

            async def complete() -> None:
                await asyncio.sleep(0)

            return complete()
        return None


@pytest.mark.parametrize(
    ("behavior", "reason"),
    [
        ("ok", "post:complete"),
        ("raise", "module_error:post"),
        ("malformed", "module_error:post"),
        ("slow", "module_timeout:post"),
    ],
)
def test_sync_post_hooks_fail_closed(behavior: str, reason: str) -> None:
    """Sync post hooks convert exceptions, malformed values, and timeouts."""
    stack = SecurityStack([PostModule(behavior)], policy_timeout_s=0.01)
    try:
        decision = stack.post(_principal(), _call(), "result")
    finally:
        stack.close()
    assert decision.reason == reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("behavior", "reason"),
    [
        ("ok", "post:complete"),
        ("raise", "module_error:post"),
        ("malformed", "module_error:post"),
        ("slow", "module_timeout:post"),
        ("awaitable", "post:complete"),
    ],
)
async def test_async_post_hooks_fail_closed(behavior: str, reason: str) -> None:
    """Async post execution has the same failure semantics as sync execution."""
    stack = SecurityStack([PostModule(behavior)], policy_timeout_s=0.01)
    try:
        decision = await stack.apost(_principal(), _call(), "result")
    finally:
        stack.close()
    assert decision.reason == reason


@pytest.mark.asyncio
async def test_async_prepare_covers_dac_transform_and_module_denial() -> None:
    """Async prepare stops on DAC and module denial and normalizes transforms."""

    class Transform(SecurityModule):
        name = "transform"

        def tool_call_prepare(self, principal, call):
            return Decision(Verdict.TRANSFORM, "narrow", new_args={"path": "/safe"})

    denied_stack = SecurityStack([Transform()])
    strict_stack = SecurityStack(
        [
            type(
                "StrictPrepare",
                (SecurityModule,),
                {
                    "name": "strict_prepare",
                    "tool_call_prepare": lambda self, principal, call: Decision(
                        Verdict.DENY, "blocked"
                    ),
                },
            )()
        ]
    )
    try:
        denied, _ = await denied_stack.aprepare(_principal(scopes=()), _call())
        allowed, transformed = await denied_stack.aprepare(_principal(), _call())
        strict, _ = await strict_stack.aprepare(_principal(), _call())
    finally:
        denied_stack.close()
        strict_stack.close()
    assert denied.reason == "dac:scope"
    assert allowed.verdict is Verdict.ALLOW
    assert transformed.normalized["path"] == "/safe"
    assert strict.reason == "blocked"


def test_approval_matches_only_the_exact_escalated_call() -> None:
    """An approval cannot authorize another request, call, or tool."""
    call = _call()
    escalation = EscalationRequest(
        "request",
        "review",
        "read_file",
        "call",
        subject_digest="subject",
        expires_at=time.time() + 60,
    )
    decision = Decision(Verdict.ESCALATE, "review", escalation=escalation)

    assert _matches_approval(
        decision, call, Approval("request", True, "reviewer", subject_digest="subject")
    )
    assert not _matches_approval(
        decision, call, Approval("request", False, "reviewer", subject_digest="subject")
    )
    assert not _matches_approval(
        decision, call, Approval("other", True, "reviewer", subject_digest="subject")
    )
    assert not _matches_approval(
        decision, call, Approval("request", True, "reviewer", subject_digest="other")
    )
    assert not _matches_approval(Decision(Verdict.ALLOW, "ok"), call, None)


def test_escalation_subject_binds_normalized_intent() -> None:
    """Argument changes produce a different approval subject digest."""
    module = FixedModule(
        "review",
        Decision(
            Verdict.ESCALATE,
            "review",
            escalation=EscalationRequest("request", "review", "read_file", "call"),
        ),
    )
    stack = SecurityStack([module])
    try:
        first = stack.permission(_principal(), _call(allowed_path="/safe"))
        second = stack.permission(_principal(), _call(allowed_path="/other"))
    finally:
        stack.close()

    assert first.escalation is not None
    assert second.escalation is not None
    assert first.escalation.subject_digest
    assert first.escalation.subject_digest != second.escalation.subject_digest


def test_expired_approval_cannot_match() -> None:
    """Approval expiry is enforced during the resumed permission check."""
    call = _call()
    decision = Decision(
        Verdict.ESCALATE,
        "review",
        escalation=EscalationRequest(
            "request",
            "review",
            "read_file",
            "call",
            subject_digest="subject",
            expires_at=time.time() - 1,
        ),
    )
    assert not _matches_approval(
        decision, call, Approval("request", True, "reviewer", subject_digest="subject")
    )


def test_replace_call_args_normalizes_each_resource_shape() -> None:
    """Transforms rebuild all derived normalizer keys used by DAC."""
    tool = Tool(
        "multi",
        ToolDac("analyst", {"analyst": "x"}),
        frozenset({Effect.READ}),
        (
            ResourceArg("url", "url", "domain"),
            ResourceArg("email", "email", "email_domain"),
            ResourceArg("sql", "table", "sql_statement_kind"),
            ResourceArg("command", "command", "shell_argv0"),
            ResourceArg("missing", "path", "realpath"),
        ),
    )
    call = ToolCall(tool, {}, {}, "call", 0)

    replaced = _replace_call_args(
        call,
        {
            "url": "https://EXAMPLE.com/path",
            "email": "a@CORP.example",
            "sql": "SELECT 1",
            "command": "printf ok",
        },
    )

    assert replaced.normalized == {
        "url": "example.com",
        "url_domain": "example.com",
        "email": "corp.example",
        "email_domain": "corp.example",
        "sql": "select",
        "sql_statement_kind": "select",
        "command": "printf",
        "command_argv0": "printf",
    }


def test_observer_records_credential_stage_without_call_attributes() -> None:
    """Credential decisions remain observable without inventing tool metadata."""
    observer = MemorySecurityObserver()
    stack = SecurityStack([], observer=observer)
    try:
        decision = stack.cred_transfer(_principal(), _principal())
    finally:
        stack.close()
    event = observer.events()[-1]
    assert decision.verdict is Verdict.ALLOW
    assert event.tool_name is None
    assert event.call_index is None
