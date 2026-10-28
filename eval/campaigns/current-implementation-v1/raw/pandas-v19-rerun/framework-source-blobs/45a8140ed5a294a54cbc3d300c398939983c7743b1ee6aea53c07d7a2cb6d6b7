"""Restrictive bridge from validated request-bound snapshots to existing hooks."""

from langgraph.prebuilt.analysis.contracts import AnalysisSnapshot
from langgraph.prebuilt.analysis.serialization import digest
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.types import Decision, Principal, ToolCall, Verdict


def request_binding(principal: Principal, call: ToolCall) -> str:
    return digest(
        {
            "principal": principal.user_id,
            "session": principal.session_id,
            "roles": sorted(principal.roles),
            "scopes": sorted(principal.scopes),
            "tool": call.tool.name,
            "args": call.args,
            "normalized": call.normalized,
            "invocation": call.call_id,
            "attempt": call.call_index,
            "authority": call.execution_binding,
        }
    )


class AnalysisGate(SecurityModule):
    """No objection only when the exact pending operation has a usable snapshot."""

    name = "analysis_gate"

    def __init__(self, policy_version: str) -> None:
        self.policy_version = policy_version

    def snapshot(self, principal: Principal, call: ToolCall) -> AnalysisSnapshot | None:
        snapshot = call.analysis_snapshot
        if not isinstance(snapshot, AnalysisSnapshot):
            return None
        if (
            snapshot.principal_id != principal.user_id
            or snapshot.event.session_id != principal.session_id
            or snapshot.policy_version != self.policy_version
            or snapshot.invocation_id != call.call_id
            or snapshot.attempt_id != str(call.call_index)
        ):
            return None
        if snapshot.event.metadata.get("request_binding") != request_binding(
            principal, call
        ):
            return None
        if snapshot.request_digest != digest(snapshot.event.wire()):
            return None
        return snapshot

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        snapshot = self.snapshot(principal, call)
        if (
            snapshot is None
            or snapshot.status in ("pending", "unavailable")
            or snapshot.unavailable_analyzers
            or any(f.status == "unavailable" for f in snapshot.findings)
        ):
            return Decision(Verdict.DENY, "analysis:unavailable")
        return Decision(Verdict.ALLOW, "analysis:complete")
