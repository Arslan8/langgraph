"""Fixed demo rule; findings may change, this policy never grants authority."""

from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate
from langgraph.prebuilt.security.types import Decision, Verdict


class RepeatAfterMePolicy(AnalysisGate):
    name = "repeat_after_me"

    def tool_call_permission(self, principal, call):
        decision = super().tool_call_permission(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            return decision
        snapshot = self.snapshot(principal, call)
        if any(
            value.risks.intersection({"example.ram.suspected", "example.ram.unknown"})
            for value in snapshot.flow
        ):
            return Decision(Verdict.DENY, "ram:affected_ancestry")
        return Decision(Verdict.ALLOW, "ram:no_objection")
