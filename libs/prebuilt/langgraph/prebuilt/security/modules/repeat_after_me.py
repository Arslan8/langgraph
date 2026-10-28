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
        if not any(
            f.analyzer_id == "example.repeat_after_me"
            and f.event_name == "model.request"
            and f.status == "complete"
            for f in snapshot.findings
        ):
            return Decision(Verdict.DENY, "ram:missing_context_coverage")
        if any(
            value.risks.intersection({"example.ram.suspected", "example.ram.unknown"})
            for value in snapshot.flow
        ):
            return Decision(Verdict.DENY, "ram:affected_ancestry")
        return Decision(Verdict.ALLOW, "ram:no_objection")

    def validate_analysis(self, runtime):
        from langgraph.prebuilt.analysis.errors import ConfigurationError

        expected = {"input.admit", "retrieval.result", "tool.result", "model.request"}
        candidates = [
            item
            for item in runtime.registry.analyzers
            if item.analyzer_id == "example.repeat_after_me"
            and item.mode == "required"
            and expected.issubset(item.event_names)
        ]
        report = {item.boundary: item.status for item in runtime.config.coverage}
        if not candidates or any(
            report.get(name, "unsupported") == "unsupported"
            for name in expected | {"tool.dispatch"}
        ):
            raise ConfigurationError("ram:incomplete_defensive_profile")
