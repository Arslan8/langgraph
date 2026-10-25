"""Restrictive label-domain checks, composed with DAC, MAC and host policy."""

import json
from types import MappingProxyType

from langgraph.prebuilt.analysis.provenance.domains import DomainRegistry
from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate
from langgraph.prebuilt.security.types import Decision, Verdict


class AnalysisFlowPolicy(AnalysisGate):
    name = "analysis_flow"

    def __init__(self, policy_version: str, domains: DomainRegistry, clearances):
        super().__init__(policy_version)
        self.domains = domains
        self.clearances = MappingProxyType(
            {
                key: None if value is None else frozenset(value)
                for key, value in clearances.items()
            }
        )

    def _flow(self, snapshot, destination):
        clearance = self.clearances.get(destination)
        if snapshot is None or clearance is None:
            return Decision(Verdict.DENY, "analysis:unknown_authority")
        for value in snapshot.flow:
            if not value.confidentiality.issubset(clearance):
                return Decision(Verdict.DENY, "analysis:confidentiality")
            for domain_id, label in json.loads(value.domains_json).items():
                if domain_id in ("analysis.risks", "analysis.confidentiality"):
                    continue
                if not self.domains.domains[domain_id].can_flow(label, destination):
                    return Decision(Verdict.DENY, "analysis:domain_flow")
        return Decision(Verdict.ALLOW, "analysis:flow_no_objection")

    def tool_call_permission(self, principal, call):
        decision = super().tool_call_permission(principal, call)
        if decision.verdict is not Verdict.ALLOW:
            return decision
        return self._flow(self.snapshot(principal, call), call.tool.name)

    def model_invoke(self, principal, request):
        return self._flow(request.analysis_snapshot, request.model)

    def output_emit(self, principal, request):
        return self._flow(request.analysis_snapshot, request.destination)
