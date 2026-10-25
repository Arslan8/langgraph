"""Demo 14: information flow."""

import json

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AnalysisConfig,
    AnalysisRuntime,
    Registry,
)
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore
from langgraph.prebuilt.security import Principal, Verdict
from langgraph.prebuilt.security.modules.analysis_flow import AnalysisFlowPolicy
from langgraph.prebuilt.security.objects import (
    LabeledValue,
    ModelInvocationRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.stack import SecurityStack


def main():
    clearances = {"model:public": (), "model:internal": ("secret",)}
    config = AnalysisConfig(json.dumps({"clearances": clearances}), ())
    registrations = ()
    store = MemoryProvenanceStore()
    registry = Registry(
        BUILTIN_EVENTS,
        registrations,
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime = AnalysisRuntime(
        config,
        registry,
        store,
        tenant_id="demo",
        session_id="session",
        run_id="lesson",
        principal_id="owner",
    )
    boundary = BoundaryAdapter(runtime)
    # The enforcing module uses the policy loaded before runtime construction.
    policy = AnalysisFlowPolicy(
        runtime.config.policy_version, store.domains, clearances
    )
    stack = SecurityStack((policy,), analysis=runtime)
    try:
        source = store.register(
            ValueRecord(
                "demo",
                "session",
                "lesson",
                b'"Private revenue"',
                labels=SecurityLabels(frozenset({"secret"}), "low"),
            )
        )
        summary = boundary.value("Revenue summary", (source,), "summarize")
        assert store.get(summary).labels.confidentiality == frozenset({"secret"})
        print("Summary inherits confidentiality: secret")
        principal = Principal("owner", frozenset(), frozenset(), "session")
        submitted = []
        for destination, expected in (
            ("model:public", Verdict.DENY),
            ("model:internal", Verdict.ALLOW),
        ):
            request = ModelInvocationRequest(
                destination,
                (LabeledValue("prompt", "Revenue summary"),),
                destination,
            )
            decision = stack.object_permission(principal, request).decision
            assert decision.verdict is expected
            if decision.verdict is Verdict.ALLOW:
                submitted.append(destination)  # Local stand-in for provider submission.
            print(f"{destination}: {decision.verdict.value}")
        assert submitted == ["model:internal"]
    finally:
        stack.close()
        runtime.close()
        store.close()


if __name__ == "__main__":
    main()
