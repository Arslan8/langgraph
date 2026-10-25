"""Deterministic flow fixture independent of the prompt classifier."""

from pathlib import Path
import json

from examples.analysis.repeat_after_me.tools import Ledger

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AnalysisConfig,
    AnalysisRuntime,
    Registry,
)
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.security import (
    Principal,
    SecurityConfig,
    SecurityDeniedError,
    guarded_tool,
    with_principal,
)
from langgraph.prebuilt.security.modules.analysis_flow import AnalysisFlowPolicy
from langgraph.prebuilt.security.objects import (
    LabeledValue,
    ModelInvocationRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import Verdict


def demonstrate(directory: Path):
    store = SqliteProvenanceStore(str(directory / "flow.db"))
    clearances = {"public_sink": (), "cleared_sink": ("secret",), "unknown_sink": ("secret",), "model:public": (), "model:cleared": ("secret",)}
    read_bounds = {"public_sink": (), "cleared_sink": (), "unknown_sink": None}
    config = AnalysisConfig(json.dumps({"profile": "confidentiality", "clearances": clearances, "read_bounds": read_bounds}), ())
    registry = Registry(
        BUILTIN_EVENTS,
        (),
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime = AnalysisRuntime(
        config,
        registry,
        store,
        tenant_id="demo",
        session_id="session",
        run_id="flow",
        principal_id="owner",
    )
    adapter = BoundaryAdapter(runtime)
    source = store.register(
        ValueRecord(
            "demo",
            "session",
            "flow",
            b'"confidential synthetic record"',
            labels=SecurityLabels(frozenset({"secret"}), "low"),
        )
    )
    summary = adapter.value("summary", (source,), "summary")
    response = adapter.value("model output", (summary,), "model.response")
    adapter.value({"message": "normalized"}, (response,), "normalize")
    principal = Principal("owner", frozenset({"demo"}), frozenset(), "session")
    results = {}
    policy = AnalysisFlowPolicy(config.policy_version, store.domains, clearances, read_bounds=read_bounds)
    security = SecurityConfig(modules=(policy,), analysis=runtime)
    for destination in ("public", "cleared", "unknown"):
        ledger = Ledger(directory / f"{destination}.db")
        guarded = guarded_tool(ledger.tool(f"{destination}_sink"), security=security)
        try:
            guarded.invoke({"message": "normalized"}, with_principal({}, principal))
        except SecurityDeniedError:
            pass
        results[destination] = ledger.count()
    stack = SecurityStack((policy,), analysis=runtime)
    for destination in ("model:public", "model:cleared"):
        request = ModelInvocationRequest(
            destination, (LabeledValue("prompt", "synthetic"),), destination
        )
        verdict = stack.object_permission(principal, request).decision.verdict
        results[destination] = verdict.value
    assert results == {
        "public": 0,
        "cleared": 1,
        "unknown": 0,
        "model:public": Verdict.DENY.value,
        "model:cleared": Verdict.ALLOW.value,
    }
    stack.close()
    runtime.close()
    store.close()
    return results
