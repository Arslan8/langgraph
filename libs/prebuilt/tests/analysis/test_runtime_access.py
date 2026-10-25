import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AccessContext,
    AnalysisClient,
    AnalysisConfig,
    AnalysisFinding,
    AnalysisQuery,
    AnalysisResult,
    AnalysisRuntime,
    AnalyzerRegistration,
    AnnotationProposal,
    Coverage,
    NotificationHub,
    Registry,
)
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.errors import (
    AccessDenied,
    AnalysisUnavailable,
    CursorExpired,
    SubscriptionOverflow,
)
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore


class Marker:
    def __init__(self):
        self.calls = 0

    def analyze(self, event, context):
        self.calls += 1
        assert context.resolver.resolve(event.input_refs[0])
        return AnalysisResult(
            findings=(
                AnalysisFinding(
                    finding_id=str(uuid4()),
                    analyzer_id="marker",
                    analyzer_version="1",
                    code="example.department.restricted",
                    subject_refs=event.input_refs,
                    status="complete",
                    configuration_digest="0" * 64,
                ),
            ),
            annotation_proposals=(
                AnnotationProposal(
                    subject=event.input_refs[0],
                    domain="analysis.risks",
                    label_json='["example.department.restricted"]',
                ),
            ),
        )

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


def setup_runtime(analyzer=None, mode="required", timeout=1):
    analyzer = analyzer or Marker()
    store = MemoryProvenanceStore()
    hub = NotificationHub(retention=4)
    registry = Registry(
        BUILTIN_EVENTS,
        (
            AnalyzerRegistration(
                "marker",
                "1",
                analyzer,
                ("input.admit",),
                mode=mode,
                timeout=timeout,
                content_access=True,
            ),
        ),
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime = AnalysisRuntime(
        AnalysisConfig("{}", (Coverage("input.admit", "explicitly_adapted", "input"),)),
        registry,
        store,
        tenant_id="tenant",
        session_id="session",
        run_id="run",
        principal_id="owner",
        notifications=hub,
    )
    access = AccessContext(
        "owner", "tenant", frozenset({"session"}), lambda _: True, lambda: True
    )
    return (
        runtime,
        BoundaryAdapter(runtime),
        AnalysisClient(runtime.journal, access, hub),
        access,
    )


async def test_shared_records_async_and_sync():
    runtime, adapter, client, _ = setup_runtime()
    sub = client.subscribe(AnalysisQuery(run_id="run"))
    ref = adapter.value("document")
    snapshot = adapter.before("input.admit", (ref,))
    pending = await anext(sub)
    notification = await anext(sub)
    assert pending.completion_status == "pending"
    assert notification.completion_status == "complete"
    view = client.get_snapshot(snapshot.snapshot_id)
    assert notification.finding_ids == tuple(
        f.finding_id for f in view.snapshot.findings
    )
    assert notification.value_refs == tuple(f.value_ref for f in snapshot.flow)
    assert view.snapshot.revision == snapshot.revision
    assert client.get_findings(AnalysisQuery()) == await client.aget_findings(
        AnalysisQuery()
    )
    assert client.get_labels(ref) == await client.aget_labels(ref)
    assert client.get_provenance(ref) == await client.aget_provenance(ref)
    assert runtime.registry.analyzers[0].analyzer.calls == 1
    with pytest.raises(Exception):
        view.snapshot.status = "complete"
    await sub.aclose()
    runtime.close()


class Broken:
    def analyze(self, event, context):
        raise RuntimeError("secret failure detail")

    async def aanalyze(self, event, context):
        raise RuntimeError("secret failure detail")


@pytest.mark.parametrize("mode", ["required", "advisory"])
async def test_failures_are_not_clean(mode):
    runtime, adapter, client, _ = setup_runtime(Broken(), mode)
    ref = adapter.value("data")
    if mode == "required":
        with pytest.raises(AnalysisUnavailable):
            adapter.before("input.admit", (ref,))
        with pytest.raises(AnalysisUnavailable):
            await adapter.abefore("input.admit", (ref,))
    else:
        assert adapter.before("input.admit", (ref,)).status == "failed"
    assert "complete" not in client.get_findings(AnalysisQuery()).statuses
    runtime.close()


async def test_access_revocation_and_overflow():
    runtime, adapter, client, access = setup_runtime()
    active = [True]
    limited = AnalysisClient(
        runtime.journal,
        replace(access, is_active=lambda: active[0]),
        runtime.notifications,
    )
    sub = limited.subscribe(AnalysisQuery(run_id="run"))
    ref = adapter.value("data")
    snapshot = adapter.before("input.admit", (ref,))
    active[0] = False
    with pytest.raises(AccessDenied):
        await anext(sub)
    foreign = AnalysisClient(
        runtime.journal, replace(access, tenant_id="other"), runtime.notifications
    )
    assert not foreign.get_findings(AnalysisQuery()).records
    with pytest.raises(AccessDenied):
        foreign.get_snapshot(snapshot.snapshot_id)
    slow = client.subscribe(AnalysisQuery(run_id="run"))
    for _ in range(257):
        runtime.notifications.publish(snapshot)
    with pytest.raises(SubscriptionOverflow):
        await anext(slow)
    with pytest.raises(CursorExpired):
        client.subscribe(AnalysisQuery(run_id="run"), "run:1")
    runtime.close()


async def test_cancellation_preserved():
    class Waiter(Broken):
        async def aanalyze(self, event, context):
            await asyncio.sleep(100)

    runtime, adapter, client, _ = setup_runtime(Waiter())
    task = asyncio.create_task(adapter.abefore("input.admit", (adapter.value("data"),)))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "unavailable" in client.get_findings(AnalysisQuery()).statuses
    runtime.close()


async def test_model_and_output_barriers_precede_effects():
    runtime, adapter, _, _ = setup_runtime()
    registry = Registry(
        BUILTIN_EVENTS,
        (
            AnalyzerRegistration(
                "marker", "1", Broken(), ("model.request", "output.emit")
            ),
        ),
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime.registry = registry
    effects = []
    ref = adapter.value("data")
    with pytest.raises(AnalysisUnavailable):
        adapter.call(
            "model.request",
            "model.response",
            (ref,),
            lambda: effects.append("provider"),
            lambda x: x,
        )
    with pytest.raises(AnalysisUnavailable):
        await adapter.abefore("output.emit", (ref,))
        effects.append("output")
    assert effects == []
    runtime.close()
