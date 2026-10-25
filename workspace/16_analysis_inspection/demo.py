"""Demo 16: inspecting analysis."""

import asyncio
from uuid import uuid4

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
    NotificationHub,
    Registry,
)
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore
from langgraph.prebuilt.analysis.serialization import digest


class DocumentMarker:
    """A deterministic teaching analyzer, not a sensitive-data detector."""

    def analyze(self, event, context):
        return AnalysisResult(
            findings=(
                AnalysisFinding(
                    finding_id=str(uuid4()),
                    analyzer_id="marker",
                    analyzer_version="1",
                    code="example.document.seen",
                    subject_refs=event.input_refs,
                    status="complete",
                    configuration_digest=digest({"version": 1}),
                ),
            )
        )

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


async def main():
    registrations = (
        AnalyzerRegistration("marker", "1", DocumentMarker(), ("input.admit",)),
    )
    store = MemoryProvenanceStore()
    registry = Registry(
        BUILTIN_EVENTS,
        registrations,
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime = AnalysisRuntime(
        AnalysisConfig("{}", ()),
        registry,
        store,
        tenant_id="demo",
        session_id="session",
        run_id="lesson",
        principal_id="owner",
        notifications=NotificationHub(),
    )
    boundary = BoundaryAdapter(runtime)
    # A trusted local caller can inspect only this demonstration session.
    access = AccessContext(
        "owner", "demo", frozenset({"session"}), lambda _: True, lambda: True
    )
    client = AnalysisClient(runtime.journal, access, runtime.notifications)
    subscription = client.subscribe(AnalysisQuery(run_id="lesson"))
    try:
        document = boundary.value("Quarterly report")
        snapshot = boundary.before("input.admit", (document,))
        findings = client.get_findings(AnalysisQuery(run_id="lesson"))
        view = client.get_snapshot(snapshot.snapshot_id)
        labels = client.get_labels(document)
        provenance = client.get_provenance(document)
        pending = await asyncio.wait_for(anext(subscription), timeout=2)
        complete = await asyncio.wait_for(anext(subscription), timeout=2)
        assert pending.completion_status == "pending"
        assert complete.completion_status == "complete"
        assert findings.records == view.snapshot.findings
        assert complete.finding_ids == tuple(f.finding_id for f in findings.records)
        assert complete.snapshot_id == snapshot.snapshot_id
        assert labels.record.value_ref == document
        assert any(record.ref == document for record in provenance.records)
        print("Query: example.document.seen")
        print("Subscription: pending -> complete")
        print("Query, snapshot and notification identify the same finding: yes")
        print("Labels and provenance refer to the admitted document: yes")
    finally:
        await subscription.aclose()
        runtime.close()
        store.close()


if __name__ == "__main__":
    asyncio.run(main())
