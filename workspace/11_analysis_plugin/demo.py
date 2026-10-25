"""Demo 11: an analysis plugin."""

from uuid import uuid4

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AnalysisConfig,
    AnalysisFinding,
    AnalysisResult,
    AnalysisRuntime,
    AnalyzerRegistration,
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


def main():
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
    )
    boundary = BoundaryAdapter(runtime)
    try:
        document = boundary.value("Quarterly report")
        snapshot = boundary.before("input.admit", (document,))
        finding = snapshot.findings[0]
        assert finding.code == "example.document.seen"
        assert finding.subject_refs == (document,)
        print("input.admit -> DocumentMarker -> example.document.seen")
        print("Finding refers to the admitted document: yes")
    finally:
        runtime.close()
        store.close()


if __name__ == "__main__":
    main()
