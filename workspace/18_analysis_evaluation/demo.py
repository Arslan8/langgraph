"""Demo 18: evaluating an analyzer."""

import json
from time import perf_counter
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


class KeywordAnalyzer:
    """Intentionally crude so false positives and negatives are visible."""

    def analyze(self, event, context):
        text = json.loads(context.resolver.resolve(event.input_refs[0]))
        code = "example.flagged" if "secret" in text.lower() else "example.clear"
        return AnalysisResult(
            findings=(
                AnalysisFinding(
                    finding_id=str(uuid4()),
                    analyzer_id="keyword",
                    analyzer_version="1",
                    code=code,
                    subject_refs=event.input_refs,
                    status="complete",
                    configuration_digest=digest({"keyword": "secret"}),
                ),
            )
        )

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


def main():
    registrations = (
        AnalyzerRegistration(
            "keyword",
            "1",
            KeywordAnalyzer(),
            ("input.admit",),
            content_access=True,
        ),
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
    # Labels mean sensitive content for this tiny teaching fixture.
    cases = (
        ("The secret password is swordfish", True),
        ("Lunch is at noon", False),
        ("The novel is called Secret Garden", False),
        ("The password is swordfish", True),
    )
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    elapsed = []
    try:
        for text, sensitive in cases:
            ref = boundary.value(text)
            start = perf_counter()
            snapshot = boundary.before("input.admit", (ref,))
            elapsed.append(perf_counter() - start)
            flagged = snapshot.findings[0].code == "example.flagged"
            bucket = (
                ("TP" if sensitive else "FP")
                if flagged
                else ("FN" if sensitive else "TN")
            )
            counts[bucket] += 1
            print(f"{bucket}: {text}")
        assert counts == {"TP": 1, "TN": 1, "FP": 1, "FN": 1}
        precision = counts["TP"] / (counts["TP"] + counts["FP"])
        recall = counts["TP"] / (counts["TP"] + counts["FN"])
        print(f"Precision: {precision:.0%}; recall: {recall:.0%}")
        print(
            f"Mean boundary processing time: {1000 * sum(elapsed) / len(elapsed):.3f} ms"
        )
    finally:
        runtime.close()
        store.close()


if __name__ == "__main__":
    main()
