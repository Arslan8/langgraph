"""Demo 16: inspect stored results without rerunning analysis."""

import asyncio

from langgraph.prebuilt.analysis import (
    AnalysisQuery,
    AnalysisResult,
    AnalyzerRegistration,
    BuiltinEvent,
    StructuredAnalysis,
)


class DocumentMarker:
    """Opt into the shared finding format so the shared client can query it."""

    def __init__(self):
        self.calls = 0

    def analyze(self, event, context):
        self.calls += 1
        return AnalysisResult(findings=(context.finding(code="example.document.seen"),))

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


async def main():
    marker = DocumentMarker()
    with StructuredAnalysis(
        AnalyzerRegistration(analyzer=marker, events={BuiltinEvent.INPUT_ADMIT})
    ) as analysis:
        client = analysis.client
        subscription = client.subscribe(AnalysisQuery())
        try:
            document = analysis.value("Quarterly report")
            snapshot = analysis.emit(BuiltinEvent.INPUT_ADMIT, (document,))
            findings = client.get_findings(AnalysisQuery())
            saved = client.get_snapshot(snapshot.snapshot_id)
            pending = await asyncio.wait_for(anext(subscription), timeout=2)
            complete = await asyncio.wait_for(anext(subscription), timeout=2)
            assert findings.records == saved.snapshot.findings
            assert complete.finding_ids == tuple(
                item.finding_id for item in findings.records
            )
            assert pending.completion_status == "pending"
            assert complete.completion_status == "complete"
            assert marker.calls == 1
            print(f"Stored finding: {findings.records[0].code}")
            print("Notifications: pending -> complete")
            print("Query, snapshot and notification identify the same finding")
            print("Analyzer executions after inspection: 1")
        finally:
            await subscription.aclose()


if __name__ == "__main__":
    asyncio.run(main())
