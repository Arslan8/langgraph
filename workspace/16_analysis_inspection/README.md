# Demo 16: inspecting stored analysis results

For plugin writers who want to use the optional shared inspection API. This demo
opts into the standard finding format, then queries a stored result without running
the analyzer again. Plugins with private formats can use their own storage/query API.

```python
with StructuredAnalysis(
    AnalyzerRegistration(analyzer=marker, events={BuiltinEvent.INPUT_ADMIT})
) as analysis:
    client = analysis.client
    findings = client.get_findings(AnalysisQuery())
```

The complete [demo.py](demo.py) records a document before querying. It also reads
the saved snapshot and receives pending/completion notifications through a
subscription. All three views refer to the same finding.

Run:

```bash
libs/prebuilt/.venv/bin/python workspace/16_analysis_inspection/demo.py
```

Expected output:

```text
Stored finding: example.document.seen
Notifications: pending -> complete
Query, snapshot and notification identify the same finding
Analyzer executions after inspection: 1
```

`StructuredAnalysis` manages the local store, notifications and isolated scope.
No tenant/session/run/principal IDs, access-context assembly, registry or runtime
construction are needed. `context.finding(...)` supplies internal record metadata.
The local client can inspect this session only; closing it revokes client access.
The subscription is explicitly closed when the example finishes.

## Try it

Query `AnalysisQuery(analyzer_id="missing")` to get no findings. Repeat the normal
query: `marker.calls` remains 1 because inspection reads stored records. Labels
and provenance are also available through `client.get_labels(document)` and
`client.get_provenance(document)`; they are not the focus of this lesson.

## Scope

These are inspection data and notifications, not authorization decisions.
The generated local scope is not authentication for an external user. Applications
serving multiple users should use the explicit authenticated `AnalysisClient`
configuration. Standardized findings are optional for plugin writers, required only
when opting into this shared consumer.

If needed, run `uv sync --directory libs/prebuilt` first. No model or service is used.

[All demos](../README.md) · [Inspection API](../../docs/security/analysis/developer-api.md)
