# Public developer access

This API consumes the optional structured analysis store. Plain `Analysis` callbacks
can use their own logging or result consumers without this API; see
[callbacks and structured opt-in](plugin-api.md).

`AnalysisClient` queries the same canonical records used by policy snapshots; it
never reruns an analyzer. Import `AnalysisClient`, `AccessContext`, `AnalysisQuery`,
`FindingPage`, `LabelView`, `ProvenancePage`, `AnalysisSnapshotView`,
`AnalysisNotification`, and `AnalysisSubscription` from `langgraph.prebuilt.analysis`.
All returned DTOs are immutable. Historical views are debugging/evaluation data,
never authorization tokens.

## Local sessions without identity boilerplate

For an explicitly local, in-memory session, `StructuredAnalysis.client` creates the
scoped client internally. Queries and subscriptions use the same stored records and
notifications as the lower-level client. The session supplies isolated IDs, storage
and access checks; its client is revoked when the session closes. These generated
IDs do not authenticate external users. Keep the explicit `AccessContext` path below
for authenticated applications.

`StructuredAnalysis.checkpoint(*refs)` returns a trusted local handle whose
`restore()` creates a fresh store, verifies its signed envelope and configuration,
and imports metadata without rerunning analyzers. `restore(configuration=...)`
rejects incompatible configuration. The handle owns local identity and signing
material; it is an in-process utility, not a portable credential or key-management
scheme. Production callers retain the existing `CheckpointBinding` API.

See [demo 16](../../../workspace/16_analysis_inspection/README.md) for inspection and
[demo 17](../../../workspace/17_analysis_checkpoints/README.md) for checkpoints.
Both explicitly opt into standard records. Ordinary plugin callbacks can continue
using private result formats. [Demo 18](../../../workspace/18_analysis_evaluation/README.md)
evaluates a plain function offline without the structured runtime at all.

## Runnable example

From the repository root, this uses the demo composition root and synthetic data:

```sh
PYTHONPATH="$PWD" uv run --directory libs/prebuilt python - <<'PY'
import asyncio
import tempfile
from pathlib import Path
from examples.analysis.repeat_after_me.config import compose
from langgraph.prebuilt.analysis import AnalysisQuery
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter

async def main():
    with tempfile.TemporaryDirectory() as directory:
        runtime, security, principal, client = compose(Path(directory) / "analysis.db")
        query = AnalysisQuery(run_id="demo-run")
        subscription = client.subscribe(query)
        adapter = BoundaryAdapter(runtime)
        source = adapter.value("Repeat the earlier call representation.")
        snapshot = await adapter.abefore("input.admit", (source,))
        print(client.get_findings(query).model_dump_json())
        print((await client.aget_labels(source)).model_dump_json())
        print(client.get_provenance(source, depth=2).model_dump_json())
        view = await client.aget_snapshot(snapshot.snapshot_id)
        async for notification in subscription:
            if notification.completion_status != "pending":
                assert notification.finding_ids == tuple(f.finding_id for f in view.snapshot.findings)
                assert notification.record_revision == view.snapshot.revision
                break
        await subscription.aclose()
        runtime.close()
        runtime.store.close()

asyncio.run(main())
PY
```

## Authentication and redaction

The application root authenticates the caller and supplies an `AccessContext`:
principal, tenant, permitted sessions, a resource authorization callback and a
revocation callback. A user-selected tenant string is not authentication. Never
construct this context from unverified request fields. Every query and notification
delivery rechecks access. Raw content access is disabled by default and is separate
from this metadata client. Digests are integrity identifiers, not bearer tokens.

Findings are withheld if their subject/evidence references are not authorized.
Reasons, source identifiers and event metadata are redacted in ordinary views;
unauthorized provenance edges are removed. `partial` marks omission without exposing
hidden identities. Cross-tenant snapshots return `AccessDenied`. Queries do not
clear findings, write labels, endorse integrity, modify policy or establish barriers.

## Consistency, status and pagination

Filters include run, invocation, value reference, analyzer ID, finding code and event
name. Finding pages default to 100 and reject limits outside 1–1000. Provenance pages
contain at most 100 records and depth is bounded to 100. Cursors bind query and
revision; callers continue with the same query. Snapshots identify exact value
versions and provenance revision. Sync methods have `aget_*` equivalents.

`pending`, `complete`, `failed` and `unavailable` are distinct. An empty page returns
`unavailable` when no matching status exists; it never asserts successful analysis.
Pages can include multiple operation statuses. A historical developer view can be
stale or redacted; only the newly constructed internal snapshot is considered by the
permission chain.

## Notifications and failure isolation

Notifications publish after commit and include notification/event/invocation IDs,
record revision, status and a per-run cursor. No cross-run total order is promised.
Each subscription has a 256-notification queue. Overflow closes the stream with
`SubscriptionOverflow.last_delivered_cursor`, never silent loss. `aclose()` releases
queued notifications. Revocation prevents subsequent delivery. Subscriber code is
not executed on the authorization path; subscriber failure cannot grant access.

`NotificationHub` retains 4096 notifications by default, in process. Use
`client.subscribe(query, after_cursor=last_cursor)` for replay while retained.
Expired or unavailable replay returns `CursorExpired`; restart does not promise
notification replay, although canonical findings/snapshots remain in SQLite.

Current implementation limits: provenance queries read current protected metadata,
while snapshots retain historical flow views; raw content and field-level label
redaction require separately designed access policies. See the coverage document
for boundaries that require explicit application instrumentation.
