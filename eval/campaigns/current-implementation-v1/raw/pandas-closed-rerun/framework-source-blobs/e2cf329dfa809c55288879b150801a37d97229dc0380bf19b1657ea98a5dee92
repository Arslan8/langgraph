"""Public scoped analysis access. Historical views are never authorization tokens."""

from langgraph.prebuilt.analysis.access.authorization import AccessContext, AccessPolicy
from langgraph.prebuilt.analysis.access.contracts import (
    AnalysisQuery,
    AnalysisSnapshotView,
    FindingPage,
    LabelView,
    PageLimit,
    ProvenancePage,
)
from langgraph.prebuilt.analysis.access.queries import (
    decode_cursor,
    encode_cursor,
    matches,
    matches_finding,
    query_binding,
)
from langgraph.prebuilt.analysis.access.subscriptions import (
    AnalysisSubscription,
    NotificationHub,
)
from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.errors import AccessDenied
from langgraph.prebuilt.analysis.journal import AnalysisJournal
from langgraph.prebuilt.analysis.serialization import freeze


class AnalysisClient:
    def __init__(
        self,
        journal: AnalysisJournal,
        access: AccessContext,
        notifications: NotificationHub,
    ) -> None:
        self._journal, self._hub = journal, notifications
        self._policy = AccessPolicy(access, journal.store)

    def get_findings(
        self, query: AnalysisQuery, cursor: str | None = None, limit: int = 100
    ) -> FindingPage:
        self._policy.check()
        limit = PageLimit(limit=limit).limit
        binding = query_binding(query)
        revision, offset = decode_cursor(cursor, self._journal.store.revision, binding)
        records = {}
        statuses = set()
        partial = False
        for snapshot in self._journal.snapshots():
            if (
                snapshot.revision > revision
                or not self._policy.snapshot(snapshot)
                or not matches(snapshot, query)
            ):
                continue
            statuses.add(snapshot.status)
            for finding in snapshot.findings:
                if not matches_finding(finding, query):
                    continue
                if self._policy.finding(finding):
                    records[finding.finding_id] = finding.model_copy(
                        update={"reason": ""}
                    )
                else:
                    partial = True
        ordered = tuple(records[key] for key in sorted(records))
        page = ordered[offset : offset + limit]
        next_cursor = (
            encode_cursor(revision, offset + limit, binding)
            if offset + limit < len(ordered)
            else None
        )
        return FindingPage(
            records=page,
            revision=revision,
            cursor=next_cursor,
            partial=partial,
            statuses=tuple(sorted(statuses)) or ("unavailable",),
        )

    async def aget_findings(
        self, query: AnalysisQuery, cursor: str | None = None, limit: int = 100
    ) -> FindingPage:
        return self.get_findings(query, cursor, limit)

    def get_labels(self, value_ref: ValueRef) -> LabelView:
        if not self._policy.value(value_ref):
            raise AccessDenied("analysis:access_denied")
        flow = self._journal.flow(value_ref)
        parents = tuple(
            edge for edge in flow.parents if self._policy.value(edge.parent)
        )
        partial = len(parents) != len(flow.parents)
        return LabelView(
            record=flow.model_copy(update={"parents": parents}),
            revision=self._journal.store.revision,
            partial=partial,
        )

    async def aget_labels(self, value_ref: ValueRef) -> LabelView:
        return self.get_labels(value_ref)

    def get_provenance(
        self, value_ref: ValueRef, depth: int = 1, cursor: str | None = None
    ) -> ProvenancePage:
        if not 0 <= depth <= 100 or not self._policy.value(value_ref):
            raise AccessDenied("analysis:access_denied")
        binding = f"{value_ref.value_id}:{value_ref.version}:{depth}"
        revision, offset = decode_cursor(cursor, self._journal.store.revision, binding)
        pending = [(value_ref, 0)]
        records = {}
        partial = False
        while pending:
            ref, level = pending.pop(0)
            if ref.value_id in records:
                continue
            record = self._journal.store.get(ref)
            edges = tuple(
                edge for edge in record.dependencies if self._policy.value(edge.parent)
            )
            partial |= len(edges) != len(record.dependencies)
            records[ref.value_id] = record.model_copy(
                update={"dependencies": edges, "origin_refs": ()}
            )
            if level < depth:
                pending.extend((edge.parent, level + 1) for edge in edges)
        if cursor is not None and revision != self._journal.store.revision:
            from langgraph.prebuilt.analysis.errors import CursorExpired

            raise CursorExpired("analysis:provenance_revision_changed")
        ordered = tuple(records[key] for key in sorted(records))
        return ProvenancePage(
            records=ordered[offset : offset + 100],
            revision=revision,
            cursor=encode_cursor(revision, offset + 100, binding)
            if offset + 100 < len(ordered)
            else None,
            partial=partial,
        )

    async def aget_provenance(
        self, value_ref: ValueRef, depth: int = 1, cursor: str | None = None
    ) -> ProvenancePage:
        return self.get_provenance(value_ref, depth, cursor)

    def get_snapshot(self, snapshot_id: str) -> AnalysisSnapshotView:
        snapshot = next(
            (
                item
                for item in self._journal.snapshots()
                if item.snapshot_id == snapshot_id and self._policy.snapshot(item)
            ),
            None,
        )
        if snapshot is None:
            raise AccessDenied("analysis:access_denied")
        findings = tuple(
            f.model_copy(update={"reason": ""})
            for f in snapshot.findings
            if self._policy.finding(f)
        )
        refs = {
            ref
            for ref in (*snapshot.event.input_refs, *snapshot.event.output_refs)
            if self._policy.value(ref)
        }
        flow = tuple(
            item.model_copy(
                update={
                    "parents": tuple(
                        edge for edge in item.parents if self._policy.value(edge.parent)
                    )
                }
            )
            for item in snapshot.flow
            if item.value_ref in refs
        )
        event = snapshot.event.model_copy(
            update={
                "metadata": freeze({}),
                "parent_event_ids": (),
                "destination": "",
                "input_refs": tuple(
                    ref for ref in snapshot.event.input_refs if ref in refs
                ),
                "output_refs": tuple(
                    ref for ref in snapshot.event.output_refs if ref in refs
                ),
            }
        )
        return AnalysisSnapshotView(
            snapshot=snapshot.model_copy(
                update={"event": event, "findings": findings, "flow": flow}
            ),
            partial=len(findings) != len(snapshot.findings)
            or len(refs) != len(snapshot.flow),
        )

    async def aget_snapshot(self, snapshot_id: str) -> AnalysisSnapshotView:
        return self.get_snapshot(snapshot_id)

    def subscribe(
        self, query: AnalysisQuery, after_cursor: str | None = None
    ) -> AnalysisSubscription:
        return self._hub.subscribe(query, self._policy, after_cursor)
