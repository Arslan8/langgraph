"""Canonical committed findings and snapshots, sharing the provenance transaction."""

from __future__ import annotations

import json
from uuid import uuid4

from langgraph.prebuilt.analysis.contracts import (
    AnalysisEvent,
    AnalysisFinding,
    AnalysisResult,
    AnalysisSnapshot,
    DependencyProposal,
    FlowView,
    ValueRef,
)
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable, StorageExhausted
from langgraph.prebuilt.analysis.provenance.records import DependencyEdge
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.analysis.serialization import canonical


class AnalysisJournal:
    def __init__(self, store: SqliteProvenanceStore) -> None:
        self.store = store
        with store._lock:
            store._db.executescript("""
                CREATE TABLE IF NOT EXISTS analysis_findings (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, session TEXT NOT NULL, run TEXT NOT NULL, event TEXT NOT NULL, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS analysis_snapshots (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, session TEXT NOT NULL, run TEXT NOT NULL, revision INTEGER NOT NULL, record TEXT NOT NULL);
            """)

    def relevant_findings(self, event: AnalysisEvent) -> tuple[AnalysisFinding, ...]:
        scope = {
            ref
            for root in (*event.input_refs, *event.output_refs)
            for ref in (root, *self.store.ancestors(root))
        }
        with self.store._lock:
            rows = self.store._db.execute(
                "SELECT record FROM analysis_findings WHERE tenant=? ORDER BY id",
                (event.tenant_id,),
            ).fetchall()
            return tuple(
                f
                for row in rows
                if set(
                    (f := AnalysisFinding.model_validate_json(row[0])).subject_refs
                ).intersection(scope)
            )

    def flow(self, ref: ValueRef) -> FlowView:
        values = [self.store.get(item) for item in (ref, *self.store.ancestors(ref))]
        domains = self.store.domains.combine(
            [json.loads(value.domains_json) for value in values]
        )
        confidentiality = {
            label for value in values for label in value.labels.confidentiality
        }
        confidentiality.update(domains.get("analysis.confidentiality", ()))
        return FlowView(
            value_ref=ref,
            confidentiality=frozenset(confidentiality),
            integrity="trusted"
            if all(value.labels.integrity == "trusted" for value in values)
            else "low",
            risks=frozenset(domains.get("analysis.risks", ())),
            domains_json=canonical(domains),
            parents=tuple(
                DependencyProposal(subject=ref, parent=edge.parent, kind=edge.kind)
                for edge in values[0].dependencies
                if edge.kind != "containment"
            ),
        )

    def commit_result(self, event: AnalysisEvent, result: AnalysisResult) -> None:
        store = self.store
        with store.transaction():
            count = store._db.execute(
                "SELECT count(*) FROM analysis_findings WHERE tenant=? AND run=?",
                (event.tenant_id, event.run_id),
            ).fetchone()[0]
            if count + len(result.findings) > store.max_records:
                raise StorageExhausted("analysis:storage_exhausted")
            revision = store._next_revision()
            for proposal in result.annotation_proposals:
                value = store.get(proposal.subject)
                labels = json.loads(value.domains_json)
                candidate = json.loads(proposal.label_json)
                domain = store.domains.domains.get(proposal.domain)
                if domain is None:
                    raise AnalysisUnavailable("analysis:unknown_domain")
                domain.validate(candidate)
                if proposal.domain in labels and not domain.is_at_least_as_restrictive(
                    candidate, labels[proposal.domain]
                ):
                    raise AnalysisUnavailable("analysis:label_relaxation")
                labels[proposal.domain] = candidate
                updated = value.model_copy(
                    update={"domains_json": canonical(labels), "revision": revision}
                )
                store._db.execute(
                    "UPDATE analysis_values SET record=? WHERE id=?",
                    (updated.model_dump_json(), value.ref.value_id),
                )
            for proposal in result.dependency_proposals:
                value = store.get(proposal.subject)
                if (
                    proposal.subject == proposal.parent
                    or proposal.subject in store.ancestors(proposal.parent)
                ):
                    raise AnalysisUnavailable("analysis:dependency_cycle")
                updated = value.model_copy(
                    update={
                        "dependencies": tuple(
                            dict.fromkeys(
                                (
                                    *value.dependencies,
                                    DependencyEdge(
                                        parent=proposal.parent, kind=proposal.kind
                                    ),
                                )
                            )
                        ),
                        "revision": revision,
                    }
                )
                store._db.execute(
                    "UPDATE analysis_values SET record=? WHERE id=?",
                    (updated.model_dump_json(), value.ref.value_id),
                )
            for finding in result.findings:
                store._db.execute(
                    "INSERT INTO analysis_findings VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        finding.finding_id,
                        event.tenant_id,
                        event.session_id,
                        event.run_id,
                        event.event_id,
                        finding.model_dump_json(),
                    ),
                )

    def snapshot(
        self,
        event: AnalysisEvent,
        *,
        principal_id: str,
        policy_version: str,
        request_digest: str,
        status: str,
        unavailable: tuple[str, ...] = (),
    ) -> AnalysisSnapshot:
        with self.store.transaction():
            count = self.store._db.execute(
                "SELECT count(*) FROM analysis_snapshots WHERE tenant=? AND run=?",
                (event.tenant_id, event.run_id),
            ).fetchone()[0]
            if count >= self.store.max_records:
                raise StorageExhausted("analysis:storage_exhausted")
            snapshot = AnalysisSnapshot(
                snapshot_id=str(uuid4()),
                event=event,
                findings=self.relevant_findings(event),
                flow=tuple(
                    self.flow(ref) for ref in (*event.input_refs, *event.output_refs)
                ),
                status=status,
                request_digest=request_digest,
                principal_id=principal_id,
                invocation_id=event.invocation_id,
                attempt_id=event.attempt_id,
                policy_version=policy_version,
                domain_digest=self.store.domains.digest,
                revision=self.store._next_revision(),
                unavailable_analyzers=unavailable,
            )
            self.store._db.execute(
                "INSERT INTO analysis_snapshots VALUES (?, ?, ?, ?, ?, ?)",
                (
                    snapshot.snapshot_id,
                    event.tenant_id,
                    event.session_id,
                    event.run_id,
                    snapshot.revision,
                    snapshot.model_dump_json(),
                ),
            )
            return snapshot

    def snapshots(self) -> tuple[AnalysisSnapshot, ...]:
        with self.store._lock:
            return tuple(
                AnalysisSnapshot.model_validate_json(row[0])
                for row in self.store._db.execute(
                    "SELECT record FROM analysis_snapshots ORDER BY revision"
                )
            )
