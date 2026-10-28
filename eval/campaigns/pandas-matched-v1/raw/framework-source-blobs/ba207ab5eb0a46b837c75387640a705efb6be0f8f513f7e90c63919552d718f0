"""Bind protected metadata to the existing authenticated checkpoint mechanism."""

import json

from langgraph.prebuilt.analysis.contracts import (
    AnalysisFinding,
    AnalysisSnapshot,
    ValueRef,
)
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable
from langgraph.prebuilt.analysis.journal import AnalysisJournal
from langgraph.prebuilt.analysis.provenance.records import StoredValue
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.analysis.serialization import canonical
from langgraph.prebuilt.security.object_manager import (
    CheckpointEnvelope,
    authenticate_checkpoint,
    seal_checkpoint,
)
from langgraph.prebuilt.security.types import Principal


class CheckpointBinding:
    def __init__(
        self,
        store: SqliteProvenanceStore,
        key: bytes,
        policy_version: str,
        role_digest: str = "none",
    ) -> None:
        self.store, self.key = store, bytes(key)
        self.policy_version, self.role_digest = policy_version, role_digest

    def save(
        self,
        principal: Principal,
        refs: tuple[ValueRef, ...],
        *,
        checkpoint_id: str,
        sequence: int = 0,
        previous_hash: str = "",
    ) -> CheckpointEnvelope:
        AnalysisJournal(self.store)
        tenants = {self.store.get(ref).tenant_id for ref in refs}
        with self.store._lock:
            journal = {
                "findings": [
                    list(row)
                    for row in self.store._db.execute("SELECT * FROM analysis_findings")
                    if row[1] in tenants
                ],
                "snapshots": [
                    list(row)
                    for row in self.store._db.execute(
                        "SELECT * FROM analysis_snapshots"
                    )
                    if row[1] in tenants
                ],
            }
        payload = {
            "schema_version": 1,
            "policy_version": self.policy_version,
            "domain_digest": self.store.domains.digest,
            "role_digest": self.role_digest,
            "values": self.store.export(refs),
            "findings": canonical(journal),
            "roots": [ref.model_dump() for ref in refs],
        }
        return seal_checkpoint(
            self.key,
            checkpoint_id=checkpoint_id,
            principal=principal,
            sequence=sequence,
            previous_hash=previous_hash,
            payload=payload,
        )

    def restore(
        self, principal: Principal, checkpoint: CheckpointEnvelope
    ) -> tuple[ValueRef, ...]:
        authenticate_checkpoint(self.key, checkpoint, principal)
        payload = checkpoint.payload
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "policy_version",
            "domain_digest",
            "role_digest",
            "values",
            "findings",
            "roots",
        }:
            raise AnalysisUnavailable("analysis:missing_checkpoint_metadata")
        if (
            payload["schema_version"],
            payload["policy_version"],
            payload["domain_digest"],
            payload["role_digest"],
        ) != (1, self.policy_version, self.store.domains.digest, self.role_digest):
            raise AnalysisUnavailable("analysis:checkpoint_configuration_mismatch")
        records = [
            (StoredValue.model_validate(item["record"]), bytes.fromhex(item["content"]))
            for item in json.loads(payload["values"])
        ]
        roots = tuple(ValueRef.model_validate(item) for item in payload["roots"])
        AnalysisJournal(self.store)
        journal = json.loads(payload["findings"])
        if set(journal) != {"findings", "snapshots"}:
            raise AnalysisUnavailable("analysis:invalid_checkpoint_journal")
        with self.store.transaction():
            for tenant, run in {
                (record.tenant_id, record.run_id) for record, _ in records
            }:
                count = self.store._db.execute(
                    "SELECT count(*) FROM analysis_values WHERE tenant=? AND run=?",
                    (tenant, run),
                ).fetchone()[0]
                new = sum(
                    1
                    for record, _ in records
                    if record.tenant_id == tenant
                    and record.run_id == run
                    and self.store._db.execute(
                        "SELECT 1 FROM analysis_values WHERE id=?",
                        (record.ref.value_id,),
                    ).fetchone()
                    is None
                )
                if count + new > self.store.max_records:
                    raise AnalysisUnavailable("analysis:checkpoint_capacity")
            for record, content in records:
                self.store.domains.validate(json.loads(record.domains_json))
                old = self.store._db.execute(
                    "SELECT record, content FROM analysis_values WHERE id=?",
                    (record.ref.value_id,),
                ).fetchone()
                if old is not None and (
                    StoredValue.model_validate_json(old[0]) != record
                    or old[1] != content
                ):
                    raise AnalysisUnavailable("analysis:checkpoint_record_mismatch")
                self.store._db.execute(
                    "INSERT OR IGNORE INTO analysis_values VALUES (?, ?, ?, ?, ?)",
                    (
                        record.ref.value_id,
                        record.tenant_id,
                        record.run_id,
                        record.model_dump_json(),
                        content,
                    ),
                )
                self.store._db.execute(
                    "UPDATE analysis_revision SET revision=MAX(revision, ?) WHERE id=1",
                    (record.revision,),
                )
            for record, _ in records:
                self.store.resolve(record.ref)
                for edge in record.dependencies:
                    if self.store.get(edge.parent).tenant_id != record.tenant_id:
                        raise AnalysisUnavailable("analysis:checkpoint_tenant_mismatch")
            for ref in roots:
                self.store.get(ref)
            for row in journal["findings"]:
                finding = AnalysisFinding.model_validate_json(row[5])
                if row[0] != finding.finding_id:
                    raise AnalysisUnavailable("analysis:checkpoint_finding_identity")
                self.store._db.execute(
                    "INSERT OR IGNORE INTO analysis_findings VALUES (?, ?, ?, ?, ?, ?)",
                    row,
                )
            for row in journal["snapshots"]:
                snapshot = AnalysisSnapshot.model_validate_json(row[5])
                if (
                    row[0] != snapshot.snapshot_id
                    or row[4] != snapshot.revision
                    or snapshot.policy_version != self.policy_version
                ):
                    raise AnalysisUnavailable("analysis:checkpoint_snapshot_identity")
                self.store._db.execute(
                    "INSERT OR IGNORE INTO analysis_snapshots VALUES (?, ?, ?, ?, ?, ?)",
                    row,
                )
                # Inspection pages use the store revision as their upper bound.
                # Imported snapshots can be newer than any imported value record.
                self.store._db.execute(
                    "UPDATE analysis_revision SET revision=MAX(revision, ?) WHERE id=1",
                    (snapshot.revision,),
                )
        return roots
