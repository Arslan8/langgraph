"""Bind protected metadata to the existing authenticated checkpoint mechanism."""

import json

from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable
from langgraph.prebuilt.analysis.provenance.records import StoredValue
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
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
        findings_json: str = "[]",
    ) -> CheckpointEnvelope:
        payload = {
            "schema_version": 1,
            "policy_version": self.policy_version,
            "domain_digest": self.store.domains.digest,
            "role_digest": self.role_digest,
            "values": self.store.export(refs),
            "findings": findings_json,
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
        with self.store.transaction():
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
        return roots
