"""Transactional metadata storage; network/plugin work never holds a transaction."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from threading import RLock
from uuid import uuid4

from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.errors import MissingValue, StorageExhausted
from langgraph.prebuilt.analysis.provenance.domains import DomainRegistry
from langgraph.prebuilt.analysis.provenance.propagation import transfer
from langgraph.prebuilt.analysis.provenance.records import (
    DependencyEdge,
    StoredValue,
    ValueRecord,
)
from langgraph.prebuilt.analysis.serialization import canonical


class SqliteProvenanceStore:
    """WAL-backed provenance DAG. The DB and its credentials are trusted storage."""

    def __init__(
        self,
        path: str,
        *,
        domains: DomainRegistry | None = None,
        max_records: int = 100000,
    ) -> None:
        if max_records <= 0:
            raise ValueError("analysis:invalid_capacity")
        self.domains = domains or DomainRegistry()
        self.max_records = max_records
        self._lock = RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS analysis_values (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run TEXT NOT NULL, record TEXT NOT NULL, content BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS analysis_revision (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, domain_digest TEXT NOT NULL);
        """)
        with self.transaction():
            self._db.execute(
                "INSERT OR IGNORE INTO analysis_revision VALUES (1, 0, ?)",
                (self.domains.digest,),
            )
            if (
                self._db.execute(
                    "SELECT domain_digest FROM analysis_revision WHERE id=1"
                ).fetchone()[0]
                != self.domains.digest
            ):
                raise ValueError("analysis:domain_configuration_mismatch")

    @contextmanager
    def transaction(self):
        """Serialize short metadata transactions, rolling back all failures."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    @property
    def revision(self) -> int:
        with self._lock:
            return self._db.execute(
                "SELECT revision FROM analysis_revision WHERE id=1"
            ).fetchone()[0]

    def _next_revision(self) -> int:
        self._db.execute("UPDATE analysis_revision SET revision=revision+1 WHERE id=1")
        return self.revision

    def register(self, value_record: ValueRecord) -> ValueRef:
        return self.derive((), value_record, "admit")

    def derive(
        self,
        inputs: tuple[ValueRef, ...],
        output: ValueRecord,
        operation: str,
        *,
        edges: tuple[DependencyEdge, ...] = (),
    ) -> ValueRef:
        if not operation:
            raise ValueError("analysis:missing_operation")
        dependencies = tuple(
            dict.fromkeys((*[DependencyEdge(parent=ref) for ref in inputs], *edges))
        )
        with self.transaction():
            count = self._db.execute(
                "SELECT count(*) FROM analysis_values WHERE tenant=? AND run=?",
                (output.tenant_id, output.run_id),
            ).fetchone()[0]
            if count >= self.max_records:
                raise StorageExhausted("analysis:storage_exhausted")
            parents = [self.get(edge.parent) for edge in dependencies]
            if any(parent.tenant_id != output.tenant_id for parent in parents):
                raise MissingValue("analysis:inaccessible_value")
            # Containment is structural; whole-container consumers explicitly join fields.
            influenced = [
                parent
                for parent, edge in zip(parents, dependencies)
                if edge.kind != "containment"
            ]
            output = transfer(influenced, output, self.domains)
            self.domains.validate(json.loads(output.domains_json))
            ref = ValueRef(
                value_id=str(uuid4()),
                version=1,
                content_digest=hashlib.sha256(output.content).hexdigest(),
                media_type=output.media_type,
            )
            record = StoredValue(
                ref=ref,
                tenant_id=output.tenant_id,
                session_id=output.session_id,
                run_id=output.run_id,
                labels=output.labels,
                domains_json=output.domains_json,
                origin_refs=output.origin_refs,
                dependencies=dependencies,
                operation=operation,
                revision=self._next_revision(),
            )
            self._db.execute(
                "INSERT INTO analysis_values VALUES (?, ?, ?, ?, ?)",
                (
                    ref.value_id,
                    output.tenant_id,
                    output.run_id,
                    record.model_dump_json(),
                    output.content,
                ),
            )
        return ref

    def get(self, value_ref: ValueRef) -> StoredValue:
        with self._lock:
            row = self._db.execute(
                "SELECT record FROM analysis_values WHERE id=?", (value_ref.value_id,)
            ).fetchone()
            if row is None:
                raise MissingValue("analysis:missing_value")
            record = StoredValue.model_validate_json(row[0])
            if record.ref != value_ref:
                raise MissingValue("analysis:reference_mismatch")
            return record

    def resolve(self, value_ref: ValueRef) -> bytes:
        with self._lock:
            self.get(value_ref)
            content = self._db.execute(
                "SELECT content FROM analysis_values WHERE id=?", (value_ref.value_id,)
            ).fetchone()[0]
            if hashlib.sha256(content).hexdigest() != value_ref.content_digest:
                raise MissingValue("analysis:content_mismatch")
            return content

    def ancestors(self, value_ref: ValueRef) -> tuple[ValueRef, ...]:
        with self._lock:
            seen: dict[str, ValueRef] = {}
            pending = [value_ref]
            while pending:
                value = self.get(pending.pop())
                for edge in value.dependencies:
                    if edge.kind != "containment" and edge.parent.value_id not in seen:
                        seen[edge.parent.value_id] = edge.parent
                        pending.append(edge.parent)
            return tuple(seen[key] for key in sorted(seen))

    def export(self, refs: tuple[ValueRef, ...]) -> str:
        """Export metadata and bytes only to trusted checkpoint integration."""
        with self._lock:
            included = {ref for root in refs for ref in (root, *self.ancestors(root))}
            # Preserve structural fields too, even when they are not influence edges.
            pending = list(included)
            while pending:
                for edge in self.get(pending.pop()).dependencies:
                    if edge.parent not in included:
                        included.add(edge.parent)
                        pending.append(edge.parent)
            return canonical(
                [
                    {
                        "record": self.get(ref).model_dump(mode="json"),
                        "content": self.resolve(ref).hex(),
                    }
                    for ref in sorted(included, key=lambda r: r.value_id)
                ]
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def run_refs(self, tenant_id: str, run_id: str) -> tuple[ValueRef, ...]:
        """Conservative run-context bound for opaque framework operations."""
        with self._lock:
            return tuple(
                StoredValue.model_validate_json(row[0]).ref
                for row in self._db.execute(
                    "SELECT record FROM analysis_values WHERE tenant=? AND run=? ORDER BY id",
                    (tenant_id, run_id),
                )
            )
