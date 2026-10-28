"""Protected storage protocol. Handles belong to the trusted composition root."""

from typing import Protocol

from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.provenance.domains import DomainRegistry
from langgraph.prebuilt.analysis.provenance.records import (
    DependencyEdge,
    StoredValue,
    ValueRecord,
)
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore


class ProvenanceStore(Protocol):
    def register(self, value_record: ValueRecord) -> ValueRef: ...
    def derive(
        self,
        inputs: tuple[ValueRef, ...],
        output: ValueRecord,
        operation: str,
        *,
        edges: tuple[DependencyEdge, ...] = (),
    ) -> ValueRef: ...
    def ancestors(self, value_ref: ValueRef) -> tuple[ValueRef, ...]: ...
    def get(self, value_ref: ValueRef) -> StoredValue: ...
    def resolve(self, value_ref: ValueRef) -> bytes: ...


class MemoryProvenanceStore(SqliteProvenanceStore):
    """Isolated transactional memory backend with the persistent store's semantics."""

    def __init__(
        self, *, domains: DomainRegistry | None = None, max_records: int = 100000
    ) -> None:
        super().__init__(":memory:", domains=domains, max_records=max_records)
