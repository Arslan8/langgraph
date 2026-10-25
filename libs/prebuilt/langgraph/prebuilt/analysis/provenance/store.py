"""Protected storage protocol. Handles belong to the trusted composition root."""

from typing import Protocol

from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.provenance.records import (
    DependencyEdge,
    StoredValue,
    ValueRecord,
)


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


# Deferred construction keeps the protocol independent of the SQLite backend.
class MemoryProvenanceStore:
    """Isolated, transactional in-memory store using SQLite's memory backend."""

    def __new__(cls, **kwargs):
        from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore

        return SqliteProvenanceStore(":memory:", **kwargs)
