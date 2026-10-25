"""Read-only analyzer capabilities scoped to runtime-validated references."""

from dataclasses import dataclass

from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.errors import AccessDenied
from langgraph.prebuilt.analysis.provenance.store import ProvenanceStore


@dataclass(frozen=True, slots=True)
class ScopedValues:
    store: ProvenanceStore
    refs: frozenset[ValueRef]
    content_access: bool

    def resolve(self, ref: ValueRef) -> bytes:
        if not self.content_access or ref not in self.refs:
            raise AccessDenied("analysis:content_access_denied")
        return self.store.resolve(ref)

    def ancestors(self, ref: ValueRef) -> tuple[ValueRef, ...]:
        if ref not in self.refs:
            raise AccessDenied("analysis:provenance_access_denied")
        return tuple(
            parent for parent in self.store.ancestors(ref) if parent in self.refs
        )
