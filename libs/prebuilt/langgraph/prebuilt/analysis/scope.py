"""Detached read-only analyzer capabilities; no store or coordinator handle."""

from types import MappingProxyType

from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.errors import AccessDenied
from langgraph.prebuilt.analysis.provenance.store import ProvenanceStore


class ScopedValues:
    __slots__ = ("refs", "_content", "_parents")

    def __init__(
        self, store: ProvenanceStore, refs: frozenset[ValueRef], content_access: bool
    ):
        self.refs = refs
        self._content = MappingProxyType(
            {ref: store.resolve(ref) for ref in refs} if content_access else {}
        )
        self._parents = MappingProxyType(
            {
                ref: tuple(parent for parent in store.ancestors(ref) if parent in refs)
                for ref in refs
            }
        )

    def resolve(self, ref: ValueRef) -> bytes:
        if ref not in self._content:
            raise AccessDenied("analysis:content_access_denied")
        return self._content[ref]

    def ancestors(self, ref: ValueRef) -> tuple[ValueRef, ...]:
        if ref not in self._parents:
            raise AccessDenied("analysis:provenance_access_denied")
        return self._parents[ref]
