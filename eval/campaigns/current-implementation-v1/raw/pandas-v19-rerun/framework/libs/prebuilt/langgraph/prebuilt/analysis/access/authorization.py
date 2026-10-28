"""Authenticated composition-root capabilities; no tenant ID as bearer authority."""

from collections.abc import Callable
from dataclasses import dataclass

from langgraph.prebuilt.analysis.contracts import (
    AnalysisFinding,
    AnalysisSnapshot,
    ValueRef,
)
from langgraph.prebuilt.analysis.errors import AccessDenied
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore


@dataclass(frozen=True, slots=True)
class AccessContext:
    """Root supplies authenticated identity, revocation and resource decisions."""

    principal_id: str
    tenant_id: str
    session_ids: frozenset[str]
    authorize_resource: Callable[[ValueRef], bool]
    is_active: Callable[[], bool]
    raw_content: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_ids", frozenset(self.session_ids))
        if not self.principal_id or not self.tenant_id:
            raise ValueError("analysis:missing_authenticated_identity")


class AccessPolicy:
    def __init__(self, context: AccessContext, store: SqliteProvenanceStore) -> None:
        self.context, self.store = context, store

    def check(self) -> None:
        if not self.context.is_active():
            raise AccessDenied("analysis:access_revoked")

    def value(self, ref: ValueRef) -> bool:
        self.check()
        value = self.store.get(ref)
        return (
            value.tenant_id == self.context.tenant_id
            and value.session_id in self.context.session_ids
            and self.context.authorize_resource(ref)
        )

    def snapshot(self, snapshot: AnalysisSnapshot) -> bool:
        self.check()
        return (
            snapshot.principal_id == self.context.principal_id
            and snapshot.event.tenant_id == self.context.tenant_id
            and snapshot.event.session_id in self.context.session_ids
        )

    def finding(self, finding: AnalysisFinding) -> bool:
        return bool(finding.subject_refs) and all(
            self.value(ref) for ref in (*finding.subject_refs, *finding.evidence_refs)
        )
