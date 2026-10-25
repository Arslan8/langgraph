"""Immutable public query, page and notification contracts."""

from pydantic import Field

from langgraph.prebuilt.analysis.contracts import (
    AnalysisFinding,
    AnalysisSnapshot,
    FlowView,
    Record,
    Status,
    ValueRef,
)
from langgraph.prebuilt.analysis.provenance.records import StoredValue


class AnalysisQuery(Record):
    run_id: str | None = None
    invocation_id: str | None = None
    value_ref: ValueRef | None = None
    analyzer_id: str | None = None
    finding_code: str | None = None
    event_name: str | None = None


class FindingPage(Record):
    records: tuple[AnalysisFinding, ...]
    revision: int
    cursor: str | None = None
    partial: bool = False
    statuses: tuple[Status, ...]


class LabelView(Record):
    record: FlowView
    revision: int
    partial: bool = False


class ProvenancePage(Record):
    records: tuple[StoredValue, ...]
    revision: int
    cursor: str | None = None
    partial: bool = False


class AnalysisSnapshotView(Record):
    snapshot: AnalysisSnapshot
    partial: bool = False


class AnalysisNotification(Record):
    notification_id: str
    event_id: str
    invocation_id: str
    snapshot_id: str
    record_revision: int
    completion_status: Status
    run_id: str
    cursor: str
    finding_ids: tuple[str, ...]
    value_refs: tuple[ValueRef, ...]
    partial: bool = False


class PageLimit(Record):
    limit: int = Field(default=100, ge=1, le=1000)
