"""Stable filter and revision-bound pagination helpers."""

import base64
import json

from langgraph.prebuilt.analysis.access.contracts import AnalysisQuery
from langgraph.prebuilt.analysis.contracts import AnalysisFinding, AnalysisSnapshot
from langgraph.prebuilt.analysis.errors import CursorExpired
from langgraph.prebuilt.analysis.serialization import canonical, digest


def matches(snapshot: AnalysisSnapshot, query: AnalysisQuery) -> bool:
    event = snapshot.event
    return all(
        (
            query.run_id is None or event.run_id == query.run_id,
            query.invocation_id is None or event.invocation_id == query.invocation_id,
            query.event_name is None or event.event_name == query.event_name,
            query.value_ref is None
            or query.value_ref in (*event.input_refs, *event.output_refs),
        )
    )


def matches_finding(finding: AnalysisFinding, query: AnalysisQuery) -> bool:
    return (
        (query.analyzer_id is None or query.analyzer_id == finding.analyzer_id)
        and (query.finding_code is None or query.finding_code == finding.code)
        and (query.value_ref is None or query.value_ref in finding.subject_refs)
    )


def encode_cursor(revision: int, offset: int, binding: str) -> str:
    return base64.urlsafe_b64encode(
        canonical([revision, offset, binding]).encode()
    ).decode()


def decode_cursor(cursor: str | None, revision: int, binding: str) -> tuple[int, int]:
    if cursor is None:
        return revision, 0
    try:
        old, offset, bound = json.loads(base64.urlsafe_b64decode(cursor))
        if (
            type(old) is not int
            or type(offset) is not int
            or old < 0
            or old > revision
            or offset < 0
            or bound != binding
        ):
            raise ValueError
        return old, offset
    except Exception as exc:
        raise CursorExpired("analysis:invalid_cursor") from exc


def query_binding(query: AnalysisQuery) -> str:
    return digest(query.model_dump(mode="json"))
