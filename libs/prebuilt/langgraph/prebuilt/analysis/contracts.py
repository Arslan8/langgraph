"""Versioned public records. Analyzers receive scoped capabilities, never state."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from langgraph.prebuilt.analysis.serialization import freeze, thaw

Status = Literal["pending", "complete", "failed", "unavailable"]
Phase = Literal["before", "after"]


class Record(BaseModel):
    """Immutable, extra-field-forbidding wire record; schema version is explicit."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1] = 1


class ValueRef(Record):
    """Runtime-issued identity; equal content never implies equal identity."""

    value_id: str = Field(min_length=1)
    version: int = Field(ge=1, strict=True)
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str = Field(min_length=1)


class AnalysisEvent(Record):
    event_id: str = Field(min_length=1)
    event_name: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    phase: Phase
    tenant_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    invocation_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    parent_event_ids: tuple[str, ...] = ()
    input_refs: tuple[ValueRef, ...] = ()
    output_refs: tuple[ValueRef, ...] = ()
    destination: str = ""
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def immutable_metadata(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return freeze(value)

    @field_serializer("metadata")
    def serialize_metadata(self, value: Mapping[str, Any]) -> Any:
        return thaw(value)

    def wire(self) -> dict[str, Any]:
        return {
            **self.model_dump(exclude={"metadata"}),
            "metadata": thaw(self.metadata),
        }


class AnalysisFinding(Record):
    event_id: str = ""
    event_name: str = ""
    finding_id: str = Field(min_length=1)
    analyzer_id: str = Field(min_length=1)
    analyzer_version: str = Field(min_length=1)
    code: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    subject_refs: tuple[ValueRef, ...]
    evidence_refs: tuple[ValueRef, ...] = ()
    status: Status
    score: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    reason: str = Field(default="", max_length=512)
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class AnnotationProposal(Record):
    subject: ValueRef
    domain: str = Field(min_length=1)
    label_json: str


class DependencyProposal(Record):
    subject: ValueRef
    parent: ValueRef
    kind: Literal["data", "control"] = "data"


class AnalysisResult(Record):
    findings: tuple[AnalysisFinding, ...] = ()
    annotation_proposals: tuple[AnnotationProposal, ...] = ()
    dependency_proposals: tuple[DependencyProposal, ...] = ()


class FlowView(Record):
    value_ref: ValueRef
    confidentiality: frozenset[str] = frozenset()
    integrity: str = "unknown"
    risks: frozenset[str] = frozenset()
    domains_json: str = "{}"
    parents: tuple[DependencyProposal, ...] = ()


class AnalysisSnapshot(Record):
    snapshot_id: str = Field(min_length=1)
    event: AnalysisEvent
    findings: tuple[AnalysisFinding, ...]
    flow: tuple[FlowView, ...]
    status: Status
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal_id: str = Field(min_length=1)
    invocation_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    domain_digest: str = Field(min_length=1)
    revision: int = Field(ge=0)
    unavailable_analyzers: tuple[str, ...] = ()


class ValueResolver(Protocol):
    """Content capability scoped to the event and separately authorized."""

    def resolve(self, ref: ValueRef) -> bytes: ...


class ProvenanceQueries(Protocol):
    def ancestors(self, ref: ValueRef) -> tuple[ValueRef, ...]: ...


class CancellationSignal(Protocol):
    def is_set(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    event: AnalysisEvent
    resolver: ValueResolver
    provenance: ProvenanceQueries
    prior_findings: tuple[AnalysisFinding, ...]
    deadline: float
    cancellation: CancellationSignal
    analyzer_id: str = ""
    analyzer_version: str = "unversioned"
    configuration_digest: str = "0" * 64

    def finding(
        self,
        *,
        code: str,
        subject_refs: tuple[ValueRef, ...] | None = None,
        evidence_refs: tuple[ValueRef, ...] = (),
        status: Status = "complete",
        score: float | None = None,
        reason: str = "",
        configuration_digest: str | None = None,
    ) -> AnalysisFinding:
        """Create a finding with runtime-owned identity and event metadata.

        The default configuration digest identifies the fixed run policy. An
        analyzer with its own configuration can supply its digest explicitly.
        Runtime scope and identity validation still applies at commit.
        """
        return AnalysisFinding(
            finding_id=str(uuid4()),
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            event_id=self.event.event_id,
            event_name=self.event.event_name,
            code=code,
            subject_refs=subject_refs
            if subject_refs is not None
            else (*self.event.input_refs, *self.event.output_refs),
            evidence_refs=evidence_refs,
            status=status,
            score=score,
            reason=reason,
            configuration_digest=configuration_digest or self.configuration_digest,
        )


class Analyzer(Protocol):
    """Trusted extension. Async-only implementations must reject sync invocation."""

    def analyze(
        self, event: AnalysisEvent, context: AnalysisContext
    ) -> AnalysisResult: ...

    async def aanalyze(
        self, event: AnalysisEvent, context: AnalysisContext
    ) -> AnalysisResult: ...


class Runtime(Protocol):
    def process(self, event: AnalysisEvent) -> AnalysisSnapshot: ...

    async def aprocess(self, event: AnalysisEvent) -> AnalysisSnapshot: ...
