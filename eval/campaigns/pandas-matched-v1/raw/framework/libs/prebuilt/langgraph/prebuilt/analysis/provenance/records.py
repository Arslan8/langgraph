"""Protected value records and typed provenance edges."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from langgraph.prebuilt.analysis.contracts import Record, ValueRef
from langgraph.prebuilt.security.objects import SecurityLabels


@dataclass(frozen=True, slots=True)
class ValueRecord:
    """Trusted admission request. Store assigns the identity, never the producer."""

    tenant_id: str
    session_id: str
    run_id: str
    content: bytes
    media_type: str = "application/json"
    labels: SecurityLabels = SecurityLabels(integrity="unknown")
    domains_json: str = "{}"
    origin_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.session_id, self.run_id, self.media_type)):
            raise ValueError("analysis:missing_identity")
        object.__setattr__(self, "content", bytes(self.content))
        object.__setattr__(self, "origin_refs", tuple(self.origin_refs))


class DependencyEdge(Record):
    parent: ValueRef
    kind: Literal["data", "control", "containment"] = "data"
    selector: str = ""


class StoredValue(Record):
    ref: ValueRef
    tenant_id: str
    session_id: str
    run_id: str
    labels: SecurityLabels
    domains_json: str
    origin_refs: tuple[str, ...]
    dependencies: tuple[DependencyEdge, ...]
    operation: str = Field(min_length=1)
    revision: int = Field(ge=1)
