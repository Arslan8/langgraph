"""Immutable framework-object requests mediated by the object manager."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.types import Decision, Principal, Tool


class DispatchKind(str, Enum):
    """Framework dispatch forms that transfer a principal."""

    SUBGRAPH = "subgraph"
    SEND = "send"
    PARALLEL_BRANCH = "parallel_branch"
    SUBAGENT = "subagent"
    NESTED_AGENT = "nested_agent"


class StateOperation(str, Enum):
    """Operations over graph state, checkpoints, and store resources."""

    WRITE = "write"
    RESTORE = "restore"
    TOOL_READ = "tool_read"
    MODEL_READ = "model_read"
    STORE_READ = "store_read"
    STORE_WRITE = "store_write"
    CHECKPOINT_READ = "checkpoint_read"
    CHECKPOINT_WRITE = "checkpoint_write"


@dataclass(frozen=True, slots=True)
class SecurityLabels:
    """Confidentiality compartments and integrity level attached to data."""

    confidentiality: frozenset[str] = frozenset()
    integrity: str = "trusted"

    def __post_init__(self) -> None:
        if not self.integrity:
            raise ValueError("integrity label must be non-empty")
        if any(not label for label in self.confidentiality):
            raise ValueError("confidentiality labels must be non-empty")
        object.__setattr__(self, "confidentiality", frozenset(self.confidentiality))


@dataclass(frozen=True, slots=True)
class DispatchRequest:
    """One explicit authority transfer to a child unit of work."""

    kind: DispatchKind
    parent: Principal
    child: Principal
    dispatch_id: str

    def __post_init__(self) -> None:
        if not self.dispatch_id:
            raise ValueError("dispatch_id must be non-empty")


@dataclass(frozen=True, slots=True)
class ToolRegistryRequest:
    """Static or dynamic tool registration and override request."""

    tool: Tool
    dynamic: bool = False
    override: bool = False


@dataclass(frozen=True, slots=True)
class StateRequest:
    """One operation over a named state channel, store key, or checkpoint."""

    operation: StateOperation
    resource: str
    owner_id: str
    tool_name: str = ""
    labels: SecurityLabels = SecurityLabels()
    value: Any = field(default=None, compare=False, repr=False)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.resource or not self.owner_id:
            raise ValueError("state resource and owner must be non-empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def replace_value(self, value: Any) -> StateRequest:
        """Return the same request identity carrying a narrowed value."""
        return replace(self, value=value)


@dataclass(frozen=True, slots=True)
class LabeledValue:
    """A value and labels visible to model and output policy hooks."""

    name: str
    value: Any = field(compare=False, repr=False)
    labels: SecurityLabels = SecurityLabels()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("labeled value name must be non-empty")


@dataclass(frozen=True, slots=True)
class ModelInvocationRequest:
    """Context presented for one model invocation before prompt assembly."""

    model: str
    context: tuple[LabeledValue, ...]
    invocation_id: str

    def __post_init__(self) -> None:
        if not self.model or not self.invocation_id:
            raise ValueError("model and invocation_id must be non-empty")
        object.__setattr__(self, "context", tuple(self.context))


@dataclass(frozen=True, slots=True)
class OutputRequest:
    """Content proposed for emission to a destination."""

    destination: str
    content: Any = field(compare=False, repr=False)
    labels: SecurityLabels = SecurityLabels()
    clearance: frozenset[str] = frozenset()
    output_id: str = ""

    def __post_init__(self) -> None:
        if not self.destination or not self.output_id:
            raise ValueError("destination and output_id must be non-empty")
        object.__setattr__(self, "clearance", frozenset(self.clearance))


FrameworkRequest = (
    DispatchRequest
    | ToolRegistryRequest
    | StateRequest
    | ModelInvocationRequest
    | OutputRequest
)


@dataclass(frozen=True, slots=True)
class ObjectAuthorization:
    """Final restrictive verdict and effective request for router dispatch."""

    decision: Decision
    request: FrameworkRequest
