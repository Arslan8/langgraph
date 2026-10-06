"""Machine-readable schema for the shared sink-exposure instrument."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.1.0"


class SinkClass(str, Enum):
    """Security-sensitive operation observed in tool code."""

    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PROCESS = "process"
    DATABASE = "database"
    SERVICE = "service"
    NATIVE = "native"
    DYNAMIC = "dynamic"
    DELEGATION = "delegation"


class ResourceClass(str, Enum):
    """Grant class that can contain a sink's consequence."""

    FILESYSTEM = "filesystem"
    NETWORK = "network"
    EXEC = "exec"
    SYSCALL = "syscall"
    SQL = "sql"
    MAIL = "mail"
    CHAT = "chat"
    DELEGATION = "delegation"
    UNKNOWN = "unknown"


class Enforcer(str, Enum):
    """Locus required to mediate the resulting operation."""

    KERNEL = "kernel"
    BROKER = "broker"
    EVALUATOR = "evaluator"
    UNKNOWN = "unknown"


class TaintOrigin(str, Enum):
    """Provenance assigned to an input for defense-specific scoring."""

    TOOL_ARGUMENT = "tool_argument"
    UNTRUSTED_TAG = "untrusted_tag"
    TRUSTED_TAG = "trusted_tag"
    AMBIENT = "ambient"


class MediationPoint(str, Enum):
    """Where taint or resource identity becomes security relevant."""

    ARGUMENT_BOUNDARY = "argument_boundary"
    POST_VALIDATION_TRANSFORM = "post_validation_transform"
    RESOURCE_RESOLUTION = "resource_resolution"
    NATIVE_CALL = "native_call"
    DYNAMIC_DISPATCH = "dynamic_dispatch"
    KERNEL_RESOURCE = "kernel_resource"
    BROKER_REQUEST = "broker_request"


class Defense(str, Enum):
    """Defense mediation model used by the common scorer."""

    NONE = "none"
    PROGENT = "progent"
    CAMEL = "camel"
    BOLT_ON = "bolt_on"
    SLANGGRAPH = "slanggraph"


@dataclass(frozen=True, slots=True)
class EnforcementAdapterModel:
    """Named capability set for one projected slangGraph deployment.

    The model is deliberately independent of a concrete implementation. A
    Linux, Windows, WASI, microVM, service, or remote-resource adapter may
    provide any subset of the same resource capabilities.
    """

    name: str
    capabilities: frozenset[ResourceClass]


@dataclass(frozen=True, slots=True)
class TaintStep:
    """One source-to-sink operation in a conservative taint path."""

    kind: str
    symbol: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class TaintPath:
    """A tainted argument path reaching a sink."""

    source: str
    origin: TaintOrigin
    steps: tuple[TaintStep, ...]
    boundary_constrainable: bool
    trusted_value_poisoned: bool = False


@dataclass(frozen=True, slots=True)
class SinkRecord:
    """One security-sensitive sink and all known tainted paths to it."""

    sink_id: str
    sink_class: SinkClass
    resource_class: ResourceClass
    alternate_resource_classes: tuple[ResourceClass, ...]
    required_enforcer: Enforcer
    path: str
    function: str
    line: int
    column: int
    symbol: str
    operation: str
    taint_paths: tuple[TaintPath, ...]
    mediation_points: tuple[MediationPoint, ...]
    resource_identity_after_boundary: bool
    grant_declared: bool

    @property
    def attacker_reachable(self) -> bool:
        """Whether attacker-controlled data or control reaches this sink."""
        return bool(self.attacker_taint_paths)

    @property
    def attacker_taint_paths(self) -> tuple[TaintPath, ...]:
        """Return taint paths whose origin is controlled by the evaluated call."""
        return tuple(path for path in self.taint_paths if path.origin is not TaintOrigin.AMBIENT)

    @property
    def resource_classes(self) -> frozenset[ResourceClass]:
        """Return every resource class the sink may select at runtime."""
        return frozenset((self.resource_class, *self.alternate_resource_classes))


@dataclass(frozen=True, slots=True)
class ToolSinkReport:
    """Static sink report for one tool function."""

    tool: str
    source: str
    sinks: tuple[SinkRecord, ...]
    parse_errors: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    @property
    def attacker_reachable_sinks(self) -> tuple[SinkRecord, ...]:
        """Return only sinks reached by a tainted data or control path."""
        return tuple(sink for sink in self.sinks if sink.attacker_reachable)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return _json_value(asdict(self))

    def to_json(self) -> str:
        """Serialize the report with stable ordering for artifact diffs."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True, slots=True)
class SinkDecision:
    """One defense's mediation decision for one sink."""

    sink_id: str
    mediated: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ExposureScore:
    """Projection of a sink report through a defense mediation model."""

    tool: str
    defense: Defense
    exposed: tuple[str, ...]
    mediated: tuple[str, ...]
    decisions: tuple[SinkDecision, ...]
    adapter_model: str | None = None
    adapter_capabilities: tuple[ResourceClass, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return _json_value(asdict(self))

    def to_json(self) -> str:
        """Serialize the score with stable ordering for artifact diffs."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    return value
