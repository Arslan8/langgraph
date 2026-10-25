"""Explicit startup registration with deterministic dependency validation."""

from dataclasses import dataclass
from math import isfinite
from types import MappingProxyType
from typing import Literal

from langgraph.prebuilt.analysis.contracts import Analyzer
from langgraph.prebuilt.analysis.errors import ConfigurationError
from langgraph.prebuilt.analysis.events import EventSpec


@dataclass(frozen=True, slots=True)
class AnalyzerRegistration:
    analyzer_id: str
    version: str
    analyzer: Analyzer
    events: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    mode: Literal["required", "advisory"] = "required"
    timeout: float = 30.0
    content_access: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        if not self.analyzer_id or not self.version or not self.events:
            raise ConfigurationError("analysis:invalid_registration")
        if (
            self.mode not in ("required", "advisory")
            or not isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ConfigurationError("analysis:invalid_registration")


class Registry:
    """Frozen after construction; no import-time or in-run registration."""

    def __init__(
        self,
        events: tuple[EventSpec, ...],
        analyzers: tuple[AnalyzerRegistration, ...],
        *,
        producers: frozenset[str],
    ) -> None:
        specs = {spec.name: spec for spec in events}
        plugins = {item.analyzer_id: item for item in analyzers}
        if len(specs) != len(events) or len(plugins) != len(analyzers):
            raise ConfigurationError("analysis:duplicate_registration")
        for item in analyzers:
            for name in item.events:
                if name not in specs or specs[name].producer not in producers:
                    raise ConfigurationError("analysis:missing_event_producer")
                if item.mode == "required" and not specs[name].barrier:
                    raise ConfigurationError("analysis:missing_barrier")
            for dependency in item.dependencies:
                if dependency not in plugins:
                    raise ConfigurationError("analysis:missing_dependency")
                if not set(item.events).issubset(plugins[dependency].events):
                    raise ConfigurationError("analysis:dependency_event_mismatch")
                if item.mode == "required" and plugins[dependency].mode != "required":
                    raise ConfigurationError("analysis:advisory_dependency")
        ordered: list[AnalyzerRegistration] = []
        remaining = dict(plugins)
        while remaining:
            ready = sorted(
                name
                for name, item in remaining.items()
                if set(item.dependencies).issubset({p.analyzer_id for p in ordered})
            )
            if not ready:
                raise ConfigurationError("analysis:dependency_cycle")
            for name in ready:
                ordered.append(remaining.pop(name))
        self.events = MappingProxyType(specs)
        self.analyzers = tuple(ordered)
