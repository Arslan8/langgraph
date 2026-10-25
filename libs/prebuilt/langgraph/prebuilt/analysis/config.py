"""Fixed per-run configuration and honest instrumentation coverage."""

from dataclasses import dataclass
from typing import Literal

from langgraph.prebuilt.analysis.errors import ConfigurationError
from langgraph.prebuilt.analysis.serialization import canonical, digest


@dataclass(frozen=True, slots=True)
class Coverage:
    boundary: str
    status: Literal["instrumented", "explicitly_adapted", "unsupported"]
    producer: str = ""

    def __post_init__(self) -> None:
        if self.status not in ("instrumented", "explicitly_adapted", "unsupported"):
            raise ConfigurationError("analysis:invalid_coverage")
        if self.status != "unsupported" and not self.producer:
            raise ConfigurationError("analysis:missing_producer")


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    policy_json: str
    coverage: tuple[Coverage, ...]
    required_paths: tuple[str, ...] = ()
    strict: bool = True
    model_destination: str = "model:local"
    max_records: int = 100000
    notification_retention: int = 4096

    def __post_init__(self) -> None:
        import json

        object.__setattr__(self, "policy_json", canonical(json.loads(self.policy_json)))
        object.__setattr__(self, "coverage", tuple(self.coverage))
        object.__setattr__(self, "required_paths", tuple(self.required_paths))
        report = {entry.boundary: entry for entry in self.coverage}
        if (
            len(report) != len(self.coverage)
            or self.max_records <= 0
            or self.notification_retention <= 0
        ):
            raise ConfigurationError("analysis:invalid_configuration")
        if self.strict and any(
            name not in report or report[name].status == "unsupported"
            for name in self.required_paths
        ):
            raise ConfigurationError("analysis:unsupported_required_path")

    @property
    def policy_version(self) -> str:
        return digest(self.policy_json)
