"""Injectable classifier service and deterministic offline implementation."""

from dataclasses import dataclass
from typing import Literal, Protocol

from langgraph.prebuilt.analysis_plugins.repeat_after_me.schema import Classification


@dataclass(frozen=True, slots=True)
class ClassificationInput:
    sources: tuple[tuple[str, str], ...]
    event_name: str
    metadata_json: str


class RepeatClassifier(Protocol):
    configuration_digest: str

    def classify(self, candidate: ClassificationInput) -> Classification: ...
    async def aclassify(self, candidate: ClassificationInput) -> Classification: ...


@dataclass(frozen=True, slots=True)
class ScriptedClassifier:
    label: Literal["repeat_to_tool", "benign", "uncertain"]
    configuration_digest: str = "0" * 64

    def classify(self, candidate: ClassificationInput) -> Classification:
        return Classification(
            label=self.label,
            score=1.0 if self.label != "uncertain" else 0.0,
            source_ids=tuple(source_id for source_id, _ in candidate.sources),
            reason="scripted_fixture",
        )

    async def aclassify(self, candidate: ClassificationInput) -> Classification:
        return self.classify(candidate)
