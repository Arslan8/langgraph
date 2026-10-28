"""Trusted label-domain semantics. A successful flow check never grants access."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from langgraph.prebuilt.analysis.errors import ConfigurationError
from langgraph.prebuilt.analysis.serialization import digest, freeze


class LabelDomain(Protocol):
    domain_id: str
    version: str

    def validate(self, label: Any) -> None: ...
    def combine(self, inputs: Sequence[Any]) -> Any: ...
    def is_at_least_as_restrictive(self, candidate: Any, current: Any) -> bool: ...
    def can_flow(self, label: Any, destination: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class SetDomain:
    """Accumulated risk tags or required confidentiality compartments."""

    domain_id: str
    version: str = "1"

    def validate(self, label: Any) -> None:
        if not isinstance(label, (tuple, list)) or any(
            not isinstance(x, str) or not x for x in label
        ):
            raise ValueError("analysis:invalid_set_label")

    def combine(self, inputs: Sequence[Any]) -> tuple[str, ...]:
        for label in inputs:
            self.validate(label)
        return tuple(sorted({item for label in inputs for item in label}))

    def is_at_least_as_restrictive(self, candidate: Any, current: Any) -> bool:
        self.validate(candidate)
        self.validate(current)
        return set(current).issubset(candidate)

    def can_flow(self, label: Any, destination: str) -> bool:
        self.validate(label)
        # Interpretation of risk tags/clearances belongs to the installed policy.
        return not label


@dataclass(frozen=True, slots=True)
class AllowedReadersDomain:
    """Public is top, reader sets intersect, unknown blocks protected release."""

    domain_id: str = "analysis.allowed_readers"
    version: str = "1"

    def validate(self, label: Any) -> None:
        if label in ("public", "unknown"):
            return
        if not isinstance(label, (tuple, list)) or any(
            not isinstance(x, str) or not x for x in label
        ):
            raise ValueError("analysis:invalid_readers")

    def combine(self, inputs: Sequence[Any]) -> Any:
        readers: set[str] | None = None
        unknown = False
        for label in inputs:
            self.validate(label)
            if label == "unknown":
                unknown = True
            elif label != "public":
                readers = set(label) if readers is None else readers.intersection(label)
        if unknown:
            return "unknown"
        return "public" if readers is None else tuple(sorted(readers))

    def is_at_least_as_restrictive(self, candidate: Any, current: Any) -> bool:
        self.validate(candidate)
        self.validate(current)
        if candidate == "unknown" or current == "public":
            return True
        if current == "unknown":
            return candidate == "unknown"
        return candidate != "public" and set(candidate).issubset(current)

    def can_flow(self, label: Any, destination: str) -> bool:
        self.validate(label)
        return label == "public" or (label != "unknown" and destination in label)


class DomainRegistry:
    """Composition-root registration with immutable identity/version binding."""

    def __init__(self, domains: Sequence[LabelDomain] = ()) -> None:
        entries = (
            SetDomain("analysis.risks"),
            SetDomain("analysis.confidentiality"),
            *domains,
        )
        self.domains = MappingProxyType({item.domain_id: item for item in entries})
        if len(self.domains) != len(entries):
            raise ConfigurationError("analysis:duplicate_domain")
        self.digest = digest({key: item.version for key, item in self.domains.items()})

    def validate(self, labels: Any) -> Any:
        for key, value in labels.items():
            if key not in self.domains:
                raise ConfigurationError("analysis:unknown_domain")
            self.domains[key].validate(value)
        return freeze(labels)

    def combine(self, inputs: Sequence[Any]) -> Any:
        for labels in inputs:
            self.validate(labels)
        return freeze(
            {
                key: domain.combine([labels[key] for labels in inputs if key in labels])
                for key, domain in self.domains.items()
                if any(key in labels for labels in inputs)
            }
        )
