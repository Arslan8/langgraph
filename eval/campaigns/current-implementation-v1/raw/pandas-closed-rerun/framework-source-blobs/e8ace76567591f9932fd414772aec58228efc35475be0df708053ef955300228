"""Canonical JSON and deeply immutable JSON metadata; no object deserialization."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


def freeze(value: Any) -> Any:
    """Copy JSON data, rejecting arbitrary objects and non-finite numbers."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("analysis:non_string_key")
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(freeze(item) for item in value)
    raise ValueError("analysis:non_json_value")


def thaw(value: Any) -> Any:
    """Produce a detached JSON representation."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def canonical(value: Any) -> str:
    return json.dumps(
        thaw(freeze(value)), sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()
