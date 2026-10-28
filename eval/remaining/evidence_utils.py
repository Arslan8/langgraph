"""Serialization of frozen evidence objects without runtime test dependencies."""

import dataclasses
import enum


def serial(value):
    if dataclasses.is_dataclass(value):
        return {f.name: serial(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): serial(v) for k, v in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [serial(v) for v in value]
    if value is None or isinstance(value, str | bool | int | float):
        return value
    return str(value)
