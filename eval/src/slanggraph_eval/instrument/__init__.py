"""Shared sink-exposure instrument."""

from .analyzer import ToolSpec, analyze_tool
from .schema import (
    Defense,
    ExposureScore,
    MediationPoint,
    ResourceClass,
    SinkClass,
    SinkRecord,
    TaintOrigin,
    TaintPath,
    ToolSinkReport,
)
from .scoring import score_defense

__all__ = [
    "Defense",
    "ExposureScore",
    "MediationPoint",
    "ResourceClass",
    "SinkClass",
    "SinkRecord",
    "TaintOrigin",
    "TaintPath",
    "ToolSinkReport",
    "ToolSpec",
    "analyze_tool",
    "score_defense",
]
