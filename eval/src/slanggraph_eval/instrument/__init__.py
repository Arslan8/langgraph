"""Shared sink-exposure instrument."""

from .analyzer import ToolSpec, analyze_tool
from .schema import (
    Defense,
    EnforcementAdapterModel,
    ExposureScore,
    MediationPoint,
    ResourceClass,
    SinkClass,
    SinkRecord,
    TaintOrigin,
    TaintPath,
    ToolSinkReport,
)
from .scoring import ADVISORY_ADAPTER, COMPOSED_ADAPTERS, HOST_ADAPTER, score_defense

__all__ = [
    "ADVISORY_ADAPTER",
    "COMPOSED_ADAPTERS",
    "HOST_ADAPTER",
    "Defense",
    "EnforcementAdapterModel",
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
