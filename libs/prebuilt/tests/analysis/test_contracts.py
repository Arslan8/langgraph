import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from langgraph.prebuilt.analysis import (
    AnalysisConfig,
    AnalysisEvent,
    AnalysisResult,
    AnalyzerRegistration,
    Coverage,
    EventSpec,
    Registry,
    ValueRef,
)
from langgraph.prebuilt.analysis.errors import ConfigurationError


def event():
    return AnalysisEvent(
        event_id="e",
        event_name="example.document",
        phase="before",
        tenant_id="t",
        session_id="s",
        run_id="r",
        invocation_id="i",
        attempt_id="a",
        metadata={"nested": {"items": [1]}},
    )


def test_immutable_roundtrip():
    original = event()
    assert AnalysisEvent.model_validate(original.wire()) == original
    with pytest.raises(TypeError):
        original.metadata["nested"]["items"] = ()
    with pytest.raises(ValidationError):
        original.run_id = "other"
    with pytest.raises(ValidationError):
        ValueRef(value_id="v", version=0, content_digest="x", media_type="text/plain")


@pytest.mark.parametrize(
    "field", ["policy_proposals", "grants", "state_writes", "rules"]
)
def test_no_authority_channel(field):
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({field: []})


def test_topological_registry():
    spec = EventSpec("example.document", "before", "fixture", True)
    upstream = AnalyzerRegistration("a", "1", object(), (spec.name,))
    downstream = AnalyzerRegistration("b", "1", object(), (spec.name,), ("a",))
    registry = Registry(
        (spec,), (downstream, upstream), producers=frozenset({"fixture"})
    )
    assert [item.analyzer_id for item in registry.analyzers] == ["a", "b"]
    for entries, producers in [
        ((upstream, upstream), {"fixture"}),
        ((downstream,), {"fixture"}),
        ((upstream,), set()),
    ]:
        with pytest.raises(ConfigurationError):
            Registry((spec,), entries, producers=frozenset(producers))
    with pytest.raises(ConfigurationError, match="cycle"):
        Registry(
            (spec,),
            (
                AnalyzerRegistration("a", "1", object(), (spec.name,), ("b",)),
                downstream,
            ),
            producers=frozenset({"fixture"}),
        )


def test_unknown_schema_and_required_coverage():
    with pytest.raises(ConfigurationError):
        EventSpec("example.document", "before", "fixture", True, schema_version=2)
    with pytest.raises(ConfigurationError):
        AnalysisConfig(
            "{}", (Coverage("model.request", "unsupported"),), ("model.request",)
        )


def test_dependency_direction():
    root = Path(__file__).parents[2] / "langgraph" / "prebuilt" / "analysis"
    for source in root.rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.ImportFrom):
                assert "analysis_plugins" not in (node.module or "")
                assert "examples" not in (node.module or "")
