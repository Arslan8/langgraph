import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AnalysisConfig,
    AnalysisEvent,
    AnalysisResult,
    AnalyzerRegistration,
    BuiltinEvent,
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
    upstream = AnalyzerRegistration(
        analyzer_id="a", version="1", analyzer=object(), events={spec}
    )
    downstream = AnalyzerRegistration(
        analyzer_id="b",
        version="1",
        analyzer=object(),
        events={spec},
        dependencies=("a",),
    )
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
                AnalyzerRegistration(
                    analyzer_id="a",
                    version="1",
                    analyzer=object(),
                    events={spec},
                    dependencies=("b",),
                ),
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


def test_typed_event_subscription_is_frozen_and_wire_compatible():
    subscriptions = {BuiltinEvent.INPUT_ADMIT, BuiltinEvent.MODEL_REQUEST}
    registration = AnalyzerRegistration(
        analyzer_id="listener", version="1", analyzer=object(), events=subscriptions
    )
    subscriptions.clear()
    assert registration.events == frozenset(
        {BuiltinEvent.INPUT_ADMIT, BuiltinEvent.MODEL_REQUEST}
    )
    assert registration.event_names == {"input.admit", "model.request"}
    assert {event.value for event in BuiltinEvent} == {
        spec.name for spec in BUILTIN_EVENTS
    }
    Registry(BUILTIN_EVENTS, (registration,), producers=frozenset({"input", "model"}))
    assert AnalysisEvent.model_validate(event().wire()).event_name == "example.document"


@pytest.mark.parametrize(
    "events", [{"input.admit"}, {"input.typo"}, {17}, "input.admit", ("input.admit",)]
)
def test_raw_or_invalid_event_subscriptions_are_rejected(events):
    with pytest.raises(ConfigurationError):
        AnalyzerRegistration(
            analyzer_id="listener", version="1", analyzer=object(), events=events
        )


def test_positional_registration_is_rejected():
    with pytest.raises(TypeError):
        AnalyzerRegistration("listener", "1", object(), {BuiltinEvent.INPUT_ADMIT})
    with pytest.raises(ValueError):
        BuiltinEvent("input.typo")


def test_custom_subscription_must_match_registered_spec():
    spec = EventSpec("example.document", "before", "fixture", True)
    registration = AnalyzerRegistration(
        analyzer_id="listener", version="1", analyzer=object(), events={spec}
    )
    with pytest.raises(ConfigurationError, match="unregistered_event_spec"):
        Registry((), (registration,), producers=frozenset({"fixture"}))
    changed = EventSpec("example.document", "after", "fixture", True)
    with pytest.raises(ConfigurationError, match="unregistered_event_spec"):
        Registry((changed,), (registration,), producers=frozenset({"fixture"}))
    Registry((spec,), (registration,), producers=frozenset({"fixture"}))


def test_registration_metadata_is_optional_but_duplicates_are_rejected():
    class Listener:
        pass

    first = AnalyzerRegistration(analyzer=Listener(), events={BuiltinEvent.INPUT_ADMIT})
    second = AnalyzerRegistration(
        analyzer=Listener(), events={BuiltinEvent.INPUT_ADMIT}
    )
    assert first.analyzer_id == f"{Listener.__module__}.{Listener.__qualname__}"
    assert first.version == "unversioned"
    with pytest.raises(ConfigurationError, match="duplicate_registration"):
        Registry(BUILTIN_EVENTS, (first, second), producers=frozenset({"input"}))
    renamed = AnalyzerRegistration(
        analyzer=Listener(),
        events={BuiltinEvent.INPUT_ADMIT},
        analyzer_id="other",
        version="release-2",
    )
    Registry(BUILTIN_EVENTS, (first, renamed), producers=frozenset({"input"}))
