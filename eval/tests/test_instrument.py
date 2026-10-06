from __future__ import annotations

import json
from pathlib import Path

from slanggraph_eval.instrument import (
    Defense,
    ResourceClass,
    TaintOrigin,
    ToolSpec,
    analyze_tool,
    score_defense,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample_tools.py"


def test_joined_path_is_below_argument_boundary() -> None:
    report = analyze_tool(
        ToolSpec(
            FIXTURE,
            "joined_read",
            declared_resources=frozenset({ResourceClass.FILESYSTEM}),
        )
    )

    assert not report.parse_errors
    assert len(report.attacker_reachable_sinks) == 1
    sink = report.attacker_reachable_sinks[0]
    assert sink.symbol == "builtins.open"
    assert {path.source for path in sink.taint_paths} == {"base", "user_path"}
    assert any(not path.boundary_constrainable for path in sink.taint_paths)
    assert score_defense(report, Defense.PROGENT).exposed == (sink.sink_id,)
    assert score_defense(report, Defense.SLANGGRAPH_LANDLOCK).mediated == (sink.sink_id,)


def test_camel_credits_only_untrusted_tagged_paths() -> None:
    untrusted = analyze_tool(
        ToolSpec(
            FIXTURE,
            "web_fetch",
            declared_resources=frozenset({ResourceClass.NETWORK}),
            argument_origins=(("url", TaintOrigin.UNTRUSTED_TAG),),
        )
    )
    trusted = analyze_tool(
        ToolSpec(
            FIXTURE,
            "trusted_join",
            declared_resources=frozenset({ResourceClass.FILESYSTEM}),
            argument_origins=(("retrieved_name", TaintOrigin.TRUSTED_TAG),),
        )
    )

    assert not score_defense(untrusted, Defense.CAMEL).exposed
    assert score_defense(trusted, Defense.CAMEL).exposed


def test_advisory_and_bolt_on_do_not_cover_in_tool_sinks() -> None:
    report = analyze_tool(
        ToolSpec(
            FIXTURE,
            "run_command",
            declared_resources=frozenset({ResourceClass.EXEC}),
        )
    )
    sink_id = report.attacker_reachable_sinks[0].sink_id

    assert score_defense(report, Defense.BOLT_ON).exposed == (sink_id,)
    assert score_defense(report, Defense.SLANGGRAPH_ADVISORY).exposed == (sink_id,)
    assert score_defense(report, Defense.SLANGGRAPH_LANDLOCK).mediated == (sink_id,)


def test_backend_capability_narrows_theoretical_coverage() -> None:
    report = analyze_tool(
        ToolSpec(
            FIXTURE,
            "web_fetch",
            declared_resources=frozenset({ResourceClass.NETWORK}),
        )
    )

    score = score_defense(
        report,
        Defense.SLANGGRAPH_LANDLOCK,
        backend_capabilities={ResourceClass.FILESYSTEM},
    )
    assert score.exposed
    assert "backend lacks network capability" in score.decisions[0].reason


def test_undeclared_resource_is_default_denied_not_exposed() -> None:
    report = analyze_tool(ToolSpec(FIXTURE, "web_fetch"))

    score = score_defense(report, Defense.SLANGGRAPH_LANDLOCK)
    assert score.mediated
    assert "default-denied" in score.decisions[0].reason


def test_delegation_requires_subset_enforcement() -> None:
    report = analyze_tool(
        ToolSpec(
            FIXTURE,
            "delegate_to_subagent",
            declared_resources=frozenset({ResourceClass.DELEGATION}),
        )
    )
    sink_id = report.attacker_reachable_sinks[0].sink_id

    assert score_defense(report, Defense.PROGENT).mediated == (sink_id,)
    assert score_defense(report, Defense.SLANGGRAPH_LANDLOCK).exposed == (sink_id,)
    assert score_defense(report, Defense.SLANGGRAPH_LANDLOCK_BROKER).mediated == (sink_id,)


def test_reports_and_scores_are_machine_readable() -> None:
    report = analyze_tool(ToolSpec(FIXTURE, "joined_read"))
    score = score_defense(report, Defense.NONE)

    report_data = json.loads(report.to_json())
    score_data = json.loads(score.to_json())
    assert report_data["schema_version"] == "1.0.0"
    assert report_data["sinks"][0]["sink_class"] == "filesystem"
    assert score_data["defense"] == "none"
