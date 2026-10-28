"""D11 closed-admission inventory of the pandas vendor graph; no model, no worker."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "campaigns/remediation-v2/raw/pandas-closed-v1/inventory.json"


def _report():
    if not EVIDENCE.is_file():
        pytest.skip("Historical inventory is local generated evidence, not distributed in Git")
    return json.loads(EVIDENCE.read_text())


def test_recorded_inventory_refuses_only_on_custom_branches():
    report = _report()
    assert report["compiles_under_closed_admission"] is False
    graphs = {graph["graph"]: graph for graph in report["graphs"]}
    assert set(graphs) == {
        "pandas_data_analyst",
        "data_wrangling_agent",
        "data_visualization_agent",
    }
    for graph in graphs.values():
        assert graph["closed_compile_refusal"] == "admission:unsupported_branch"
        assert graph["diagnostic_compile_without_branches"] == "admitted"
        for node in graph["nodes"]:
            assert node["runnable_type"] == "RunnableCallable"
            assert node["function_type"] == "function"
            assert node["is_compiled_subgraph"] is False
            assert node["declared_kind"] == "trusted_application"
            assert node["undeclared_refusal"] == "admission:unsupported_node_body"
    assert sorted(
        (blocker["graph"], blocker["placement"], blocker["refusal"])
        for blocker in report["blockers"]
    ) == [
        (
            "data_visualization_agent",
            "execute_data_visualization_code:branch:condition",
            "admission:unsupported_branch",
        ),
        (
            "data_wrangling_agent",
            "execute_data_wrangler_code:branch:condition",
            "admission:unsupported_branch",
        ),
        (
            "pandas_data_analyst",
            "data_wrangling_agent:branch:router_chart_or_table",
            "admission:unsupported_branch",
        ),
    ]


def test_trusted_declaration_does_not_cover_a_custom_branch():
    """Same shape as the vendor graph: declared plain nodes, custom router."""
    pytest.importorskip("langgraph.prebuilt.security")
    from typing import TypedDict

    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt.security import SecurityConfig

    class State(TypedDict):
        route: str

    def wrangle(state: State):
        return {"route": "table"}

    def finalize(state: State):
        return {}

    def router(state: State):
        return "chart" if state["route"] == "chart" else "table"

    builder = StateGraph(State)
    builder.add_node("wrangle", wrangle)
    builder.add_node("finalize", finalize)
    builder.add_edge(START, "wrangle")
    builder.add_conditional_edges("wrangle", router, {"chart": END, "table": "finalize"})
    builder.add_edge("finalize", END)
    config = SecurityConfig(
        closed_admission=True,
        trusted_application_nodes=frozenset({"wrangle", "finalize"}),
    )
    with pytest.raises(PermissionError, match="admission:unsupported_branch"):
        builder.compile(security=config)
