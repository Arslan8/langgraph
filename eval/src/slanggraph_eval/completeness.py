"""E4 synthetic graph-shape completeness experiment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, NotRequired, TypedDict

from langchain_core.runnables import Runnable
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt.security import (
    Decision,
    Principal,
    SecurityConfig,
    SecurityConfigurationError,
    SecurityModule,
    Verdict,
    with_principal,
)
from langgraph.types import Send

from .audit import AuditWriter


class _State(TypedDict):
    value: NotRequired[str]


class _DenyDispatch(SecurityModule):
    name = "e4_deny_dispatch"

    def __init__(self) -> None:
        self.transfers = 0

    def cred_transfer(self, parent, child, slot):
        self.transfers += 1
        return Decision(Verdict.DENY, "e4:dispatch_denied")


def _config():
    return with_principal({}, Principal("e4", frozenset({"tester"}), frozenset(), "e4-session"))


def _leaf_case(kind: str) -> dict[str, Any]:
    executed: list[str] = []

    def child(state: _State) -> _State:
        executed.append(kind)
        return {"value": kind}

    module = _DenyDispatch()
    builder = StateGraph(_State)
    builder.add_node("child", child, metadata={"security_kind": kind})
    builder.add_edge(START, "child")
    builder.add_edge("child", END)
    graph = builder.compile(security=SecurityConfig(modules=(module,)))
    denied = False
    try:
        graph.invoke({}, _config())
    except PermissionError:
        denied = True
    return {
        "case": kind,
        "denied": denied,
        "executed_children": len(executed),
        "transfer_records": module.transfers,
    }


def _send_case() -> dict[str, Any]:
    executed: list[str] = []

    def route(state: _State):
        return [Send("child", {"value": "a"}), Send("child", {"value": "b"})]

    def child(state: _State) -> _State:
        executed.append(state["value"])
        return state

    module = _DenyDispatch()
    builder = StateGraph(_State)
    builder.add_node("child", child)
    builder.add_conditional_edges(START, route)
    builder.add_edge("child", END)
    graph = builder.compile(security=SecurityConfig(modules=(module,)))
    denied = False
    try:
        graph.invoke({}, _config())
    except PermissionError:
        denied = True
    return {
        "case": "send",
        "denied": denied,
        "executed_children": len(executed),
        "transfer_records": module.transfers,
    }


def _subgraph_case() -> dict[str, Any]:
    executed: list[str] = []

    def child(state: _State) -> _State:
        executed.append("subgraph-child")
        return {"value": "child"}

    child_builder = StateGraph(_State)
    child_builder.add_node("child", child)
    child_builder.add_edge(START, "child")
    child_builder.add_edge("child", END)
    child_graph = child_builder.compile()
    module = _DenyDispatch()
    parent = StateGraph(_State)
    parent.add_node(
        "subgraph",
        child_graph,
        metadata={
            "security_kind": "subgraph",
            "security_trust": "trusted",
            "security_promotion_reason": "E4 operator-built synthetic subgraph",
        },
    )
    parent.add_edge(START, "subgraph")
    parent.add_edge("subgraph", END)
    graph = parent.compile(security=SecurityConfig(modules=(module,)))
    denied = False
    try:
        graph.invoke({}, _config())
    except PermissionError:
        denied = True
    return {
        "case": "subgraph",
        "denied": denied,
        "executed_children": len(executed),
        "transfer_records": module.transfers,
    }


class _ImportedNode(Runnable):
    def invoke(self, input, config=None, **kwargs):
        return input


def _untrusted_compile_case() -> dict[str, Any]:
    builder = StateGraph(_State)
    builder.add_node("imported", _ImportedNode())
    builder.add_edge(START, "imported")
    rejected = False
    try:
        builder.compile(security=SecurityConfig())
    except (SecurityConfigurationError, TypeError):
        rejected = True
    return {
        "case": "untrusted_in_process",
        "denied": rejected,
        "executed_children": 0,
        "transfer_records": 0,
    }


def run_completeness(root: Path, output: Path, audit_db: Path) -> dict[str, Any]:
    """Run all synthetic dispatch shapes and attach compile-gate evidence."""
    rows = [
        _leaf_case("standard"),
        _leaf_case("subagent"),
        _leaf_case("nested_agent"),
        _subgraph_case(),
        _send_case(),
        _untrusted_compile_case(),
    ]
    waiver_manifest = json.loads(
        (root / "docs/security/escape-waivers.json").read_text(encoding="utf-8")
    )
    certificate = json.loads(
        (root / "docs/security/host-router-certificate.json").read_text(encoding="utf-8")
    )
    payload = {
        "schema_version": "1.0.0",
        "experiment": "E4",
        "rows": rows,
        "all_shapes_refused_before_effect": all(
            row["denied"] and row["executed_children"] == 0 for row in rows
        ),
        "escape_findings_waived": len(waiver_manifest["waivers"]),
        "router_certificate": certificate,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    with AuditWriter(
        audit_db,
        experiment="E4",
        condition="synthetic_graph_shapes",
        metadata={"hardware": "eval/HARDWARE.md", "model": None},
    ) as audit:
        audit.append("e4_completeness", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    args = parser.parse_args()
    payload = run_completeness(args.root, args.output, args.audit_db)
    return 0 if payload["all_shapes_refused_before_effect"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
