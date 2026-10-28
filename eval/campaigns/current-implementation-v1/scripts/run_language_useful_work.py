"""Run a meaningful two-input decision through the immutable language sandbox."""

# ruff: noqa: SIM102 -- the closed branch grammar uses nested literal comparisons.

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Principal,
    SqliteAuditSink,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.inprocess import ManifestAdmission, read_text
from langgraph.prebuilt.security.object_policy import (
    ObjectPolicyHostExecutor,
    _LanguageSandboxDispatcher,
)

POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
MANDATORY = 'forbid(principal == slangGraph::User::"bob", action, resource);'
MANIFEST = "runs inprocess\nfs read @{left} need\nfs read @{right} need"


@tool("compliance_decision")
def compliance_decision(left: str, right: str) -> str:
    """Compare two granted immutable instructions and return a bounded decision."""
    first = read_text(left)
    second = read_text(right)
    if first == "retain seven years":
        if second == "retain seven years":
            return "approved"
    return "manual_review"


@tool("raw_file_bypass")
def raw_file_bypass(path: str) -> str:
    """Attempt an unsupported direct file API."""
    return open(path).read()


def _write(stream, row: dict) -> None:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
    stream.flush()


def _refusal() -> dict:
    start = time.perf_counter_ns()
    try:
        cedar_security(
            raw_file_bypass,
            manifest="runs inprocess\nfs read @{path} need",
            policy=POLICY,
        )
    except Exception as exc:
        return {
            "refused": True,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
        }
    return {
        "refused": False,
        "error_type": None,
        "error": None,
        "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
    }


def run_session(output: Path, session: int, warmups: int, measured: int) -> None:
    """Run one fresh process/session with a reused compiled graph."""
    output.parent.mkdir(parents=True, exist_ok=True)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    install_mac_policy(MANDATORY)
    with tempfile.TemporaryDirectory(prefix="slg-language-work-") as folder:
        root = Path(folder)
        left = root / "left.txt"
        right = root / "right.txt"
        left.write_text("retain seven years")
        right.write_text("retain seven years")
        sink = SqliteAuditSink(root / "audit.sqlite")
        setup_start = time.perf_counter_ns()
        security = cedar_security(
            compliance_decision,
            manifest=MANIFEST,
            policy=POLICY,
        )
        security = replace(security, audit_sink=sink, closed_admission=True)
        node = ToolNode([compliance_decision], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
        principal = Principal("alice", frozenset(), frozenset(), f"session-{session}")
        config = with_principal({}, principal, modules=security.modules)
        spans = {
            "authorization_ms": 0.0,
            "dispatcher_ms": 0.0,
            "execution_ms": 0.0,
            "audit_ms": 0.0,
        }
        originals = {
            "authorize": ObjectPolicyHostExecutor._authorize,
            "dispatch": _LanguageSandboxDispatcher.invoke,
            "execute": ManifestAdmission.invoke,
            "audit": sink.write,
        }

        def timed(name, function):
            def wrapper(*args, **kwargs):
                start = time.perf_counter_ns()
                try:
                    return function(*args, **kwargs)
                finally:
                    spans[name] += (time.perf_counter_ns() - start) / 1e6

            return wrapper

        ObjectPolicyHostExecutor._authorize = timed("authorization_ms", originals["authorize"])
        _LanguageSandboxDispatcher.invoke = timed("dispatcher_ms", originals["dispatch"])
        ManifestAdmission.invoke = timed("execution_ms", originals["execute"])
        sink.write = timed("audit_ms", originals["audit"])
        try:
            with output.open("x") as stream:
                _write(
                    stream,
                    {
                        "kind": "setup",
                        "session": session,
                        "cpu_affinity": sorted(os.sched_getaffinity(0)),
                        "setup_ms": setup_ms,
                        "closed_admission": True,
                        "mandatory_policy": MANDATORY,
                        "policy": POLICY,
                        "manifest": MANIFEST,
                        "raw_file_bypass": _refusal(),
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    for name in spans:
                        spans[name] = 0.0
                    request = {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": "compliance_decision",
                                        "args": {"left": str(left), "right": str(right)},
                                        "id": f"language-{session}-{index}-{uuid.uuid4().hex}",
                                    }
                                ],
                            )
                        ]
                    }
                    start = time.perf_counter_ns()
                    result = graph.invoke(request, config=config)
                    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
                    content = result["messages"][-1].content
                    activation_ms = max(0.0, spans["dispatcher_ms"] - spans["execution_ms"])
                    accounted = (
                        spans["authorization_ms"]
                        + activation_ms
                        + spans["execution_ms"]
                        + spans["audit_ms"]
                    )
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "language",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": elapsed_ms,
                            "authorization_ms": spans["authorization_ms"],
                            "activation_ms": activation_ms,
                            "execution_ms": spans["execution_ms"],
                            "audit_ms": spans["audit_ms"],
                            "framework_residual_ms": elapsed_ms - accounted,
                            "valid": "approved" in content,
                            "audit_records": len(sink.records()),
                        },
                    )

                    start = time.perf_counter_ns()
                    plain = "approved" if left.read_text() == right.read_text() else "manual_review"
                    direct_ms = (time.perf_counter_ns() - start) / 1e6
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "upstream",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": direct_ms,
                            "valid": plain == "approved",
                        },
                    )
        finally:
            ObjectPolicyHostExecutor._authorize = originals["authorize"]
            _LanguageSandboxDispatcher.invoke = originals["dispatch"]
            ManifestAdmission.invoke = originals["execute"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--measured", type=int, default=20)
    parser.add_argument("--session", type=int)
    args = parser.parse_args()
    if args.session is not None:
        run_session(args.output, args.session, args.warmups, args.measured)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    for session in range(args.sessions):
        command = [
            sys.executable,
            __file__,
            "--output",
            str(args.output / f"session-{session}.jsonl"),
            "--warmups",
            str(args.warmups),
            "--measured",
            str(args.measured),
            "--session",
            str(session),
        ]
        log = args.output / f"session-{session}.log"
        with log.open("x") as stream:
            subprocess.run(command, check=True, stdout=stream, stderr=subprocess.STDOUT)
        print(f"language session {session} complete", flush=True)


if __name__ == "__main__":
    main()
