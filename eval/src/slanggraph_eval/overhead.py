"""E5 measured framework and kernel-enforcement overhead."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import tempfile
import time
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt.security import (
    LandlockSandboxExecutor,
    LinuxToolSpec,
    Principal,
    SecurityConfig,
    Tool,
    ToolCall,
    ToolDac,
    TypedPolicyBackend,
    parse_profiles,
    probe_landlock_abi,
    with_principal,
)

from .audit import AuditWriter


class _State(TypedDict):
    value: int


def _increment(state: _State) -> _State:
    return {"value": state["value"] + 1}


def _measure(operation, iterations: int) -> list[float]:
    values: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    return values


def _row(stage: str, mechanism: str, samples: list[float]) -> dict[str, Any]:
    ordered = sorted(samples)
    p95_index = max(0, min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1))
    middle = len(ordered) // 2
    median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2
    return {
        "stage": stage,
        "mechanism": mechanism,
        "iterations": len(samples),
        "median_ms": round(median, 6),
        "p95_ms": round(ordered[p95_index], 6),
    }


def _graph(secure: bool):
    builder = StateGraph(_State)
    builder.add_node("increment", _increment)
    builder.add_edge(START, "increment")
    builder.add_edge("increment", END)
    return builder.compile(security=SecurityConfig() if secure else None)


def _landlock_samples(iterations: int) -> list[float]:
    with tempfile.TemporaryDirectory(prefix="slanggraph-e5-") as raw:
        root = Path(raw)
        artifact = root / "e5_tool.py"
        artifact.write_text("def noop(): return 'ok'\n", encoding="utf-8")
        profiles = parse_profiles(
            """
tool noop {
  owner evaluator
  grant evaluator: call
  runs linux
  syscalls @minimal
}
principal e5 {
  roles evaluator
}
"""
        )
        executor = LandlockSandboxExecutor(
            profiles,
            {
                "noop": LinuxToolSpec(
                    "e5_tool:noop",
                    artifact,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=(root,),
            policy_backend=TypedPolicyBackend(),
        )
        principal = Principal("e5", frozenset({"evaluator"}), frozenset(), "e5")
        tool = Tool("noop", ToolDac("evaluator", {"evaluator": "x"}), frozenset(), ())
        call_index = 0

        def run() -> None:
            nonlocal call_index
            call_index += 1
            result = executor.invoke(
                principal,
                ToolCall(tool, {}, {}, f"e5-{call_index}", call_index),
                (),
            )
            if result.value != "ok":
                raise RuntimeError("E5 worker returned an unexpected value")

        return _measure(run, iterations)


def run_overhead(
    output: Path,
    audit_db: Path,
    *,
    framework_iterations: int = 100,
    landlock_iterations: int = 10,
    include_landlock: bool = True,
) -> dict[str, Any]:
    """Measure identical graph work with and without object mediation."""
    if framework_iterations <= 0 or landlock_iterations <= 0:
        raise ValueError("iteration counts must be positive")
    baseline = _graph(False)
    secured = _graph(True)
    principal = Principal("e5", frozenset({"evaluator"}), frozenset(), "e5")
    config = with_principal({}, principal)
    rows = [
        _row(
            "framework-baseline",
            "langgraph",
            _measure(lambda: baseline.invoke({"value": 0}), framework_iterations),
        ),
        _row(
            "framework-object-manager",
            "HostRouter hooks + state/output placement",
            _measure(lambda: secured.invoke({"value": 0}, config), framework_iterations),
        ),
    ]
    abi = probe_landlock_abi()
    if include_landlock and abi >= 1:
        rows.append(
            _row(
                "host-end-to-end",
                "Landlock + seccomp + supervisor",
                _landlock_samples(landlock_iterations),
            )
        )
    payload = {
        "schema_version": "1.0.0",
        "experiment": "E5",
        "kernel": platform.release(),
        "landlock_abi": abi,
        "rows": rows,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    with AuditWriter(
        audit_db,
        experiment="E5",
        condition="measured_overhead",
        metadata={
            "hardware": "eval/HARDWARE.md",
            "kernel": platform.release(),
            "landlock_abi": abi,
            "model": None,
        },
    ) as audit:
        audit.append("e5_overhead", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--framework-iterations", type=int, default=100)
    parser.add_argument("--landlock-iterations", type=int, default=10)
    args = parser.parse_args()
    run_overhead(
        args.output,
        args.audit_db,
        framework_iterations=args.framework_iterations,
        landlock_iterations=args.landlock_iterations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
