"""Regenerate campaign statistics and paper-ready Markdown from raw JSONL."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

T95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    24: 2.064,
    29: 2.045,
}


def ci95(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"n": 0, "mean": math.nan, "low": math.nan, "high": math.nan}
    mean = statistics.mean(values)
    if len(values) == 1:
        return {"n": 1, "mean": mean, "low": mean, "high": mean}
    degrees = len(values) - 1
    critical = T95.get(degrees, 1.96 if degrees >= 30 else T95[29])
    half = critical * statistics.stdev(values) / math.sqrt(len(values))
    return {"n": len(values), "mean": mean, "low": mean - half, "high": mean + half}


def read_rows(raw: Path) -> list[dict]:
    rows = []
    for path in sorted(raw.rglob("*.jsonl")):
        if path.name != "trials.jsonl" and "session-" not in path.name:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.strip():
                row = json.loads(line)
                row["_source"] = str(path.relative_to(raw))
                row["_line"] = number
                rows.append(row)
    return rows


def performance(rows: list[dict], phase: str = "measured") -> list[dict]:
    samples: dict[tuple[str, str], dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    metrics = (
        "elapsed_ms",
        "authorization_ms",
        "policy_lowering_ms",
        "activation_ms",
        "execution_ms",
        "mediator_transport_ms",
        "lean_ms",
        "audit_ms",
        "cleanup_ms",
    )
    for row in rows:
        if row.get("kind") != "call" or row.get("phase") != phase:
            continue
        route = row.get("route")
        session = row.get("session")
        if not isinstance(route, str) or not isinstance(session, int):
            continue
        for metric in metrics:
            value = row.get(metric)
            if isinstance(value, int | float) and math.isfinite(value):
                samples[(route, metric)][session].append(float(value))
    result = []
    for (route, metric), sessions in sorted(samples.items()):
        session_means = [statistics.mean(values) for values in sessions.values()]
        result.append(
            {
                "route": route,
                "metric": metric,
                "calls": sum(map(len, sessions.values())),
                "sessions": len(sessions),
                **ci95(session_means),
            }
        )
    elapsed = {row["route"]: row for row in result if row["metric"] == "elapsed_ms"}
    direct = elapsed.get("direct") or elapsed.get("upstream")
    if direct:
        for row in result:
            if row["metric"] == "elapsed_ms":
                row["added_ms"] = row["mean"] - direct["mean"]
                row["ratio"] = row["mean"] / direct["mean"]
                row["overhead_percent"] = (row["ratio"] - 1) * 100
    return result


def application(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        # The attacked application runs share the C-full mode name but answer a
        # separate security question.  Keep them out of the utility/timing
        # cohort while retaining them in the attack table below.
        if row.get("application") == "pandas" and row.get("attack") is None:
            groups[str(row.get("mode"))].append(row)
    result = []
    for mode, selected in sorted(groups.items()):
        by_session: dict[int, list[dict]] = defaultdict(list)
        for row in selected:
            by_session[int(row["session"])].append(row)
        session_success = [
            statistics.mean(bool(row.get("legitimate_result")) for row in values)
            for values in by_session.values()
        ]
        session_wall = [
            statistics.mean(float(row["wall_ms"]) for row in values)
            for values in by_session.values()
        ]
        session_model = [
            statistics.mean(float(row["model_ms"]) for row in values)
            for values in by_session.values()
        ]
        result.append(
            {
                "configuration": mode,
                "trials": len(selected),
                "successes": sum(bool(row.get("legitimate_result")) for row in selected),
                "output_validation_failures": sum(
                    int(row.get("output_validation_failures", 0)) for row in selected
                ),
                "mean_wall_ms": statistics.mean(float(row["wall_ms"]) for row in selected),
                "mean_model_ms": statistics.mean(float(row["model_ms"]) for row in selected),
                "wall_ms_ci": ci95(session_wall),
                "model_ms_ci": ci95(session_model),
                "success_rate_ci": ci95(session_success),
            }
        )
    return result


def attacks(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        if row.get("application") == "pandas" and row.get("attack") is None:
            continue
        case = row.get("case_id")
        if not isinstance(case, str) or "legitimate_result" not in row:
            continue
        system = str(row.get("baseline") or row.get("mode") or row.get("host") or "slangGraph")
        source = str(row["_source"]).split("/", 1)[0]
        groups[(source, system, case)].append(row)
    return [
        {
            "experiment": experiment,
            "system": system,
            "case_id": case,
            "trials": len(selected),
            "legitimate_completed": sum(bool(row.get("legitimate_result")) for row in selected),
            "unauthorized_effects": sum(
                bool(row.get("unauthorized_effect", row.get("observed_effect", False)))
                for row in selected
            ),
            "classifications": sorted(
                {str(row["classification"]) for row in selected if row.get("classification")}
            ),
        }
        for (experiment, system, case), selected in sorted(groups.items())
    ]


def markdown(summary: dict) -> str:
    lines = ["# Consolidated evaluation results", "", "## Pandas application", ""]
    lines += [
        "| Configuration | Success | Validation failures | Wall ms (95% CI) | Model ms (95% CI) |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in summary["application"]:
        lines.append(
            f"| {row['configuration']} | {row['successes']}/{row['trials']} | "
            f"{row['output_validation_failures']} | {row['mean_wall_ms']:.1f} "
            f"[{row['wall_ms_ci']['low']:.1f}, {row['wall_ms_ci']['high']:.1f}] | "
            f"{row['mean_model_ms']:.1f} [{row['model_ms_ci']['low']:.1f}, "
            f"{row['model_ms_ci']['high']:.1f}] |"
        )
    lines += ["", "## Common-workload performance", ""]
    lines += [
        "| Route | Mean ms | 95% CI | Added ms | Ratio | Sessions/calls |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in summary["performance"]:
        if row["metric"] != "elapsed_ms":
            continue
        added = row.get("added_ms")
        ratio = row.get("ratio")
        lines.append(
            f"| {row['route']} | {row['mean']:.3f} | "
            f"[{row['low']:.3f}, {row['high']:.3f}] | "
            f"{added:.3f} | {ratio:.2f}x | {row['sessions']}/{row['calls']} |"
            if added is not None and ratio is not None
            else f"| {row['route']} | {row['mean']:.3f} | "
            f"[{row['low']:.3f}, {row['high']:.3f}] | — | — | "
            f"{row['sessions']}/{row['calls']} |"
        )
    lines += [
        "",
        "Ratios use the tiny direct file-read baseline; absolute added milliseconds "
        "are the primary comparison.",
        "",
        "### First invocation in each fresh session",
        "",
        "| Route | Mean ms | 95% CI | Sessions |",
        "|---|---:|---:|---:|",
    ]
    for row in summary["cold_starts"]:
        if row["metric"] == "elapsed_ms":
            lines.append(
                f"| {row['route']} | {row['mean']:.3f} | "
                f"[{row['low']:.3f}, {row['high']:.3f}] | {row['sessions']} |"
            )
    lines += [
        "",
        "### Measured phase costs",
        "",
        "| Route | Phase | Mean ms | 95% CI |",
        "|---|---|---:|---:|",
    ]
    for row in summary["performance"]:
        if row["metric"] == "elapsed_ms":
            continue
        lines.append(
            f"| {row['route']} | {row['metric']} | {row['mean']:.3f} | "
            f"[{row['low']:.3f}, {row['high']:.3f}] |"
        )
    lines += [
        "",
        "## Attack outcomes",
        "",
        "| Experiment | System | Case | Legitimate | Unauthorized effects | Classification |",
        "|---|---|---|---:|---:|---|",
    ]
    for row in summary["attacks"]:
        lines.append(
            f"| {row['experiment']} | {row['system']} | {row['case_id']} | "
            f"{row['legitimate_completed']}/{row['trials']} | "
            f"{row['unauthorized_effects']}/{row['trials']} | "
            f"{', '.join(row['classifications']) or 'observed'} |"
        )
    return "\n".join(lines) + "\n"


def run(raw: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    rows = read_rows(raw)
    summary = {
        "raw_root": str(raw),
        "jsonl_rows": len(rows),
        "application": application(rows),
        "performance": performance(rows),
        "cold_starts": performance(rows, "first_use"),
        "attacks": attacks(rows),
        "confidence_interval_unit": "independent-session means",
    }
    (output / "statistics.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "RESULTS.md").write_text(markdown(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.raw, arguments.output)
