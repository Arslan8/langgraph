# ruff: noqa: E501
"""Regenerate the frozen demo preflight summary and unsupported-result table."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(campaign: Path) -> None:
    campaign = campaign.resolve()

    def ref(path: Path) -> str:
        return str(path.relative_to(campaign))

    tasks = json.loads((campaign / "tasks.json").read_text())
    configuration_hash = digest(
        {
            "model": "qwen3:8b@500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41",
            "seed": 20261005,
            "upstream": "23961cff61a42b52525f3b20b4094d8d2fba1744",
            "tasks": tasks,
        }
    )
    rows = []
    d1_checks = {
        1: lambda answer: "3,503" in answer or "3503" in answer,
        2: lambda answer: "Sci Fi & Fantasy" in answer and "2911783" in answer,
        3: lambda answer: all(
            value in answer
            for value in ("Iron Maiden", "Led Zeppelin", "Deep Purple", "Metallica", "U2")
        ),
        4: lambda answer: all(
            value in answer for value in ("Argentina", "Canada", "United Kingdom", "112.86")
        ),
        5: lambda answer: all(
            value in answer for value in ("Helena", "Richard", "Luis", "Ladislav", "Hugh")
        ),
    }
    for task_id in range(1, 6):
        path = campaign / "preflight" / f"D1-{task_id}" / "output.json"
        output = json.loads(path.read_text())
        answer = output["answer"]
        rows.append(
            {
                "application": "D1",
                "task": task_id,
                "repetition": "preflight",
                "mode": "Baseline",
                "configuration_hash": configuration_hash,
                "status": "completed",
                "correct": bool(d1_checks[task_id](answer)),
                "output": ref(path),
                "wall_ms": None,
                "note": "preflight only; no symmetric process wall measurement",
            }
        )
    for task_id in range(1, 6):
        path = campaign / "preflight" / f"D2-{task_id}" / "output.json"
        output = json.loads(path.read_text())
        rows.append(
            {
                "application": "D2",
                "task": task_id,
                "repetition": "preflight",
                "mode": "Baseline",
                "configuration_hash": configuration_hash,
                "status": "completed",
                "correct": True,
                "output": ref(path),
                "wall_ms": output["wall_ms"],
                "note": "manual required-fact checklist passed",
            }
        )
    for task_id in range(1, 6):
        folder = campaign / "preflight" / f"D3-{task_id}"
        output_path = folder / "output.json"
        process = folder / "process.log"
        rows.append(
            {
                "application": "D3",
                "task": task_id,
                "repetition": "preflight",
                "mode": "Baseline",
                "configuration_hash": configuration_hash,
                "status": "completed" if output_path.exists() else "error",
                "correct": False,
                "output": ref(output_path) if output_path.exists() else None,
                "error_trace": ref(process) if process.exists() else None,
                "wall_ms": None,
                "note": "empty-plan/recursion baseline compatibility failure retained",
            }
        )
    for task_id, task in enumerate(tasks["D4"]["tasks"], 1):
        folder = campaign / "preflight" / f"D4-{task_id}"
        observer = json.loads((folder / "plot.json").read_text())
        values = observer["lines"][0]["y"]
        output = json.loads((folder / "output.json").read_text())
        correct = values == task["expected"] and (folder / "chart.png").stat().st_size > 0
        rows.append(
            {
                "application": "D4",
                "task": task_id,
                "repetition": "preflight",
                "mode": "Baseline",
                "configuration_hash": configuration_hash,
                "status": "completed",
                "correct": correct,
                "output": ref(folder / "output.json"),
                "artifact": ref(folder / "chart.png"),
                "resource_snapshot": ref(folder / "plot.json"),
                "wall_ms": output["wall_ms"],
            }
        )
    for task_id, task in enumerate(tasks["D5"]["tasks"], 1):
        folder = campaign / "preflight" / f"D5-{task_id}"
        output = json.loads((folder / "output.json").read_text())
        correct = (
            output["after"]["flight_ids"] == task["expected_flight_ids"]
            and output["after"]["owner"] == tasks["D5"]["passenger_id"]
            and (
                task["approval"] is None
                or (
                    len(output["interrupts"]) == 1
                    and output["interrupts"][0]["approved"] == task["approval"]
                )
            )
        )
        rows.append(
            {
                "application": "D5",
                "task": task_id,
                "repetition": "preflight",
                "mode": "Baseline",
                "configuration_hash": configuration_hash,
                "status": "completed",
                "correct": correct,
                "output": ref(folder / "output.json"),
                "resource_snapshot": {"before": output["before"], "after": output["after"]},
                "wall_ms": output["wall_ms"],
                "note": "task 3 exposes tutorial tool updating both ticket legs"
                if task_id == 3
                else None,
            }
        )
    raw = campaign / "raw"
    raw.mkdir(exist_ok=True)
    (raw / "preflight.jsonl").write_text(
        "".join(json.dumps(row, default=str) + "\n" for row in rows)
    )
    unsupported = {
        f"D{index}": {
            "status": "unsupported",
            "probe_log": f"integration-probes/D{index}.log",
            "argus_trials": 0,
            "measured_trials_started": False,
        }
        for index in range(1, 6)
    }
    success = {
        app: sum(row["correct"] for row in rows if row["application"] == app) for app in unsupported
    }
    statistics = {
        "schema_version": 1,
        "configuration_hash": configuration_hash,
        "upstream_revision": "23961cff61a42b52525f3b20b4094d8d2fba1744",
        "baseline_preflight": {
            app: {"successes": success[app], "attempts": 5} for app in unsupported
        },
        "argus_integration": unsupported,
        "performance": {
            "available": False,
            "reason": "No demo reached a supported full-Argus configuration; the paired 50-trial protocol was not started.",
            "ratios": {},
            "geometric_mean": None,
        },
    }
    (campaign / "statistics.json").write_text(json.dumps(statistics, indent=2) + "\n")
    labels = {
        "D1": "SQL agent",
        "D2": "Agentic RAG",
        "D3": "Plan and execute",
        "D4": "Multi-agent network",
        "D5": "Customer support Part 3",
    }
    adaptations = {
        "D1": "Model wrapper; full custom graph retained",
        "D2": "Frozen HTML, local TF-IDF retriever, frozen RAG prompt",
        "D3": "Frozen-search backend; async graph retained",
        "D4": "Frozen-search backend, Agg and plotting observer; REPL retained",
        "D5": "Frozen date/policy backend and deterministic approval harness",
    }
    lines = [
        "# Ordinary LangGraph demo evaluation",
        "",
        "All five baseline preflights were attempted before Argus integration. Every full-Argus integration requires a missing adapter or runtime capability, so no application entered the paired timing campaign. Unsupported applications are reported rather than replaced or measured under a weakened configuration.",
        "",
        "| Application | Integration status and adaptations | Baseline success / attempts | Argus success / attempts | Baseline mean | Argus mean | Full-system overhead and interval |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for app in labels:
        lines.append(
            f"| {app}: {labels[app]} | Unsupported; {adaptations[app]} | {success[app]}/5 preflight | 0/0 (not run) | — | — | unavailable |"
        )
    lines += [
        "",
        "## Baseline observations",
        "",
        "- D1 passed tasks 1 and 3. Tasks 2 and 5 ended with empty answers; task 4 returned only five of 24 countries.",
        "- D2 passed the frozen required-fact checklists for all five answers.",
        "- D3 failed all five preflights: the pinned model produced empty plans or the unchanged graph reached its recursion limit. These are baseline compatibility failures.",
        "- D4 passed all five numeric-series and chart-artifact checks. The observer validates years and values rather than PNG pixels or model claims.",
        "- D5 passed tasks 1, 2, 4, and 5. Task 3 exposed the tutorial tool's broad `UPDATE`: both ticket legs became flight 1472 rather than only the intended leg.",
        "",
        "## Timing conclusion",
        "",
        "No full-system overhead ratio or graph is reported. Preflight durations are retained as diagnostic data but do not have matching Argus observations or the frozen paired timing boundary. Reporting them as application overhead would be misleading.",
        "",
        "See `CONFIGURATIONS.md` and `integration-probes/` for the five exact unsupported boundaries.",
    ]
    (campaign / "RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    run(parser.parse_args().campaign)
