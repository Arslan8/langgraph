"""Rebuild macro pilot metrics from explicitly identified cohorts."""

import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def stats(values):
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    return {
        "n": len(values),
        "mean": statistics.mean(values),
        "sd": statistics.stdev(values) if len(values) > 1 else None,
        "variance": statistics.variance(values) if len(values) > 1 else None,
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "p95": ordered[(95 * len(values) + 99) // 100 - 1],
    }


def main():
    repeats = ROOT / "results/pandas-e2e-repetitions-20261026-attempt2"
    rows = []
    for line in (repeats / "launches.jsonl").read_text().splitlines():
        launch = json.loads(line)
        result = json.loads(Path(json.loads(launch["stdout"])["result"]).read_text())
        rows.append(result)
    output = {
        "cohort": str(repeats.relative_to(ROOT)),
        "end_to_end_units": "seconds",
        "original_infrastructure_failures": sum(
            json.loads(Path(json.loads(json.loads(line)["stdout"])["result"]).read_text())["status"]
            == "infrastructure_failure"
            for line in (ROOT / "results/pandas-e2e-repetitions-20261026-v1/launches.jsonl")
            .read_text()
            .splitlines()
        ),
        "qualified": (
            "One clean task and one paired injection, five repetitions each. "
            "No across-task uncertainty estimate."
        ),
        "end_to_end": {},
        "injection": {},
        "paired_clean_differences": {},
        "run_ids": [r["run_id"] for r in rows],
    }
    for config in "ABC":
        clean = [r for r in rows if r["configuration"] == config and r["case_id"] == "february"]
        attack = [
            r for r in rows if r["configuration"] == config and r["case_id"] == "csv-injection"
        ]
        output["end_to_end"][config] = {
            **stats([r["elapsed_seconds"] for r in clean]),
            "task_successes": sum(r["task_success"] is True for r in clean),
            "statuses": [r["status"] for r in clean],
        }
        output["injection"][config] = {
            "scheduled": len(attack),
            "completed": sum(r["status"] == "completed" for r in attack),
            "task_successes": sum(r["task_success"] is True for r in attack),
            "proposals": sum(r.get("proposed_operation") is not None for r in attack),
            "attempts": sum(r.get("actual_attempted_operation") is not None for r in attack),
            "effects": sum(r.get("observed_external_effect") is True for r in attack),
            "outcomes": [r["enforcement_outcome"] for r in attack],
        }
    for left, right in [("B", "A"), ("C", "A"), ("C", "B")]:
        ls = {
            r["repetition_id"]: r["elapsed_seconds"]
            for r in rows
            if r["configuration"] == left and r["case_id"] == "february"
        }
        rs = {
            r["repetition_id"]: r["elapsed_seconds"]
            for r in rows
            if r["configuration"] == right and r["case_id"] == "february"
        }
        shared = sorted(ls.keys() & rs.keys())
        output["paired_clean_differences"][left + "-" + right] = stats(
            [ls[k] - rs[k] for k in shared]
        )
        output["paired_clean_differences"][left + "-" + right]["ratio_of_means"] = statistics.mean(
            ls[k] for k in shared
        ) / statistics.mean(rs[k] for k in shared)
    output["audit_diagnostic"] = json.loads(
        (ROOT / "results/pandas-runtime-audit-profile-20261026-v1/summary.json").read_text()
    )
    output["local_replay"] = json.loads(
        (ROOT / "results/pandas-runtime-20261026-v1/summary.json").read_text()
    )
    output["local_cold"] = [
        json.loads(line)
        for line in (ROOT / "results/pandas-runtime-20261026-v1/samples.jsonl")
        .read_text()
        .splitlines()
        if json.loads(line)["phase"] == "cold"
    ]
    output["local_setup"] = json.loads(
        (ROOT / "results/pandas-runtime-20261026-v1/setup.json").read_text()
    )
    extra = ROOT / "results/pandas-dispatch-20261026-v1/summary.json"
    if extra.exists():
        output["dispatch"] = json.loads(extra.read_text())
    (ROOT / "reports/macro-metrics.json").write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {k: v for k, v in output.items() if k not in {"local_replay", "run_ids", "dispatch"}},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
