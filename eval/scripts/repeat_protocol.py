"""Frozen 5-session protocol: 100 measured calls per workload/condition."""

import argparse
import json
import math
import shutil
import statistics
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from slanggraph_eval.isolation.operations import operations
from slanggraph_eval.isolation.operations import report as operation_report
from slanggraph_eval.isolation.operations import summarize as operation_summary
from slanggraph_eval.isolation.run import digest
from slanggraph_eval.isolation.runtime import stats
from slanggraph_eval.isolation.runtime import summarize as runtime_summary
from slanggraph_eval.isolation.verified import report as verified_report
from slanggraph_eval.isolation.verified import summarize as verified_summary

REPO = Path(__file__).resolve().parents[2]
SESSIONS = 5
SAMPLES = 20
WARMUP = 10


def macro_summary(rows):
    selected = [r for r in rows if r["phase"] == "measured"]
    out = {"configurations": {}, "paired_differences": {}}
    for c in "ABC":
        group = [r for r in selected if r["configuration"] == c]
        out["configurations"][c] = stats([r["elapsed_ms"] for r in group]) | {
            "stages": {k: stats([r["spans"][k] for r in group]) for k in group[0]["spans"]}
        }
    for a, b in [("B", "A"), ("C", "A"), ("C", "B")]:
        x = {r["round"]: r["elapsed_ms"] for r in selected if r["configuration"] == a}
        y = {r["round"]: r["elapsed_ms"] for r in selected if r["configuration"] == b}
        assert x.keys() == y.keys()
        out["paired_differences"][a + "-" + b] = stats([x[k] - y[k] for k in sorted(x)]) | {
            "ratio_of_means": statistics.mean(x.values()) / statistics.mean(y.values())
        }
    return out


def session_inference(rows):
    """Approximate t interval across 5 session means, not 100 independent calls."""
    rows = [r for r in rows if r["phase"] == "measured"]
    cases = sorted({r.get("case", "pandas_replay") for r in rows})
    result = {}
    for case in cases:
        subset = [r for r in rows if r.get("case", "pandas_replay") == case]
        conditions = sorted({r.get("condition", r.get("configuration")) for r in subset})
        pairs = (
            [("C", "A"), ("B", "A"), ("C", "B")]
            if "A" in conditions
            else ([("host", "verified")] if "verified" in conditions else [("host", "trusted")])
        )
        if "host_language_helper" in conditions:
            pairs += [("host_language_helper", "language_helper"), ("host_language_helper", "host")]
        result[case] = {}
        for left, right in pairs:
            means = []
            for session in range(SESSIONS):
                group = [r for r in subset if r["session"] == session]
                a = {
                    r["round"]: r["elapsed_ms"]
                    for r in group
                    if r.get("condition", r.get("configuration")) == left
                }
                b = {
                    r["round"]: r["elapsed_ms"]
                    for r in group
                    if r.get("condition", r.get("configuration")) == right
                }
                for condition in (left, right):
                    assert (
                        sum(r.get("condition", r.get("configuration")) == condition for r in group)
                        == SAMPLES
                    )
                assert a.keys() == b.keys() and len(a) == SAMPLES
                means.append(statistics.mean(a[k] - b[k] for k in a))
            center, sd = statistics.mean(means), statistics.stdev(means)
            half = 2.7764451051977987 * sd / math.sqrt(SESSIONS)
            result[case][left + "-" + right] = {
                "session_means_ms": means,
                "mean_ms": center,
                "between_session_sd_ms": sd,
                "ci95_ms": [center - half, center + half],
                "df": 4,
                "method": "Student t interval on five session mean paired differences",
            }
    return result


def aggregate(folder, kind):
    rows, setups = [], []
    manifests = []
    for session in range(SESSIONS):
        source = folder / f"session-{session + 1}"
        plan = json.loads((source / "plan.json").read_text())
        manifests.append(
            {
                "session": session,
                "plan_sha256": digest(source / "plan.json"),
                "samples_sha256": digest(source / "samples.jsonl"),
            }
        )
        part = [json.loads(line) for line in (source / "samples.jsonl").read_text().splitlines()]
        for row in part:
            row["session"] = session
            row["session_round"] = row["round"]
            row["round"] += session * (1 + WARMUP + SAMPLES)
            if row["phase"] == "cold":
                row["phase"] = "first_use"
        rows.extend(part)
        if kind == "verified":
            setups.extend(
                dict(r, session=session) for r in json.loads((source / "setup.json").read_text())
            )
    counts = Counter(
        (r.get("case", "pandas_replay"), r.get("condition", r.get("configuration")), r["phase"])
        for r in rows
    )
    cells = {
        (r.get("case", "pandas_replay"), r.get("condition", r.get("configuration"))) for r in rows
    }
    for case, condition in cells:
        for phase, expected in [("measured", 100), ("warmup", 50), ("first_use", 5)]:
            assert counts[(case, condition, phase)] == expected
    assert all(r.get("valid", r.get("effect_observed", False)) for r in rows)
    (folder / "samples.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    plan.update(
        samples=100,
        warmup=10,
        sessions=5,
        measured_per_session=20,
        warmup_per_session=10,
        first_use_per_session=1,
        session_manifests=manifests,
    )
    (folder / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    if kind in ("verified", "operations", "runtime"):
        for name in ("sources.tar.gz", "host-before.json", "host-after.json"):
            source = folder / ("session-5" if name == "host-after.json" else "session-1") / name
            shutil.copy2(source, folder / name)
    if kind in ("verified", "operations", "runtime"):
        plan["archive_sha256"] = digest(folder / "sources.tar.gz")
        (folder / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    if kind == "verified":
        summary = verified_summary(rows, 100)
        (folder / "setup.json").write_text(json.dumps(setups, indent=2))
        shutil.copy2(folder / "session-1/admission-census.json", folder / "admission-census.json")
        verified_report(folder, summary, setups, SimpleNamespace(samples=100, warmup=10))
    elif kind == "operations":
        summary = operation_summary(rows, tuple(c.name for c in operations()), 100)
        operation_report(folder, summary, plan)
    elif kind == "runtime":
        summary = runtime_summary(rows)
    else:
        summary = macro_summary(rows)
    (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    inference = session_inference(rows)
    (folder / "session-inference.json").write_text(json.dumps(inference, indent=2) + "\n")
    note = (
        "Protocol: 100 measured calls per workload/mode across five fresh sequential "
        "process sessions (20 each), plus 10 warmups and one first-use call per session. "
        "This gives 50 excluded warmups and 5 separately retained first-use calls per cell. "
        "Sessions share one machine and are not independent host replications. "
        "Each session retains its own source archive and host capture.\n\n"
    )
    report = folder / "report.md"
    text = report.read_text() if report.exists() else "# Standardized timing protocol\n"
    # Replace old single-session introductory count, not measured values.
    if kind == "verified":
        start = text.index("100 randomized")
        end = text.index("\n\n", start)
        text = text[:start] + note.strip() + text[end:]
    elif kind == "operations":
        start = text.index("100 measured")
        end = text.index("\n\n", start)
        text = text[:start] + note.strip() + text[end:]
    else:
        text += "\n" + note
    text += "\n## Between-session uncertainty\n\nApproximate 95% Student t intervals use "
    text += "five session means (4 degrees of freedom). They assume independent, approximately "
    text += "normal session means; adjacent same-host sessions may remain correlated.\n\n"
    text += "| Workload / contrast | Mean added ms | Session SD ms | 95% CI ms |\n"
    text += "| --- | ---: | ---: | --- |\n"
    for case, contrasts in inference.items():
        for contrast, item in contrasts.items():
            low, high = item["ci95_ms"]
            text += (
                f"| {case} / {contrast} | {item['mean_ms']:.3f} | "
                f"{item['between_session_sd_ms']:.3f} | [{low:.3f}, {high:.3f}] |\n"
            )
    report.write_text(text)
    return {
        "cells": len(cells),
        "measured_per_cell": 100,
        "sessions": 5,
        "samples_sha256": digest(folder / "samples.jsonl"),
        "summary_sha256": digest(folder / "summary.json"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--app-python",
        type=Path,
        default=Path("/data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python"),
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "protocol.json").write_text(
        json.dumps(
            {
                "version": 1,
                "sessions": 5,
                "measured_per_session": 20,
                "warmup_per_session": 10,
                "measured_total_per_cell": 100,
                "first_use_per_session": 1,
                "execution": "sequential; no concurrent benchmark processes",
                "seed_base": 20261030,
                "stopping_rule": "fixed counts, no precision-based optional stopping",
                "scope": "primary tool-call timings; model-driven workflow is exploratory",
                "ci": "Student t on five session mean paired deltas, df=4",
            },
            indent=2,
        )
    )
    shutil.copy2(__file__, output / "repeat_protocol.py.txt")
    probe_cmd = [
        "bwrap",
        "--unshare-all",
        "--unshare-user",
        "--die-with-parent",
        "--new-session",
        "--disable-userns",
        "--assert-userns-disabled",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--",
        "/usr/bin/true",
    ]
    probe = subprocess.run(probe_cmd, capture_output=True, text=True)
    (output / "preflight.json").write_text(
        json.dumps(
            {
                "argv": probe_cmd,
                "returncode": probe.returncode,
                "stdout": probe.stdout,
                "stderr": probe.stderr,
                "app_python": str(args.app_python),
                "app_python_exists": args.app_python.is_file(),
            },
            indent=2,
        )
    )
    if probe.returncode:
        (output / "status.json").write_text(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "production host isolation preflight failed",
                    "measured_samples": 0,
                },
                indent=2,
            )
        )
        raise SystemExit(
            "Host isolation unavailable; no benchmark timings collected. See preflight.json"
        )
    outcomes = {}
    for kind in ("verified", "operations", "runtime", "pandas", "audit"):
        folder = output / kind
        folder.mkdir()
        for session in range(SESSIONS):
            destination = folder / f"session-{session + 1}"
            if kind in ("pandas", "audit"):
                cmd = [str(args.app_python), str(REPO / "eval/scripts/pandas_runtime.py")]
                if kind == "audit":
                    cmd.append("--profile-audit")
            else:
                cmd = [sys.executable, "-m", f"slanggraph_eval.isolation.{kind}"]
            cmd += [
                "--output",
                str(destination),
                "--samples",
                "20",
                "--warmup",
                "10",
                "--seed",
                str(20261030 + session),
            ]
            if kind == "verified":
                cmd += ["--setup-samples", "20"]
            print(f"START {kind} session {session + 1}/5", flush=True)
            with (folder / f"session-{session + 1}.log").open("w") as log:
                completed = subprocess.run(cmd, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
            if completed.returncode:
                outcomes[kind] = {"failed_session": session + 1, "returncode": completed.returncode}
                (output / "status.json").write_text(json.dumps(outcomes, indent=2))
                break
            print(f"DONE {kind} session {session + 1}/5", flush=True)
        else:
            outcomes[kind] = aggregate(folder, kind)
            (output / "status.json").write_text(json.dumps(outcomes, indent=2))
    if any("failed_session" in value for value in outcomes.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
