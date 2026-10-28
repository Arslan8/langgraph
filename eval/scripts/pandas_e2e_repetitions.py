"""Fixed single-task repetition amendment; preserve every failed attempt."""

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--attempt", type=int, default=1)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
folder = args.output or (
    root / f"eval/results/pandas-e2e-repetitions-20261026-attempt{args.attempt}"
)
folder.mkdir(exist_ok=False)
entries = []
for repetition in range(2, 7):
    order = "ABC"[(repetition - 2) % 3 :] + "ABC"[: (repetition - 2) % 3]
    for config in order:
        for case in ["february", "csv-injection"]:
            entries.append({"configuration": config, "repetition": repetition, "case": case})
plan = {
    "started_at": datetime.now(UTC).isoformat(),
    "phase": "pilot repetition amendment",
    "entries": entries,
    "manifest_version": "v9",
    "profile": "narrow",
    "scope": (
        "One fixed clean task, five fresh repetitions per configuration; "
        "not five independent tasks."
    ),
    "timing": (
        "Existing runner elapsed_seconds includes setup, "
        "source/environment capture, strace-instrumented subprocess and "
        "oracle. Not isolated enforcement latency."
    ),
    "attempt_id": args.attempt,
    "retries": (
        "Attempt 2 retries attempt 1 after Ollama restart; original "
        "infrastructure failures retained."
    ),
}
(folder / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
for entry in entries:
    cmd = [
        "uv",
        "run",
        "--project",
        "eval",
        "python",
        "eval/run.py",
        "--app",
        "pandas",
        "--configuration",
        entry["configuration"],
        "--case",
        entry["case"],
        "--repetition",
        str(entry["repetition"]),
        "--attempt",
        str(args.attempt),
        "--manifest-version",
        "v9",
        "--profile",
        "narrow",
        "--checkouts",
        "/data/slanggraph-eval-upstreams",
    ]
    completed = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    row = {
        **entry,
        "argv": cmd,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    with (folder / "launches.jsonl").open("a") as stream:
        stream.write(json.dumps(row) + "\n")
    print(json.dumps(row), flush=True)
