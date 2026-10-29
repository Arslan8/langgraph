"""Run the one-repetition exploratory add-tools compatibility pilot."""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parent
ROOT = CAMPAIGN.parents[2]
APP = ROOT / "eval/apps/demos/add_tools_protected.py"
WORKER = ROOT / "eval/campaigns/pandas-matched-v1/raw/workerRoute"
SEED = 20261028
TASKS = (
    ("1996", "Atlanta", "United States", "USD"),
    ("2000", "Sydney", "Australia", "AUD"),
    ("2004", "Athens", "Greece", "EUR"),
    ("2012", "London", "United Kingdom", "GBP"),
    ("2016", "Rio de Janeiro", "Brazil", "BRL"),
)


def main() -> None:
    raw = CAMPAIGN / "raw/trials"
    raw.mkdir(parents=True, exist_ok=True)
    jobs = [(mode, task) for mode in ("Baseline", "Argus") for task in TASKS]
    random.Random(SEED).shuffle(jobs)
    records = []
    environment = os.environ.copy()
    environment["PYTHONPATH"] = ":".join(
        str(ROOT / path) for path in ("libs/prebuilt", "libs/langgraph", "libs/checkpoint")
    )
    for index, (mode, task) in enumerate(jobs):
        year, city, country, currency = task
        output = raw / f"{index:02d}-{mode.lower()}-{year}.json"
        prompt = (
            "You must use the search tool. Which city and country hosted the "
            f"{year} Summer Olympics, and what currency did that country use at the time?"
        )
        command = [
            sys.executable,
            str(APP),
            "--mode",
            mode,
            "--prompt",
            prompt,
            "--output",
            str(output),
        ]
        if mode == "Argus":
            command.extend(("--worker-route", str(WORKER)))
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        record = json.loads(output.read_text()) if output.exists() else {}
        answer = str(record.get("answer", ""))
        expected = (city, country, currency)
        correct = all(value.lower() in answer.lower() for value in expected)
        record.update(
            {
                "task_id": year,
                "prompt": prompt,
                "expected": expected,
                "correct": correct,
                "process_returncode": completed.returncode,
                "stderr": completed.stderr,
                "record_path": str(output.relative_to(ROOT)),
            }
        )
        records.append(record)
    summaries = {}
    for mode in ("Baseline", "Argus"):
        selected = [record for record in records if record.get("mode") == mode]
        summaries[mode] = {
            "attempts": len(selected),
            "successes": sum(
                bool(record["correct"] and record["process_returncode"] == 0) for record in selected
            ),
            "mean_wall_ms": sum(record["wall_ms"] for record in selected) / len(selected),
        }
    summaries["runtime_ratio"] = (
        summaries["Argus"]["mean_wall_ms"] / summaries["Baseline"]["mean_wall_ms"]
    )
    result = {
        "campaign": "argus-compatible-demo-v1",
        "design": (
            "exploratory one-repetition compatibility pilot; not the fixed five-demo campaign"
        ),
        "upstream_commit": "23961cff61a42b52525f3b20b4094d8d2fba1744",
        "randomization_seed": SEED,
        "worker_sha256": hashlib.sha256(WORKER.read_bytes()).hexdigest(),
        "summary": summaries,
        "records": records,
    }
    (CAMPAIGN / "statistics.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
