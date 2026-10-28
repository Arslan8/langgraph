"""Profile every frozen Pandas task separately from uninstrumented utility timing."""

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    source = args.source.resolve()
    plan = read(source / "plan.json")
    tasks = plan["tasks"]
    if len(tasks) != 10 or args.repetitions < 1:
        parser.error("Require the complete ten-task cohort and positive repetitions")
    # Use the cohort's preserved oracle rather than whatever is now in the checkout.
    driver = source / "harness/application_campaign.py"
    spec = importlib.util.spec_from_file_location("frozen_pandas_oracle", driver)
    oracle_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle_module)
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    runner = Path(__file__).with_name("run_profiles.py")
    metadata = {
        "source": str(source),
        "cases": [task[0] for task in tasks],
        "configuration": "C",
        "repetitions": args.repetitions,
        "oracle_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
        "scope": "intrusive inclusive nested spans; separate from workflow timing",
        "host_load": "uncontrolled shared host",
    }
    (output / "plan.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for case, _, expected in tasks:
        destination = output / case
        command = [
            sys.executable,
            str(runner),
            "--source",
            str(source / f"{case}-C-0"),
            "--script",
            str(source / "harness/backend.py"),
            "--output",
            str(destination),
            "--python",
            str(args.python.absolute()),
            "--cwd",
            str(args.cwd.resolve()),
            "--repetitions",
            str(args.repetitions),
        ]
        completed = subprocess.run(command, check=False)
        trial_file = destination / "trials.jsonl"
        rows = (
            [json.loads(line) for line in trial_file.read_text().splitlines()]
            if trial_file.exists()
            else []
        )
        if len(rows) != args.repetitions:
            raise RuntimeError(
                f"Incomplete profiling observations for {case}: {completed.returncode}"
            )
        for row in rows:
            folder = destination / str(row["repeat"])
            result = read(folder / "output.json") if (folder / "output.json").exists() else {}
            spans = read(folder / "spans.json") if (folder / "spans.json").exists() else []
            policy = [
                span
                for span in spans
                if Path(span["file"]).name == "profile.py" and span["function"] == "evaluate"
            ]
            audit = [
                span
                for span in spans
                if Path(span["file"]).name == "audit.py" and span["function"] == "write"
            ]
            row.update(
                case_id=case,
                utility_verified=row["status"] == "completed"
                and oracle_module.oracle(result, expected, case == "monthly_chart"),
                policy_spans=len(policy),
                audit_spans=len(audit),
                phase_coverage_complete=bool(policy and audit),
            )
            with (output / "trials.jsonl").open("a") as stream:
                stream.write(json.dumps(row) + "\n")
        print(case, rows[-1]["utility_verified"], rows[-1]["phase_coverage_complete"], flush=True)


if __name__ == "__main__":
    main()
