"""Run the specified production suites with fresh pytest processes and fixtures."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = [
    "test_enforcement",
    "test_object_broker",
    "test_resource_mediator",
    "test_runtime_mac",
    "test_sqlite_mediator",
    "test_pump_example",
    "test_manifest_admission",
]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--repetitions", type=int, default=20)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
source = {
    str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
    for base in [
        "libs/prebuilt/langgraph",
        "libs/langgraph/langgraph",
        "libs/prebuilt/tests/security",
        "eval/scripts",
    ]
    for p in sorted((ROOT / base).rglob("*.py"))
}
digest = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
(args.output / "sources.json").write_text(json.dumps(source, indent=2) + "\n")
statuses = []
for repetition in range(args.repetitions):
    env = dict(
        os.environ,
        SLG_REPEAT=str(repetition),
        SLG_SOURCE_HASH=digest,
        SLG_TRIALS=str((args.output / "trials.jsonl").resolve()),
        PYTHONPATH=str(ROOT / "eval/scripts") + os.pathsep + os.environ.get("PYTHONPATH", ""),
    )
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "mechanism_evidence_plugin",
        *[str(ROOT / f"libs/prebuilt/tests/security/{f}.py") for f in FILES],
        "-q",
    ]
    with (args.output / f"repeat-{repetition}.log").open("w") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    statuses.append(dict(repeat=repetition, exit_status=result.returncode, command=command))
    (args.output / "exit-statuses.json").write_text(json.dumps(statuses, indent=2) + "\n")
    print(f"repeat {repetition}: exit {result.returncode}", flush=True)
