"""Create a separate attribution cohort from an explicitly selected source trial."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    args = parser.parse_args()
    if args.repetitions < 1 or args.timeout <= 0:
        parser.error("repetitions and timeout must be positive")
    if args.cpu not in os.sched_getaffinity(0):
        parser.error("cpu is outside the current affinity mask")
    source, script, out = args.source.resolve(), args.script.resolve(), args.output.resolve()
    source_request = (source / "request.json").read_text()
    out.mkdir(parents=True, exist_ok=False)
    profiler = out / "profile_workflow.py"
    shutil.copyfile(ROOT / "eval/remaining/profile_workflow.py", profiler)
    shutil.copyfile(Path(__file__), out / "run_profiles.py")
    (out / "source-request.json").write_text(source_request)
    source_metadata = json.loads(source_request)
    identity = {
        "schema_version": 2,
        "source_trial": str(source),
        "source_request_sha256": hashlib.sha256(source_request.encode()).hexdigest(),
        "model": source_metadata.get("model"),
        "configuration": source_metadata.get("configuration"),
        "source_run_id": source_metadata.get("run_id"),
        "workflow_contract": source_metadata.get("workflow_contract"),
        "sandbox_serialization": source_metadata.get("sandbox_serialization"),
        "computation_api": source_metadata.get("computation_api"),
        "script": str(script),
        "script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "profiler_sha256": hashlib.sha256(profiler.read_bytes()).hexdigest(),
        "python": str(args.python.absolute()),
        "scope": "intrusive nested Python attribution; never pool with workflow timings",
        "host_load": "uncontrolled shared host",
        "cpu_affinity": [args.cpu],
    }
    (out / "plan.json").write_text(json.dumps(identity, indent=2) + "\n")
    for repeat in range(args.repetitions):
        folder = out / str(repeat)
        folder.mkdir()
        for name in ["fixture", "private"]:
            if (source / name).exists():
                shutil.copytree(source / name, folder / name)
        if (source / "policy.slp").exists():
            (folder / "policy.slp").write_text(
                (source / "policy.slp").read_text().replace(str(source), str(folder))
            )
        request = source_request.replace(str(source), str(folder))
        (folder / "request.json").write_text(request)
        started_at = datetime.now(UTC).isoformat()
        start = time.perf_counter()
        exit_status = None
        status = "error"
        error = None
        command = [
            "taskset",
            "--cpu-list",
            str(args.cpu),
            str(args.python.absolute()),
            str(profiler),
            str(script),
            str(folder / "request.json"),
            str(folder / "spans.json"),
        ]
        with (folder / "process.log").open("w") as log:
            try:
                completed = subprocess.run(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=args.timeout,
                    cwd=args.cwd,
                    env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"},
                )
                exit_status = completed.returncode
                status = "completed" if exit_status == 0 else "error"
            except subprocess.TimeoutExpired:
                status = "timeout"
            except OSError as exc:
                error = str(exc)
        output = Path(json.loads(request)["output"])
        row = {
            **identity,
            "repeat": repeat,
            "command": command,
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "exit_status": exit_status,
            "status": status,
            "error": error,
            "wall_ms": (time.perf_counter() - start) * 1000,
            "spans": str(folder / "spans.json"),
            "spans_recorded": (folder / "spans.json").exists(),
            "output_recorded": output.is_file(),
            "utility_verified": False,
        }
        with (out / "trials.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(repeat, status, exit_status, flush=True)


if __name__ == "__main__":
    main()
