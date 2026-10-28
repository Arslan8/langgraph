"""Paired real A/B/C serialization checks, separate from full-workflow utility."""

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_case(folder, mode, repaired, serializer):
    sys.path[:0] = [str(ROOT / "libs/prebuilt"), str(ROOT / "libs/langgraph")]
    import ai_data_science_team.agents.data_wrangling_agent as wrangling
    import ai_data_science_team.utils.sandbox as upstream

    source = Path(upstream.__file__).resolve()
    (folder / "outputs").mkdir()
    (folder / "sales.csv").write_text("date,sales\n2026-01-05,100\n")
    policy = (ROOT / "eval/apps/pandas/policy/compute-v3.slp.template").read_text()
    for key, value in {
        "DATASET": str(folder / "sales.csv"),
        "OUTPUT": str(folder / "outputs"),
        "PACKAGES": str(source.parents[2]),
        "EXTRA_TOOL": "",
        "EXTRA_PRINCIPAL": "",
    }.items():
        policy = policy.replace("@" + key + "@", value)
    (folder / "policy.slp").write_text(policy)
    request = {
        "events": str(folder / "events.jsonl"),
        "configuration": mode,
        "effective_policy": str(folder / "policy.slp"),
        "run_id": folder.name,
        "fixture_root": str(folder),
        "sandbox_serialization": serializer if repaired else None,
    }
    (folder / "request.json").write_text(json.dumps(request, indent=2) + "\n")
    spec = importlib.util.spec_from_file_location(
        "integration", ROOT / "eval/apps/pandas/integration.py"
    )
    integration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(integration)
    original_runner = upstream.SANDBOX_RUNNER_SCRIPT
    integration.install(request)
    if original_runner != upstream.SANDBOX_RUNNER_SCRIPT:
        raise AssertionError("Adapter changed the original condition's global runner")
    code = "def compute(df):\n    return df.assign(date=pd.to_datetime(df['date'])"
    expected = {"date": {"0": "2026-01-05T00:00:00"}, "sales": {"0": 100}}
    if serializer == "recursive-json-v2":
        code += ", period=pd.to_datetime(df['date']).dt.to_period('M')"
        expected["period"] = {"0": "2026-01"}
    code += ")"
    result, error = wrangling.run_code_sandboxed_subprocess(
        code_snippet=code,
        function_name="compute",
        data={"date": {"0": "2026-01-05"}, "sales": {"0": 100}},
        timeout=15,
        memory_limit_mb=512,
    )
    passed = (
        error is None and result == expected
        if repaired
        else result is None and isinstance(error, str) and "Timestamp" in error
    )
    (folder / "result.json").write_text(
        json.dumps(
            {
                "result": result,
                "error": error,
                "expected_behavior_observed": passed,
                "upstream_sandbox_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=["A", "B", "C"])
    parser.add_argument("--repaired", action="store_true")
    parser.add_argument(
        "--serializer",
        choices=["recursive-json-v1", "recursive-json-v2"],
        default="recursive-json-v2",
    )
    args = parser.parse_args()
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    out = args.output.absolute()
    if args.mode:
        return run_case(out, args.mode, args.repaired, args.serializer)
    out.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), *sorted((ROOT / "eval/apps/pandas").glob("*.py"))]
    for source in sources:
        snapshot = out / "sources" / source.relative_to(ROOT)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(source.read_bytes())
    identity = {
        "schema_version": 1,
        "kind": "deterministic serialization regression, not full-workflow utility",
        "model_calls": 0,
        "python": sys.executable,
        "serializer": args.serializer,
        "host_load": "uncontrolled shared host; no performance claim",
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "sources": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
        },
        "framework_sources": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for library in ["prebuilt", "langgraph"]
            for p in (ROOT / "libs" / library / "langgraph").rglob("*.py")
        },
    }
    (out / "plan.json").write_text(json.dumps(identity, indent=2) + "\n")
    failures = 0
    for repaired in [False, True]:
        for mode in ["A", "B", "C"]:
            folder = out / f"{'repaired' if repaired else 'original'}-{mode}"
            folder.mkdir()
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--output",
                str(folder),
                "--mode",
                mode,
            ]
            if repaired:
                command.append("--repaired")
            command.extend(["--serializer", args.serializer])
            started = datetime.now(UTC).isoformat()
            status = "timeout"
            exit_status = None
            with (folder / "process.log").open("w") as log:
                try:
                    completed = subprocess.run(
                        command,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=60,
                        env={**os.environ, "OPENBLAS_NUM_THREADS": "1"},
                    )
                    exit_status = completed.returncode
                    status = "completed" if exit_status == 0 else "error"
                except subprocess.TimeoutExpired:
                    pass
            failures += status != "completed"
            with (out / "trials.jsonl").open("a") as stream:
                stream.write(
                    json.dumps(
                        {
                            **identity,
                            "mode": mode,
                            "repaired": repaired,
                            "started_at": started,
                            "finished_at": datetime.now(UTC).isoformat(),
                            "command": command,
                            "status": status,
                            "exit_status": exit_status,
                        }
                    )
                    + "\n"
                )
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
