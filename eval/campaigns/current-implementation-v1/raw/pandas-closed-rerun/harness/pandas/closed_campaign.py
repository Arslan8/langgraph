"""C-closed cohort over the frozen ten pandas tasks (D11 closed admission).

Reuses the frozen task list, fixture rows, utility oracle and framework
capture helpers from `eval/remaining/application_campaign.py` by import, so the
oracle is the same function object the A/B/C cohorts used. Trial rows keep the
schema of that script (`schema_version` 2) with `mode="C-closed"` and a few
added C-closed fields. The output directory must not exist.

    python eval/apps/pandas/closed_campaign.py --output DIR [--pilot] \
        [--repetitions 5]
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import random
import shutil
import subprocess
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MODE = "C-closed"
MANIFESTS = {
    "v20": HERE / "policy/manifest-v20-closed.json",
    "v21": HERE / "policy/manifest-v21-closed.json",
}


def _campaign():
    spec = importlib.util.spec_from_file_location(
        "pandas_application_campaign", ROOT / "eval/remaining/application_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


campaign = _campaign()
TASKS = campaign.TASKS
ROWS = campaign.ROWS
UPSTREAM = campaign.UPSTREAM
oracle = campaign.oracle


def write_fixture(fixture):
    """Write the frozen sales fixture exactly as application_campaign.py does."""
    fixture.mkdir()
    (fixture / "outputs").mkdir()
    with (fixture / "sales.csv").open("w") as stream:
        writer = csv.writer(stream)
        writer.writerow(["date", "region", "product", "sales"])
        writer.writerows(ROWS)
    return fixture / "sales.csv"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--manifest", choices=sorted(MANIFESTS), default="v20")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    manifest_path = MANIFESTS[args.manifest]
    manifest = json.loads(manifest_path.read_text())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    selection = manifest["lean_worker"]
    lean_worker = campaign.capture_lean_worker(out, Path(selection["binary"]), selection["sha256"])
    tasks = [TASKS[5]] if args.pilot else TASKS
    tags = json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10))
    if not any(
        m["name"] == manifest["model"]["name"] and m["digest"] == manifest["model"]["digest"]
        for m in tags["models"]
    ):
        raise SystemExit("Pinned model is not served")
    campaign.dump(out / "models.json", tags)
    snapshot = out / "harness"
    shutil.copytree(
        HERE, snapshot / "pandas", ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    shutil.copy2(ROOT / "eval/remaining/application_campaign.py", snapshot)
    sources = {
        str(p.relative_to(snapshot)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in snapshot.rglob("*.py")
    }
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    framework_root = campaign.freeze_framework(out)
    framework_sources = campaign.capture_framework(out, framework_root)
    campaign.dump(out / "framework-sources.json", framework_sources)
    framework_digest = campaign.identity_digest(framework_sources)
    dataset = manifest["dataset"]
    campaign.dump(
        out / "plan.json",
        dict(
            tasks=tasks,
            fixture=ROWS,
            conditions=[MODE],
            repetitions=args.repetitions,
            pilot=args.pilot,
            model=manifest["model"],
            graph_retries=manifest["graph_retries"],
            sandbox_serialization=manifest["sandbox_serialization"],
            workflow_contract=manifest["workflow_contract"],
            computation_api=manifest["computation_api"],
            manifest_version=manifest["version"],
            manifest_sha256=manifest_sha256,
            lean_worker=lean_worker,
            lean_worker_configuration=MODE,
            dataset=dataset,
            trusted_declarations=manifest["trusted_declarations"],
            state_normalization=manifest.get("state_normalization"),
            timeout_s=180,
            seed=20261026,
            timer="subprocess wall time including graph/model/authorization/audit; setup separate",
            sources=sources,
            framework_sources_sha256=framework_digest,
            framework_runtime_root=str(framework_root),
            frozen_framework=True,
            host_load="uncontrolled shared host",
            upstream_revision=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=UPSTREAM, text=True
            ).strip(),
            model_service="coordinator-owned ollama serve; not started or stopped here",
        ),
    )
    trials = out / "trials.jsonl"
    template_source = (HERE / "policy" / manifest["policy_template"]).read_text()
    for repetition in range(args.repetitions):
        jobs = list(tasks)
        random.Random(20261026 + repetition).shuffle(jobs)
        for case, prompt, expected in jobs:
            run_id = f"{case}-{MODE}-{repetition}"
            folder = out / run_id
            folder.mkdir()
            fixture = folder / "fixture"
            sales = write_fixture(fixture)
            fixture_sha256 = hashlib.sha256(sales.read_bytes()).hexdigest()
            if fixture_sha256 != dataset["sha256"]:
                raise SystemExit("Fixture bytes differ from the pinned dataset digest")
            template = template_source
            for key, value in dict(
                DATASET=str(sales),
                OUTPUT=str(fixture / "outputs"),
                PACKAGES=str(UPSTREAM / ".venv/lib/python3.13/site-packages"),
                EXTRA_TOOL="",
                EXTRA_PRINCIPAL="",
            ).items():
                template = template.replace("@" + key + "@", value)
            (folder / "policy.slp").write_text(template)
            request = dict(
                app="pandas",
                task=prompt,
                model=manifest["model"],
                fixture_root=str(fixture),
                output=str(folder / "output.json"),
                events=str(folder / "events.jsonl"),
                configuration=MODE,
                integration=True,
                slanggraph_root=str(framework_root),
                run_id=run_id,
                effective_policy=str(folder / "policy.slp"),
                sandbox_serialization=manifest["sandbox_serialization"],
                workflow_contract=manifest["workflow_contract"],
                computation_api=manifest["computation_api"],
                graph_retries=manifest["graph_retries"],
                lean_worker=lean_worker,
                dataset=dict(
                    path=str(sales.resolve()),
                    sha256=dataset["sha256"],
                    max_bytes=dataset["max_bytes"],
                ),
                trusted_declarations=manifest["trusted_declarations"],
            )
            if manifest.get("state_normalization") is not None:
                request["state_normalization"] = manifest["state_normalization"]
            campaign.dump(folder / "request.json", request)
            trial_sources = campaign.capture_framework(out, framework_root)
            campaign.dump(folder / "framework-sources-before.json", trial_sources)
            started_at = datetime.now(UTC).isoformat()
            start = time.perf_counter()
            status = "error"
            code = None
            command = [
                "taskset",
                "--cpu-list",
                str(min(os.sched_getaffinity(0))),
                str(UPSTREAM / ".venv/bin/python"),
                str(snapshot / "pandas/backend_closed.py"),
                str(folder / "request.json"),
            ]
            with (folder / "process.log").open("w") as log:
                try:
                    completed = subprocess.run(
                        command,
                        cwd=UPSTREAM,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=180,
                        env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"},
                    )
                    code = completed.returncode
                    status = "completed" if code == 0 else "error"
                except subprocess.TimeoutExpired:
                    status = "timeout"
            elapsed = (time.perf_counter() - start) * 1000
            trial_sources_after = campaign.capture_framework(out, framework_root)
            campaign.dump(folder / "framework-sources-after.json", trial_sources_after)
            result = (
                json.loads((folder / "output.json").read_text())
                if (folder / "output.json").exists()
                else {}
            )
            oracle_match = oracle(result, expected, case == "monthly_chart")
            success = status == "completed" and oracle_match
            events = (
                [json.loads(line) for line in (folder / "events.jsonl").read_text().splitlines()]
                if (folder / "events.jsonl").exists()
                else []
            )
            starts = [x["monotonic"] for x in events if x.get("kind") == "model_start"]
            ends = [x["monotonic"] for x in events if x.get("kind") == "model_end"]
            row = dict(
                schema_version=2,
                application="pandas",
                started_at=started_at,
                finished_at=datetime.now(UTC).isoformat(),
                model=manifest["model"],
                sources=sources,
                framework_sources_sha256=campaign.identity_digest(trial_sources),
                framework_sources=trial_sources,
                source_hashes_unchanged_before_after=trial_sources == trial_sources_after,
                policy_sha256=hashlib.sha256(template.encode()).hexdigest(),
                sandbox_serialization=manifest["sandbox_serialization"],
                workflow_contract=manifest["workflow_contract"],
                computation_api=manifest["computation_api"],
                graph_retries=manifest["graph_retries"],
                manifest_version=manifest["version"],
                state_normalization=manifest.get("state_normalization"),
                lean_worker=lean_worker,
                timing_scope="subprocess wall time; setup excluded; shared host",
                missing_phases=["policy", "audit"],
                case_id=case,
                repeat=repetition,
                session=repetition,
                mode=MODE,
                concrete_executor="LinuxSandboxExecutor",
                run_id=run_id,
                status=status,
                exit_status=code,
                legitimate_result=success,
                output_matches_oracle=oracle_match,
                observed_effect="not-tested: clean utility task",
                wall_ms=elapsed,
                model_calls=len(starts),
                model_ms=sum((b - a) * 1000 for a, b in zip(starts, ends, strict=False)),
                computation_calls=sum(x.get("kind") == "computation" for x in events),
                dataset_reads=sum(x.get("kind") == "dataset_read" for x in events),
                fixture_sha256=fixture_sha256,
                closed_inventory=str(folder / "closed-inventory.json")
                if (folder / "closed-inventory.json").exists()
                else "missing",
                activation_evidence=str(folder / "activation-receipts.json")
                if (folder / "activation-receipts.json").exists()
                else "not-applicable",
                audit=str(folder / "security.sqlite")
                if (folder / "security.sqlite").exists()
                else "not-applicable",
                expected=expected,
            )
            with trials.open("a") as stream:
                stream.write(json.dumps(row) + "\n")
            print(run_id, status, success, round(elapsed), flush=True)


if __name__ == "__main__":
    main()
