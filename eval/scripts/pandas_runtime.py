"""Replay a recorded application computation; no model calls or synthetic noop."""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stats(values):
    return {
        "n": len(values),
        "mean_ms": statistics.mean(values),
        "sd_ms": statistics.stdev(values) if len(values) > 1 else None,
        "variance_ms2": statistics.variance(values) if len(values) > 1 else None,
        "median_ms": statistics.median(values),
        "p95_ms": sorted(values)[max(0, (95 * len(values) + 99) // 100 - 1)],
        "min_ms": min(values),
        "max_ms": max(values),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--profile-audit", action="store_true")
    parser.add_argument("--seed", type=int, default=20261028)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    for name in ["LANGCHAIN_TRACING_V2", "LANGSMITH_TRACING"]:
        os.environ[name] = "false"
    os.environ["OPENBLAS_NUM_THREADS"] = "1"
    os.environ["OMP_NUM_THREADS"] = "1"
    sys.path[:0] = [str(ROOT / "libs/prebuilt"), str(ROOT / "libs/langgraph")]
    seed = ROOT / "eval/results/pandas-C-february-r1-cd25840ffd594f5a896b160041a2b6a4"
    manifest = json.loads((ROOT / "eval/apps/pandas/policy/manifest-v8.json").read_text())
    for name, expected in manifest["integration_sources"].items():
        assert digest(ROOT / "eval" / name) == expected, name
    inventory = json.loads((ROOT / "eval/intake/slanggraph-source-hashes.json").read_text())
    # Keep the same source identity check as the application runner.
    for name, expected in inventory.items():
        if isinstance(expected, str) and (ROOT / name).is_file():
            assert digest(ROOT / name) == expected, name
    events = [json.loads(line) for line in (seed / "events.jsonl").read_text().splitlines()]
    payload = next(e["payload"] for e in events if e["kind"] == "computation")
    (out / "trace.json").write_text(json.dumps(payload, indent=2) + "\n")
    shutil.copy2(__file__, out / "benchmark.py")
    plan = {
        "kind": "local recorded-application computation replay",
        "seed_run": seed.name,
        "warmup_per_configuration": args.warmup,
        "measured_per_configuration": args.samples,
        "order": "shuffle ABC within each matched round",
        "seed": args.seed,
        "clock": "perf_counter_ns",
        "model_calls": 0,
        "diagnostic_audit_profiling": args.profile_audit,
        "strace": False,
        "cpu_affinity": [cpu],
        "policy_version": 3,
        "integration_sources": manifest["integration_sources"],
        "trace_sha256": digest(out / "trace.json"),
        "script_sha256": digest(out / "benchmark.py"),
        "cold_definition": "first invocation per initialized configuration, not cold OS cache",
        "timing_scope": (
            "bridge invocation including event/audit/receipt IO; fixture reset "
            "and initialization excluded"
        ),
        "stage_scope": (
            "nested spans, not additive: original subprocess, Linux invoke, "
            "grant compilation, worker path"
        ),
        "started_at": datetime.now(UTC).isoformat(),
    }
    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    host = {
        "kernel": platform.release(),
        "python": sys.version,
        "affinity": [cpu],
        "meminfo": Path("/proc/meminfo").read_text(),
        "lscpu": json.loads(subprocess.check_output(["lscpu", "-J"])),
        "gpu": subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv"],
            text=True,
        ),
        "loadavg": list(os.getloadavg()),
    }
    (out / "host.json").write_text(json.dumps(host, indent=2) + "\n")
    imports_start = time.perf_counter_ns()
    import ai_data_science_team.agents.data_wrangling_agent as wrangling
    import ai_data_science_team.utils.sandbox as sandbox
    from langgraph.prebuilt.security import LinuxSandboxExecutor

    imports_ms = (time.perf_counter_ns() - imports_start) / 1e6
    spans = {}

    def timed(name, fn):
        def wrapped(*a, **kw):
            started = time.perf_counter_ns()
            try:
                return fn(*a, **kw)
            finally:
                spans[name] = spans.get(name, 0) + (time.perf_counter_ns() - started) / 1e6

        return wrapped

    if args.profile_audit:
        from langgraph.prebuilt.security import SqliteAuditSink

        SqliteAuditSink.write = timed("audit_write_ms", SqliteAuditSink.write)
    sandbox.run_code_sandboxed_subprocess = timed(
        "upstream_subprocess_ms", sandbox.run_code_sandboxed_subprocess
    )
    for name in ["invoke", "_compile_grant", "_run_worker"]:
        setattr(
            LinuxSandboxExecutor, name, timed(name + "_ms", getattr(LinuxSandboxExecutor, name))
        )
    spec = importlib.util.spec_from_file_location(
        "pandas_replay_integration", ROOT / "eval/apps/pandas/integration.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    contexts = {}
    setup = {}
    for config in "ABC":
        folder = out / config
        folder.mkdir()
        scratch = Path(tempfile.mkdtemp(prefix="slanggraph-runtime-"))
        fixture = scratch / "fixture"
        fixture.mkdir()
        (fixture / "outputs").mkdir()
        # Reconstruct the table from the recorded application input, no model.
        import pandas as pd

        pd.DataFrame(payload["data"]).to_csv(fixture / "sales.csv", index=False)
        request = json.loads((seed / "request.json").read_text())
        old_root = request["fixture_root"]
        policy = (seed / "policy.slp").read_text().replace(old_root, str(fixture))
        (folder / "policy.slp").write_text(policy)
        request.update(
            configuration=config,
            fixture_root=str(fixture),
            events=str(folder / "events.jsonl"),
            effective_policy=str(folder / "policy.slp"),
            run_id=out.name + "-" + config,
        )
        (folder / "request.json").write_text(json.dumps(request, indent=2) + "\n")
        started = time.perf_counter_ns()
        module.install(request)
        setup[config] = {
            "install_ms": (time.perf_counter_ns() - started) / 1e6,
            "policy_sha256": digest(folder / "policy.slp"),
        }
        contexts[config] = wrangling.run_code_sandboxed_subprocess
    (out / "setup.json").write_text(
        json.dumps({"shared_imports_ms": imports_ms, "configurations": setup}, indent=2) + "\n"
    )
    rows = []
    rng = random.Random(args.seed)
    for index in range(1 + args.warmup + args.samples):
        phase = "cold" if index == 0 else "warmup" if index <= args.warmup else "measured"
        order = list("ABC")
        rng.shuffle(order)
        for config in order:
            spans.clear()
            started = time.perf_counter_ns()
            result, error = contexts[config](
                code_snippet=payload["code"],
                function_name=payload["function_name"],
                data=payload["data"],
                timeout=15,
                memory_limit_mb=512,
                data_format=payload["data_format"],
            )
            elapsed = (time.perf_counter_ns() - started) / 1e6
            actual = pd.DataFrame(result)
            valid = error is None and actual.shape == (1, 1) and float(actual.iloc[0, 0]) == 120
            row = {
                "configuration": config,
                "round": index,
                "phase": phase,
                "elapsed_ms": elapsed,
                "valid": valid,
                "error": error,
                "spans": dict(spans),
            }
            rows.append(row)
            with (out / "samples.jsonl").open("a") as stream:
                stream.write(json.dumps(row) + "\n")
            if not valid:
                raise RuntimeError("Replay failed outcome check; samples retained")
        if index % 10 == 0:
            print(json.dumps({"round": index, "phase": phase}), flush=True)
    measured = [r for r in rows if r["phase"] == "measured"]
    summary = {
        "configurations": {},
        "paired_differences": {},
        "qualification": (
            "One recorded task; repeated local timing observations, not "
            "independent task samples or model-driven quality evaluation."
        ),
    }
    for config in "ABC":
        selected = [r for r in measured if r["configuration"] == config]
        summary["configurations"][config] = stats([r["elapsed_ms"] for r in selected])
        summary["configurations"][config]["stages"] = {
            k: stats([r["spans"][k] for r in selected]) for k in selected[0]["spans"]
        }
    for left, right in [("B", "A"), ("C", "A"), ("C", "B")]:
        ls = [r["elapsed_ms"] for r in measured if r["configuration"] == left]
        rs = [r["elapsed_ms"] for r in measured if r["configuration"] == right]
        summary["paired_differences"][left + "-" + right] = stats(
            [a - b for a, b in zip(ls, rs, strict=False)]
        )
        summary["paired_differences"][left + "-" + right]["ratio_of_means"] = statistics.mean(
            ls
        ) / statistics.mean(rs)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
