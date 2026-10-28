"""Matched successful-workload latency and exclusive host-stage decomposition."""

from __future__ import annotations

import argparse
import functools
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import tarfile
import time
from collections import defaultdict
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from .cases import cases
from .run import digest, trial

CONDITIONS = ("trusted", "language_helper", "host", "host_language_helper")
WORKLOADS = ("arithmetic", "allowed_read", "allowed_small_file")


def stats(values):
    if not values:
        raise ValueError("empty timing series")
    return {
        "n": len(values),
        "mean_ms": statistics.mean(values),
        "sd_ms": statistics.stdev(values) if len(values) > 1 else None,
        "variance_ms2": statistics.variance(values) if len(values) > 1 else None,
        "median_ms": statistics.median(values),
        "p95_ms": sorted(values)[(95 * len(values) + 99) // 100 - 1],
        "min_ms": min(values),
        "max_ms": max(values),
    }


def summarize(rows):
    measured = [r for r in rows if r["phase"] == "measured"]
    output = {}
    for workload in WORKLOADS:
        selected = [r for r in measured if r["case"] == workload]
        values = {}
        for condition in CONDITIONS:
            condition_rows = [r for r in selected if r["condition"] == condition]
            values[condition] = {
                "dispatch": stats([r["elapsed_ms"] for r in condition_rows]),
                "setup": stats([r["setup_ms"] for r in condition_rows]),
                "stages": {
                    key: stats([r["stages_ms"][key] for r in condition_rows])
                    for key in condition_rows[0]["stages_ms"]
                },
                "valid": all(r.get("effect_observed") for r in condition_rows),
            }
        pairs = {}
        for left, right in [
            ("host", "trusted"),
            ("host_language_helper", "language_helper"),
            ("host_language_helper", "host"),
        ]:
            a = {r["round"]: r for r in selected if r["condition"] == left}
            b = {r["round"]: r for r in selected if r["condition"] == right}
            if a.keys() != b.keys() or len(a) != len(
                [r for r in selected if r["condition"] == left]
            ):
                raise ValueError("unpaired or duplicate timing samples")
            delta = [a[k]["elapsed_ms"] - b[k]["elapsed_ms"] for k in sorted(a)]
            ratio = statistics.mean(r["elapsed_ms"] for r in a.values()) / statistics.mean(
                r["elapsed_ms"] for r in b.values()
            )
            pairs[left + "-" + right] = stats(delta) | {
                "ratio_of_means": ratio,
                "overhead_percent": 100 * (ratio - 1),
            }
        output[workload] = {"conditions": values, "paired": pairs}
    return output


def timed(spans, name, function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        start = time.perf_counter_ns()
        try:
            return function(*args, **kwargs)
        finally:
            spans[name] += (time.perf_counter_ns() - start) / 1e6

    return wrapped


def host_snapshot():
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        return {
            "command": args,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    return {
        "recorded_at": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "os_release": Path("/etc/os-release").read_text(),
        "lscpu": command(["lscpu", "-J"]),
        "memory": Path("/proc/meminfo").read_text(),
        "affinity": sorted(os.sched_getaffinity(0)),
        "loadavg": list(os.getloadavg()),
        "bubblewrap": command(["bwrap", "--version"]),
        "filesystem": command(["findmnt", "-T", str(Path(__file__).resolve()), "-J"]),
        "block_devices": command(["lsblk", "-J", "-o", "NAME,MODEL,ROTA,TYPE"]),
        "gpu": command(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv"]
        ),
        "clock": vars(time.get_clock_info("perf_counter")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20261026)
    args = parser.parse_args()
    if args.samples < 2 or args.warmup < 0:
        parser.error("samples >= 2 and warmup >= 0 required")
    args.output.mkdir(parents=True, exist_ok=False)
    cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    (args.output / "host-before.json").write_text(json.dumps(host_snapshot(), indent=2) + "\n")
    repo = Path(__file__).resolve().parents[4]
    inventory = {}
    with tarfile.open(args.output / "sources.tar.gz", "w:gz") as archive:
        for root in [
            Path(__file__).parent,
            repo / "libs/prebuilt/langgraph",
            repo / "libs/langgraph/langgraph",
            repo / "libs/checkpoint/langgraph",
        ]:
            for path in sorted(root.rglob("*.py")):
                relative = str(path.relative_to(repo))
                inventory[relative] = digest(path)
                archive.add(path, arcname=relative)
    plan = {
        "samples": args.samples,
        "warmup": args.warmup,
        "seed": args.seed,
        "workloads": WORKLOADS,
        "conditions": CONDITIONS,
        "order": "seeded shuffle of workload/condition pairs within every round",
        "source_hashes": inventory,
        "archive_sha256": digest(args.output / "sources.tar.gz"),
        "timer": "perf_counter_ns",
        "fresh_worker_each_call": True,
        "setup_scope": "fresh executor construction and preflight; outside dispatch timer",
        "dispatch_scope": "same E6 trial dispatch; fixture/reset/oracle/evidence IO excluded",
        "stage_scope": "nested inclusive spans; explicit residuals form exclusive partition",
        "audit": "no durable audit sink in direct-executor E6; receipts retained",
        "model_calls": 0,
        "affinity": [cpu],
        "os_cache": "uncontrolled",
        "instrumented": True,
        "started_at": datetime.now(UTC).isoformat(),
    }
    (args.output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    from langgraph.prebuilt.security import linux
    from langgraph.prebuilt.security.enforcement import EnforcementCoordinator

    spans = defaultdict(float)
    probes = {c.name: c for c in cases()}
    rows = []
    rng = random.Random(args.seed)
    with ExitStack() as stack, (args.output / "samples.jsonl").open("x") as stream:
        targets = [
            (linux.LinuxSandboxExecutor, "invoke", "invoke"),
            (linux.LinuxSandboxExecutor, "_compile_grant", "grant"),
            (linux.LinuxSandboxExecutor, "_run_worker", "worker"),
            (linux.CedarPolicyBackend, "filter", "policy"),
            (linux._LinuxBubblewrapAdapter, "attest", "attest"),
            (EnforcementCoordinator, "negotiate", "negotiate"),
        ]
        for owner, attribute, name in targets:
            stack.enter_context(
                patch.object(owner, attribute, timed(spans, name, getattr(owner, attribute)))
            )
        for index in range(1 + args.warmup + args.samples):
            phase = "first_use" if index == 0 else "warmup" if index <= args.warmup else "measured"
            jobs = [(w, c) for w in WORKLOADS for c in CONDITIONS]
            rng.shuffle(jobs)
            for workload, condition in jobs:
                spans.clear()
                row = trial(probes[workload], condition, index)
                row.update(round=index, phase=phase, inclusive_spans_ms=dict(spans))
                if condition.startswith("host") and "invoke" in spans:
                    components = {
                        key: spans[key]
                        for key in ("grant", "policy", "attest", "negotiate", "worker")
                    }
                    components["other_invoke"] = spans["invoke"] - sum(components.values())
                    components["outside_invoke"] = row["elapsed_ms"] - spans["invoke"]
                    if min(components.values()) < -0.001:
                        raise RuntimeError("unexpected overlapping stage instrumentation")
                else:
                    components = {"subprocess_and_transport": row.get("elapsed_ms", 0)}
                row["stages_ms"] = components
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
                rows.append(row)
                if not row.get("effect_observed"):
                    raise RuntimeError(f"failed positive control: {workload}/{condition}")
            if index % 10 == 0:
                print(f"round {index}: {phase}", flush=True)
    (args.output / "host-after.json").write_text(json.dumps(host_snapshot(), indent=2) + "\n")
    (args.output / "summary.json").write_text(json.dumps(summarize(rows), indent=2) + "\n")
    print(f"Saved {len(rows)} samples to {args.output}", flush=True)


if __name__ == "__main__":
    main()
