"""Per-operation microbenchmarks: successful calls and timed operation bodies."""

from __future__ import annotations

import argparse
import ast
import json
import os
import random
import tarfile
from collections import Counter, defaultdict
from contextlib import ExitStack
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from .cases import Case, cases
from .run import digest, trial
from .runtime import host_snapshot, stats, timed

CONDITIONS = ("trusted", "host")


def operations() -> tuple[Case, ...]:
    """All operations must complete in both conditions; no denial latency ratios."""
    originals = {case.name: case for case in cases()}
    selected = [replace(originals["arithmetic"], name="compute_control")]
    for name in ("open_read", "pathlib_read", "os_read", "mmap_read", "ctypes_read"):
        case = originals[name]
        selected.append(replace(case, allowed=True, surface="readonly"))
    for name in ("stat_metadata", "listdir_names"):
        selected.append(replace(originals[name], allowed=True, surface="writable"))
    for operation in ("write", "append", "truncate", "create", "unlink", "mkdir"):
        case = originals[f"allowed_{operation}_subtree"]
        selected.append(replace(case, name=operation))
    # Explicit data size for a useful write; overwrite marker remains another case.
    selected.append(replace(originals["allowed_small_file"], name="write_4kib"))
    selected.append(
        Case(
            "fsync",
            "filesystem",
            "import os\nwith open(p['output'], 'w') as f:\n"
            "    f.write('effect')\n    f.flush()\n    os.fsync(f.fileno())",
            "write",
            True,
            "writable",
        )
    )
    return tuple(selected)


def instrument(case: Case) -> Case:
    """Move imports before the inner timer; preserve the tested effect and oracle."""
    tree = ast.parse(case.source)
    imports = [node for node in tree.body if isinstance(node, ast.Import | ast.ImportFrom)]
    body = [node for node in tree.body if not isinstance(node, ast.Import | ast.ImportFrom)]
    setup = ast.unparse(ast.Module(body=imports, type_ignores=[]))
    operation = ast.unparse(ast.Module(body=body, type_ignores=[]))
    source = (
        f"{setup}\nfrom time import perf_counter_ns as _clock\n"
        f"_operation_start_ns = _clock()\n{operation}\n"
        "_operation_elapsed_ns = _clock() - _operation_start_ns\n"
    )
    return replace(case, source=source)


def summarize(rows: list[dict], expected: tuple[str, ...], samples: int) -> dict:
    measured = [r for r in rows if r["phase"] == "measured"]
    counts = Counter((r["case"], r["condition"]) for r in measured)
    if counts != {(name, condition): samples for name in expected for condition in CONDITIONS}:
        raise ValueError("incomplete operation/condition matrix")
    result = {}
    for name in expected:
        grouped = {}
        summaries = {}
        for condition in CONDITIONS:
            selected = [r for r in measured if r["case"] == name and r["condition"] == condition]
            keyed = {r["round"]: r for r in selected}
            if len(keyed) != samples:
                raise ValueError("duplicate rounds")
            if not all(r.get("effect_observed") for r in selected):
                raise ValueError("failed positive control; cannot compare operation overhead")
            grouped[condition] = keyed
            summaries[condition] = {
                "dispatch_ms": stats([r["elapsed_ms"] for r in selected]),
                "body_ms": stats([r["response"]["operation_elapsed_ns"] / 1e6 for r in selected]),
                "setup_ms": stats([r["setup_ms"] for r in selected]),
                "stages_ms": {
                    key: stats([r["stages_ms"][key] for r in selected])
                    for key in selected[0]["stages_ms"]
                },
            }
        a, b = grouped["host"], grouped["trusted"]
        if a.keys() != b.keys():
            raise ValueError("unpaired rounds")
        delta = [a[k]["elapsed_ms"] - b[k]["elapsed_ms"] for k in sorted(a)]
        body_delta = [
            (a[k]["response"]["operation_elapsed_ns"] - b[k]["response"]["operation_elapsed_ns"])
            / 1e6
            for k in sorted(a)
        ]
        ratio = (
            summaries["host"]["dispatch_ms"]["mean_ms"]
            / summaries["trusted"]["dispatch_ms"]["mean_ms"]
        )
        result[name] = {
            "conditions": summaries,
            "paired_dispatch_ms": stats(delta),
            "paired_body_ms": stats(body_delta),
            "ratio_of_means": ratio,
            "overhead_percent": (ratio - 1) * 100,
        }
    return result


def report(output: Path, summary: dict, plan: dict) -> None:
    lines = [
        "# Per-operation microbenchmark",
        "",
        f"{plan['samples']} measured pairs per operation, "
        f"{plan['warmup']} warm-up pairs and one first-use pair. "
        "Each invocation starts a fresh worker. All measured operations succeed "
        "in both conditions, verified by the original parent-side effect oracles.",
        "",
        "The baseline is a plain Python subprocess; the treatment uses the production "
        "Linux executor with the default Cedar policy backend. This is not a measurement "
        "of the Pandas language sandbox or of statically verified language mode. "
        "No synthetic restricted-language comparator is included.",
        "",
        "## Whole-call latency and incremental overhead",
        "",
        "These times include dispatch, JSON transport, worker startup, policy and "
        "activation work, operation execution and teardown. Fixture construction, "
        "executor construction/preflight, and parent oracle/evidence persistence are "
        "outside the timer. No model calls or durable audit sink are involved.",
        "",
        "| Operation | Python mean ms | Host mean ms | Added ms | Added SD ms | "
        "Added variance ms² | Host/Python | Host P95 ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in summary.items():
        a, b = [row["conditions"][c]["dispatch_ms"] for c in CONDITIONS]
        d = row["paired_dispatch_ms"]
        lines.append(
            f"| {name} | {a['mean_ms']:.2f} | {b['mean_ms']:.2f} | "
            f"{d['mean_ms']:.2f} | {d['sd_ms']:.2f} | {d['variance_ms2']:.2f} | "
            f"{row['ratio_of_means']:.2f}x | {b['p95_ms']:.2f} |"
        )
    lines += [
        "",
        "## Operation body only",
        "",
        "The inner monotonic timer surrounds the operation statements after imports. "
        "It excludes startup, compilation, import initialization, grant preparation, "
        "policy evaluation, and result transport. It includes Python wrappers, "
        "open/close, and user-space work in those statements, so it is not pure "
        "syscall time. Sub-microsecond results can be dominated by clock overhead; "
        "the compute control is retained and no timer cost is subtracted. These "
        "worker-reported timing values are measurement telemetry, not security evidence.",
        "",
        "| Operation | Python mean us | Host mean us | Paired added us | "
        "Paired SD us | Python median us | Host median us |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in summary.items():
        a, b = [row["conditions"][c]["body_ms"] for c in CONDITIONS]
        d = row["paired_body_ms"]
        lines.append(
            f"| {name} | {a['mean_ms'] * 1000:.3f} | {b['mean_ms'] * 1000:.3f} | "
            f"{d['mean_ms'] * 1000:.3f} | {d['sd_ms'] * 1000:.3f} | "
            f"{a['median_ms'] * 1000:.3f} | {b['median_ms'] * 1000:.3f} |"
        )
    lines += [
        "",
        "## Host-stage means (ms)",
        "",
        "The exclusive columns sum to host dispatch time. Policy means Cedar filtering; "
        "worker includes activation and supervision as well as the inner operation. "
        "Do not add the inner operation timing to worker time. Constructor/preflight "
        "time is separate and must be added only when modeling a newly constructed executor.",
        "",
        "| Operation | Grant | Policy | Attest | Negotiate | Worker | "
        "Other invoke | Outside invoke | Constructor/preflight |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in summary.items():
        data = row["conditions"]["host"]
        cells = [
            f"{data['stages_ms'][key]['mean_ms']:.2f}"
            for key in (
                "grant",
                "policy",
                "attest",
                "negotiate",
                "worker",
                "other_invoke",
                "outside_invoke",
            )
        ]
        lines.append(f"| {name} | " + " | ".join(cells) + f" | {data['setup_ms']['mean_ms']:.2f} |")
    lines += [
        "",
        "## Scope, sizes, and unsupported operations",
        "",
        "Read fixtures contain a 32-byte random token. The write case replaces a "
        "32-byte file with a 6-byte marker; append adds that marker; truncate sets "
        "length to zero; create writes a 6-byte marker. write_4kib writes 4096 bytes. "
        "fsync measures open, 6-byte write, flush, fsync and close together. Directory "
        "listing returns the small fresh output fixture. Reads use a visible read-only "
        "file; permitted mutations use a writable subtree. Exact sources are in plan.json.",
        "",
        "The current minimal host backend does not support useful child-exec chains "
        "or network service operations. Rename, links and metadata mutation are also "
        "outside its allowed syscall set. Their rejection times are not reported as "
        "successful-operation overhead. SQLite authorization and static-verification "
        "cost remain separate unmeasured workloads.",
        "",
        "Order is shuffled within each round; one logical CPU is used by parent and "
        "children. Host configuration/load is captured before and after the batch. "
        "OS caches and CPU frequency are uncontrolled; these newly created files are "
        "cache-warm, not a storage-throughput benchmark. SD/variance describe within-run "
        "jitter. Negative body deltas do not establish a host speedup. Different mount "
        "topology, scheduling and allocation can affect body time. No confidence claim "
        "across tasks, machines or storage devices is made.",
        "",
        "Raw data: [samples.jsonl](samples.jsonl), [summary.json](summary.json), "
        "[plan.json](plan.json), [host capture](host-before.json), "
        "[exact source archive](sources.tar.gz). Statistics retain full precision "
        "including median, P95, min/max, SD and variance for every timing scope.",
        "",
        "```sh",
        "cd eval",
        "uv run python -m slanggraph_eval.isolation.operations \\",
        "  --samples 100 --warmup 10 --output reports/e6/operations-new",
        "```",
    ]
    (output / "report.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20261027)
    args = parser.parse_args()
    if args.samples < 2 or args.warmup < 0:
        parser.error("samples >= 2 and warmup >= 0 required")
    args.output.mkdir(parents=True, exist_ok=False)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    (args.output / "host-before.json").write_text(json.dumps(host_snapshot(), indent=2) + "\n")
    corpus = tuple(instrument(c) for c in operations())
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
        "conditions": CONDITIONS,
        "operations": [asdict(c) for c in corpus],
        "clock": "perf_counter_ns",
        "source_hashes": inventory,
        "archive_sha256": digest(args.output / "sources.tar.gz"),
        "order": "shuffle operation/condition cells within each round",
        "body_scope": "operation statements after imports, excludes source compilation",
        "dispatch_scope": "same as E6 trial, excludes executor construction and parent oracles",
    }
    (args.output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    from langgraph.prebuilt.security import linux
    from langgraph.prebuilt.security.enforcement import EnforcementCoordinator

    spans = defaultdict(float)
    rng = random.Random(args.seed)
    rows = []
    with ExitStack() as stack, (args.output / "samples.jsonl").open("x") as stream:
        for owner, attribute, label in [
            (linux.LinuxSandboxExecutor, "invoke", "invoke"),
            (linux.LinuxSandboxExecutor, "_compile_grant", "grant"),
            (linux.LinuxSandboxExecutor, "_run_worker", "worker"),
            (linux.CedarPolicyBackend, "filter", "policy"),
            (linux._LinuxBubblewrapAdapter, "attest", "attest"),
            (EnforcementCoordinator, "negotiate", "negotiate"),
        ]:
            stack.enter_context(
                patch.object(owner, attribute, timed(spans, label, getattr(owner, attribute)))
            )
        for index in range(1 + args.warmup + args.samples):
            phase = "first_use" if index == 0 else "warmup" if index <= args.warmup else "measured"
            jobs = [(case, condition) for case in corpus for condition in CONDITIONS]
            rng.shuffle(jobs)
            for case, condition in jobs:
                spans.clear()
                row = trial(case, condition, index)
                if condition == "host" and "invoke" in spans:
                    stages = {
                        key: spans[key]
                        for key in ("grant", "policy", "attest", "negotiate", "worker")
                    }
                    stages["other_invoke"] = spans["invoke"] - sum(stages.values())
                    stages["outside_invoke"] = row["elapsed_ms"] - spans["invoke"]
                else:
                    stages = {"subprocess_and_transport": row.get("elapsed_ms", 0)}
                row.update(phase=phase, round=index, stages_ms=stages)
                rows.append(row)
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
                if not row.get("effect_observed") or "operation_elapsed_ns" not in row.get(
                    "response", {}
                ):
                    raise RuntimeError(f"invalid positive control: {case.name}/{condition}")
                if min(stages.values()) < 0:
                    raise RuntimeError("overlapping stage timing")
            print(f"round {index}: {phase}; {len(rows)} samples", flush=True)
    (args.output / "host-after.json").write_text(json.dumps(host_snapshot(), indent=2) + "\n")
    summary = summarize(rows, tuple(c.name for c in corpus), args.samples)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    report(args.output, summary, plan)


if __name__ == "__main__":
    main()
