"""Production source-verified in-process versus Linux invocation measurements."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import random
import tarfile
import tempfile
import time
from collections import defaultdict
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from langchain_core.tools import tool
from langgraph.prebuilt.security import cedar_security
from langgraph.prebuilt.security.inprocess import ManifestAdmission, read_text
from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor

from .operations import operations
from .run import LIMITS, WORKER, digest, invoke_host
from .runtime import host_snapshot, stats, timed


@tool("run")
def verified_read(path: str) -> str:
    """Read one granted UTF-8 file."""
    return read_text(path)


@tool("run")
def verified_two_reads(path: str) -> str:
    """Read the granted file twice and return the second result."""
    read_text(path)
    return read_text(path)


@tool("run")
def verified_compute() -> int:
    """Return the constant-return control."""
    return 42


POLICY = "permit(principal, action, resource);"
MANIFEST = "runs inprocess\nfs read @{path} need"
WORKLOADS = {
    "constant_control": (verified_compute, 0, 0),
    "read_32b": (verified_read, 32, 1),
    "read_4kib": (verified_read, 4096, 1),
    "read_64kib": (verified_read, 65536, 1),
    "two_reads_32b": (verified_two_reads, 32, 2),
}


def make_matched_executor(root: Path, reads: bool):
    """Grant the host only the same read resource used by verified mode."""
    from langgraph.prebuilt.security import LinuxSandboxExecutor, LinuxToolSpec, parse_profiles

    rule = f"fs read {root}/allowed" if reads else ""
    profile = (
        "tool run {\n owner analyst\n grant analyst: call\n runs linux\n"
        " syscalls @minimal\n "
        + (rule + " need" if rule else "")
        + "\n}\nprincipal evaluator {\n roles analyst\n "
        + rule
        + "\n}\n"
    )
    return LinuxSandboxExecutor(
        parse_profiles(profile, source="verified-matched.slp"),
        {"run": LinuxToolSpec("worker:run", WORKER, digest(WORKER))},
        runtime_roots=(WORKER.parent,),
        default_wall_timeout_s=5,
        default_limits=LIMITS,
    )


def admission_census(directory: Path) -> list[dict]:
    """Ask the real admission checker about each original raw-API operation."""
    rows = []
    for case in operations():
        source = (
            "from langchain_core.tools import tool\n@tool('run')\n"
            'def candidate(p: str, path: str):\n    """Admission probe; never executed."""\n'
            + "\n".join("    " + line for line in case.source.splitlines())
            + "\n"
        )
        path = directory / f"probe_{case.name}.py"
        path.write_text(source)
        spec = importlib.util.spec_from_file_location(f"probe_{case.name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        start = time.perf_counter_ns()
        try:
            cedar_security(
                module.candidate,
                policy=POLICY,
                manifest="runs inprocess"
                if case.name == "compute_control"
                else "runs inprocess\nfs read+write+truncate @{path} need",
            )
            status, reason = "admitted", None
        except Exception as exc:
            status, reason = "rejected", f"{type(exc).__name__}: {exc}"
        rows.append(
            dict(
                case=case.name,
                source=source,
                status=status,
                reason=reason,
                elapsed_ms=(time.perf_counter_ns() - start) / 1e6,
            )
        )
    return rows


def summarize(rows, samples):
    result = {}
    for name in WORKLOADS:
        selected = [r for r in rows if r["case"] == name and r["phase"] == "measured"]
        groups = {
            c: {r["round"]: r for r in selected if r["condition"] == c}
            for c in ("verified", "host")
        }
        assert len(selected) == 2 * samples
        assert all(len(g) == samples for g in groups.values())
        assert groups["verified"].keys() == groups["host"].keys()
        assert all(r["valid"] and r["receipt"] for r in selected)
        summaries = {
            c: {
                key: stats([r[key] for r in g.values()])
                for key in ("elapsed_ms", "policy_ms", "execution_ms")
            }
            for c, g in groups.items()
        }
        delta = stats(
            [
                groups["host"][k]["elapsed_ms"] - groups["verified"][k]["elapsed_ms"]
                for k in sorted(groups["host"])
            ]
        )
        result[name] = dict(
            conditions=summaries,
            paired_added_ms=delta,
            host_over_verified=summaries["host"]["elapsed_ms"]["mean_ms"]
            / summaries["verified"]["elapsed_ms"]["mean_ms"],
        )
    return result


def report(output, summary, setup, args):
    lines = [
        "# Production verified-language versus host isolation",
        "",
        f"{args.samples} randomized paired measured calls per workload; {args.warmup} warmups "
        "and one first-use pair. Every returned value is checked against the full expected "
        "content, and every invocation has a production receipt.",
        "",
        "Verified means actual cedar_security source admission (ManifestAdmission), "
        "runtime binding validation, Cedar authorization, grant activation, and the "
        "approved read_text API. No synthetic checker or unchecked Python baseline is used. "
        "Host means LinuxSandboxExecutor with its default Cedar policy and fresh confined "
        "worker. Both application resource grants contain only the read fixture "
        "(no resources for the constant control). "
        "Executors are reused; host workers remain fresh per invocation.",
        "",
        "| Workload | Verified mean ms | Host mean ms | Paired added ms | Added SD ms | "
        "Added variance ms² | Host / verified |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in summary.items():
        a, b = [row["conditions"][c]["elapsed_ms"]["mean_ms"] for c in ("verified", "host")]
        d = row["paired_added_ms"]
        lines.append(
            f"| {name} | {a:.3f} | {b:.3f} | {d['mean_ms']:.3f} | {d['sd_ms']:.3f} | "
            f"{d['variance_ms2']:.3f} | {row['host_over_verified']:.2f}x |"
        )
    lines += [
        "",
        "## Attribution and setup",
        "",
        "Whole-call timing includes call construction, executor.invoke and "
        "receipt canonicalization. The following "
        "nested timing scopes are not additive: verified execution is its dispatcher "
        "(binding validation, grant activation, admitted function, receipt); host execution "
        "is _run_worker (activation, transport, supervision, operation, teardown). Policy "
        "is verified _authorize versus host Cedar filter. Different policy frontends mean "
        "the total difference measures these implementations, not a universal isolation tax.",
        "",
        "| Workload | Verified policy ms | Host policy ms | Verified execution ms | "
        "Host worker ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, row in summary.items():
        c = row["conditions"]
        values = [
            c[k][scope]["mean_ms"]
            for scope in ("policy_ms", "execution_ms")
            for k in ("verified", "host")
        ]
        lines.append("| " + name + " | " + " | ".join(f"{v:.3f}" for v in values) + " |")
    lines += [
        "",
        "Setup is excluded from invocation latency. Repeated in-process setup "
        "samples per workload "
        "include the real static admission pass; nested admission timing is separately retained.",
        "",
        "| Workload | Verified setup mean ms | Static admission mean ms | Admission SD ms | "
        "Host setup mean ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name in WORKLOADS:
        data = [r for r in setup if r["case"] == name]
        a = stats([r["admission_ms"] for r in data])
        lines.append(
            f"| {name} | {stats([r['verified_ms'] for r in data])['mean_ms']:.3f} | "
            f"{a['mean_ms']:.3f} | {a['sd_ms']:.3f} | "
            f"{stats([r['host_ms'] for r in data])['mean_ms']:.3f} |"
        )
    lines += [
        "",
        "## Coverage and interpretation",
        "",
        "The built-in verified filesystem API currently exposes read_text. The direct "
        "open/pathlib/os/mmap/ctypes and mutation programs from the 16-operation experiment "
        "are also submitted to the real checker; see admission-census.json for exact source "
        "and rejection diagnostics. These are raw-API admission probes, not evidence that "
        "all equivalent functionality is impossible through registered typed resource clients. "
        "Read workloads are ported to the approved API. A rejected operation is not assigned "
        "a runtime or counted as a successful operation.",
        "",
        "Both modes perform equivalent computation or read identical UTF-8 bytes from the "
        "same read-only fixture. The two-read workload returns the second read in both "
        "modes. Host uses the existing JSON worker; verified mode returns directly, so "
        "serialization and process lifecycle are intentionally included in whole-call cost. "
        "The 64 KiB read is a size variant, not an additional API operation.",
        "",
        "Trusted assumptions remain: coordinator, approved API, interpreter and stable bindings. "
        "This does not establish confinement of opaque native binaries by static verification. "
        "No model calls or durable audit sink. Single CPU affinity, cache-warm files, uncontrolled "
        "CPU frequency. SD/variance are within-run variability, not across-machine confidence.",
        "",
        "Evidence: [raw samples](samples.jsonl), [summary](summary.json), "
        "[setup samples](setup.json), [admission census](admission-census.json), "
        "[plan](plan.json), [host before](host-before.json), "
        "[host after](host-after.json), [source archive](sources.tar.gz).",
        "",
        "Reproduce from eval: `uv run python -m slanggraph_eval.isolation.verified "
        "--output reports/e6/verified-new --samples 100 --warmup 10`",
    ]
    (output / "report.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20261028)
    parser.add_argument("--setup-samples", type=int, default=100)
    args = parser.parse_args()
    if args.samples < 2 or args.warmup < 0:
        parser.error("samples >= 2 and warmup >= 0 required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    (output / "host-before.json").write_text(json.dumps(host_snapshot(), indent=2))
    repo = Path(__file__).resolve().parents[4]
    inventory = {}
    with tarfile.open(output / "sources.tar.gz", "w:gz") as archive:
        for root in (
            Path(__file__).parent,
            repo / "libs/prebuilt/langgraph",
            repo / "libs/langgraph/langgraph",
            repo / "libs/checkpoint/langgraph",
        ):
            for path in sorted(root.rglob("*.py")):
                relative = str(path.relative_to(repo))
                inventory[relative] = digest(path)
                archive.add(path, arcname=relative)
    (output / "plan.json").write_text(
        json.dumps(
            dict(
                samples=args.samples,
                warmup=args.warmup,
                seed=args.seed,
                setup_samples=args.setup_samples,
                source_hashes=inventory,
                archive_sha256=digest(output / "sources.tar.gz"),
                policy=POLICY,
                manifest=MANIFEST,
                workloads={k: dict(bytes=v[1], reads=v[2]) for k, v in WORKLOADS.items()},
            ),
            indent=2,
        )
    )
    from langgraph.prebuilt.security import linux

    spans = defaultdict(float)
    rows, setups = [], []
    rng = random.Random(args.seed)
    with tempfile.TemporaryDirectory(prefix="e6-verified-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        (root / "output").mkdir()
        census = admission_census(root)
        (output / "admission-census.json").write_text(json.dumps(census, indent=2))
        for owner, attr, key in [
            (ManifestAdmission, "__init__", "admission"),
            (ObjectPolicyHostExecutor, "_authorize", "verified_policy"),
            (linux.CedarPolicyBackend, "filter", "host_policy"),
            (linux.LinuxSandboxExecutor, "_run_worker", "host_execution"),
        ]:
            stack.enter_context(patch.object(owner, attr, timed(spans, key, getattr(owner, attr))))
        from langgraph.prebuilt.security.object_policy import _LanguageSandboxDispatcher

        stack.enter_context(
            patch.object(
                _LanguageSandboxDispatcher,
                "invoke",
                timed(spans, "verified_execution", _LanguageSandboxDispatcher.invoke),
            )
        )
        executors = {}
        for name, (function, _size, repeats) in WORKLOADS.items():
            for index in range(args.setup_samples):
                spans.clear()
                start = time.perf_counter_ns()
                security = cedar_security(
                    function, policy=POLICY, manifest=MANIFEST if repeats else "runs inprocess"
                )
                verified_ms = (time.perf_counter_ns() - start) / 1e6
                admission_ms = spans["admission"]
                start = time.perf_counter_ns()
                host = make_matched_executor(root, bool(repeats))
                host_ms = (time.perf_counter_ns() - start) / 1e6
                setups.append(
                    dict(
                        case=name,
                        round=index,
                        verified_ms=verified_ms,
                        admission_ms=admission_ms,
                        host_ms=host_ms,
                    )
                )
            executors[name] = {"verified": security.host_executor, "host": host}
        (output / "setup.json").write_text(json.dumps(setups, indent=2))
        with (output / "samples.jsonl").open("x") as stream:
            for index in range(1 + args.warmup + args.samples):
                jobs = [(name, c) for name in WORKLOADS for c in ("verified", "host")]
                rng.shuffle(jobs)
                for name, condition in jobs:
                    _, size, repeats = WORKLOADS[name]
                    payload = ("0123456789abcdef" * ((size + 15) // 16))[:size]
                    (root / "allowed").write_text(payload)
                    expected = payload if repeats else 42
                    if condition == "verified":
                        arguments = {"path": str(root / "allowed")} if repeats else {}
                    else:
                        source = "result = open(p['path']).read()"
                        if repeats == 2:
                            source += "\nresult = open(p['path']).read()"
                        if not repeats:
                            source = "result = 42"
                        arguments = dict(
                            source=source, p={"path": str(root / "allowed")}, language="none"
                        )
                    spans.clear()
                    start = time.perf_counter_ns()
                    value, receipt = invoke_host(executors[name][condition], arguments)
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    if condition == "host":
                        value = value.get("value")
                    valid = value == expected
                    row = dict(
                        case=name,
                        condition=condition,
                        round=index,
                        phase="first_use"
                        if index == 0
                        else "warmup"
                        if index <= args.warmup
                        else "measured",
                        elapsed_ms=elapsed,
                        policy_ms=spans[condition + "_policy"],
                        execution_ms=spans[condition + "_execution"],
                        valid=valid,
                        receipt=receipt,
                        value_sha256=hashlib.sha256(str(value).encode()).hexdigest(),
                        expected_sha256=hashlib.sha256(str(expected).encode()).hexdigest(),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
                    rows.append(row)
                    if not valid:
                        raise RuntimeError(f"invalid result: {name}/{condition}")
                print(f"round {index}: {len(rows)} calls", flush=True)
    summary = summarize(rows, args.samples)
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    (output / "host-after.json").write_text(json.dumps(host_snapshot(), indent=2))
    report(output, summary, setups, args)


if __name__ == "__main__":
    main()
