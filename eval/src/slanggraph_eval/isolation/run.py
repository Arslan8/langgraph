"""E6 matched operation census: synthetic language boundary versus Linux executor."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.metadata
import json
import os
import platform
import random
import socket
import sqlite3
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from .cases import Case, cases

CONDITIONS = {
    "trusted": (False, "none"),
    "language_direct": (False, "direct"),
    "language_helper": (False, "helper"),
    "host": (True, "none"),
    "host_language_helper": (True, "helper"),
}
LIMITS = {
    "address_space_bytes": 1073741824,
    "cpu_ms": 5000,
    "file_size_bytes": 1048576,
    "nofile": 64,
    "pids": 1,
    "tmpfs_bytes": 67108864,
    "wall_ms": 5000,
}
WORKER = Path(__file__).with_name("worker.py").resolve()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile(root: Path) -> str:
    rules = f"fs read {root}/allowed need, read+write+create+delete+truncate {root}/output/** need"
    return f"""
tool run {{
 owner analyst
 grant analyst: call
 runs linux
 syscalls @minimal
 {rules}
}}
principal evaluator {{
 roles analyst
 {rules.replace(" need", "")}
}}
"""


def make_executor(root: Path):
    from langgraph.prebuilt.security import LinuxSandboxExecutor, LinuxToolSpec, parse_profiles

    return LinuxSandboxExecutor(
        parse_profiles(profile(root), source="e6.slp"),
        {"run": LinuxToolSpec("worker:run", WORKER, digest(WORKER))},
        runtime_roots=(WORKER.parent,),
        default_wall_timeout_s=5,
        default_limits=LIMITS,
    )


def invoke_host(executor, arguments: dict):
    from langgraph.prebuilt.security import Effect, Principal, ToolCall
    from langgraph.prebuilt.security.types import Tool, ToolDac

    tool = Tool(
        "run",
        ToolDac("analyst", {"analyst": "x", "*": "-"}),
        frozenset({Effect.READ, Effect.WRITE, Effect.EXEC}),
        (),
    )
    call = ToolCall(tool, arguments, arguments, uuid.uuid4().hex, 0)
    principal = Principal("evaluator", frozenset({"analyst"}), frozenset(), "e6")
    result = executor.invoke(principal, call, ())
    return result.value, result.receipt.canonical()


def observe(case: Case, p: dict, response: dict, before: dict, received: bytes) -> bool:
    """Use parent-side effects or an unpredictable returned canary as the oracle."""
    target, new = Path(p["target"]), Path(p["new"])
    value = response.get("value")
    match case.oracle:
        case "answer":
            return value == 42
        case "read":
            return value == p["token"]
        case "contains":
            return isinstance(value, str) and p["token"] in value
        case "names":
            return isinstance(value, list) and any(p["basename"] in str(v) for v in value)
        case "size":
            return value == len(p["token"])
        case "write":
            return Path(p["output"]).read_text() == "effect"
        case "large_file":
            return Path(p["output"]).stat().st_size == 2097152
        case "small_file":
            return Path(p["output"]).stat().st_size == 4096
        case "mutation":
            return not target.exists() or target.read_text() != p["token"]
        case "metadata":
            stat = target.stat()
            return (stat.st_mode, stat.st_mtime_ns) != (before["mode"], before["mtime"])
        case "new":
            return os.path.lexists(new)
        case "network":
            return received == p["token"].encode()
        case "database":
            with sqlite3.connect(p["database"]) as connection:
                return connection.execute("SELECT value FROM canary").fetchone()[0] == "effect"
        case _:
            raise ValueError(case.oracle)


def classify(*, effect: bool, response: dict, host: bool, receipt: dict | None) -> str:
    if effect:
        return "effect_observed"
    if response.get("phase") == "admission":
        return "admission_rejected"
    if response.get("phase") == "operation" and (not host or receipt):
        if response.get("error") in {"PermissionError", "FileNotFoundError"} or response.get(
            "errno"
        ) in {errno.EACCES, errno.EPERM, errno.EROFS, errno.EBUSY, errno.EFBIG}:
            return "operation_denied"
        return "operation_error"
    if response.get("phase") == "executed" and (not host or receipt):
        return "no_effect_observed"
    return "inconclusive"


def trial(case: Case, condition: str, repetition: int) -> dict:
    host, language = CONDITIONS[condition]
    row = {
        "case": case.name,
        "family": case.family,
        "allowed": case.allowed,
        "surface": case.surface,
        "condition": condition,
        "repetition": repetition,
    }
    with tempfile.TemporaryDirectory(prefix="e6-isolation-") as temp:
        root = Path(temp)
        (root / "secret").mkdir()
        (root / "output").mkdir()
        token = uuid.uuid4().hex
        target = root / "secret" / ("canary-" + uuid.uuid4().hex)
        target.write_text(token)
        target.chmod(0o644)
        if case.surface == "readonly":
            target = root / "allowed"
        elif case.surface == "writable":
            target = root / "output" / "target"
        target.write_text(token)
        target.chmod(0o644)
        (root / "allowed").write_text(token)
        (root / "output" / "result").write_text("")
        (root / "output" / "link").symlink_to(target)
        db = root / "secret" / "canary.sqlite"
        with sqlite3.connect(db) as connection:
            connection.execute("CREATE TABLE canary(value TEXT)")
            connection.execute("INSERT INTO canary VALUES (?)", (token,))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(0.02)
            p = {
                "target": str(target),
                "new": str(target.parent / "new"),
                "secret_dir": str(target.parent),
                "basename": target.name,
                "allowed": str(root / "allowed"),
                "output": str(root / "output" / "result"),
                "link": str(root / "output" / "link"),
                "traversal": str(root / "output") + "/../secret/" + target.name,
                "database": str(db),
                "port": listener.getsockname()[1],
                "token": token,
            }
            # The expected canary is withheld from workers except the network send probe.
            arguments = {
                "source": case.source,
                "p": {k: v for k, v in p.items() if k != "token" or case.oracle == "network"},
                "language": language,
            }
            stat = target.stat()
            before = {"mode": stat.st_mode, "mtime": stat.st_mtime_ns}
            receipt = None
            executor = None
            setup_start = time.perf_counter_ns()
            try:
                if host:
                    executor = make_executor(root)
            except Exception as error:
                return row | {
                    "outcome": "setup_unavailable",
                    "error": str(error),
                    "error_type": type(error).__name__,
                }
            row["setup_ms"] = (time.perf_counter_ns() - setup_start) / 1e6
            start = time.perf_counter_ns()
            try:
                if host:
                    with patch.dict(os.environ, {"EVAL_ISOLATION_CANARY": token}):
                        response, receipt = invoke_host(executor, arguments)
                else:
                    result = subprocess.run(
                        [sys.executable, "-I", "-S", str(WORKER)],
                        input=json.dumps(arguments),
                        capture_output=True,
                        text=True,
                        timeout=7,
                        env=os.environ | {"EVAL_ISOLATION_CANARY": token},
                    )
                    if result.returncode:
                        raise RuntimeError(
                            f"worker exit {result.returncode}: {result.stderr[:500]}"
                        )
                    response = json.loads(result.stdout)
            except Exception as error:
                response = {"phase": "harness", "error": type(error).__name__, "detail": str(error)}
                if executor and executor.activation_receipts():
                    receipt = executor.activation_receipts()[-1].canonical()
            row["elapsed_ms"] = (time.perf_counter_ns() - start) / 1e6
            received = b""
            try:
                client, _ = listener.accept()
                with client:
                    client.settimeout(1)
                    received = client.recv(4096)
            except TimeoutError:
                pass
            effect = observe(case, p, response, before, received)
            row.update(
                response=response,
                oracle=case.oracle,
                evidence={
                    "expected_token": token,
                    "before": before,
                    "target_exists": target.exists(),
                    "target_sha256": digest(target) if target.is_file() else None,
                    "target_mode": target.stat().st_mode if target.exists() else None,
                    "target_mtime_ns": target.stat().st_mtime_ns if target.exists() else None,
                    "new_exists": os.path.lexists(p["new"]),
                    "output_size": Path(p["output"]).stat().st_size,
                    "output_sha256": digest(Path(p["output"])),
                    "network_received_hex": received.hex(),
                    "database_sha256": digest(db),
                },
                effect_observed=effect,
                activation_receipt=receipt,
                outcome=classify(effect=effect, response=response, host=host, receipt=receipt),
                policy=profile(root),
                policy_sha256=hashlib.sha256(profile(root).encode()).hexdigest(),
            )
    return row


def summarize(rows: list[dict]) -> dict:
    """Report repetitions separately from distinct cases; controls gate interpretation."""
    summaries = {}
    validated = {
        name
        for name in {row["case"] for row in rows}
        if (baseline := [r for r in rows if r["case"] == name and r["condition"] == "trusted"])
        and all(r.get("effect_observed", False) for r in baseline)
    }
    for condition in CONDITIONS:
        selected = [r for r in rows if r["condition"] == condition]
        controls = [r for r in selected if r["allowed"]]
        negative = [r for r in selected if not r["allowed"]]
        timing = [r["elapsed_ms"] for r in selected if "elapsed_ms" in r]
        summaries[condition] = {
            "trials": len(selected),
            "distinct_cases": len({r["case"] for r in selected}),
            "control_effects": sum(r.get("effect_observed", False) for r in controls),
            "control_trials": len(controls),
            "forbidden_effects": sum(r.get("effect_observed", False) for r in negative),
            "forbidden_trials": len(negative),
            "outcomes": dict(Counter(r["outcome"] for r in selected)),
            "median_ms": statistics.median(timing) if timing else None,
            "validated_forbidden_cases": len(
                {r["case"] for r in negative if r["case"] in validated}
            ),
            "cases_with_forbidden_effect": sorted(
                {r["case"] for r in negative if r.get("effect_observed")}
            ),
            "cases_with_unavailable_setup": sorted(
                {r["case"] for r in selected if r["outcome"] == "setup_unavailable"}
            ),
            "controls_all_passed": bool(controls)
            and all(r.get("effect_observed") for r in controls),
        }
    return summaries


def write_report(output: Path, rows: list[dict], summary: dict, metadata: dict) -> None:
    """Render descriptive counts without treating variants/replays as IID trials."""
    lines = [
        "# E6 operation-level isolation evaluation",
        "",
        f"Recorded: {metadata['created_at']}. Seed: {metadata['seed']}. "
        f"Repetitions: {metadata['repetitions']}.",
        "",
        "These are deterministic synthetic probes, not prompt-injection ASR or "
        "a comparison against a released language sandbox. Counts below are "
        "trials; repeated cases are not independent samples.",
        "",
        "| Condition | Allowed effects / controls | Forbidden effects / trials | "
        "Validated forbidden cases | Median dispatch ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for condition, values in summary.items():
        median = values["median_ms"]
        timing = f"{median:.2f}" if median is not None else "unavailable"
        lines.append(
            f"| {condition} | {values['control_effects']}/{values['control_trials']} | "
            f"{values['forbidden_effects']}/{values['forbidden_trials']} | "
            f"{values['validated_forbidden_cases']} | {timing} |"
        )
    lines += [
        "",
        "Dispatch time includes fresh-worker launch and execution, excludes executor "
        "construction/preflight and fixture/oracle work, and mixes operation types. "
        "It is descriptive; use matched successful controls for performance claims. "
        "Per-trial setup and dispatch times are retained in trials.jsonl.",
        "",
        "## Every case and observed outcome",
        "",
        "E = effect observed; D = operation denied; A = admission rejected; "
        "N = no effect observed; X = operation error; U = setup unavailable; "
        "? = inconclusive. Only E establishes the effect; N/X/U/? are not "
        "credited as runtime blocking. D in a host condition requires activation "
        "evidence. Baseline validation is also required before interpreting D.",
        "",
        "| Case | Family | Surface | Intended | " + " | ".join(CONDITIONS) + " |",
        "| --- | --- | --- | --- | " + " | ".join("---" for _ in CONDITIONS) + " |",
    ]
    abbreviations = {
        "effect_observed": "E",
        "operation_denied": "D",
        "admission_rejected": "A",
        "no_effect_observed": "N",
        "operation_error": "X",
        "setup_unavailable": "U",
        "inconclusive": "?",
    }
    for case in cases():
        cells = []
        for condition in CONDITIONS:
            outcomes = Counter(
                r["outcome"] for r in rows if r["case"] == case.name and r["condition"] == condition
            )
            cells.append(
                ", ".join(
                    f"{abbreviations[key]}:{value}" for key, value in sorted(outcomes.items())
                )
            )
        lines.append(
            f"| {case.name} | {case.family} | {case.surface} | "
            f"{'allow' if case.allowed else 'deny'} | " + " | ".join(cells) + " |"
        )
    lines += [
        "",
        "## Interpretation limits",
        "",
        "The language frontend accepts arithmetic and a prebound helper only. "
        "The helper is a deliberate trusted-code assumption. This establishes "
        "a trust-boundary contrast, not that language sandboxes are inherently "
        "unsound. Host enforcement still trusts the coordinator, policy compiler, "
        "launcher, worker shim, runtime baseline, and kernel.",
        "",
        "This single-host finite corpus excludes kernel exploits, races, "
        "cross-session information flow, external services, network allow policies, "
        "distributed brokers, and destructive exhaustion. SQLite failures alone "
        "do not demonstrate SQL authorization. Repetitions check stability; "
        "no population ASR, binomial confidence interval, or universal containment "
        "claim is supported.",
        "",
        "See eval/ISOLATION.md for the protocol and remaining evaluation scope.",
    ]
    (output / "report.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261025)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    corpus = cases()
    jobs = [
        (case, condition, repeat)
        for repeat in range(args.repetitions)
        for case in corpus
        for condition in CONDITIONS
    ]
    random.Random(args.seed).shuffle(jobs)
    repo = Path(__file__).resolve().parents[4]
    inventory = {}
    for folder in [
        WORKER.parent,
        repo / "libs/prebuilt/langgraph",
        repo / "libs/langgraph/langgraph",
        repo / "libs/checkpoint/langgraph",
    ]:
        for path in sorted(folder.rglob("*.py")):
            inventory[str(path.relative_to(repo))] = digest(path)
    with tarfile.open(args.output / "sources.tar.gz", "w:gz") as archive:
        for relative in inventory:
            archive.add(repo / relative, arcname=relative)
    metadata = {
        "schema_version": 1,
        "experiment": "E6",
        "created_at": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "seed": args.seed,
        "repetitions": args.repetitions,
        "source_hashes": inventory,
        "source_archive_sha256": digest(args.output / "sources.tar.gz"),
        "distributions": sorted(
            (d.metadata["Name"], d.version) for d in importlib.metadata.distributions()
        ),
        "worker_sha256": digest(WORKER),
        "interpreter_sha256": digest(Path(sys.executable)),
        "corpus": [asdict(case) for case in corpus],
        "conditions": CONDITIONS,
        "host_limits": LIMITS,
        "git_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip(),
    }
    (args.output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    with (args.output / "trials.jsonl").open("x") as stream:
        for index, (case, condition, repeat) in enumerate(jobs):
            row = trial(case, condition, repeat)
            rows.append(row)
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            if (index + 1) % 25 == 0:
                print(f"{index + 1}/{len(jobs)} trials", flush=True)
    summary = summarize(rows)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    write_report(args.output, rows, summary, metadata)
    print(json.dumps(summary, indent=2))
    if any(
        r.get("effect_observed") and not r["allowed"] and CONDITIONS[r["condition"]][0]
        for r in rows
    ):
        return 1
    if any(r["outcome"] in {"setup_unavailable", "inconclusive"} for r in rows):
        return 2
    if any(
        not value["controls_all_passed"]
        for name, value in summary.items()
        if name != "language_direct"
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
