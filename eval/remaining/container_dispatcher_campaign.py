"""Prospective lifecycle matrix through the production object host executor.

Policy changes here are graph-local. Sealed operator policy replacement is not
supported. Timing is shared-host wall time, not an isolated performance result.
"""

import argparse
import hashlib
import json
import subprocess
import tempfile
import time
from pathlib import Path

from container_executor_probe import IMAGE, SOURCE, compute
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher

CASES = ("principal", "graph_local_policy", "broad_to_narrow")


def identities():
    root = Path(__file__).resolve().parents[2]
    paths = sorted((root / "libs/prebuilt/langgraph/prebuilt/security").glob("*.py"))
    paths += [Path(__file__).resolve(), Path(__file__).with_name("container_executor_probe.py")]
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def absent(dispatcher, container_id):
    result = subprocess.run(
        [
            *dispatcher._client,
            "ps",
            "-a",
            "--no-trunc",
            "--filter",
            f"id={container_id}",
            "--format",
            "{{.ID}}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def trial(case, repetition):
    row = {
        "case": case,
        "repetition": repetition,
        "started_at": time.time(),
        "image": IMAGE,
        "route": "production-DockerObjectDispatcher",
        "calls": [],
    }
    with tempfile.TemporaryDirectory(prefix="slg-production-cohort-") as tmp:
        root = Path(tmp)
        source, allowed, private = root / "compute.py", root / "allowed.json", root / "private.txt"
        source.write_text(SOURCE)
        allowed.write_text("[7, 11, 23]")
        private.write_text("PRIVATE_CANARY")
        dispatcher = DockerObjectDispatcher(
            {
                "compute": LinuxToolSpec(
                    "compute:compute", source, hashlib.sha256(source.read_bytes()).hexdigest()
                )
            },
            image=IMAGE,
            private_roots=[root],
        )
        try:
            for phase in ("seed", "reuse", "transition"):
                changed = phase == "transition"
                broad = case == "broad_to_narrow" and not changed
                policy = "permit(principal,action,resource)" + (
                    " when {true};" if changed and case == "graph_local_policy" else ";"
                )
                security = cedar_security(
                    compute,
                    manifest="runs linux\nfs read @{path} need"
                    + ("\nfs read @{private} need" if broad else ""),
                    policy=policy,
                    dispatcher=dispatcher,
                )
                principal = Principal(
                    "bob" if changed and case == "principal" else "alice",
                    frozenset(),
                    frozenset(),
                    "session",
                )
                call = ToolCall(
                    Tool("compute", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                    {"path": str(allowed), "private": str(private), "seed": phase == "seed"},
                    {},
                    f"{case}-{repetition}-{phase}",
                    0,
                )
                result = security.host_executor.invoke(principal, call, ())
                row["calls"].append(
                    {
                        "phase": phase,
                        "principal": principal.user_id,
                        "policy": policy,
                        "broad": broad,
                        "value": result.value,
                        "receipt": result.receipt.canonical(),
                        "execution": dict(dispatcher.execution_records()[-1]),
                    }
                )
            row["old_absence"] = absent(dispatcher, row["calls"][0]["execution"]["container_id"])
        except Exception as exc:
            row["error"] = {"type": type(exc).__name__, "message": str(exc)}
        finally:
            try:
                dispatcher.close()
                row["cleanup"] = [
                    absent(dispatcher, c["execution"]["container_id"]) for c in row["calls"]
                ]
            except Exception as exc:
                row["cleanup_error"] = str(exc)
    row["ended_at"] = time.time()
    return row


def verify(rows, repetitions):
    errors = []
    expected = {(c, r) for c in CASES for r in range(repetitions)}
    if len(rows) != len(expected) or {(r["case"], r["repetition"]) for r in rows} != expected:
        errors.append("incomplete or duplicate matrix")
    for row in rows:
        label = f"{row['case']}:{row['repetition']}"
        try:
            assert "error" not in row and "cleanup_error" not in row
            first, reuse, last = row["calls"]
            for call in (first, reuse, last):
                assert call["value"]["sum"] == 41
                assert call["value"]["residual"] == (call["phase"] == "reuse")
                if call["broad"]:
                    assert call["value"]["private"] == "PRIVATE_CANARY"
                else:
                    assert "private" not in call["value"]
                    assert call["value"]["private_error"] == "FileNotFoundError"
            assert first["execution"]["container_id"] == reuse["execution"]["container_id"]
            assert reuse["execution"]["reused"] is True
            assert last["execution"]["container_id"] != first["execution"]["container_id"]
            assert last["execution"]["reused"] is False
            assert len({c["receipt"]["nonce"] for c in row["calls"]}) == 3
            assert len(row["cleanup"]) == 3
            assert all(
                a["returncode"] == 0 and not a["stdout"].strip()
                for a in [row["old_absence"], *row["cleanup"]]
            )
        except (AssertionError, KeyError, ValueError):
            errors.append(label)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    before = identities()
    for path, digest in before.items():
        destination = args.output / "sources" / digest
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes((Path(__file__).resolve().parents[2] / path).read_bytes())
    rows = []
    with (args.output / "observations.jsonl").open("w") as stream:
        for repetition in range(args.repetitions):
            for case in CASES:
                row = trial(case, repetition)
                rows.append(row)
                stream.write(json.dumps(row) + "\n")
                stream.flush()
                print(case, repetition, "error" if "error" in row else "executed", flush=True)
    after = identities()
    errors = verify(rows, args.repetitions)
    if before != after:
        errors.append("source changed during cohort")
    report = {
        "passed": not errors,
        "pairs": len(rows),
        "repetitions": args.repetitions,
        "errors": errors,
        "source_before": before,
        "source_after": after,
        "unsupported": ["live sealed operator policy replacement", "controller crash cleanup"],
        "timing_scope": "shared-host wall time; no comparative performance claim",
    }
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
