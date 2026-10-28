"""Capture one boundary-validation trial for each current execution route.

These pilots prove that the frozen revision and host can execute each route.  Their
pytest process walls are diagnostics, not paper performance samples; the full
campaign uses in-process phase instrumentation after the boundary review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

REVISION = "bdb0cb9d467e426354ad8beba20407374947ce51"
LEAN_SHA256 = "6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08"
ROUTES = {
    "language_interpreter": {
        "selector": (
            "libs/prebuilt/tests/security/test_manifest_admission.py::"
            "test_grant_scoped_read_and_restriction[none-False]"
        ),
        "oracle": (
            "admitted read_text returns the complete granted fixture and the grant "
            "is gone afterward"
        ),
        "shape": "one useful admitted-language invocation",
    },
    "landlock_worker": {
        "selector": (
            "libs/prebuilt/tests/security/test_lean_native_execution.py::"
            "test_selected_native_route_reads_granted_file"
        ),
        "oracle": (
            "Lean-selected native route returns the complete granted file with "
            "enforced receipt and confirmed cleanup"
        ),
        "shape": "one fresh Lean-checked Linux worker invocation",
    },
    "container": {
        "selector": (
            "libs/prebuilt/tests/security/test_container_execution.py::"
            "test_native_dispatch_and_identical_authority_reuse"
        ),
        "oracle": (
            "cold call returns authorized data and denies Bob; reused call preserves "
            "only same-authority private state"
        ),
        "shape": "one cold creation followed by one same-authority reused invocation, then removal",
    },
    "object_broker": {
        "selector": (
            "libs/prebuilt/tests/security/test_object_broker.py::"
            "test_exact_capability[inspect-pump-1-inspected]"
        ),
        "oracle": "Landlock worker reaches the exact pump capability once and returns inspected",
        "shape": "one fresh brokered worker invocation",
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--python",
        type=Path,
        default=Path("/data/langgraph/libs/prebuilt/.venv/bin/python"),
    )
    parser.add_argument(
        "--lean-worker",
        type=Path,
        default=Path("/data/langgraph/proofs/worker-route/.lake/build/bin/workerRoute"),
    )
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    actual_revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, text=True
    ).strip()
    if actual_revision != REVISION:
        raise SystemExit("source checkout is not the frozen revision")
    if sha256(args.lean_worker) != LEAN_SHA256:
        raise SystemExit("Lean worker does not match the frozen digest")
    output.mkdir(parents=True, exist_ok=False)
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            str(source / path) for path in ("libs/prebuilt", "libs/langgraph", "libs/checkpoint")
        ),
        "LANGGRAPH_REQUIRE_LEAN_NATIVE": "1",
        "LANGGRAPH_LEAN_WORKER_BINARY": str(args.lean_worker.resolve()),
    }
    rows = []
    for route, spec in ROUTES.items():
        route_dir = output / route
        route_dir.mkdir()
        command = [
            str(args.python),
            "-m",
            "pytest",
            "-q",
            "-vv",
            "--durations=1",
            spec["selector"],
        ]
        started_at = datetime.now(UTC).isoformat()
        started = time.perf_counter_ns()
        completed = subprocess.run(
            command,
            cwd=source,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        wall_ns = time.perf_counter_ns() - started
        stdout = completed.stdout
        stderr = completed.stderr
        (route_dir / "stdout.log").write_text(stdout)
        (route_dir / "stderr.log").write_text(stderr)
        duration = re.search(r"([0-9.]+)s call\s+", stdout)
        row = {
            "schema_version": 1,
            "trial_kind": "boundary_validation_pilot",
            "performance_eligible": False,
            "route": route,
            "route_shape": spec["shape"],
            "revision": REVISION,
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "command": command,
            "cwd": str(source),
            "python": subprocess.check_output(
                [str(args.python), "--version"], text=True, stderr=subprocess.STDOUT
            ).strip(),
            "host": platform.node(),
            "kernel": platform.release(),
            "exit_status": completed.returncode,
            "correctness_oracle": spec["oracle"],
            "correctness_passed": completed.returncode == 0,
            "pytest_call_ms": float(duration.group(1)) * 1000 if duration else None,
            "subprocess_wall_ms": wall_ns / 1_000_000,
            "timing_scope": (
                "pytest process diagnostic including collection/setup/teardown; "
                "excluded from performance claims"
            ),
            "phase_ledger": {
                "admission_setup_ms": None,
                "cedar_authorization_ms": None,
                "lean_checking_ms": None,
                "activation_ms": None,
                "execution_ms": None,
                "audit_ms": None,
                "cleanup_ms": None,
                "status": (
                    "pending reviewed in-process instrumentation; no nested span is "
                    "inferred from pytest wall"
                ),
            },
            "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
            "lean_worker_sha256": LEAN_SHA256 if route == "landlock_worker" else None,
        }
        (route_dir / "trial.json").write_text(json.dumps(row, indent=2) + "\n")
        rows.append(row)
    (output / "trials.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    if not all(row["correctness_passed"] for row in rows):
        raise SystemExit("one or more route pilots failed")


if __name__ == "__main__":
    main()
