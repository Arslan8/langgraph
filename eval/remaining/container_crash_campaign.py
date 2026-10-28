"""Prospective real-controller crash matrix for the production guardian."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

from container_dispatcher_campaign import identities
from langgraph.prebuilt.security.linux import _readline_json

ROOT = Path(__file__).resolve().parents[2]
CASE_SOURCE = ROOT / "libs/prebuilt/tests/security/test_container_guardian.py"
spec = importlib.util.spec_from_file_location("guardian_cases", CASE_SOURCE)
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)
PHASES = ("idle", "active", "creating", "inherited_pipe")


def sources():
    result = identities()
    for path in (Path(__file__).resolve(), CASE_SOURCE):
        result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def presence(container_id):
    result = subprocess.run(
        [
            "docker",
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
        timeout=5,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "at": time.time(),
    }


def pidfd(pid):
    library = ctypes.CDLL(None, use_errno=True)
    operation = library.pidfd_open
    operation.argtypes = [ctypes.c_int, ctypes.c_uint]
    operation.restype = ctypes.c_int
    descriptor = operation(pid, 0)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


def trial(directory, phase, repetition):
    directory.mkdir(mode=0o700)
    root = directory / "fixture"
    root.mkdir(mode=0o700)
    row = {
        "phase": phase,
        "repetition": repetition,
        "started_at": time.time(),
        "image": cases.IMAGE,
        "route": "production-DockerObjectDispatcher",
        "absence_polls": [],
    }
    env = cases.delayed_client(root) if phase == "creating" else None
    if env is not None:
        row["injection"] = "delay second real Docker run reply by four seconds"
        row["wrapper_sha256"] = hashlib.sha256((root / "client/docker").read_bytes()).hexdigest()
    ready = None
    guardian_fd = None
    with (directory / "stderr.log").open("w") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-c", cases.CONTROLLER, str(root), phase, cases.IMAGE],
            stdout=subprocess.PIPE,
            stderr=stderr,
            env=env,
        )
        row["controller_pid"] = process.pid
        try:
            ready = _readline_json(process, 40)
            row["ready"] = ready
            guardian_fd = pidfd(ready["guardian_pid"])
            row["before_kill"] = presence(ready["container_id"])
            row["killed_at"] = time.time()
            process.kill()
            row["controller_returncode"] = process.wait(timeout=5)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                observed = presence(ready["container_id"])
                row["absence_polls"].append(observed)
                if observed["returncode"] == 0 and not observed["stdout"].strip():
                    row["guardian_removed_container"] = True
                    break
                time.sleep(0.1)
            row["guardian_exited"] = bool(select.select([guardian_fd], [], [], 20)[0])
            row["control_container_after"] = presence(ready["control_container_id"])
        except Exception as exc:
            row["error"] = {"type": type(exc).__name__, "message": str(exc)}
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if ready is not None:
                descendant = ready["descendant_pid"]
                if descendant is not None:
                    with suppress(ProcessLookupError):
                        os.kill(descendant, signal.SIGKILL)
                # This occurs after the measured absence/exit observations and
                # cannot turn a failed guardian observation into a success.
                result = subprocess.run(
                    ["docker", "rm", "-f", "--volumes", ready["container_id"]],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                row["harness_cleanup"] = {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            if guardian_fd is not None:
                os.close(guardian_fd)
            process.stdout.close()
    row["ended_at"] = time.time()
    (directory / "observation.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def verify(rows, repetitions):
    errors = []
    expected = {(phase, repetition) for phase in PHASES for repetition in range(repetitions)}
    if len(rows) != len(expected) or {(r["phase"], r["repetition"]) for r in rows} != expected:
        errors.append("incomplete or duplicate crash matrix")
    for row in rows:
        try:
            assert "error" not in row
            ready = row["ready"]
            assert ready["status"] == "ready" and ready["phase"] == row["phase"]
            assert ready["control"] == 41 and ready["receipts"]
            assert re.fullmatch(r"[0-9a-f]{64}", ready["container_id"])
            assert re.fullmatch(r"[0-9a-f]{64}", ready["control_container_id"])
            assert ready["guardian_pid"] > 0 and ready["guardian_pid"] != row["controller_pid"]
            assert len(ready["receipts"]) == (2 if row["phase"] == "active" else 1)
            assert all(receipt["mode"] == "enforced" for receipt in ready["receipts"])
            assert row["controller_returncode"] == -signal.SIGKILL
            assert row["before_kill"]["returncode"] == 0
            assert row["before_kill"]["stdout"].strip() == ready["container_id"]
            assert row["guardian_removed_container"] is True and row["guardian_exited"] is True
            last = row["absence_polls"][-1]
            assert last["returncode"] == 0 and not last["stdout"].strip()
            assert last["at"] >= row["killed_at"]
            assert row["control_container_after"]["returncode"] == 0
            assert not row["control_container_after"]["stdout"].strip()
            if row["phase"] == "creating":
                assert ready["container_id"] != ready["control_container_id"]
                assert row["wrapper_sha256"]
            elif row["phase"] == "inherited_pipe":
                assert ready["descendant_pid"] is not None
        except (AssertionError, KeyError, ValueError, TypeError, IndexError):
            errors.append(f"{row['phase']}:{row['repetition']}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("positive repetitions required")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "controller.py").write_text(cases.CONTROLLER)
    before = sources()
    for path, digest in before.items():
        target = args.output / "sources" / digest
        target.parent.mkdir(exist_ok=True)
        target.write_bytes((ROOT / path).read_bytes())
    rows = []
    with (args.output / "observations.jsonl").open("w") as stream:
        for repetition in range(args.repetitions):
            for phase in PHASES:
                row = trial(args.output / f"{repetition:02d}-{phase}", phase, repetition)
                rows.append(row)
                stream.write(json.dumps(row) + "\n")
                stream.flush()
                print(repetition, phase, "error" not in row, flush=True)
    after = sources()
    errors = verify(rows, args.repetitions)
    if before != after:
        errors.append("source changed during cohort")
    report = {
        "passed": not errors,
        "trials": len(rows),
        "errors": errors,
        "source_before": before,
        "source_after": after,
        "controller_sha256": hashlib.sha256(cases.CONTROLLER.encode()).hexdigest(),
        "scope": "controller SIGKILL; guardian and daemon available; shared-host timing",
    }
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
