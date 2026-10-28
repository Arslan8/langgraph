"""Capture the exact evaluation revision, host, kernels, and dependency pins."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import urllib.request
from pathlib import Path


def command(*arguments: str, cwd: Path | None = None) -> dict:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return {
        "command": list(arguments),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run(output: Path, root: Path, evaluated_commit: str) -> None:
    output.mkdir(parents=True, exist_ok=False)
    resolved = subprocess.check_output(
        ["git", "rev-parse", evaluated_commit], cwd=root, text=True
    ).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True)
    model = json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10))
    python = Path("/data/langgraph/libs/prebuilt/.venv/bin/python")
    dependencies = command("uv", "pip", "freeze", "--python", str(python))
    (output / "dependencies.txt").write_text(dependencies["stdout"])
    lean_worker = root / "proofs/worker-route/.lake/build/bin/workerRoute"
    if not lean_worker.exists():
        lean_worker = Path("/data/langgraph/proofs/worker-route/.lake/build/bin/workerRoute")
    host = {
        "evaluated_commit": resolved,
        "capture_worktree_status": status.splitlines(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version,
        "kernel": platform.release(),
        "uname": platform.uname()._asdict(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "cpu": command("lscpu", "--json"),
        "memory": command("free", "-b"),
        "os_release": Path("/etc/os-release").read_text(),
        "cedar": command("cedar", "--version"),
        "docker": command("docker", "version", "--format", "{{json .}}"),
        "ollama": command("ollama", "--version"),
        "models": model,
        "lean_toolchain": (root / "proofs/worker-route/lean-toolchain").read_text().strip(),
        "lean_worker_path": str(lean_worker),
        "lean_worker_sha256": hashlib.sha256(lean_worker.read_bytes()).hexdigest(),
    }
    (output / "frozen-environment.json").write_text(json.dumps(host, indent=2, default=str) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--root", default=Path(__file__).resolve().parents[2], type=Path)
    parser.add_argument("--evaluated-commit", required=True)
    arguments = parser.parse_args()
    run(arguments.output, arguments.root, arguments.evaluated_commit)
