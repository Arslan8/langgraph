"""End-to-end tests for the custom pump class demonstration."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[4]
SIMULATOR = REPOSITORY / "workspace" / "05_pump_simulator.py"
CONTROLLER = REPOSITORY / "workspace" / "05_custom_class_quickstart.py"


def test_pump_demo_enforces_operations_before_socket_dispatch() -> None:
    """Use real Cedar and prove denied operations never reach the simulator."""
    cedar = shutil.which("cedar")
    assert cedar is not None, "the pump integration test requires the real Cedar CLI"
    suffix = uuid.uuid4().hex[:12]
    socket_path = Path(f"/tmp/slanggraph-pump-{suffix}.sock")
    log_path = Path(f"/tmp/slanggraph-pump-{suffix}.jsonl")
    simulator = subprocess.Popen(
        [
            sys.executable,
            os.fspath(SIMULATOR),
            "--socket",
            os.fspath(socket_path),
            "--log",
            os.fspath(log_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not socket_path.exists() and time.monotonic() < deadline:
            if simulator.poll() is not None:
                raise AssertionError(
                    simulator.stdout.read() if simulator.stdout else ""
                )
            time.sleep(0.02)
        assert socket_path.exists(), "pump simulator did not create its socket"

        completed = subprocess.run(
            [
                sys.executable,
                os.fspath(CONTROLLER),
                "--demo",
                "--socket",
                os.fspath(socket_path),
                "--log",
                os.fspath(log_path),
                "--cedar",
                cedar,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPOSITORY,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert completed.stdout.count("Authorization: ALLOW") == 4
        assert completed.stdout.count("Authorization: DENY") == 4
        assert "Derived: rejected; operation is not in the manifest's closed map" in (
            completed.stdout
        )
        assert "flow rate must be between 0 and 100" in completed.stdout
        assert "set_flow and calibrate used the same socket" in completed.stdout

        artifact_paths = [
            Path(value)
            for value in re.findall(r"^Cedar artifacts: (.+)$", completed.stdout, re.M)
        ]
        # Every Cedar evaluation is retained. The unknown operation is rejected
        # by the closed manifest map before Cedar and therefore has no bundle.
        assert len(artifact_paths) == 7
        pump_entity_ids = set()
        for artifact_path in artifact_paths:
            entities = json.loads(
                (artifact_path / "entities.json").read_text(encoding="utf-8")
            )
            pump_entities = [
                entity
                for entity in entities
                if entity["uid"]["type"] == "slangGraph::PumpDevice"
            ]
            assert len(pump_entities) == 1
            pump_entity_ids.add(pump_entities[0]["uid"]["id"])
        assert len(pump_entity_ids) == 1

        entries = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [entry["operation"] for entry in entries] == [
            "set_flow",
            "calibrate",
            "inspect",
        ]
        assert entries[-1]["after"] == {
            "running": False,
            "flow_rate": 25.0,
            "calibration_offset": 1.5,
        }
    finally:
        simulator.terminate()
        try:
            simulator.wait(timeout=5)
        except subprocess.TimeoutExpired:
            simulator.kill()
            simulator.wait(timeout=5)
        socket_path.unlink(missing_ok=True)
        log_path.unlink(missing_ok=True)
