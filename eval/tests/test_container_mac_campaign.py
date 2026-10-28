"""Operator-restart acceptance requires useful execution and actual cleanup."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def campaign(monkeypatch):
    directory = Path(__file__).resolve().parents[1] / "remaining"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location(
        "container_mac_campaign", directory / "container_mac_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def observation():
    controllers = []
    for phase, pid in (("broad", 1), ("narrow", 2)):
        calls = []
        for index in range(2 if phase == "broad" else 1):
            value = {"sum": 41, "residual": index == 1}
            value.update(
                {"private": "PRIVATE_CANARY"}
                if phase == "broad"
                else {"private_error": "FileNotFoundError"}
            )
            calls.append(
                {
                    "status": "success",
                    "content": json.dumps(value),
                    "receipt": {
                        "mode": "enforced",
                        "activated_obligations": ["allowed", "private"]
                        if phase == "broad"
                        else ["allowed"],
                    },
                    "execution": {"container_id": phase, "identity_digest": phase},
                }
            )
        controllers.append(
            {
                "returncode": 0,
                "result": {
                    "phase": phase,
                    "pid": pid,
                    "calls": calls,
                    "replacement_refusal": "runtime policy is already installed",
                    "cleanup": [{"returncode": 0, "stdout": ""} for _ in calls],
                },
            }
        )
    return {"controllers": controllers}


@pytest.mark.parametrize(
    "failure",
    ["disposition", "leak", "residual", "cleanup", "no_restart", "no_seal", "missing_call"],
)
def test_rejects_incomplete_or_unsafe_restart_evidence(campaign, failure):
    row = observation()
    assert campaign.verify_pair(row)
    narrow = row["controllers"][1]["result"]
    if failure == "disposition":
        narrow["calls"][0]["status"] = "error"
    elif failure in ("leak", "residual"):
        value = json.loads(narrow["calls"][0]["content"])
        value["private" if failure == "leak" else "residual"] = True
        narrow["calls"][0]["content"] = json.dumps(value)
    elif failure == "cleanup":
        narrow["cleanup"][0]["stdout"] = "remaining-container"
    elif failure == "no_restart":
        narrow["pid"] = 1
    elif failure == "no_seal":
        del narrow["replacement_refusal"]
    elif failure == "missing_call":
        narrow["calls"] = []
    assert not campaign.verify_pair(row)


@pytest.mark.parametrize("failure", ["cleanup", "archive", "matrix", "policy", "saved_result"])
def test_saved_verifier_rejects_missing_or_inconsistent_evidence(campaign, tmp_path, failure):
    spec = importlib.util.spec_from_file_location(
        "verify_container_mac_campaign",
        Path(__file__).resolve().parents[1] / "remaining/verify_container_mac_campaign.py",
    )
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    row = {**observation(), "repetition": 0, "async": False}
    sources = tmp_path / "sources"
    sources.mkdir()
    digest = hashlib.sha256(b"fixture source").hexdigest()
    (sources / digest).write_bytes(b"fixture source")
    inventory = {
        f"libs/prebuilt/langgraph/prebuilt/security/{name}": digest
        for name in ("mac.py", "container.py", "_container_lifecycle.py", "_linux_worker.py")
    }
    (tmp_path / "verification.json").write_text(
        json.dumps({"source_before": inventory, "source_after": inventory})
    )
    for controller, phase in zip(row["controllers"], ("broad", "narrow"), strict=False):
        controller["phase"] = phase
        output = tmp_path / f"00-{phase}"
        output.mkdir()
        (output / "result.json").write_text(json.dumps(controller["result"]))
        (output / "request.json").write_text(
            json.dumps({"phase": phase, "async": False, "root": "/fixture"})
        )
        (output / "stdout.log").touch()
        (output / "stderr.log").touch()
        policy = (
            "forbid(principal, action, resource) when {false};"
            if phase == "broad"
            else 'forbid(principal, action == slangGraph::Action::"fs::read", resource) '
            'when {resource.selector == "/fixture/private.txt"};'
        )
        (output / "operator.cedar").write_text(policy)
    observations = tmp_path / "observations.json"
    observations.write_text(json.dumps([row]))
    assert verifier.verify_saved(tmp_path, 1)["passed"]
    if failure == "cleanup":
        row["controllers"][1]["result"]["cleanup"] = []
        (tmp_path / "00-narrow/result.json").write_text(json.dumps(row["controllers"][1]["result"]))
        observations.write_text(json.dumps([row]))
    elif failure == "archive":
        (sources / digest).write_bytes(b"changed source")
    elif failure == "matrix":
        observations.write_text(json.dumps([row, row]))
    elif failure == "policy":
        (tmp_path / "00-narrow/operator.cedar").write_text(
            "forbid(principal, action, resource) when {false};"
        )
    elif failure == "saved_result":
        (tmp_path / "00-narrow/result.json").write_text("{}")
    assert not verifier.verify_saved(tmp_path, 1)["passed"]
