"""Crash acceptance cannot substitute harness cleanup or missing observations."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def campaign(monkeypatch):
    directory = Path(__file__).resolve().parents[1] / "remaining"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location(
        "container_crash_campaign", directory / "container_crash_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def observations(campaign):
    rows = []
    for phase in campaign.PHASES:
        rows.append(
            {
                "phase": phase,
                "repetition": 0,
                "controller_pid": 11,
                "ready": {
                    "status": "ready",
                    "phase": phase,
                    "control": 41,
                    "container_id": "a" * 64,
                    "control_container_id": "b" * 64 if phase == "creating" else "a" * 64,
                    "guardian_pid": 12,
                    "descendant_pid": 13 if phase == "inherited_pipe" else None,
                    "receipts": [
                        {"mode": "enforced"} for _ in range(2 if phase == "active" else 1)
                    ],
                },
                "controller_returncode": -9,
                "killed_at": 1,
                "before_kill": {"returncode": 0, "stdout": "a" * 64 + "\n"},
                "guardian_removed_container": True,
                "guardian_exited": True,
                "absence_polls": [{"returncode": 0, "stdout": "", "at": 2}],
                "control_container_after": {"returncode": 0, "stdout": ""},
                "wrapper_sha256": "c" * 64,
                "harness_cleanup": {"returncode": 0},
            }
        )
    return rows


@pytest.mark.parametrize(
    "failure",
    [
        "harness_only",
        "live_guardian",
        "refusal",
        "utility",
        "normal_exit",
        "old_container",
        "invalid_identity",
        "missing",
        "duplicate",
        "pre_crash_absence",
    ],
)
def test_rejects_invalid_crash_evidence(campaign, failure):
    rows = observations(campaign)
    assert not campaign.verify(rows, 1)
    row = rows[0]
    if failure == "harness_only":
        row["guardian_removed_container"] = False
        row["absence_polls"][-1]["stdout"] = "a" * 64
    elif failure == "live_guardian":
        row["guardian_exited"] = False
    elif failure == "refusal":
        row["ready"]["status"] = "denied"
    elif failure == "utility":
        row["ready"]["control"] = None
    elif failure == "normal_exit":
        row["controller_returncode"] = 0
    elif failure == "old_container":
        row["control_container_after"]["stdout"] = "a" * 64
    elif failure == "invalid_identity":
        row["ready"]["container_id"] = ""
    elif failure == "missing":
        rows.pop()
    elif failure == "duplicate":
        rows.append(row)
    elif failure == "pre_crash_absence":
        row["absence_polls"][-1]["at"] = 0
    assert campaign.verify(rows, 1)
