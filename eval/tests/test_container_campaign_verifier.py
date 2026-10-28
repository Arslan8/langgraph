"""Lifecycle acceptance must reject lost state, leaked authority and cleanup gaps."""

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / "remaining"


@pytest.fixture
def campaign(monkeypatch):
    monkeypatch.syspath_prepend(str(DIRECTORY))
    spec = importlib.util.spec_from_file_location(
        "container_dispatcher_campaign", DIRECTORY / "container_dispatcher_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def rows_for(campaign):
    rows = []
    for case in campaign.CASES:
        calls = []
        for index, phase in enumerate(("seed", "reuse", "transition")):
            broad = case == "broad_to_narrow" and index < 2
            value = {"sum": 41, "residual": index == 1}
            value.update(
                {"private": "PRIVATE_CANARY"} if broad else {"private_error": "FileNotFoundError"}
            )
            calls.append(
                {
                    "phase": phase,
                    "broad": broad,
                    "value": value,
                    "receipt": {"nonce": str(index)},
                    "execution": {
                        "container_id": "old" if index < 2 else "new",
                        "reused": index == 1,
                    },
                }
            )
        rows.append(
            {
                "case": case,
                "repetition": 0,
                "calls": calls,
                "old_absence": {"returncode": 0, "stdout": ""},
                "cleanup": [{"returncode": 0, "stdout": ""} for _ in calls],
            }
        )
    return rows


def test_rejects_missing_duplicate_and_failed_observations(campaign):
    rows = rows_for(campaign)
    assert campaign.verify(rows, 1) == []
    assert campaign.verify(rows[:-1], 1)
    assert campaign.verify([*rows[:-1], rows[0]], 1)
    rows[0]["error"] = {"type": "RuntimeError"}
    assert campaign.verify(rows, 1)


@pytest.mark.parametrize(
    "failure",
    ["residual", "leak", "same_container", "no_reuse", "cleanup", "lost_utility", "nonce"],
)
def test_rejects_runtime_regressions(campaign, failure):
    rows = copy.deepcopy(rows_for(campaign))
    row = rows[0]
    last = row["calls"][-1]
    if failure == "residual":
        last["value"]["residual"] = True
    elif failure == "leak":
        last["value"]["private"] = "PRIVATE_CANARY"
    elif failure == "same_container":
        last["execution"]["container_id"] = "old"
    elif failure == "no_reuse":
        row["calls"][1]["execution"]["container_id"] = "another"
    elif failure == "cleanup":
        row["cleanup"][0]["returncode"] = 1
    elif failure == "lost_utility":
        last["value"]["sum"] = 0
    elif failure == "nonce":
        last["receipt"]["nonce"] = "0"
    assert campaign.verify(rows, 1)
