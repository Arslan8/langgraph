"""The native matrix cannot pass by dropping trials or failing positive controls."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "native_matrix_verifier",
    Path(__file__).resolve().parents[1] / "remaining/verify_native_filesystem.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(tmp_path, rows):
    for name, content in {
        "plan.json": {"cases": ["omitted_read"], "repetitions": 1},
        "framework-before.json": {"worker": "same"},
        "framework-after.json": {"worker": "same"},
    }.items():
        (tmp_path / name).write_text(json.dumps(content))
    (tmp_path / "trials.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_missing_attempt_or_positive_failure_cannot_pass(tmp_path):
    row = dict(
        case_id="omitted_read",
        repeat=0,
        control=True,
        status="completed",
        observed_effect=False,
        broker_decisions=[],
        resource_after={"alice": "ALICE_ALLOWED", "bob": "BOB_NATIVE_CANARY"},
        legitimate_result=True,
        activation={"evidence": "test"},
        error=None,
        result={"attempted": False},
    )
    negative = {**row, "control": False, "result": {"attempted": True, "denied": "PermissionError"}}
    fixture(tmp_path, [row, negative])
    assert module.verify(tmp_path)["passed"]
    fixture(tmp_path, [row])
    assert not module.verify(tmp_path)["passed"]
    fixture(tmp_path, [row, {**negative, "result": {"attempted": False}}])
    assert not module.verify(tmp_path)["passed"]
    fixture(tmp_path, [{**row, "legitimate_result": False}, negative])
    assert not module.verify(tmp_path)["passed"]
    fixture(tmp_path, [row, {**negative, "observed_effect": True}])
    assert not module.verify(tmp_path)["passed"]
