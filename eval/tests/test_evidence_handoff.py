"""Corruption tests for completed-cohort validation; never invoke a benchmark."""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/evidence_handoff.py"
spec = importlib.util.spec_from_file_location("handoff", SCRIPT)
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)
REPORTS = SCRIPT.parents[1] / "reports"
pytestmark = pytest.mark.skipif(
    not (REPORTS / "native-chain-v2/samples.jsonl").is_file(),
    reason="Saved native cohort is local generated evidence",
)


def test_completed_native_cohort(tmp_path):
    result = handoff.timing(
        REPORTS / "native-chain-v2",
        "samples",
        ["env_to_cat"],
        ["plain", "landlock", "container"],
        20261401,
        tmp_path,
    )
    assert len(result) == 2


@pytest.mark.parametrize("corruption", ["missing_sample", "duplicate_pair", "false_oracle"])
def test_rejects_corrupt_observations(tmp_path, monkeypatch, corruption):
    original = handoff.read

    def read(path):
        data = original(path)
        if path.name == "samples.jsonl":
            if corruption == "missing_sample":
                data.pop(0)
            elif corruption == "duplicate_pair":
                data[1] = data[0]
            elif data[0]["session"] == 0:
                data[0]["response"]["value"]["stdout"] = "wrong canary"
        return data

    monkeypatch.setattr(handoff, "read", read)
    with pytest.raises(ValueError):
        handoff.timing(
            REPORTS / "native-chain-v2",
            "samples",
            ["env_to_cat"],
            ["plain", "landlock", "container"],
            20261401,
            tmp_path,
        )
    if corruption == "false_oracle":
        failures = json.loads((tmp_path / "samples-oracle-failures.json").read_text())
        assert failures and failures[0]["row"]["response"]["value"]["stdout"] == "wrong canary"
