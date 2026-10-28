"""Ensure timing cohorts actually use production admission and complete pairing."""

import json
from pathlib import Path

import pytest
from langgraph.prebuilt.security import cedar_security
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied

from slanggraph_eval.isolation.verified import MANIFEST, POLICY, summarize, verified_read


def test_production_admission_rejects_manifest_mismatch():
    with pytest.raises(SecurityConfigurationError, match="manifest_consistency"):
        cedar_security(verified_read, policy=POLICY, manifest="runs inprocess")


def test_admission_guards_function_binding_after_setup():
    security = cedar_security(verified_read, policy=POLICY, manifest=MANIFEST)
    original = verified_read.func
    try:
        verified_read.func = lambda path: "bypassed"
        with pytest.raises(HostExecutionDenied, match="tool_changed"):
            security.host_executor.dispatcher.admission.validate()
    finally:
        verified_read.func = original


def test_saved_production_cohort():
    folder = Path(__file__).parents[1] / "reports/e6/verified-v2"
    if not (folder / "plan.json").is_file():
        pytest.skip("Saved production cohort is local generated evidence")
    plan = json.loads((folder / "plan.json").read_text())
    rows = [json.loads(line) for line in (folder / "samples.jsonl").read_text().splitlines()]
    assert all(r["valid"] and r["value_sha256"] == r["expected_sha256"] for r in rows)
    assert summarize(rows, plan["samples"]) == json.loads((folder / "summary.json").read_text())
    for r in rows:
        assert 0 < r["execution_ms"] < r["elapsed_ms"]
        assert 0 < r["policy_ms"] < r["elapsed_ms"]
    for fault in (rows[:-1], [*rows, rows[-1]]):
        with pytest.raises(AssertionError):
            summarize(fault, plan["samples"])


def test_frozen_sources_match_recorded_hashes():
    import hashlib
    import tarfile

    folder = Path(__file__).parents[1] / "reports/e6/verified-v2"
    if not (folder / "plan.json").is_file():
        pytest.skip("Saved production cohort is local generated evidence")
    plan = json.loads((folder / "plan.json").read_text())
    archive = folder / "sources.tar.gz"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == plan["archive_sha256"]
    with tarfile.open(archive) as source:
        for name, expected in plan["source_hashes"].items():
            assert hashlib.sha256(source.extractfile(name).read()).hexdigest() == expected
