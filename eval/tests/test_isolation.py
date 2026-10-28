"""Evaluation validity tests, including false-success and trust-boundary checks."""

import json

import pytest

from slanggraph_eval.isolation.cases import cases
from slanggraph_eval.isolation.run import classify, make_executor, summarize, trial
from slanggraph_eval.isolation.worker import admit, run


def test_corpus_unique_and_valid():
    corpus = cases()
    assert len({case.name for case in corpus}) == len(corpus)
    assert len(corpus) >= 50
    assert {case.surface for case in corpus} == {"hidden", "readonly", "writable"}
    for case in corpus:
        compile(case.source, case.name, "exec")


@pytest.mark.parametrize("source", ["import os", "open('x')", "helper.__globals__", "helper(1)"])
def test_language_admission_rejects_unsupported_source(source):
    with pytest.raises(PermissionError):
        admit(source)


def test_helper_trust_is_explicit_and_read_canary_not_in_inputs(tmp_path):
    path = tmp_path / "canary"
    path.write_text("secret")
    source = "result = open(p['target']).read()"
    args = {"target": str(path)}
    assert run(source, args, "direct")["phase"] == "admission"
    assert run(source, args, "helper")["value"] == "secret"


@pytest.mark.parametrize("host,receipt", [(False, None), (True, {"activated": True})])
def test_absence_is_not_denial(host, receipt):
    assert (
        classify(effect=False, response={"phase": "executed"}, host=host, receipt=receipt)
        == "no_effect_observed"
    )
    assert (
        classify(
            effect=False,
            response={"phase": "harness", "error": "TimeoutError"},
            host=host,
            receipt=receipt,
        )
        == "inconclusive"
    )


def test_host_requires_activation_before_denial_credit():
    assert (
        classify(
            effect=False,
            response={"phase": "operation", "error": "PermissionError"},
            host=True,
            receipt=None,
        )
        == "inconclusive"
    )


def test_effect_overrides_error():
    assert (
        classify(effect=True, response={"phase": "harness"}, host=True, receipt=None)
        == "effect_observed"
    )


def test_baseline_and_language_controls():
    corpus = {case.name: case for case in cases()}
    for name in ["arithmetic", "open_read", "write", "tcp_connect", "sqlite_write"]:
        row = trial(corpus[name], "trusted", 0)
        assert row["effect_observed"], row
    row = trial(corpus["allowed_read"], "language_direct", 0)
    assert row["outcome"] == "admission_rejected"
    assert summarize([row])["language_direct"]["control_effects"] == 0


def test_real_host_controls_and_denials(tmp_path):
    # Only a failed real preflight permits a skip; runtime failures fail the test.
    (tmp_path / "allowed").touch()
    (tmp_path / "output").mkdir()
    try:
        make_executor(tmp_path)
    except RuntimeError as error:
        pytest.skip(str(error))
    corpus = {case.name: case for case in cases()}
    for name in ["allowed_read", "allowed_write", "allowed_mkdir_subtree"]:
        row = trial(corpus[name], "host", 0)
        assert row["effect_observed"], row
        assert row["activation_receipt"]
    for name in ["open_read", "readonly_write", "writable_chmod", "tcp_connect", "native_write"]:
        row = trial(corpus[name], "host", 0)
        assert row["outcome"] == "operation_denied", row
        assert row["activation_receipt"]
    row = trial(corpus["file_size_limit"], "host", 0)
    assert not row["effect_observed"]
    assert row["evidence"]["output_size"] <= 1048576
    # Evidence is serializable and does not depend on retaining temporary paths.
    assert json.loads(json.dumps(row))["oracle"] == "large_file"


def test_recorded_artifact_is_complete_and_recomputes():
    import hashlib
    import tarfile
    from collections import Counter
    from pathlib import Path

    artifact = Path(__file__).parents[1] / "reports/e6/isolation-v1"
    if not (artifact / "manifest.json").is_file():
        pytest.skip("Saved isolation cohort is local generated evidence")
    manifest = json.loads((artifact / "manifest.json").read_text())
    rows = [json.loads(line) for line in (artifact / "trials.jsonl").read_text().splitlines()]
    expected = {
        (case["name"], condition, repetition)
        for case in manifest["corpus"]
        for condition in manifest["conditions"]
        for repetition in range(manifest["repetitions"])
    }
    observed = Counter((r["case"], r["condition"], r["repetition"]) for r in rows)
    assert set(observed) == expected
    assert set(observed.values()) == {1}
    assert summarize(rows) == json.loads((artifact / "summary.json").read_text())
    assert (
        hashlib.sha256((artifact / "sources.tar.gz").read_bytes()).hexdigest()
        == (manifest["source_archive_sha256"])
    )
    with tarfile.open(artifact / "sources.tar.gz") as archive:
        for name, expected_hash in manifest["source_hashes"].items():
            source = archive.extractfile(name)
            assert source is not None
            assert hashlib.sha256(source.read()).hexdigest() == expected_hash
    for row in rows:
        if manifest["conditions"][row["condition"]][0]:
            assert row["activation_receipt"]
