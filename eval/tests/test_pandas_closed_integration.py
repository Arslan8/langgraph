"""C-closed adapter: declarations, dataset_read wiring and state normalization."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "apps/pandas/policy"


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


closed = _load("pandas_integration_closed_test", "apps/pandas/integration_closed.py")


def test_pinned_declarations_match_recorded_vendor_inventory():
    evidence = ROOT / "campaigns/remediation-v2/raw/pandas-closed-v1/inventory.json"
    if not evidence.is_file():
        pytest.skip("Historical inventory is local generated evidence, not distributed in Git")
    inventory = json.loads(evidence.read_text())
    for version in ("v20", "v21"):
        manifest = json.loads((POLICY / f"manifest-{version}-closed.json").read_text())
        declared = manifest["trusted_declarations"]
        for graph in inventory["graphs"]:
            pinned = declared[graph["graph"]]
            assert sorted(pinned["nodes"]) == sorted(n["name"] for n in graph["nodes"])
            assert sorted(pinned["branches"]) == sorted(b["placement"] for b in graph["branches"])


def test_manifests_differ_only_by_declared_normalization():
    v20 = json.loads((POLICY / "manifest-v20-closed.json").read_text())
    v21 = json.loads((POLICY / "manifest-v21-closed.json").read_text())
    assert "state_normalization" not in v20
    assert v21["state_normalization"] == "json-null-v1"
    ignored = {"version", "base_manifest", "state_normalization", "amendment"}
    assert {k: v for k, v in v20.items() if k not in ignored} == {
        k: v for k, v in v21.items() if k not in ignored
    }


def test_fixture_pin_matches_frozen_rows(tmp_path):
    campaign = _load("pandas_closed_campaign_test", "apps/pandas/closed_campaign.py")
    manifest = json.loads((POLICY / "manifest-v21-closed.json").read_text())
    sales = campaign.write_fixture(tmp_path / "fixture")
    import hashlib

    data = sales.read_bytes()
    assert hashlib.sha256(data).hexdigest() == manifest["dataset"]["sha256"]
    assert len(data) == manifest["dataset"]["bytes"] <= manifest["dataset"]["max_bytes"]


def test_json_state_maps_keys_to_strings_and_nonfinite_to_null():
    state = {"sales": {0: 1.5, 1: float("nan"), 2: float("inf")}, "n": [1, None]}
    assert closed.json_state(state) == {"sales": {"0": 1.5, "1": None, "2": None}, "n": [1, None]}


def test_unknown_normalization_refuses():
    assert closed.normalization({}) is None
    assert closed.normalization({"state_normalization": "json-null-v1"}) == "json-null-v1"
    with pytest.raises(ValueError):
        closed.normalization({"state_normalization": "anything-else"})


def test_dataset_read_allows_only_pinned_dataset_for_principal(tmp_path):
    pytest.importorskip("langgraph.prebuilt.security.dataset_operation")
    import hashlib
    import sys

    from langgraph.prebuilt.security import Principal
    from langgraph.prebuilt.security.dataset_operation import read_dataset
    from langgraph.prebuilt.security.unsupported import UnsupportedFeatureError

    if sys.platform != "linux":
        pytest.skip("dataset_read requires Linux openat2")
    sales = tmp_path / "sales.csv"
    sales.write_bytes(b"date,sales\n2026-01-01,1\n")
    digest = hashlib.sha256(sales.read_bytes()).hexdigest()
    events = tmp_path / "events.jsonl"
    registry = closed.dataset_registry(sales.resolve(), digest, 1024)
    authorize = closed.make_authorize(events)
    alice = Principal("alice", frozenset({"analyst"}), frozenset(), "run")
    mallory = Principal("mallory", frozenset({"analyst"}), frozenset(), "run")
    assert read_dataset(alice, "sales", registry=registry, authorize=authorize) == (
        sales.read_bytes()
    )
    with pytest.raises(UnsupportedFeatureError, match="dataset:denied"):
        read_dataset(mallory, "sales", registry=registry, authorize=authorize)
    with pytest.raises(UnsupportedFeatureError, match="dataset:unknown"):
        read_dataset(alice, "other", registry=registry, authorize=authorize)
    sales.write_bytes(b"date,sales\n2026-01-01,2\n")
    with pytest.raises(UnsupportedFeatureError, match="dataset:changed"):
        read_dataset(alice, "sales", registry=registry, authorize=authorize)
    verdicts = [json.loads(line)["verdict"] for line in events.read_text().splitlines()]
    assert verdicts == ["allow", "deny", "allow"]
