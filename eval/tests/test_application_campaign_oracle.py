"""Malformed outputs count as failures without aborting the remaining cohort."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "application_campaign",
    Path(__file__).resolve().parents[1] / "remaining/application_campaign.py",
)
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


@pytest.mark.parametrize(
    "output,chart",
    [
        (None, False),
        ({"table": [None]}, False),
        ({"plot": {"data": None}}, True),
        ({"plot": {"data": [None]}}, True),
        ({"plot": {"data": [{"x": ["2026-01"], "y": []}]}}, True),
    ],
)
def test_malformed_output_is_failure(output, chart):
    assert campaign.oracle(output, [["2026-01", 1]], chart) is False


def test_frozen_valid_table_and_series_semantics():
    expected = [["2026-01", 1]]
    assert campaign.oracle({"table": [{"month": "2026-01", "total": 1}]}, expected, False)
    assert campaign.oracle({"plot": {"data": [{"x": ["2026-01"], "y": [1]}]}}, expected, True)


def test_trial_source_capture_preserves_each_observed_version(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    source = root / "libs/prebuilt/langgraph/example.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n")
    output = tmp_path / "cohort"
    output.mkdir()
    monkeypatch.setattr(campaign, "ROOT", root)
    first = campaign.capture_framework(output)
    source.write_text("value = 2\n")
    second = campaign.capture_framework(output)
    key = "libs/prebuilt/langgraph/example.py"
    assert campaign.identity_digest(first) != campaign.identity_digest(second)
    assert (output / "framework-source-blobs" / first[key]).read_text() == "value = 1\n"
    assert (output / "framework-source-blobs" / second[key]).read_text() == "value = 2\n"


def test_frozen_framework_is_independent_of_live_checkout(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    for library in ["prebuilt", "langgraph", "checkpoint"]:
        package = root / "libs" / library / "langgraph"
        package.mkdir(parents=True)
        (package / "example.py").write_text("value = 'frozen'\n")
        (package / "asset.txt").write_text("package asset")
    monkeypatch.setattr(campaign, "ROOT", root)
    output = tmp_path / "cohort"
    frozen = campaign.freeze_framework(output)
    live = root / "libs/prebuilt/langgraph/example.py"
    live.write_text("value = 'new development code'\n")
    identities = campaign.capture_framework(output, frozen)
    key = "libs/prebuilt/langgraph/example.py"
    assert (output / "framework-source-blobs" / identities[key]).read_text() == "value = 'frozen'\n"
    assert (frozen / "libs/prebuilt/langgraph/asset.txt").read_text() == "package asset"
