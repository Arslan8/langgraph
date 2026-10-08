from __future__ import annotations

from pathlib import Path

import pytest

from langgraph.prebuilt.security import layered_verification as layered


@pytest.fixture
def sources():
    repo = Path(__file__).resolve().parents[4]
    return {name: (repo / name).read_text() for name in layered._REQUIRED}


def test_operation_universe_is_independent_of_placement(sources):
    report = layered.inventory_sources(sources)
    assert not report["issues"]
    assert len(layered.OPERATIONS) == 10
    assert sum(map(len, layered.OPERATIONS.values())) == 30
    assert report["call_candidates"]
    assert report["declared_methods"]
    assert not report["path_cover_proved"]
    assert report["discovery_only"]


@pytest.mark.parametrize(
    "change", ["add_operation", "remove_operation", "add_request", "missing", "syntax"]
)
def test_changed_or_incomplete_universe_cannot_pass_inventory(sources, change):
    path = layered._SECURITY + "objects.py"
    if change == "add_operation":
        sources[path] = sources[path].replace(
            'WRITE = "write"', 'WRITE = "write"\n    DELETE = "delete"'
        )
    elif change == "remove_operation":
        sources[path] = sources[path].replace('    WRITE = "write"\n', "")
    elif change == "add_request":
        sources[path] += "\nclass NewRequest:\n    pass\n"
    elif change == "missing":
        del sources[path]
    else:
        sources[path] = "invalid python ("
    assert layered.inventory_sources(sources)["issues"]


def test_new_adapter_method_is_discovered_without_admission(sources):
    path = layered._SECURITY + "checkpoint_security.py"
    sources[path] += (
        "\nclass Adapter:\n    def read(self, config):\n        return self.inner.get_tuple(config)\n"
    )
    report = layered.inventory_sources(sources)
    assert any(site["symbol"] == "Adapter.read" for site in report["declared_methods"])
    assert any(site["function"] == "Adapter.read" for site in report["call_candidates"])
    assert not report["path_cover_proved"]


def test_empty_input_is_not_a_complete_inventory():
    report = layered.inventory_sources({})
    assert report["issues"]
    assert not report["path_cover_proved"]


def test_source_edits_change_evidence_binding(sources):
    before = layered.inventory_sources(sources)
    path = layered._SECURITY + "placement.py"
    sources[path] += "\n# reviewed source changed\n"
    after = layered.inventory_sources(sources)
    assert before["source_sha256"][path] != after["source_sha256"][path]


def test_complete_gate_cannot_pass_on_router_proof_alone(monkeypatch, tmp_path):
    report = {
        "complete": False,
        "router": {"complete": True},
        "placement": {"issues": []},
        "adapters": {"checks_passed": True},
        "escape_discovery": {"errors": [], "unwaived": 0},
    }
    monkeypatch.setattr(layered, "verify_layers", lambda repo: report)
    monkeypatch.setattr(
        "sys.argv",
        ["layered", "--require-complete", "--output", str(tmp_path / "report.json")],
    )
    assert layered._main() == 1
