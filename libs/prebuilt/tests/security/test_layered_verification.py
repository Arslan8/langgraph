from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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


def test_new_source_file_is_in_the_api_obligation_ledger(sources):
    path = "libs/prebuilt/langgraph/prebuilt/new_component.py"
    sources[path] = (
        "class NewTool:\n    def new_api(self):\n        return self.inner.read()\n"
    )
    inventory = layered.inventory_sources(sources)
    ledger = layered.obligation_ledger(
        inventory, {"entries": [], "complete": False}, {"complete": False}
    )
    entry = next(item for item in ledger if item["path"] == path)
    assert (
        entry["qualified_symbol"] == "langgraph.prebuilt.new_component.NewTool.new_api"
    )
    assert entry["status"] == "unresolved"
    assert entry["publication_transfer"] == "not_analyzed"
    assert entry["source_sha256"] == inventory["source_sha256"][path]


def test_partial_publication_proof_never_becomes_whole_api_proof(sources):
    inventory = layered.inventory_sources(sources)
    publications = {
        "complete": False,
        "entries": [
            {
                "entry": "langgraph.prebuilt.security.object_manager.MediatedStore.batch",
                "status": "verified",
            }
        ],
    }
    ledger = layered.obligation_ledger(inventory, publications, {"complete": False})
    entry = next(
        item
        for item in ledger
        if item["qualified_symbol"].endswith("MediatedStore.batch")
    )
    assert entry["publication_transfer"] == "verified"
    assert not entry["publication_model_closed"]
    assert entry["status"] == "unresolved"


def test_source_edits_change_evidence_binding(sources):
    before = layered.inventory_sources(sources)
    path = layered._SECURITY + "placement.py"
    sources[path] += "\n# reviewed source changed\n"
    after = layered.inventory_sources(sources)
    assert before["source_sha256"][path] != after["source_sha256"][path]


def test_primitive_evidence_uses_audited_source_and_never_closes_gate(
    monkeypatch, tmp_path, sources
):
    # Isolate the composition report from unrelated discovery passes. The output
    # source derivation itself is real and must be recomputed after a source edit.
    for name in ("output_data.py", "objects.py"):
        path = tmp_path / layered._SECURITY / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sources[layered._SECURITY + name])
    monkeypatch.setattr(
        layered,
        "check_adapters",
        lambda sources: {"proof": True, "checks_passed": True},
    )
    monkeypatch.setattr(
        layered, "verify_publications", lambda sources: {"complete": True}
    )
    monkeypatch.setattr(
        layered,
        "verify_host_router",
        lambda: {
            "complete": True,
            "runtime_binding": {"source_sha256": "missing-router"},
            "summary": {},
        },
    )
    monkeypatch.setattr(layered, "obligation_ledger", lambda *args: [])
    monkeypatch.setattr(
        layered,
        "analyze_source",
        lambda *args: SimpleNamespace(findings=[], parse_errors=[]),
    )
    monkeypatch.setattr(
        layered,
        "apply_waivers",
        lambda *args: SimpleNamespace(waived=[], unwaived=[], errors=[]),
    )
    before = layered.verify_layers(tmp_path)
    primitive = before["output_data_primitives"]
    assert primitive["primitive_contracts_complete"]
    # The real validator derivation succeeds, yet no host source is supplied
    # here, so the composed correspondence and the system gate stay open.
    assert primitive["validator_admission_proved"]
    assert not before["host_output_correspondence"]["proved"]
    assert not before["complete"]
    key = "langgraph.prebuilt.security.output_data"
    assert (
        primitive["source_sha256"][key]
        == before["placement"]["source_sha256"][layered._SECURITY + "output_data.py"]
    )
    path = tmp_path / layered._SECURITY / "output_data.py"
    source = path.read_text()
    changed = source.replace(
        "def charge(self, amount: int = 0) -> None:",
        "def charge(self, amount: int = 0) -> None:\n        publish(amount)",
    )
    assert changed != source
    path.write_text(changed)
    after = layered.verify_layers(tmp_path)
    assert not after["output_data_primitives"]["primitive_contracts_complete"]
    assert not after["output_data_primitives"]["validator_admission_proved"]
    assert (
        after["output_data_primitives"]["source_sha256"] != primitive["source_sha256"]
    )
    assert not after["complete"]


@pytest.mark.parametrize("strict", [False, True])
def test_complete_gate_cannot_pass_on_router_proof_alone(monkeypatch, tmp_path, strict):
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
        ["layered", "--output", str(tmp_path / "report.json")]
        + (["--require-complete"] if strict else []),
    )
    assert layered._main() == 1


def test_admission_surface_is_evidence_only(monkeypatch, tmp_path):
    # Real admission sources are copied so the derivation runs on the actual
    # gate; unrelated discovery passes are isolated. The evidence key must not
    # move `complete` or the placement path-cover verdict.
    repo = Path(__file__).resolve().parents[4]
    for name in ("admission.py", "config.py", "placement.py", "mac.py"):
        path = tmp_path / layered._SECURITY / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text((repo / layered._SECURITY / name).read_text())
    monkeypatch.setattr(
        layered,
        "check_adapters",
        lambda sources: {"proof": True, "checks_passed": True},
    )
    monkeypatch.setattr(
        layered, "verify_publications", lambda sources: {"complete": True}
    )
    monkeypatch.setattr(
        layered,
        "verify_host_router",
        lambda: {
            "complete": True,
            "runtime_binding": {"source_sha256": "missing-router"},
            "summary": {},
        },
    )
    monkeypatch.setattr(layered, "obligation_ledger", lambda *args: [])
    monkeypatch.setattr(
        layered,
        "analyze_source",
        lambda *args: SimpleNamespace(findings=[], parse_errors=[]),
    )
    monkeypatch.setattr(
        layered,
        "apply_waivers",
        lambda *args: SimpleNamespace(waived=[], unwaived=[], errors=[]),
    )
    report = layered.verify_layers(tmp_path)
    surface = report["admission_surface"]
    assert surface["proved"]
    assert surface["system_complete"] is False
    assert surface["sgv901_closed"] is False
    assert (
        surface["source_sha256"]["langgraph.prebuilt.security.admission"]
        == report["placement"]["source_sha256"][layered._SECURITY + "admission.py"]
    )
    assert not report["complete"]
    assert not report["placement"]["path_cover_proved"]
    path = tmp_path / layered._SECURITY / "placement.py"
    source = path.read_text()
    changed = source.replace(
        "result = function(captured.node, data, narrowed, runtime)",
        "result = self.runnable.invoke(data, narrowed)",
    )
    assert changed != source
    path.write_text(changed)
    after = layered.verify_layers(tmp_path)
    assert not after["admission_surface"]["proved"]
    assert not after["complete"]
    assert not after["placement"]["path_cover_proved"]
