from __future__ import annotations

import copy
import json

import pytest

from langgraph.prebuilt.security import developer_verification as gate


@pytest.fixture
def evidence():
    return {
        "complete": False,
        "router": {
            "complete": True,
            "issues": [],
            "summary": {"verified": 21, "discovered": 21},
        },
        "placement": {"issues": [], "path_cover_proved": False},
        "adapters": {"diagnostics": [], "proof": False},
        "escape_discovery": {"unwaived_findings": [], "errors": []},
    }


def test_clear_regressions_do_not_prove_completeness(evidence):
    report = gate.developer_report(evidence)
    assert report["regression_checks_passed"]
    assert not report["acceptance_passed"]
    assert not report["complete"]
    assert {item["rule"] for item in report["proof_gaps"]} == {
        "SGV901",
        "SGV902",
        "SGV903",
    }
    assert all(item["owner"] == "verifier" for item in report["proof_gaps"])
    assert "NOT ESTABLISHED" in gate.render_text(report)


def test_failures_have_actionable_locations_and_owners(evidence):
    evidence["escape_discovery"]["unwaived_findings"] = [
        {
            "message": "Unmediated node",
            "path": "prebuilt/node.py",
            "line": 7,
            "fingerprint": "exact-site",
        }
    ]
    evidence["escape_discovery"]["errors"] = ["waiver_manifest:stale:old-site"]
    report = gate.developer_report(evidence)
    assert not report["acceptance_passed"]
    assert report["summary"]["implementation_tasks"] == 2
    text = gate.render_text(report)
    assert "libs/prebuilt/node.py:7" in text
    assert "Fix:" in text


def test_comparison_only_tracks_tasks_never_reuses_pass_evidence(evidence):
    old = gate.developer_report(evidence)
    changed = copy.deepcopy(evidence)
    changed["placement"]["issues"] = ["missing source"]
    current = gate.developer_report(changed)
    delta = gate.compare_reports(current, old)
    assert len(delta["new"]) == 1
    assert not delta["resolved"]
    assert not current["acceptance_passed"]
    assert len(gate.compare_reports(old, current)["resolved"]) == 1
    with pytest.raises(ValueError, match="comparison file"):
        gate.compare_reports(current, {"complete": True})


@pytest.mark.parametrize("strict,expected", [(False, 1), (True, 1)])
def test_cli_exit_contract_and_json(monkeypatch, tmp_path, evidence, strict, expected):
    monkeypatch.setattr(gate, "verify_layers", lambda repo: evidence)
    output = tmp_path / "report.json"
    args = ["--output", str(output)] + (["--require-complete"] if strict else [])
    assert gate.main(args) == expected
    assert json.loads(output.read_text())["complete"] is False


def test_forged_top_level_success_cannot_hide_missing_proofs(evidence):
    evidence["complete"] = True
    report = gate.developer_report(evidence)
    assert not report["acceptance_passed"]
    assert not report["complete"]


def test_schema_one_comparison_does_not_preserve_old_acceptance(evidence):
    old = gate.developer_report(evidence)
    old["schema_version"] = 1
    old["acceptance_passed"] = True
    current = gate.developer_report(evidence)
    assert not gate.compare_reports(current, old)["new"]
    assert not current["acceptance_passed"]


def test_cli_invalid_comparison_is_error_not_success(monkeypatch, tmp_path, evidence):
    monkeypatch.setattr(gate, "verify_layers", lambda repo: evidence)
    path = tmp_path / "bad.json"
    path.write_text("not json")
    assert gate.main(["--compare", str(path)]) == 2


def test_cli_lists_checks_without_loading_application(monkeypatch, capsys):
    def unexpected(repo):
        raise AssertionError("not a source-analysis run")

    monkeypatch.setattr(gate, "verify_layers", unexpected)
    assert gate.main(["--list-checks"]) == 0
    assert "SGV101" in capsys.readouterr().out


def test_failed_router_always_blocks_acceptance(evidence):
    evidence["router"]["complete"] = False
    report = gate.developer_report(evidence)
    assert not report["acceptance_passed"]
    assert any(task["rule"] == "SGV201" for task in report["tasks"])
