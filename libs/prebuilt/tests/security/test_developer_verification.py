from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from langgraph.prebuilt.security import developer_verification as gate
from langgraph.prebuilt.security.layered_verification import verify_layers

ROUTE = "pandas-c-generated-computation"
OBLIGATIONS = ("SGV901", "SGV902", "SGV903")


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


def _check(check_id: str, passed: bool) -> dict[str, Any]:
    return {
        "id": check_id,
        "passed": passed,
        "proof": passed,
        "recomputed": True,
        "detail": "fresh" if passed else "failing",
        "source_sha256": {},
    }


def _route(
    route_id: str = ROUTE, *, failing: tuple[str, ...] = (), status: str = "supported"
) -> dict[str, Any]:
    obligations = {}
    for rule in OBLIGATIONS:
        check_id = f"{rule.lower()}-check"
        passed = rule not in failing
        obligations[rule] = {
            "applicable": True,
            "reason": "declared by the manifest",
            "required_evidence": [check_id],
            "checks": [_check(check_id, passed)],
            "discharged": passed,
        }
    return {
        "id": route_id,
        "status": status,
        "accepted": status == "supported" and not failing,
        "obligations": obligations,
        "exclusions": [],
    }


def _routes(*routes: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    routes = routes or (_route(),)
    supported = [route for route in routes if route["status"] == "supported"]
    accepted = sum(route["accepted"] for route in supported)
    report = {
        "kind": "route-scoped-acceptance",
        "schema_version": 1,
        "manifest": "docs/security/supported-surface.json",
        "manifest_ok": True,
        "claim": "route-scoped acceptance only; not whole-system completeness",
        "system_complete": False,
        "complete": bool(supported) and accepted == len(supported),
        "routes": list(routes),
        "checks": {},
        "ungated_exclusions": [],
        "unregistered_gates": [],
        "issues": [],
        "lean_audit_run": True,
        "evidence_dir": "/tmp/evidence",
        "summary": {
            "routes": len(routes),
            "supported_routes": len(supported),
            "accepted_routes": accepted,
            "failing_checks": [],
        },
    }
    report.update(overrides)
    return report


@pytest.fixture
def routes():
    return _routes()


def _gaps(report: dict[str, Any]) -> dict[str, str]:
    return {item["rule"]: item["route_scope"] for item in report["proof_gaps"]}


def test_clear_regressions_do_not_prove_completeness(evidence):
    report = gate.developer_report(evidence)
    assert report["regression_checks_passed"]
    assert not report["acceptance_passed"]
    assert not report["complete"]
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)
    assert all(item["owner"] == "verifier" for item in report["proof_gaps"])
    assert "NOT ESTABLISHED" in gate.render_text(report)


def test_without_route_report_acceptance_is_not_evaluated(evidence):
    report = gate.developer_report(evidence, None)
    assert not report["acceptance_passed"]
    assert report["route_acceptance"] is None
    assert report["summary"]["route_scoped_acceptance"] is False
    assert report["summary"]["route_summary"] is None
    assert set(_gaps(report).values()) == {"not evaluated"}
    assert "Route-scoped acceptance: FAIL (not evaluated)" in gate.render_text(report)


def test_route_scoped_acceptance_passes_without_system_completeness(evidence, routes):
    report = gate.developer_report(evidence, routes)
    assert report["acceptance_passed"]
    assert not report["complete"]
    assert report["regression_checks_passed"]
    assert report["route_acceptance"] is routes
    assert report["summary"]["route_scoped_acceptance"] is True
    assert report["summary"]["route_summary"] == routes["summary"]
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)
    assert set(_gaps(report).values()) == {"discharged on every supported route"}
    assert report["summary"]["verifier_tasks"] == 3
    text = gate.render_text(report)
    assert "Acceptance: PASS. System completeness: NOT ESTABLISHED." in text
    assert "Route-scoped acceptance: PASS (claim: route-scoped" in text
    assert "does not establish whole-system completeness" in text


def test_implementation_task_blocks_route_scoped_acceptance(evidence, routes):
    evidence["escape_discovery"]["unwaived_findings"] = [
        {
            "message": "Unmediated node",
            "path": "prebuilt/node.py",
            "line": 7,
            "fingerprint": "exact-site",
        }
    ]
    report = gate.developer_report(evidence, routes)
    assert not report["acceptance_passed"]
    assert not report["regression_checks_passed"]
    assert report["summary"]["route_scoped_acceptance"] is True
    assert set(_gaps(report).values()) == {"discharged on every supported route"}


def test_verifier_task_blocks_route_scoped_acceptance(evidence, routes):
    evidence["placement"]["issues"] = ["missing source"]
    report = gate.developer_report(evidence, routes)
    assert not report["acceptance_passed"]
    assert any(task["rule"] == "SGV190" for task in report["tasks"])


def test_open_route_obligations_block_acceptance_and_are_named(evidence):
    routes = _routes(
        _route("route-a", failing=("SGV902",)),
        _route("route-b"),
        _route("route-c", failing=("SGV902", "SGV903")),
        _route("route-d", failing=OBLIGATIONS, status="unsupported"),
    )
    assert not routes["complete"]
    report = gate.developer_report(evidence, routes)
    assert not report["acceptance_passed"]
    assert report["summary"]["route_scoped_acceptance"] is False
    assert _gaps(report) == {
        "SGV901": "discharged on every supported route",
        "SGV902": "open on route-a, route-c",
        "SGV903": "open on route-c",
    }
    text = gate.render_text(report)
    assert "Route-scoped acceptance: FAIL (claim:" in text
    assert "  route-a: SGV901 ok, SGV902 FAIL(sgv902-check), SGV903 ok" in text
    assert "  route-b: SGV901 ok, SGV902 ok, SGV903 ok" in text
    assert (
        "  route-c: SGV901 ok, SGV902 FAIL(sgv902-check), SGV903 FAIL(sgv903-check)"
        in text
    )
    assert "route-d:" not in text
    assert "Route scope: open on route-a, route-c" in text


def test_forged_route_complete_flag_still_needs_every_supported_route(evidence):
    routes = _routes(_route("route-a", failing=("SGV901",)), complete=True)
    report = gate.developer_report(evidence, routes)
    # The flag is trusted only from a fresh verify_routes run; the annotation
    # still reports the open route so a forged flag is visible in the report.
    assert _gaps(report)["SGV901"] == "open on route-a"
    assert report["acceptance_passed"]
    routes["complete"] = "yes"
    assert not gate.developer_report(evidence, routes)["acceptance_passed"]


def test_manifest_without_supported_routes_is_not_evaluated(evidence):
    routes = _routes(
        _route("route-d", status="unsupported"),
        manifest_ok=False,
        complete=False,
        issues=["unsupported manifest schema_version: 1 (expected 2)"],
    )
    report = gate.developer_report(evidence, routes)
    assert not report["acceptance_passed"]
    for scope in _gaps(report).values():
        assert scope.startswith("not evaluated")
    assert "Issue: unsupported manifest schema_version" in gate.render_text(report)


def test_render_text_lists_route_gating_problems(evidence):
    routes = _routes(
        _route(),
        complete=False,
        ungated_exclusions=[{"route": ROUTE, "feature": "subprocess"}, "raw-entry"],
        unregistered_gates=[{"route": ROUTE, "gate_code": "SGV-UNKNOWN"}],
        issues=["manifest overclaims proof for lean-audit:x"],
        lean_audit_run=False,
        evidence_dir=None,
    )
    report = gate.developer_report(evidence, routes)
    assert not report["acceptance_passed"]
    text = gate.render_text(report)
    assert f"Ungated exclusion: {ROUTE}: subprocess" in text
    assert "Ungated exclusion: raw-entry" in text
    assert f"Unregistered gate: {ROUTE}: SGV-UNKNOWN" in text
    assert "Issue: manifest overclaims proof for lean-audit:x" in text
    assert "Lean audit skipped; evidence dir: None" in text
    assert f"  {ROUTE}: SGV901 ok, SGV902 ok, SGV903 ok" in text


def test_primitive_contracts_are_reported_without_promoting_composition(evidence):
    evidence["output_data_primitives"] = {
        "primitive_contracts_complete": True,
        "validator_admission_proved": False,
    }
    report = gate.developer_report(evidence)
    assert report["summary"]["output_data_primitive_contracts_complete"]
    assert not report["acceptance_passed"]
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)


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


def test_route_scope_does_not_change_gap_fingerprints(evidence, routes):
    without = gate.developer_report(evidence)
    with_routes = gate.developer_report(evidence, routes)
    assert [item["fingerprint"] for item in without["proof_gaps"]] == [
        item["fingerprint"] for item in with_routes["proof_gaps"]
    ]


def _patch_cli(monkeypatch, evidence, routes, calls=None):
    monkeypatch.setattr(gate, "verify_layers", lambda repo: evidence)

    def fake_routes(repo, *, run_lean_audit, evidence_dir):
        if calls is not None:
            calls.append(
                {"repo": repo, "run_lean_audit": run_lean_audit, "dir": evidence_dir}
            )
        return routes

    monkeypatch.setattr(gate, "verify_routes", fake_routes)


@pytest.mark.parametrize("strict,expected", [(False, 0), (True, 1)])
def test_cli_default_gate_is_route_scoped_and_strict_gate_is_system_wide(
    monkeypatch, tmp_path, evidence, routes, strict, expected
):
    calls: list[dict[str, Any]] = []
    _patch_cli(monkeypatch, evidence, routes, calls)
    output = tmp_path / "report.json"
    args = ["--output", str(output)] + (["--require-complete"] if strict else [])
    assert gate.main(args) == expected
    report = json.loads(output.read_text())
    assert report["complete"] is False
    assert report["acceptance_passed"] is True
    assert report["route_acceptance"]["complete"] is True
    [call] = calls
    assert call["run_lean_audit"] is True
    assert call["dir"] is not None and Path(call["dir"]).is_dir()


@pytest.mark.parametrize("strict,expected", [(False, 1), (True, 1)])
def test_cli_incomplete_routes_fail_both_gates(
    monkeypatch, tmp_path, evidence, strict, expected
):
    _patch_cli(monkeypatch, evidence, _routes(_route(failing=("SGV903",))))
    output = tmp_path / "report.json"
    args = ["--output", str(output)] + (["--require-complete"] if strict else [])
    assert gate.main(args) == expected
    report = json.loads(output.read_text())
    assert report["complete"] is False
    assert report["acceptance_passed"] is False


def test_cli_passes_lean_audit_flags_to_route_verification(
    monkeypatch, tmp_path, evidence, routes
):
    calls: list[dict[str, Any]] = []
    _patch_cli(monkeypatch, evidence, routes, calls)
    evidence_dir = tmp_path / "evidence"
    assert gate.main(["--no-lean-audit", "--evidence-dir", str(evidence_dir)]) == 0
    assert gate.main(["--evidence-dir", str(evidence_dir)]) == 0
    assert gate.main(["--no-lean-audit"]) == 0
    assert [call["run_lean_audit"] for call in calls] == [False, True, False]
    assert calls[0]["dir"] == evidence_dir
    assert calls[1]["dir"] == evidence_dir
    assert calls[2]["dir"] is None
    assert all(call["repo"].is_absolute() for call in calls)


def test_regression_clean_mode_does_not_claim_completeness(
    monkeypatch, tmp_path, evidence
):
    _patch_cli(monkeypatch, evidence, _routes(_route(failing=("SGV902",))))
    output = tmp_path / "report.json"
    assert gate.main(["--require-regression-clean", "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["regression_checks_passed"]
    assert not report["acceptance_passed"]
    assert not report["complete"]
    evidence["placement"]["issues"] = ["missing source"]
    assert gate.main(["--require-regression-clean"]) == 1


def test_forged_top_level_success_cannot_hide_missing_proofs(evidence, routes):
    evidence["complete"] = True
    report = gate.developer_report(evidence)
    assert not report["acceptance_passed"]
    assert not report["complete"]
    report = gate.developer_report(evidence, routes)
    assert report["acceptance_passed"]
    assert not report["complete"]


def test_schema_one_comparison_does_not_preserve_old_acceptance(evidence):
    old = gate.developer_report(evidence)
    old["schema_version"] = 1
    old["acceptance_passed"] = True
    current = gate.developer_report(evidence)
    assert not gate.compare_reports(current, old)["new"]
    assert not current["acceptance_passed"]


def test_cli_invalid_comparison_is_error_not_success(
    monkeypatch, tmp_path, evidence, routes
):
    _patch_cli(monkeypatch, evidence, routes)
    path = tmp_path / "bad.json"
    path.write_text("not json")
    assert gate.main(["--compare", str(path)]) == 2


def test_cli_lists_checks_without_loading_application(monkeypatch, capsys):
    def unexpected(*args, **kwargs):
        raise AssertionError("not a source-analysis run")

    monkeypatch.setattr(gate, "verify_layers", unexpected)
    monkeypatch.setattr(gate, "verify_routes", unexpected)
    assert gate.main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    assert "SGV101" in out
    assert "SGV901–903: Verifier-owned proof gaps" in out


def test_failed_router_always_blocks_acceptance(evidence, routes):
    evidence["router"]["complete"] = False
    report = gate.developer_report(evidence)
    assert not report["acceptance_passed"]
    assert any(task["rule"] == "SGV201" for task in report["tasks"])
    # Even a (forged or stale) complete route report cannot outvote the task;
    # a fresh run also fails `router-source-proof` on every route that needs it.
    report = gate.developer_report(evidence, routes)
    assert not report["acceptance_passed"]
    assert any(task["rule"] == "SGV201" for task in report["tasks"])


def test_admission_surface_evidence_never_closes_sgv901_to_903(evidence, routes):
    evidence["admission_surface"] = {"proved": True, "sgv901_closed": False}
    report = gate.developer_report(evidence)
    assert report["summary"]["admission_surface_proved"]
    assert not report["acceptance_passed"]
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)
    report = gate.developer_report(evidence, routes)
    assert report["acceptance_passed"]
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)
    del evidence["admission_surface"]
    assert not gate.developer_report(evidence)["summary"]["admission_surface_proved"]


def test_real_evidence_reports_admission_surface_and_still_fails_the_gate():
    repo = Path(__file__).resolve().parents[4]
    report = gate.developer_report(verify_layers(repo))
    assert report["summary"]["admission_surface_proved"]
    assert report["evidence"]["admission_surface"]["sgv901_closed"] is False
    assert not report["acceptance_passed"]
    assert not report["complete"]
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)


def test_cli_real_tree_without_lean_audit_matches_route_result(tmp_path, capsys):
    repo = Path(__file__).resolve().parents[4]
    output = tmp_path / "report.json"
    code = gate.main(["--repo", str(repo), "--no-lean-audit", "--output", str(output)])
    report = json.loads(output.read_text())
    routes = report["route_acceptance"]
    assert routes["kind"] == "route-scoped-acceptance"
    assert routes["lean_audit_run"] is False
    assert routes["system_complete"] is False
    # Exit status and acceptance follow the recomputed route result exactly;
    # whole-system completeness stays false either way.
    assert report["acceptance_passed"] is (routes["complete"] and not report["tasks"])
    assert code == (0 if report["acceptance_passed"] else 1)
    assert report["complete"] is False
    assert {item["rule"] for item in report["proof_gaps"]} == set(OBLIGATIONS)
    assert all("route_scope" in item for item in report["proof_gaps"])
    out = capsys.readouterr().out
    verdict = "PASS" if report["acceptance_passed"] else "FAIL"
    assert f"Route-scoped acceptance: {verdict} (claim:" in out
    assert "Lean audit skipped" in out
    assert "NOT ESTABLISHED" in out
