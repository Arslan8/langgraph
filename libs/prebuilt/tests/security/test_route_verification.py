from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

from langgraph.prebuilt.security import route_verification as route

SECURITY = route._SECURITY
SOURCES = (
    "object_manager.py",
    "objects.py",
    "output_data.py",
    "placement.py",
    "host_router.py",
    "admission.py",
    "config.py",
    "mac.py",
    "linux.py",
    "_linux_worker.py",
)
MEDIATOR = "langgraph.prebuilt.security.output_mediator_verification"
ADMISSION = "langgraph.prebuilt.security.admission_verification"
EVIDENCE = "eval/evidence.json"
LEAN = "proofs/model"
SUPPORTED_CHECKS = {
    "SGV901": ["router-source-proof", "gate:adapter_rule_unsupported"],
    "SGV902": [
        "host-output-correspondence",
        "output-validator-contract",
        "output-mediator-correspondence",
        "admission-surface",
    ],
    "SGV903": [
        "host-route:linux-sandbox",
        f"lean-audit:{LEAN}",
        f"runtime-evidence:{EVIDENCE}",
    ],
}
ALL_CHECKS = [check for checks in SUPPORTED_CHECKS.values() for check in checks]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _obligations(checks: dict[str, list[str]]) -> dict:
    return {
        key: {"applicable": True, "required_evidence": list(ids), "reason": "r"}
        for key, ids in checks.items()
    }


def _route(route_id: str, status: str, checks: dict[str, list[str]], **extra) -> dict:
    return {
        "id": route_id,
        "status": status,
        "entry_points": [],
        "enforcement_points": [],
        "obligations": _obligations(checks),
        "exclusions": [
            {"feature": "exact", "gate_code": "host:unsupported_rule"},
            {
                "feature": "prefixed",
                "gate_code": "adapter_rule_unsupported",
                "gate_code_prefix": True,
            },
        ],
        "premises": [],
        **extra,
    }


def _manifest(repo: Path, routes: list[dict], **extra) -> None:
    manifest = {
        "schema_version": 2,
        "kind": "slanggraph-supported-surface",
        "check_ids": {},
        "routes": routes,
        "ungated_exclusions": [],
        "applications": [],
        "unsupported_capabilities": [],
        **extra,
    }
    path = repo / route.MANIFEST
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest))


def _default_routes() -> list[dict]:
    return [
        _route("supported-route", "supported", SUPPORTED_CHECKS),
        _route(
            "unsupported-route",
            "unsupported",
            {
                "SGV901": ["gate:not_registered_anywhere"],
                "SGV902": ["runtime-evidence:eval/missing.json"],
                "SGV903": [],
            },
        ),
    ]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for name in SOURCES:
        path = repo / SECURITY / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {name}\n")
    lean = repo / LEAN
    lean.mkdir(parents=True)
    (lean / "check.py").write_text("raise SystemExit(3)\n")
    (lean / "Model.lean").write_text("theorem t : True := trivial\n")
    evidence = repo / EVIDENCE
    evidence.parent.mkdir(parents=True)
    evidence.write_text(
        json.dumps(
            {
                "passed": True,
                "failures": [],
                "issues": [],
                "source_sha256": {
                    SECURITY + "objects.py": _sha(repo / SECURITY / "objects.py")
                },
            }
        )
    )
    _manifest(repo, _default_routes())
    return repo


def _fake_module(name: str, **attributes) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    return module


def _fake_lean_audit(check_py: Path, output: Path, lake: Path) -> dict:
    output.mkdir(parents=True)
    identities = {
        path.name: {"sha256": _sha(path), "bytes": path.stat().st_size}
        for path in [*sorted(check_py.parent.glob("*.lean")), check_py]
    }
    return {
        "passed": True,
        "kernel_replay_checked": True,
        "kernel_typecheck_passed": True,
        "model_proved": True,
        "system_complete": False,
        "source_after": identities,
    }


@pytest.fixture
def passing(monkeypatch, repo: Path) -> dict:
    """Make every component report success; returns the kwargs for a run."""
    monkeypatch.setattr(
        route,
        "verify_host_router",
        lambda: {
            "complete": True,
            "summary": {"verified": 3, "discovered": 3},
            "runtime_binding": {
                "source_sha256": _sha(repo / SECURITY / "host_router.py")
            },
        },
    )
    monkeypatch.setattr(
        route, "verify_output_correspondence", lambda *a, **k: {"proved": True}
    )
    monkeypatch.setattr(
        route,
        "verify_output_data_primitives",
        lambda *a: {
            "proved": True,
            "validator_admission_proved": True,
            "effect_safety_proved": True,
        },
    )
    monkeypatch.setattr(
        route,
        "verify_linux_host_route",
        lambda *a, **k: {"structural_checks": {"one": True, "two": True}},
    )
    monkeypatch.setitem(
        sys.modules,
        MEDIATOR,
        _fake_module(
            MEDIATOR,
            verify_output_mediator_correspondence=lambda *a, **k: {"proved": True},
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        ADMISSION,
        _fake_module(
            ADMISSION,
            verify_admission_surface=lambda *a: {"proved": {"a": True, "b": True}},
        ),
    )
    monkeypatch.setattr(route, "_execute_lean_audit", _fake_lean_audit)
    lake = repo.parent / "lake"
    lake.write_text("#!/bin/sh\n")
    return {
        "run_lean_audit": True,
        "evidence_dir": repo.parent / "evidence",
        "lake": lake,
    }


def _fail_check(monkeypatch, repo: Path, check_id: str) -> None:
    """Flip exactly one component so that `check_id` fails."""
    if check_id == "router-source-proof":
        monkeypatch.setattr(
            route,
            "verify_host_router",
            lambda: {
                "complete": True,
                "summary": {"verified": 2, "discovered": 3},
                "runtime_binding": {
                    "source_sha256": _sha(repo / SECURITY / "host_router.py")
                },
            },
        )
    elif check_id == "gate:adapter_rule_unsupported":
        monkeypatch.setattr(route.unsupported, "PREFIXES", types.MappingProxyType({}))
    elif check_id == "host-output-correspondence":
        monkeypatch.setattr(
            route, "verify_output_correspondence", lambda *a, **k: {"proved": False}
        )
    elif check_id == "output-validator-contract":
        monkeypatch.setattr(
            route,
            "verify_output_data_primitives",
            lambda *a: {
                "proved": True,
                "validator_admission_proved": True,
                "effect_safety_proved": False,
            },
        )
    elif check_id == "output-mediator-correspondence":
        monkeypatch.setitem(
            sys.modules,
            MEDIATOR,
            _fake_module(
                MEDIATOR,
                verify_output_mediator_correspondence=lambda *a, **k: {"proved": False},
            ),
        )
    elif check_id == "admission-surface":
        monkeypatch.setitem(
            sys.modules,
            ADMISSION,
            _fake_module(
                ADMISSION,
                verify_admission_surface=lambda *a: {"proved": {"a": True, "b": False}},
            ),
        )
    elif check_id == "host-route:linux-sandbox":
        monkeypatch.setattr(
            route,
            "verify_linux_host_route",
            lambda *a, **k: {"structural_checks": {"one": True, "two": False}},
        )
    elif check_id.startswith("lean-audit:"):

        def stale(check_py: Path, output: Path, lake: Path) -> dict:
            report = _fake_lean_audit(check_py, output, lake)
            report["kernel_replay_checked"] = False
            return report

        monkeypatch.setattr(route, "_execute_lean_audit", stale)
    elif check_id.startswith("runtime-evidence:"):
        path = repo / check_id.partition(":")[2]
        path.write_text(json.dumps({"passed": False}))
    else:
        raise AssertionError(check_id)


def test_all_checks_pass_gives_route_scoped_acceptance(repo, passing):
    report = route.verify_routes(repo, **passing)
    assert report["kind"] == "route-scoped-acceptance"
    assert report["schema_version"] == 1
    assert report["complete"] is True
    assert report["system_complete"] is False
    assert "not whole-system completeness" in report["claim"]
    assert report["manifest_sha256"] == _sha(repo / route.MANIFEST)
    assert report["checker_sha256"] == _sha(Path(route.__file__))
    assert not report["issues"]
    assert not report["ungated_exclusions"]
    assert not report["unregistered_gates"]
    supported = next(r for r in report["routes"] if r["id"] == "supported-route")
    assert supported["accepted"] is True
    for key, ids in SUPPORTED_CHECKS.items():
        obligation = supported["obligations"][key]
        assert obligation["discharged"] is True
        assert [check["id"] for check in obligation["checks"]] == ids
        assert all(check["passed"] for check in obligation["checks"])
    checks = report["checks"]
    proofs = {
        "router-source-proof": True,
        "host-output-correspondence": True,
        "output-validator-contract": True,
        "output-mediator-correspondence": True,
        "admission-surface": True,
        "host-route:linux-sandbox": False,
        f"lean-audit:{LEAN}": True,
        f"runtime-evidence:{EVIDENCE}": False,
        "gate:adapter_rule_unsupported": False,
    }
    for check_id, proof in proofs.items():
        assert checks[check_id]["proof"] is proof, check_id
    assert "finite model only" in checks[f"lean-audit:{LEAN}"]["detail"]
    assert "runtime evidence" in checks[f"runtime-evidence:{EVIDENCE}"]["detail"]
    assert checks[f"runtime-evidence:{EVIDENCE}"]["recomputed"] is False
    assert (
        "1 recorded source identities"
        in checks[f"runtime-evidence:{EVIDENCE}"]["detail"]
    )
    assert (passing["evidence_dir"] / "lean-audit" / "proofs__model").is_dir()


def test_unsupported_route_failures_do_not_block(repo, passing):
    report = route.verify_routes(repo, **passing)
    unsupported = next(r for r in report["routes"] if r["id"] == "unsupported-route")
    assert unsupported["accepted"] is False
    assert not unsupported["obligations"]["SGV901"]["discharged"]
    assert not unsupported["obligations"]["SGV902"]["discharged"]
    assert "gate:not_registered_anywhere" in report["summary"]["failing_checks"]
    assert report["complete"] is True
    assert report["summary"]["accepted_routes"] == 1


@pytest.mark.parametrize("check_id", ALL_CHECKS)
def test_any_single_failing_check_blocks(repo, passing, monkeypatch, check_id):
    _fail_check(monkeypatch, repo, check_id)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert report["checks"][check_id]["passed"] is False
    assert report["checks"][check_id]["proof"] is False
    assert check_id in report["summary"]["failing_checks"]
    supported = next(r for r in report["routes"] if r["id"] == "supported-route")
    assert supported["accepted"] is False
    blocked = [key for key, ids in SUPPORTED_CHECKS.items() if check_id in ids]
    for key in SUPPORTED_CHECKS:
        assert supported["obligations"][key]["discharged"] is (key not in blocked)


def test_ungated_exclusion_blocks(repo, passing):
    routes = _default_routes()
    routes[0]["exclusions"].append({"feature": "open", "gate_code": None})
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert [entry["feature"] for entry in report["ungated_exclusions"]] == ["open"]
    assert report["routes"][0]["accepted"] is False


def test_manifest_level_ungated_exclusions_block(repo, passing):
    _manifest(
        repo,
        _default_routes(),
        ungated_exclusions=[{"route": "unsupported-route", "feature": "raw api"}],
    )
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert report["ungated_exclusions"][0]["feature"] == "raw api"


@pytest.mark.parametrize(
    "exclusion",
    [
        {"feature": "unknown", "gate_code": "never:registered"},
        {"feature": "prefix-without-flag", "gate_code": "adapter_rule_unsupported"},
        {"feature": "exact-as-prefix", "gate_code": "nope", "gate_code_prefix": True},
    ],
)
def test_unregistered_gate_code_blocks(repo, passing, exclusion):
    routes = _default_routes()
    routes[0]["exclusions"].append(exclusion)
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert not report["ungated_exclusions"]
    assert [entry["gate_code"] for entry in report["unregistered_gates"]] == [
        exclusion["gate_code"]
    ]


def test_unregistered_gate_on_unsupported_route_does_not_block(repo, passing):
    routes = _default_routes()
    routes[1]["exclusions"].append({"feature": "x", "gate_code": None})
    routes[1]["exclusions"].append({"feature": "y", "gate_code": "never:registered"})
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is True


def test_unknown_check_id_blocks(repo, passing):
    routes = _default_routes()
    routes[0]["obligations"]["SGV901"]["required_evidence"].append(
        "publication-entries:X"
    )
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert report["unknown_check_ids"] == ["publication-entries:X"]
    assert any("unknown check ids" in issue for issue in report["issues"])
    assert report["checks"]["publication-entries:X"]["passed"] is False


def test_unknown_check_id_on_unsupported_route_still_blocks(repo, passing):
    routes = _default_routes()
    routes[1]["obligations"]["SGV903"]["required_evidence"].append("mystery")
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert report["unknown_check_ids"] == ["mystery"]


def test_skipped_lean_audit_never_passes(repo, passing):
    report = route.verify_routes(repo, **{**passing, "run_lean_audit": False})
    assert report["complete"] is False
    check = report["checks"][f"lean-audit:{LEAN}"]
    assert check["passed"] is False
    assert check["recomputed"] is False
    assert check["detail"] == "lean audit not run"
    assert not (passing["evidence_dir"]).exists()


def test_lean_audit_requires_matching_source_identities(repo, passing, monkeypatch):
    def drifted(check_py: Path, output: Path, lake: Path) -> dict:
        report = _fake_lean_audit(check_py, output, lake)
        report["source_after"]["Model.lean"]["sha256"] = "0" * 64
        return report

    monkeypatch.setattr(route, "_execute_lean_audit", drifted)
    report = route.verify_routes(repo, **passing)
    check = report["checks"][f"lean-audit:{LEAN}"]
    assert check["passed"] is False
    assert "identity mismatch Model.lean" in check["detail"]
    assert report["complete"] is False


def test_lean_audit_refuses_existing_evidence_directory(repo, passing):
    (passing["evidence_dir"] / "lean-audit" / "proofs__model").mkdir(parents=True)
    report = route.verify_routes(repo, **passing)
    check = report["checks"][f"lean-audit:{LEAN}"]
    assert check["passed"] is False
    assert "refusing existing evidence directory" in check["detail"]


def test_lean_audit_requires_evidence_dir_and_lake(repo, passing, tmp_path):
    report = route.verify_routes(repo, **{**passing, "evidence_dir": None})
    assert "needs an evidence_dir" in report["checks"][f"lean-audit:{LEAN}"]["detail"]
    report = route.verify_routes(repo, **{**passing, "lake": tmp_path / "no-lake"})
    assert "lake executable missing" in report["checks"][f"lean-audit:{LEAN}"]["detail"]


@pytest.mark.parametrize(
    "record, fragment",
    [
        ({"ok": True, "source_sha256": {SECURITY + "objects.py": "0" * 64}}, "changed"),
        ({"system_complete": True}, "no pass field"),
        ({"passed": True, "failures": ["one"]}, "1 recorded failures"),
        ({"passed": True}, "no recorded source identities match"),
        (
            {"passed": True, "source_sha256": {"missing.py": "0" * 64}},
            "no recorded source identities match",
        ),
        ({"passed": "yes"}, "passed is not true"),
        ("not json", "unparsable"),
        ([1, 2], "not an object"),
    ],
)
def test_runtime_evidence_fails_closed(repo, passing, record, fragment):
    path = repo / EVIDENCE
    path.write_text(record if isinstance(record, str) else json.dumps(record))
    report = route.verify_routes(repo, **passing)
    check = report["checks"][f"runtime-evidence:{EVIDENCE}"]
    assert check["passed"] is False
    assert fragment in check["detail"]
    assert report["complete"] is False


def test_manifest_paths_cannot_escape_repository(repo, passing, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"passed": True}))
    routes = _default_routes()
    routes[0]["obligations"]["SGV903"]["required_evidence"] = [
        "runtime-evidence:../outside.json",
        f"lean-audit:{tmp_path}",
    ]
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    for check_id in routes[0]["obligations"]["SGV903"]["required_evidence"]:
        assert "escapes repository" in report["checks"][check_id]["detail"]


@pytest.mark.parametrize("module", [MEDIATOR, ADMISSION])
def test_missing_component_module_fails_that_check(repo, passing, monkeypatch, module):
    monkeypatch.setitem(sys.modules, module, None)
    report = route.verify_routes(repo, **passing)
    check_id = (
        "output-mediator-correspondence" if module == MEDIATOR else "admission-surface"
    )
    check = report["checks"][check_id]
    assert check["passed"] is False
    assert check["recomputed"] is False
    assert check["detail"].startswith("component missing")
    assert report["complete"] is False


def test_component_without_function_is_missing(repo, passing, monkeypatch):
    monkeypatch.setitem(sys.modules, ADMISSION, _fake_module(ADMISSION))
    report = route.verify_routes(repo, **passing)
    assert report["checks"]["admission-surface"]["detail"].startswith(
        "component missing"
    )


@pytest.mark.parametrize(
    "report, passed",
    [
        ({"proved": True, "obligations": {"a": {"proved": True}}}, True),
        ({"proved": True, "obligations": {"a": {"proved": True}, "b": {}}}, False),
        ({"proved": False, "obligations": {"a": {"proved": True}}}, False),
        ({"proved": True}, False),
        ({"proved": {}}, False),
        ({"proved": None}, False),
        ("text", False),
    ],
)
def test_admission_report_shape_is_inspected(
    repo, passing, monkeypatch, report, passed
):
    monkeypatch.setitem(
        sys.modules,
        ADMISSION,
        _fake_module(ADMISSION, verify_admission_surface=lambda *a: report),
    )
    result = route.verify_routes(repo, **passing)
    assert result["checks"]["admission-surface"]["passed"] is passed
    assert result["complete"] is passed


def test_component_exception_fails_closed(repo, passing, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("component crashed")

    monkeypatch.setattr(route, "verify_output_correspondence", boom)
    report = route.verify_routes(repo, **passing)
    check = report["checks"]["host-output-correspondence"]
    assert check["passed"] is False
    assert "RuntimeError" in check["detail"]
    assert report["complete"] is False


def test_saved_reports_are_never_read(repo, passing, monkeypatch):
    saved = {
        "complete": True,
        "proved": True,
        "passed": True,
        "kernel_replay_checked": True,
        "kernel_typecheck_passed": True,
    }
    for name in (
        "docs/security/route-verification-report.json",
        "docs/security/layered-verification-report.json",
        "docs/security/developer-verification-report.json",
        "docs/security/host-router-certificate.json",
        f"{LEAN}/report.json",
    ):
        (repo / name).write_text(json.dumps(saved))
    read: list[Path] = []
    real_text, real_bytes = Path.read_text, Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **k: (read.append(self), real_text(self, *a, **k))[1],
    )
    monkeypatch.setattr(
        Path, "read_bytes", lambda self: (read.append(self), real_bytes(self))[1]
    )
    # With every component failing, saved passing reports cannot rescue the gate.
    for check_id in ALL_CHECKS:
        _fail_check(monkeypatch, repo, check_id)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert all(not check["passed"] for check in report["checks"].values())
    json_reads = {
        path.resolve().relative_to(repo.resolve()).as_posix()
        for path in read
        if path.suffix == ".json" and repo.resolve() in path.resolve().parents
    }
    assert json_reads == {route.MANIFEST, EVIDENCE}


@pytest.mark.parametrize("version", [1, 3, "2", None])
def test_other_manifest_schema_versions_fail_closed(repo, passing, version):
    manifest = json.loads((repo / route.MANIFEST).read_text())
    manifest["schema_version"] = version
    (repo / route.MANIFEST).write_text(json.dumps(manifest))
    report = route.verify_routes(repo, **passing)
    assert report["manifest_ok"] is False
    assert report["complete"] is False
    assert report["routes"] == []
    assert any("schema_version" in issue for issue in report["issues"])


def test_missing_manifest_fails_closed(repo, passing):
    (repo / route.MANIFEST).unlink()
    report = route.verify_routes(repo, **passing)
    assert report["manifest_ok"] is False
    assert report["complete"] is False
    assert report["manifest_sha256"] is None


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda r: r[0]["obligations"].pop("SGV902"), "not declared"),
        (lambda r: r[0]["obligations"]["SGV901"].update(applicable="yes"), "not bool"),
        (lambda r: r[0]["obligations"]["SGV901"].update(reason=""), "no reason"),
        (lambda r: r[0]["obligations"]["SGV901"].update(required_evidence=[]), ""),
        (lambda r: r[0].update(status="partial"), "unknown status"),
        (lambda r: r.pop(0), "no supported route"),
        (lambda r: r.append(dict(r[0])), "duplicate route ids"),
    ],
)
def test_malformed_supported_route_blocks(repo, passing, mutate, fragment):
    routes = _default_routes()
    mutate(routes)
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert any(fragment in issue for issue in report["issues"]) or fragment == ""


def test_not_applicable_obligation_needs_no_evidence(repo, passing):
    routes = _default_routes()
    routes[0]["obligations"]["SGV903"] = {
        "applicable": False,
        "required_evidence": [],
        "reason": "trusted runtime",
    }
    _manifest(repo, routes)
    report = route.verify_routes(repo, **passing)
    obligation = report["routes"][0]["obligations"]["SGV903"]
    assert obligation["discharged"] is True
    assert obligation["applicable"] is False
    assert report["complete"] is True


def test_manifest_proof_overclaim_is_an_issue(repo, passing):
    _manifest(
        repo,
        _default_routes(),
        check_ids={"host-route:linux-sandbox": {"proof": True}},
    )
    report = route.verify_routes(repo, **passing)
    assert report["complete"] is False
    assert any("overclaims proof" in issue for issue in report["issues"])


def test_result_never_records_proof_without_a_recomputed_pass():
    failed = route._result("x", passed=False, proof=True, recomputed=True, detail="d")
    assert failed["proof"] is False
    stale = route._result("x", passed=True, proof=True, recomputed=False, detail="d")
    assert stale["proof"] is False


def test_cli_exit_codes(repo, passing, tmp_path, capsys):
    output = tmp_path / "report.json"
    argv = [
        "--repo",
        str(repo),
        "--output",
        str(output),
        "--lake",
        str(passing["lake"]),
    ]
    assert route._main([*argv, "--evidence-dir", str(tmp_path / "ev1")]) == 0
    assert json.loads(output.read_text())["complete"] is True
    assert "COMPLETE" in capsys.readouterr().out
    assert route._main([*argv, "--no-lean-audit"]) == 1
    text = capsys.readouterr().out
    assert "NOT COMPLETE" in text
    assert f"FAIL lean-audit:{LEAN}: lean audit not run" in text
    manifest = json.loads((repo / route.MANIFEST).read_text())
    manifest["schema_version"] = 1
    (repo / route.MANIFEST).write_text(json.dumps(manifest))
    assert route._main([*argv, "--no-lean-audit"]) == 2
    assert route._main(["--repo", str(tmp_path / "missing"), "--no-lean-audit"]) == 2


def test_real_tree_smoke_without_lean_audit():
    repo = Path(__file__).resolve().parents[4]
    report = route.verify_routes(repo, run_lean_audit=False)
    assert report["kind"] == "route-scoped-acceptance"
    assert report["schema_version"] == 1
    assert report["system_complete"] is False
    supported = [item for item in report["routes"] if item["status"] == "supported"]
    # The live outcome may pass or fail; it must equal the per-route result, and
    # no accepted route may rest on the skipped Lean audit.
    assert report["complete"] is bool(
        supported
        and all(item["accepted"] for item in supported)
        and not report["issues"]
    )
    for item in supported:
        if item["accepted"]:
            for obligation in item["obligations"].values():
                assert not any(
                    check.startswith("lean-audit:")
                    for check in obligation.get("required_evidence", [])
                )
    assert report["checker_sha256"] == _sha(Path(route.__file__))
    for key in (
        "manifest_sha256",
        "claim",
        "routes",
        "checks",
        "ungated_exclusions",
        "unregistered_gates",
        "issues",
        "summary",
    ):
        assert key in report
    if report["manifest_ok"]:
        # A current-schema manifest is evaluated; the skipped lean audit and
        # any unresolved evidence keep the gate closed.
        assert report["routes"]
        assert all(
            not check["passed"]
            for check_id, check in report["checks"].items()
            if check_id.startswith("lean-audit:")
        )
    else:
        assert report["routes"] == []
