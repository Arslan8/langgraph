"""Tests for the pandas runtime operation catalog."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from langgraph.prebuilt.security.operation_catalog import (
    load_catalog,
    verify_catalog,
)

REPO = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="module")
def catalog() -> dict[str, Any]:
    return load_catalog(REPO)


def _op(catalog: dict[str, Any], oid: str) -> dict[str, Any]:
    return next(op for op in catalog["operations"] if op["id"] == oid)


def test_catalog_loads(catalog: dict[str, Any]) -> None:
    ids = {op["id"] for op in catalog["operations"]}
    assert ids == {
        "compute",
        "output_publish",
        "model_invoke",
        "tool_dispatch",
        "state_read",
        "state_write",
        "checkpoint",
        "approval_resume",
        "dataset_read",
    }
    assert catalog["route_operations"]["linux-worker-compute"] == ["compute"]


def test_current_repo_verifies(catalog: dict[str, Any]) -> None:
    report = verify_catalog(REPO, catalog)
    assert report["issues"] == []
    assert report["gate_wired"] is False
    unfinished = [
        oid
        for oid, entry in report["operations"].items()
        if entry["status"] != "implemented" or entry["proof"] == "missing"
    ]
    assert set(unfinished) <= {"dataset_read"}
    assert report["complete"] is (not unfinished and not report["pending"])


def test_unknown_router_method_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "output_publish")["router_methods"].append("publish_anything")
    report = verify_catalog(REPO, mutated)
    assert not report["complete"]
    assert any("publish_anything" in issue for issue in report["issues"])


def test_unknown_function_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "compute")["functions"].append(
        "security/linux.py::LinuxSandboxExecutor.run_anything"
    )
    report = verify_catalog(REPO, mutated)
    assert any("run_anything" in issue for issue in report["issues"])


def test_unknown_request_class_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "state_read")["request_classes"].append("GenericRequest")
    report = verify_catalog(REPO, mutated)
    assert any("GenericRequest" in issue for issue in report["issues"])


def test_unregistered_refusal_code_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "compute")["refusals"].append(
        {"code": "compute:not_a_registered_code", "kind": "registered"}
    )
    report = verify_catalog(REPO, mutated)
    assert not report["complete"]
    assert any("compute:not_a_registered_code" in i for i in report["issues"])


def test_missing_literal_refusal_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "output_publish")["refusals"].append(
        {
            "code": "output:not_raised",
            "kind": "literal",
            "source": "security/object_manager.py",
        }
    )
    report = verify_catalog(REPO, mutated)
    assert any("output:not_raised" in issue for issue in report["issues"])


def test_supported_route_with_uncatalogued_operation_fails(
    catalog: dict[str, Any],
) -> None:
    mutated = copy.deepcopy(catalog)
    mutated["route_operations"]["output-publication"].append("generic_effect")
    report = verify_catalog(REPO, mutated)
    assert not report["complete"]
    assert any("generic_effect" in issue for issue in report["issues"])


def test_supported_route_unmapped_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    del mutated["route_operations"]["model-invoke-hook"]
    report = verify_catalog(REPO, mutated)
    assert any("model-invoke-hook" in issue for issue in report["issues"])


def test_framework_operation_unmapped_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    mutated["excluded"] = [
        entry
        for entry in mutated["excluded"]
        if entry["operation"] != "FrameworkOp.guard_operation"
    ]
    report = verify_catalog(REPO, mutated)
    assert not report["complete"]
    assert any("FrameworkOp.guard_operation" in i for i in report["issues"])


def test_proof_check_outside_route_fails(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "model_invoke")["proof"]["checks"].append(
        "lean-audit:proofs/worker-route"
    )
    report = verify_catalog(REPO, mutated)
    assert any("lean-audit:proofs/worker-route" in i for i in report["issues"])


def test_in_progress_operation_is_never_complete(catalog: dict[str, Any]) -> None:
    mutated = copy.deepcopy(catalog)
    _op(mutated, "state_write")["status"] = "in_progress"
    report = verify_catalog(REPO, mutated)
    assert report["complete"] is False
    assert any("state_write" in entry for entry in report["pending"])
