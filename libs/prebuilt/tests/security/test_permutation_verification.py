"""Finite source permutations and non-actuating runtime denial observers."""

from dataclasses import replace

import pytest

from langgraph.prebuilt.security import permutation_verification as matrix
from langgraph.prebuilt.security.verification import verify


def test_all_declared_source_binding_permutations():
    report = matrix.verify_binding_permutations()
    assert report["passed"], report["failures"][:3]
    assert report["cases"] == 2 * 5 * 5 * 24 * 24
    assert report["unique_case_ids"]


@pytest.mark.asyncio
async def test_all_declared_runtime_denial_permutations():
    report = await matrix.verify_denial_permutations()
    assert report["passed"], report["failures"][:3]
    assert len(report["apis"]) == 21
    verdicts = len(report["verdicts"])
    assert report["cases"] == (
        5 * (verdicts - 1)
        + 2 * (verdicts**4 - 1)
        + 14 * report["request_variants"] * (verdicts - 1)
    )


def test_observer_records_effects_and_keeps_argument_identity():
    observer = matrix._Observer()
    first, second = object(), object()
    observer.invoke(first, second)
    assert len(observer.effects) == 1
    assert observer.effects[0][0] is first
    assert observer.effects[0][1] is second


@pytest.mark.asyncio
async def test_unexpected_policy_failure_is_not_successful_denial(monkeypatch):
    def broken(self, stage, args):
        raise RuntimeError("observer failed")

    monkeypatch.setattr(matrix._Observer, "decision", broken)
    report = await matrix.verify_denial_permutations()
    assert not report["passed"]
    assert len(report["failures"]) == report["cases"]
    assert all(
        item["actual"] == "unexpected:RuntimeError" for item in report["failures"]
    )


@pytest.mark.asyncio
async def test_invalid_admission_cannot_be_reported_as_zero_successful_tests(
    monkeypatch,
):
    monkeypatch.setattr(matrix, "verify_host_router", lambda: {"complete": False})
    report = await matrix.verify_denial_permutations()
    assert not report["passed"]
    assert report["cases"] == 0
    assert report["failures"]


def test_empty_or_duplicate_case_inventory_does_not_pass():
    assert not matrix._summary([], [])["passed"]
    assert not matrix._summary(["same", "same"], [])["passed"]


def test_negative_source_case_must_be_a_violation_not_merely_unresolved(monkeypatch):
    monkeypatch.setattr(
        matrix,
        "verify",
        lambda spec: {
            "complete": False,
            "issues": [],
            "entries": [
                {
                    "status": "unresolved",
                    "dispatches": [{}],
                    "issues": ["missing model"],
                }
            ],
        },
    )
    report = matrix.verify_binding_permutations()
    assert not report["passed"]
    assert len(report["failures"]) == report["cases"]


def test_matching_wrong_bindings_are_rejected_against_original_entry():
    changed = (*matrix.SLOTS[1:], matrix.SLOTS[0])
    proof = verify(matrix.binding_spec(changed, changed, "helper", False))
    assert proof["entries"][0]["status"] == "violated"
    assert all(site["authorized"] for site in proof["entries"][0]["dispatches"])
    assert not proof["entries"][0]["authorizations"][0]["entry_bound"]


def test_new_api_requires_an_entry_contract():
    spec = matrix.binding_spec(matrix.SLOTS, matrix.SLOTS, "direct", False)
    source = (
        spec.sources["fixture"]
        + "\n    def added(self, principal, resource, operation, call, flag):\n        return self.invoke(principal, resource, operation, call, flag)\n"
    )
    proof = verify(replace(spec, sources={"fixture": source}))
    assert not proof["complete"]
    assert any(
        "lacks an original-entry" in issue["reason"]
        for entry in proof["entries"]
        for issue in entry["issues"]
    )


def test_stale_contract_is_not_silent_coverage():
    spec = matrix.binding_spec(matrix.SLOTS, matrix.SLOTS, "direct", False)
    proof = verify(
        replace(
            spec,
            entry_bindings={
                **spec.entry_bindings,
                "fixture.Entry.removed": spec.entry_bindings["fixture.Entry.invoke"],
            },
        )
    )
    assert not proof["complete"]
    assert any("undiscovered API" in issue["reason"] for issue in proof["issues"])


@pytest.mark.parametrize("selectors", [("result:",), (), ("arg:wrong",)])
def test_entry_bindings_require_original_argument_selectors(selectors):
    spec = matrix.binding_spec(matrix.SLOTS, matrix.SLOTS, "direct", False)
    with pytest.raises(ValueError, match="entry bindings"):
        replace(
            spec,
            entry_bindings={"fixture.Entry.invoke": {"policy.authorize": selectors}},
        )
