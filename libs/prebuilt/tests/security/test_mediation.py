"""Model-level authorization coverage tests; snippets are parsed, never run."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

from langgraph.prebuilt.security import _mediation_catalog
from langgraph.prebuilt.security._mediation_catalog import framework_report
from langgraph.prebuilt.security.mediation import (
    Authorizer,
    Contract,
    Operation,
    analyze_function,
)

_ROOT = Path(__file__).parents[2] / "langgraph" / "prebuilt"
_CONTRACT = Contract(
    "run",
    (Authorizer("authorize", ("arg:0", "arg:1")),),
    (Operation("execute", ("arg:0", "arg:1")),),
    trusted_calls=("Denied", "other_request", "other_principal"),
    assumptions=("authorize returns the decision for its two immutable arguments",),
)


@pytest.mark.parametrize(
    "replacement", ["()", "other_constraints", "first.constraints"]
)
def test_host_constraints_must_match_the_current_decision(replacement: str) -> None:
    contract = Contract(
        "run",
        (Authorizer("authorize", ("arg:0", "arg:1", "result:constraints")),),
        (Operation("execute", ("arg:0", "arg:1", "arg:2")),),
        trusted_calls=("Denied",),
    )
    source = dedent(f"""
        def run(principal, request, other_constraints):
            first = authorize(principal, request)
            if first.verdict is not Verdict.ALLOW:
                raise Denied()
            second = authorize(principal, request)
            if second.verdict is not Verdict.ALLOW:
                raise Denied()
            return execute(principal, request, {replacement})
    """)
    assert analyze_function(source, contract)["status"] == "unverified"
    corrected = source.replace(
        f"execute(principal, request, {replacement})",
        "execute(principal, request, second.constraints)",
    )
    assert analyze_function(corrected, contract)["status"] == "verified_under_contract"


def test_framework_host_constraint_checks_are_required(tmp_path: Path) -> None:
    shutil.copytree(_ROOT, tmp_path / "prebuilt")
    root = tmp_path / "prebuilt"
    guarded = root / "security" / "guarded.py"
    source = guarded.read_text()
    assert "principal, call, authorization" in source
    guarded.write_text(
        source.replace("principal, call, authorization", "principal, call, decision")
    )
    report = framework_report(root)
    assert not report["claims_passed"]
    assert any(check["status"] == "unverified" for check in report["constraint_checks"])


def _check(body: str, **options):
    return analyze_function(dedent(body), _CONTRACT, **options)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_successful_authorization_binds_subject_and_request(asynchronous: bool) -> None:
    prefix, wait = ("async ", "await ") if asynchronous else ("", "")
    report = _check(
        f"""
        {prefix}def run(principal, request):
            decision = {wait}authorize(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                raise Denied()
            return {wait}execute(principal, request)
        """
    )
    assert report["status"] == "verified_under_contract"
    assert len(report["operations"]) == 1
    assert report["source_sha256"]
    assert report["assumptions"]


@pytest.mark.parametrize(
    "body",
    [
        "return execute(principal, request)",
        "decision = authorize(principal, request)\nreturn execute(principal, request)",
        "decision = authorize(principal, request)\nif decision.verdict is Verdict.DENY:\n    return execute(principal, request)",
        "decision = authorize(principal, request)\nif decision.verdict is not Verdict.ALLOW:\n    pass\nreturn execute(principal, request)",
        "decision = authorize(principal, request)\nassert decision.verdict is Verdict.ALLOW\nreturn execute(principal, request)",
    ],
)
def test_a_decision_is_not_authorization_without_an_allow_guard(body: str) -> None:
    report = _check(
        "def run(principal, request):\n"
        + "\n".join("    " + line for line in body.splitlines())
    )
    assert report["status"] == "unverified"


@pytest.mark.parametrize("changed", ["request", "principal"])
def test_rebinding_after_authorization_requires_another_decision(changed: str) -> None:
    report = _check(
        f"""
        def run(principal, request):
            decision = authorize(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                return
            {changed} = other_{changed}()
            return execute(principal, request)
        """
    )
    assert report["status"] == "unverified"


def test_alias_of_the_authorized_object_is_preserved() -> None:
    report = _check(
        """
        def run(principal, request):
            alias = request
            decision = authorize(principal, alias)
            if decision.verdict is Verdict.ALLOW:
                return execute(principal, request)
        """
    )
    assert report["status"] == "verified_under_contract"


def test_permission_class_must_match_the_operation() -> None:
    contract = Contract(
        "run",
        (Authorizer("authorize", ("arg:0", "arg:1"), permission="read"),),
        (Operation("execute", ("arg:0", "arg:1"), permission="write"),),
    )
    report = analyze_function(
        "def run(p, r):\n d = authorize(p, r)\n if d.verdict is Verdict.ALLOW:\n  execute(p, r)\n",
        contract,
    )
    assert report["status"] == "unverified"


def test_conditional_check_does_not_cover_other_branch() -> None:
    report = _check(
        """
        def run(principal, request, flag):
            if flag:
                decision = authorize(principal, request)
                if decision.verdict is not Verdict.ALLOW:
                    return
            return execute(principal, request)
        """
    )
    assert report["status"] == "unverified"


def test_either_branch_can_authorize_independently() -> None:
    report = _check(
        """
        def run(principal, request, flag):
            if flag:
                decision = authorize(principal, request)
            else:
                decision = authorize(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                return
            return execute(principal, request)
        """
    )
    assert report["status"] == "verified_under_contract"


@pytest.mark.parametrize(
    "operator,expected", [("and", "verified_under_contract"), ("or", "unverified")]
)
def test_boolean_paths(operator: str, expected: str) -> None:
    report = _check(
        f"""
        def run(principal, request, flag):
            decision = authorize(principal, request)
            if decision.verdict is Verdict.ALLOW {operator} flag:
                return execute(principal, request)
        """
    )
    assert report["status"] == expected


def test_each_physical_dispatch_consumes_authorization() -> None:
    report = _check(
        """
        def run(principal, request):
            decision = authorize(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                return
            execute(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return execute(principal, request)
        """
    )
    assert [item["status"] for item in report["operations"]] == [
        "verified_under_contract",
        "unverified",
    ]


def test_new_policy_decision_supersedes_an_old_allow() -> None:
    report = _check(
        """
        def run(principal, request):
            old = authorize(principal, request)
            if old.verdict is not Verdict.ALLOW:
                return
            current = authorize(principal, request)
            if current.verdict is Verdict.DENY:
                return execute(principal, request)
        """
    )
    assert report["status"] == "unverified"


def test_untyped_input_is_not_assumed_to_be_an_exhaustive_verdict_enum() -> None:
    report = _check(
        """
        def run(principal, request, input_decision):
            if input_decision.verdict is Verdict.ALLOW:
                decision = authorize(principal, request)
                if decision.verdict is not Verdict.ALLOW:
                    return
            elif input_decision.verdict is Verdict.DENY:
                return
            elif input_decision.verdict is Verdict.ESCALATE:
                return
            elif input_decision.verdict is Verdict.TRANSFORM:
                return
            return execute(principal, request)
        """
    )
    assert report["status"] == "unverified"


@pytest.mark.parametrize(
    "statement",
    [
        "unknown(request)",
        "request.payload = 1",
        "alias = request\n    alias.payload = 1",
        "authorize = other_request",
        "for item in request:\n        pass",
        "request = request if flag else request",
    ],
)
def test_unsupported_behavior_is_unresolved(statement: str) -> None:
    source = (
        "def run(principal, request, flag):\n"
        "    decision = authorize(principal, request)\n"
        "    if decision.verdict is not Verdict.ALLOW:\n"
        "        return\n"
        f"    {statement}\n"
        "    return execute(principal, request)\n"
    )
    report = _check(source)
    assert report["status"] == "unresolved"
    assert report["issues"]


def test_handler_does_not_inherit_a_successful_authorization() -> None:
    report = _check(
        """
        def run(principal, request):
            try:
                decision = authorize(principal, request)
                if decision.verdict is not Verdict.ALLOW:
                    raise Denied()
            except Exception:
                return execute(principal, request)
        """
    )
    assert report["status"] == "unverified"


def test_finally_is_analyzed_even_after_return() -> None:
    report = _check(
        """
        def run(principal, request):
            try:
                return
            finally:
                execute(principal, request)
        """
    )
    assert report["status"] == "unverified"


def test_nested_exception_cleanup_preserves_normal_dispatch_evidence() -> None:
    report = _check(
        """
        def run(principal, request):
            try:
                decision = authorize(principal, request)
            except Exception:
                raise Denied()
            if decision.verdict is not Verdict.ALLOW:
                return
            try:
                return execute(principal, request)
            finally:
                pass
        """
    )
    assert report["status"] == "verified_under_contract"


def test_tuple_authorizer_tracks_returned_objects() -> None:
    contract = Contract(
        "run",
        (Authorizer("prepare", ("result:1.principal", "result:2"), decision="0"),),
        _CONTRACT.operations,
    )
    source = """
def run(request):
    decision, request, call = prepare(request)
    if decision.verdict is not Verdict.ALLOW:
        return
    return execute(request.principal, call)
"""
    assert analyze_function(source, contract)["status"] == "verified_under_contract"


@pytest.mark.parametrize(
    "source",
    [
        "def run(:",
        "def other(): pass",
        "def run(): pass",
        "def run():\n return\n execute(p, r)",
    ],
)
def test_missing_invalid_or_unvisited_input_never_verifies(source: str) -> None:
    assert _check(source)["status"] == "unresolved"


def test_path_budget_exhaustion_is_unresolved() -> None:
    report = _check(
        """
        def run(principal, request, flag):
            if flag:
                value = 1
            else:
                value = 2
            decision = authorize(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                return
            return execute(principal, request)
        """,
        max_states=1,
    )
    assert report["status"] == "unresolved"
    assert any("budget" in issue["reason"] for issue in report["issues"])


def test_framework_report_does_not_confuse_dispatch_with_completeness() -> None:
    report = framework_report(_ROOT)
    assert report["claims_passed"], report["checks"]
    assert len(report["checks"]) == 4
    assert sum(len(check["operations"]) for check in report["checks"]) == 8
    assert not report["complete"]
    assert {item["status"] for item in report["coverage"]} == {
        "analyzed",
        "source_bound",
        "verified_under_contract",
        "partially_verified",
        "unsupported",
    }
    assert {item["id"] for item in report["obligations"]} == {
        "authorization-helper-validation",
        "in-process-execution",
        "confinement-activation",
        "execution-lifetime",
        "delegation-and-transfer",
        "publication-inventory",
    }
    assert all(
        evidence["status"] == "source_bound" for evidence in report["source_evidence"]
    )
    assert all(
        summary["source_evidence"]
        for check in report["checks"]
        for summary in check["authorizer_summaries"]
    )
    assert report == framework_report(_ROOT)


def test_missing_framework_source_fails_closed(tmp_path: Path) -> None:
    report = framework_report(tmp_path)
    assert not report["claims_passed"]
    assert all(check["status"] == "unresolved" for check in report["checks"])
    assert all(item["status"] == "unresolved" for item in report["obligations"])


def test_reviewed_helper_digest_drift_fails_closed(monkeypatch) -> None:
    monkeypatch.setitem(
        _mediation_catalog._REVIEWED_DIGESTS, "authorization-stack", "changed"
    )
    report = framework_report(_ROOT)
    evidence = {item["id"]: item for item in report["source_evidence"]}
    assert evidence["authorization-stack"]["status"] == "unresolved"
    assert not report["claims_passed"]
    assert report["coverage"][0]["status"] == "unresolved"
    assert report["coverage"][1]["status"] == "unresolved"
    obligation = next(
        item
        for item in report["obligations"]
        if item["id"] == "authorization-helper-validation"
    )
    assert obligation["status"] == "unresolved"


@pytest.mark.parametrize("check_claims,exit_code", [(False, 1), (True, 0)])
def test_cli_distinguishes_claim_gate_from_completeness(
    check_claims: bool, exit_code: int
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "langgraph.prebuilt.security.mediation",
            *(["--check-claims"] if check_claims else []),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == exit_code, completed.stderr
    report = json.loads(completed.stdout)
    assert report["claims_passed"] and not report["complete"]
