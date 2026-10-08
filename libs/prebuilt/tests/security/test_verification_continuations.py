"""Terminated paths are retired only beyond every handler and finalizer."""

from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import VerificationSpec, verify


def check(body, helpers="", parameters="", max_paths=64):
    source = (
        "from policy import permission, Verdict\nfrom legacy import dispatch\n"
        + dedent(helpers)
        + f"class Tool:\n    def invoke(self, principal, request{parameters}):\n"
        + "\n".join("        " + line for line in dedent(body).strip().splitlines())
        + "\n"
    )
    return verify(
        VerificationSpec(
            sources={"example": source},
            surfaces=("example.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
            max_paths=max_paths,
        )
    )


AUTHORIZE = """
d = permission(principal, request)
if d.verdict is not Verdict.ALLOW:
    raise PermissionError('denied')
"""


@pytest.mark.parametrize("helper", [False, True])
def test_uncaught_terminal_paths_do_not_accumulate_against_live_path_budget(helper):
    names = [f"fail_{index}" for index in range(32)]
    body = "\n".join(
        f"reject({name})" if helper else f'if {name}:\n    raise ValueError("failed")'
        for name in names
    )
    body += AUTHORIZE + "\nreturn dispatch(principal, request)"
    helpers = (
        """
        def reject(enabled):
            if enabled:
                raise ValueError('failed')
    """
        if helper
        else ""
    )
    report = check(body, helpers, parameters=", " + ", ".join(names), max_paths=1)
    assert report["complete"], report
    assert report["entries"][0]["settled_exceptions"] >= len(names)
    assert len(report["entries"][0]["dispatches"]) == 1


def test_live_paths_still_exhaust_the_configured_budget():
    report = check(
        """
        if first:
            selected = principal
        else:
            selected = request
        if second:
            other = principal
        else:
            other = request
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        parameters=", first, second",
        max_paths=2,
    )
    assert not report["complete"]
    assert any("budget" in issue["reason"] for issue in report["entries"][0]["issues"])


def test_callee_exception_can_still_reach_caller_handler_dispatch():
    report = check(
        """
        try:
            fail()
        except ValueError:
            return dispatch(principal, request)
    """,
        """
        def fail():
            raise ValueError('failed')
    """,
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_callee_exception_can_still_reach_caller_finalizer_dispatch():
    report = check(
        """
        try:
            fail()
        finally:
            dispatch(principal, request)
    """,
        """
        def fail():
            raise ValueError('failed')
    """,
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


@pytest.mark.parametrize(
    "body",
    [
        "raise ValueError(dispatch)",
        "fail()",
        "try:\n    fail()\nexcept ValueError as error:\n    raise RuntimeError(error)",
        "try:\n    pass\nfinally:\n    fail()",
    ],
)
def test_uncaught_exception_retirement_checks_nested_payloads(body):
    report = check(
        AUTHORIZE + "\ndispatch(principal, request)\n" + body,
        """
        def fail():
            raise ValueError({'executable':dispatch})
    """,
    )
    assert not report["complete"]
    assert any("escapes" in issue["reason"] for issue in report["entries"][0]["issues"])


def test_finalizer_can_replace_exception_before_escape_check():
    report = check(
        AUTHORIZE
        + """
dispatch(principal, request)
try:
    raise ValueError(dispatch)
finally:
    return None
"""
    )
    assert report["complete"], report


def test_nested_helper_finalizers_preserve_unauthorized_effects():
    report = check(
        """
        try:
            fail(principal, request)
        except Exception:
            pass
    """,
        """
        def fail(principal, request):
            try:
                raise ValueError('failed')
            finally:
                dispatch(principal, request)
    """,
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_handler_may_reauthorize_after_a_callee_failure():
    report = check(
        """
        try:
            fail()
        except ValueError:
            d = permission(principal, request)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
            return dispatch(principal, request)
    """,
        """
        def fail():
            raise ValueError('failed')
    """,
    )
    assert report["complete"], report


def test_raising_after_dispatch_keeps_the_consumed_grant_consumed():
    report = check(
        AUTHORIZE
        + """
try:
    executed(principal, request)
except ValueError:
    return dispatch(principal, request)
""",
        """
        def executed(principal, request):
            dispatch(principal, request)
            raise ValueError('failed')
    """,
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])
