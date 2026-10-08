"""Literal source bindings may resolve identities without trusting module code."""

from dataclasses import replace

import pytest

from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec

BODY = """
class Tool:
    def invoke(self, principal, request):
        arguments = {KEY: request}
        selected = arguments.get(KEY)
        d = permission(principal, selected)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
"""


@pytest.mark.parametrize("declaration", ["KEY = 'value'", "ALIAS = KEY = 'value'"])
def test_literal_module_key_preserves_request_identity(declaration):
    report = verify(spec(declaration + "\n" + BODY))
    assert report["complete"], report


def test_postponed_global_annotation_is_not_executable_initialization():
    original = spec("KEY: annotation_factory() = 'value'\n" + BODY)
    source = "from __future__ import annotations\n" + original.sources["example"]
    report = verify(replace(original, sources={"example": source}))
    assert report["complete"], report


def test_eager_global_annotation_still_blocks_verification():
    report = verify(spec("KEY: annotation_factory() = 'value'\n" + BODY))
    assert not report["complete"]
    assert any("initialization" in issue["reason"] for issue in report["issues"])


@pytest.mark.parametrize(
    "declaration",
    [
        "KEY = make_key()",
        "if enabled:\n    KEY = 'value'",
        "KEY = 'first'\nKEY = 'second'",
    ],
)
def test_dynamic_or_rebound_global_key_remains_unresolved(declaration):
    report = verify(spec(declaration + "\n" + BODY))
    assert not report["complete"]
    assert report["issues"]


@pytest.mark.parametrize("module_attribute", [False, True])
def test_imported_constant_resolves_without_importing_candidate_module(
    module_attribute,
):
    original = spec(
        (
            "import keys as constants\n"
            if module_attribute
            else "from facade import KEY\n"
        )
        + (BODY.replace("KEY", "constants.KEY") if module_attribute else BODY)
    )
    report = verify(
        replace(
            original,
            sources={
                **original.sources,
                "keys": "KEY = 'value'\n",
                "facade": "from keys import KEY\n",
            },
        )
    )
    assert report["complete"], report


@pytest.mark.parametrize("enabled", [True, False])
def test_literal_mode_selects_the_actual_authorization_branch(enabled):
    report = verify(
        spec(f"""
SECURED = {enabled}
class Tool:
    def invoke(self, principal, request):
        if SECURED:
            d = permission(principal, request)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
        return dispatch(principal, request)
    """)
    )
    assert report["complete"] is enabled, report
    assert report["entries"][0]["dispatches"][0]["authorized"] is enabled


def test_literal_shadowing_prevents_using_a_builtin_model():
    report = verify(
        spec("""
isinstance = 7
class Tool:
    def invoke(self, principal, request):
        isinstance(request, int)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert not report["complete"]
    assert any(
        "isinstance" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


def test_literal_verdict_name_cannot_establish_an_allow_fact():
    original = spec("""
Verdict = None
class Tool:
    def invoke(self, principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    source = original.sources["example"].replace(
        "from policy import permission, apermission, Verdict",
        "from policy import permission, apermission",
    )
    report = verify(replace(original, sources={"example": source}))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])
