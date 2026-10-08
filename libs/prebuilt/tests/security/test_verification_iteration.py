"""Source-only checks for finite iteration and live mapping views."""

from textwrap import dedent, indent

import pytest

from tests.security.test_verification_control_flow import check


@pytest.mark.parametrize(
    "expression",
    [
        "(request, request)",
        "{'first': request, 'second': request}.values()",
    ],
)
@pytest.mark.parametrize("reauthorize", [False, True])
def test_every_iteration_requires_fresh_authority(expression, reauthorize):
    authorization = dedent("""
        d = permission(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
    """).strip()
    body = authorization + f"\nfor call in {expression}:\n"
    if reauthorize:
        body += indent(authorization, "    ") + "\n"
    body += "    dispatch(principal, call)"
    report = check(body)
    assert report["complete"] is reauthorize, report
    assert len(report["entries"][0]["dispatches"]) == 2


@pytest.mark.parametrize(
    "source",
    [
        "('first', 'second')",
        "{'first': 1, 'second': 2}",
        "{'first': 1, 'second': 2}.keys()",
    ],
)
def test_keys_and_tuple_elements_retain_exact_bindings(source):
    report = check(f"""
        for key in {source}:
            d = permission(principal, key)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, key)
    """)
    assert report["complete"], report
    sites = report["entries"][0]["dispatches"]
    assert {site["bindings"][2] for site in sites} == {
        "constant:'first'",
        "constant:'second'",
    }


def test_items_unpacking_preserves_live_values_before_iteration_starts():
    report = check("""
        calls = {'key': None}
        view = calls.items()
        calls['key'] = request
        for key, call in view:
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, call)
    """)
    assert report["complete"], report


def test_mapping_proxy_views_follow_the_original_mapping():
    report = check(
        """
        calls = {'key': None}
        view = MappingProxyType(calls).values()
        calls['key'] = request
        for call in view:
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, call)
    """,
        "from types import MappingProxyType\n",
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "view",
    [
        "calls",
        "calls.items()",
        "calls.keys()",
        "calls.values()",
        "MappingProxyType(calls).items()",
    ],
)
def test_mutation_during_iteration_stays_unresolved(view):
    report = check(
        f"""
        calls = {{'first': request, 'second': request}}
        for element in {view}:
            calls['first'] = None
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        "from types import MappingProxyType\n",
    )
    assert not report["complete"]
    assert any(
        "mapping changed during active iteration" == item["reason"]
        for item in report["entries"][0]["issues"]
    )


def test_mutating_nested_values_does_not_change_iteration_but_revokes_grants():
    report = check("""
        call = {'value': request}
        calls = {'key': call}
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            for item in calls.values():
                item['value'] = None
                dispatch(principal, call)
    """)
    assert report["entries"][0]["status"] == "violated", report


@pytest.mark.parametrize("view", ["calls.keys()", "calls.values()", "calls.items()"])
def test_view_dependency_revokes_authority_when_backing_mapping_changes(view):
    report = check(f"""
        calls = {{'key': request}}
        view = {view}
        d = permission(principal, view)
        if d.verdict is Verdict.ALLOW:
            calls['key'] = None
            dispatch(principal, view)
    """)
    assert report["entries"][0]["status"] == "violated", report


@pytest.mark.parametrize("source", ["()", "{}", "{}.items()"])
def test_empty_iteration_prunes_body_but_runs_else(source):
    report = check(f"""
        for item in {source}:
            dispatch(principal, request)
        else:
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("control", ["break", "return None"])
def test_early_exit_skips_remaining_elements_and_else(control):
    report = check(f"""
        for call in (request, None):
            d = permission(principal, call)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
            dispatch(principal, call)
            {control}
        else:
            dispatch(None, None)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_continue_runs_remaining_iterations_and_else():
    report = check("""
        for call in (None, request):
            if call is None:
                continue
            d = permission(principal, call)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, call)
        else:
            dispatch(principal, request)
    """)
    assert report["entries"][0]["status"] == "violated", report
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_finalizer_runs_before_break_and_needs_its_own_authorization():
    report = check("""
        for call in (request,):
            try:
                break
            finally:
                dispatch(principal, call)
    """)
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_nested_break_only_exits_inner_loop():
    report = check("""
        for call in (request, request):
            for inner in (None,):
                break
            d = permission(principal, call)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, call)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 3


def test_view_can_neither_hide_nor_forget_a_live_callable_alias():
    report = check("""
        calls = {}
        view = calls.values()
        calls['key'] = dispatch
        return view
    """)
    assert not report["complete"]
    assert any("escapes" in item["reason"] for item in report["entries"][0]["issues"])


def test_unknown_iterable_remains_unresolved():
    report = check("""
        for call in request:
            dispatch(principal, call)
    """)
    assert not report["complete"]
    assert any(
        "iteration requires" in item["reason"]
        for item in report["entries"][0]["issues"]
    )


def test_mapping_view_is_live_in_running_python():
    mapping = {"key": None}
    view = mapping.items()
    supplied = object()
    mapping["key"] = supplied
    assert list(view) == [("key", supplied)]
