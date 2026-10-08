"""Lock scopes preserve mediation obligations and exact mapping aliases."""

from dataclasses import replace
from threading import RLock

import pytest

from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec
from tests.security.test_verification_control_flow import check


@pytest.mark.parametrize("constructor", ["RLock", "threading.RLock", "_thread.RLock"])
def test_lock_scope_follows_authorization_and_dispatch(constructor):
    report = check(
        f"""
        with {constructor}() as acquired:
            if acquired is not True:
                return dispatch(None, None)
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """,
        "from threading import RLock\nimport threading\nimport _thread\n",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_reentrant_lock_does_not_grant_authority():
    report = check(
        """
        lock = RLock()
        with lock, lock:
            dispatch(principal, request)
    """,
        "from threading import RLock\n",
    )
    assert report["entries"][0]["status"] == "violated", report


def test_lock_does_not_prevent_revocation_after_mutation():
    report = check(
        """
        call = {'key': request}
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            with RLock():
                call['key'] = None
                dispatch(principal, call)
    """,
        "from threading import RLock\n",
    )
    assert report["entries"][0]["status"] == "violated", report


def test_lock_does_not_suppress_exceptions_or_execute_later_body_calls():
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, request)
        with RLock():
            raise ValueError('stop')
            dispatch(None, None)
        dispatch(None, None)
    """,
        "from threading import RLock\n",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_lock_preserves_exception_payloads_for_enclosing_handlers():
    report = check(
        """
        try:
            with RLock():
                raise ValueError(dispatch)
        except ValueError as error:
            return error
    """,
        "from threading import RLock\n",
    )
    assert not report["complete"]
    assert any("escapes" in item["reason"] for item in report["entries"][0]["issues"])


def test_lock_body_remains_visible_with_an_unknown_manager():
    report = check("""
        with request:
            dispatch(principal, request)
    """)
    assert report["entries"][0]["status"] == "unresolved", report
    assert report["entries"][0]["dispatches"]


def test_source_constructor_shadowing_is_not_a_native_lock():
    report = check(
        """
        with RLock(principal, request):
            pass
    """,
        """
        def RLock(principal, request):
            return dispatch(principal, request)
    """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


@pytest.mark.parametrize("module", ["threading", "_thread"])
def test_supplied_stdlib_override_invalidates_lock_model(module):
    original = spec("""
from threading import RLock
class Tool:
    def invoke(self, principal, request):
        with RLock():
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """)
    report = verify(replace(original, sources={**original.sources, module: ""}))
    assert not report["complete"]
    assert any("source overrides" in issue["reason"] for issue in report["issues"])


@pytest.mark.parametrize("present", [False, True])
def test_setdefault_insertion_revokes_but_existing_key_does_not(present):
    initial = "{'key': request}" if present else "{}"
    report = check(
        f"""
        call = {initial}
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            with RLock():
                returned = call.setdefault('key', request)
                dispatch(principal, call)
    """,
        "from threading import RLock\n",
    )
    assert report["complete"] is present, report


def test_setdefault_always_evaluates_its_default_argument():
    report = check("""
        call = {'key': request}
        call.setdefault('key', dispatch(principal, request))
    """)
    assert report["entries"][0]["status"] == "violated", report


def test_proxy_rejects_setdefault_before_evaluating_arguments():
    report = check(
        """
        call = MappingProxyType({'key': request})
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, request)
        call.setdefault('key', dispatch(None, None))
    """,
        "from types import MappingProxyType\n",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_setdefault_preserves_the_existing_value_identity():
    report = check("""
        call = {'key': request}
        returned = call.setdefault('key', None)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, returned)
    """)
    assert report["complete"], report


def test_native_lock_contract_matches_running_python():
    """The only executed lock is stdlib; no candidate code runs in tests."""
    lock = RLock()
    with lock as outer, lock as inner:
        assert outer is True
        assert inner is True
    with pytest.raises(ValueError):
        with lock:
            raise ValueError("not suppressed")
