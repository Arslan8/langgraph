"""Native dictionary updates preserve order, aliases and grant revocation."""

import pytest

from tests.security.test_verification_records import check


@pytest.mark.parametrize(
    "update",
    [
        "box.update({'value': request})",
        "box.update(value=request)",
        "box.update({'value': None}, value=request)",
        "box.update(**{'value': request})",
        "box.update(MappingProxyType({'value': request}))",
    ],
)
def test_update_preserves_final_value_identity(update):
    report = check(f"""
        box = {{}}
        {update}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, box['value'])
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "update", ["box.update(value=None)", "box.update({'extra': None})"]
)
def test_update_revokes_container_authority(update):
    report = check(f"""
        box = {{'value': request}}
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            {update}
            return dispatch(principal, box)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_update_changes_live_proxy_and_dependent_authority():
    report = check("""
        box = {'value': request}
        view = MappingProxyType(box)
        d = permission(principal, view)
        if d.verdict is Verdict.ALLOW:
            box.update(value=None)
            return dispatch(principal, view)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_proxy_does_not_expose_mutating_method():
    report = check("""
        view = MappingProxyType({})
        view.update(value=request)
        return dispatch(principal, request)
    """)
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_empty_update_does_not_change_authorized_container():
    report = check("""
        box = {'value': request}
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            box.update({})
            box.update()
            return dispatch(principal, box)
    """)
    assert report["complete"], report


def test_update_shares_nested_values_without_sharing_source_storage():
    report = check("""
        nested = {'value': request}
        source = {'nested': nested}
        box = {}
        box.update(source)
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            nested['value'] = None
            return dispatch(principal, box)
    """)
    assert report["entries"][0]["status"] == "violated"
    report = check("""
        source = {'value': request}
        box = {}
        box.update(source)
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            source['value'] = None
            return dispatch(principal, box)
    """)
    assert report["complete"], report


def test_update_reads_positional_mapping_after_keyword_effects():
    report = check(
        """
        source = {'value': None}
        box = {}
        box.update(source, extra=change(source, request))
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, box['value'])
        """,
        """
        def change(box, value):
            box['value'] = value
            return None
        """,
    )
    assert report["complete"], report


def test_keyword_effects_are_checked_before_arity_error():
    report = check("""
        box = {}
        box.update({}, {}, value=dispatch(principal, request))
    """)
    assert report["entries"][0]["status"] == "violated"


def test_argument_mismatch_has_no_normal_continuation():
    report = check("""
        box = {}
        box.update({}, {})
        return dispatch(principal, request)
    """)
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_self_update_keeps_value_identity_and_returns_none():
    report = check("""
        box = {'value': request}
        result = box.update(box)
        if result is not None:
            return dispatch(principal, None)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, box['value'])
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "method", ["update", "get", "copy", "setdefault", "pop", "items"]
)
def test_bound_mapping_methods_retain_receiver_dependencies(method):
    report = check(f"""
        box = {{'value': request}}
        operation = box.{method}
        d = permission(principal, operation)
        if d.verdict is Verdict.ALLOW:
            box.update(value=None)
            return dispatch(principal, operation)
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize("source", ["request", "(('value', request),)"])
def test_unknown_or_unmodeled_iterable_update_remains_unresolved(source):
    report = check(f"""
        box = {{}}
        box.update({source})
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, box)
    """)
    assert not report["complete"]
    assert any(
        "known finite mapping" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_update_cannot_hide_an_executable_escape():
    report = check("""
        box = {}
        box.update(value=dispatch)
        return box
    """)
    assert report["entries"][0]["status"] == "unresolved"


def test_native_update_contract():
    marker = object()
    source = {"value": None}
    target = {}

    def change():
        source["value"] = marker
        return None

    result = target.update(source, extra=change())
    assert result is None and target["value"] is marker
    source["value"] = None
    assert target["value"] is marker
