"""Eager comprehension proofs keep order, scope and per-iteration authority."""

import pytest

from tests.security.test_verification_records import check


@pytest.mark.parametrize(
    ("construction", "projection"),
    [
        ("{key: request for key in ('value',)}", "values['value']"),
        ("[request for key in ('value',)]", "values[0]"),
        (
            "{key: value for key, value in {'value': request}.items()}",
            "values['value']",
        ),
        ("[value for value in {'value': request}.values()]", "values[0]"),
        (
            "{key: value for key in ('value',) for value in (request,)}",
            "values['value']",
        ),
        ("[value for key in ('value',) for value in (request,)]", "values[0]"),
        ("[[value for value in (request,)] for key in ('value',)]", "values[0][0]"),
        (
            "{key: request for key in ('skip', 'value') if key != 'skip'}",
            "values['value']",
        ),
        ("[value for value in (None, request) if value is not None]", "values[0]"),
    ],
)
def test_comprehension_preserves_projected_request_identity(construction, projection):
    report = check(f"""
        values = {construction}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, {projection})
    """)
    assert report["complete"], report


def test_dictionary_key_runs_before_value():
    report = check(
        """
        box = {'value': None}
        values = {set_key(box, request): box['value'] for item in (None,)}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, values['value'])
        """,
        """
        def set_key(box, request):
            box['value'] = request
            return 'value'
        """,
    )
    assert report["complete"], report


def test_target_binding_does_not_leak_into_outer_scope():
    report = check("""
        values = [principal for principal in (None,)]
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert report["complete"], report
    assert report["entries"][0]["dispatches"][0]["bindings"][1:] == [
        "input:principal",
        "input:request",
    ]


def test_first_iterable_reads_outer_scope_before_target_shadowing():
    report = check("""
        value = (request,)
        values = [value for value in value]
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, values[0])
    """)
    assert report["complete"], report


def test_later_target_cannot_fall_back_to_same_named_module_global():
    report = check(
        """
        values = [value for key in (None,) for value in (value,)]
        return dispatch(principal, request)
        """,
        "value = None\n",
    )
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_outer_variables_remain_accessible_in_comprehension():
    report = check("""
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return [dispatch(principal, request) for key in (None,)]
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "expression",
    [
        "[dispatch(principal, request) for key in ('a', 'b')]",
        "{key: dispatch(principal, request) for key in ('a', 'b')}",
        "{'duplicate': dispatch(principal, request) for key in ('a', 'b')}",
    ],
)
def test_one_grant_cannot_authorize_two_iterations(expression):
    report = check(f"""
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return {expression}
    """)
    dispatches = report["entries"][0]["dispatches"]
    assert [site["authorized"] for site in dispatches] == [True, False]
    assert report["entries"][0]["status"] == "violated"


def test_each_iteration_can_establish_fresh_authority():
    report = check(
        "return [execute(principal, request) for key in ('a', 'b')]",
        """
        def execute(principal, request):
            d = permission(principal, request)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
            return dispatch(principal, request)
        """,
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 2


def test_filter_calls_are_checked_even_when_no_element_is_emitted():
    report = check(
        "return [None for key in (None,) if rejected(principal, request)]",
        """
        def rejected(principal, request):
            dispatch(principal, request)
            return False
        """,
    )
    assert report["entries"][0]["status"] == "violated"


def test_filter_evaluation_short_circuits_in_source_order():
    report = check("""
        values = [dispatch(principal, request) for key in (None,) if False if dispatch(principal, request)]
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_duplicate_keys_keep_last_value_after_evaluating_every_value():
    report = check("""
        values = {'value': value for value in (None, request)}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, values['value'])
    """)
    assert report["complete"], report


def test_comprehension_retains_nested_aliases():
    report = check("""
        box = {'value': request}
        values = [box for key in (None,)]
        d = permission(principal, values)
        if d.verdict is Verdict.ALLOW:
            box['value'] = None
            return dispatch(principal, values)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_mutations_from_element_expressions_revoke_outer_authority():
    report = check(
        """
        box = {'value': request}
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            values = [change(box) for key in (None,)]
            return dispatch(principal, box)
        """,
        """
        def change(box):
            box['value'] = None
            return None
        """,
    )
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "expression",
    [
        "[dispatch(principal, request) for value in ()]",
        "{key: dispatch(principal, request) for key in ()}",
    ],
)
def test_empty_iterables_do_not_execute_elements(expression):
    report = check(f"""
        values = {expression}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert report["complete"], report


def test_failed_first_iterable_does_not_execute_elements():
    report = check(
        "return [dispatch(principal, request) for key in fail()]",
        """
        def fail():
            raise ValueError('failed')
        """,
    )
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_failed_key_does_not_execute_value():
    report = check(
        "return {fail(): dispatch(principal, request) for key in (None,)}",
        """
        def fail():
            raise ValueError('failed')
        """,
    )
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


@pytest.mark.parametrize(
    "expression",
    [
        "[current for current in request]",
        "{key: value for key, value in request.items()}",
        "[(saved := current) for current in (request,)]",
        "[current async for current in request]",
    ],
)
def test_unknown_iteration_or_unmodeled_scope_stays_unresolved(expression):
    report = check(f"return {expression}")
    assert report["entries"][0]["status"] == "unresolved"


@pytest.mark.parametrize(
    "expression",
    [
        "[values.append(None) for value in values]",
        "{key: values.append(None) for key in values}",
    ],
)
def test_mutating_active_list_iteration_is_unresolved(expression):
    report = check("values = ['key']\nreturn " + expression)
    assert not report["complete"]
    assert any(
        "list changed during active iteration" in i["reason"]
        for i in report["entries"][0]["issues"]
    )


def test_mutating_active_mapping_iteration_is_unresolved():
    report = check("""
        values = {'key': request}
        return [values.update(other=None) for key in values]
    """)
    assert not report["complete"]
    assert any(
        "mapping changed during active iteration" in i["reason"]
        for i in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "expression",
    ["[dispatch for key in (None,)]", "{key: dispatch for key in ('key',)}"],
)
def test_comprehension_cannot_hide_executable_escape(expression):
    report = check("return " + expression)
    assert report["entries"][0]["status"] == "unresolved"
    assert any(
        "capability escapes" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_native_comprehension_evaluation_order_and_scope():
    order = []
    outer = ("key",)
    values = {order.append("key") or outer: order.append("value") for outer in outer}
    assert order == ["key", "value"]
    assert values == {"key": None}
    assert outer == ("key",)
