"""Native list aliases, writes and snapshots preserve authorization bindings."""

from textwrap import dedent

import pytest

from tests.security.test_verification_control_flow import check as check_source
from tests.security.test_verification_records import check as record_check


def check(body, helpers=""):
    return check_source(dedent(body), dedent(helpers).rstrip() + "\n")


@pytest.mark.parametrize(
    "expression",
    [
        "[request]",
        "list((request,))",
        "list([request])",
        "[None, request][1:]",
        "[*[request]]",
    ],
)
@pytest.mark.parametrize("index", ["0", "-1", "False"])
def test_list_projections_keep_exact_authorized_identity(expression, index):
    report = check(f"""
        items = {expression}
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, items[{index}])
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "mutation",
    [
        "alias.append(None)",
        "alias.extend((None,))",
        "alias.insert(0, None)",
        "alias.pop()",
        "alias.clear()",
        "alias.reverse()",
        "alias[0] = None",
        "del alias[0]",
        "alias[:] = [None]",
        "del alias[:]",
    ],
)
def test_list_alias_writes_revoke_container_authority(mutation):
    report = check(f"""
        items = [request]
        alias = items
        decision = permission(principal, items)
        if decision.verdict is Verdict.ALLOW:
            {mutation}
            return dispatch(principal, items)
    """)
    assert not report["complete"]
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


@pytest.mark.parametrize("copy", ["items.copy()", "items[:]", "list(items)"])
def test_shallow_copy_has_independent_outer_storage(copy):
    report = check(f"""
        items = [request]
        copied = {copy}
        decision = permission(principal, copied)
        if decision.verdict is Verdict.ALLOW:
            items.clear()
            return dispatch(principal, copied)
    """)
    assert report["complete"], report


@pytest.mark.parametrize("copy", ["items.copy()", "items[:]", "list(items)"])
def test_shallow_copy_retains_mutable_element_dependencies(copy):
    report = check(f"""
        nested = {{'value': request}}
        items = [nested]
        copied = {copy}
        decision = permission(principal, copied)
        if decision.verdict is Verdict.ALLOW:
            nested['value'] = None
            return dispatch(principal, copied)
    """)
    assert not report["complete"]
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_nested_list_write_invalidates_an_outer_mapping_grant():
    report = check("""
        items = [request]
        container = {'items': items}
        decision = permission(principal, container)
        if decision.verdict is Verdict.ALLOW:
            items.append(None)
            return dispatch(principal, container)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_pop_preserves_element_identity_and_self_extend_snapshots_once():
    report = check("""
        items = [request]
        items.extend(items)
        if len(items) == 2:
            selected = items.pop(0)
            decision = permission(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return dispatch(principal, selected)
    """)
    assert report["complete"], report


def test_list_unpacking_snapshots_before_assigning_targets():
    report = check("""
        items = [request, 'next']
        items[1], selected = items
        decision = permission(principal, 'next')
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, selected)
    """)
    assert report["complete"], report


def test_list_argument_expansion_precedes_later_argument_mutation():
    report = check(
        """
        items = [principal, request]
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return execute(*items, unused=change(items))
    """,
        """
        def change(items):
            items[1] = 'changed'
        def execute(principal, request, unused=None):
            return dispatch(principal, request)
    """,
    )
    assert report["complete"], report


def test_list_literal_expansion_precedes_later_element_mutation():
    report = check(
        """
        items = [request]
        expanded = [*items, change(items)]
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, expanded[0])
    """,
        """
        def change(items):
            items.clear()
    """,
    )
    assert report["complete"], report


def test_index_expression_can_change_the_selected_request():
    report = check(
        """
        items = [request]
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, items[change(items)])
    """,
        """
        def change(items):
            items[0] = 'changed'
            return 0
    """,
    )
    assert report["entries"][0]["status"] == "violated"


def test_all_slice_bounds_are_evaluated_before_index_validation():
    report = check("""
        items = [request]
        return items['invalid':dispatch(principal, request)]
    """)
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


@pytest.mark.parametrize(
    "operation",
    [
        "items[5]",
        "items.pop(5)",
        "items[::0]",
        "items[::2] = []",
        "items['invalid']",
        "items.append()",
        "list(iterable=items)",
    ],
)
def test_native_list_errors_prevent_later_dispatch(operation):
    report = check(
        "items = [request]\n" + operation + "\nreturn dispatch(principal, request)"
    )
    assert report["entries"][0]["status"] == "verified", report
    assert not report["entries"][0]["dispatches"]


def test_list_error_handler_still_needs_authorization():
    report = check("""
        items = []
        try:
            items.pop()
        except Exception:
            return dispatch(principal, request)
    """)
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


@pytest.mark.parametrize("reauthorize", [False, True])
def test_every_list_iteration_requires_fresh_authority(reauthorize):
    renewal = (
        "decision = permission(principal, selected)\n    if decision.verdict is not Verdict.ALLOW:\n        raise PermissionError('denied')\n    "
        if reauthorize
        else ""
    )
    report = check(
        "decision = permission(principal, request)\nif decision.verdict is not Verdict.ALLOW:\n    raise PermissionError('denied')\nfor selected in [request, request]:\n    "
        + renewal
        + "dispatch(principal, selected)"
    )
    assert report["complete"] is reauthorize, report
    assert len(report["entries"][0]["dispatches"]) == 2


def test_list_mutation_during_iteration_cannot_certify_a_snapshot():
    report = check("""
        items = [request]
        for selected in items:
            items.append(None)
            decision = permission(principal, selected)
            if decision.verdict is Verdict.ALLOW:
                dispatch(principal, selected)
    """)
    assert not report["complete"]
    assert any(
        i["reason"] == "list changed during active iteration"
        for i in report["entries"][0]["issues"]
    )


def test_list_loop_break_ends_iteration_before_the_next_read():
    report = check("""
        items = [request]
        for selected in items:
            items.clear()
            decision = permission(principal, selected)
            if decision.verdict is Verdict.ALLOW:
                dispatch(principal, selected)
            break
    """)
    assert report["complete"], report


def test_exception_prefix_cannot_reuse_old_list_contents():
    report = check("""
        items = [request]
        try:
            items[0] = 'changed'
            raise ValueError('failed')
        except Exception:
            decision = permission(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return dispatch(principal, items[0])
    """)
    assert not report["complete"]
    assert any(
        "exceptional list" in i["reason"] for i in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize("result", ["items", "items.append", "items.copy()"])
def test_lists_do_not_hide_executable_capabilities(result):
    report = check("items = [dispatch]\nreturn " + result)
    assert not report["complete"]
    assert any(
        "capability escapes" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_cyclic_lists_cannot_hide_executable_capabilities():
    report = check(
        "items = []\nitems.append(items)\nitems.append(dispatch)\nreturn items"
    )
    assert not report["complete"]
    assert any(
        "capability escapes" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_bound_list_method_keeps_receiver_dependency():
    report = check("""
        items = []
        method = items.append
        decision = permission(principal, method)
        if decision.verdict is Verdict.ALLOW:
            items.append(request)
            return dispatch(principal, method)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_native_list_type_query_and_empty_truth_are_precise():
    report = check("""
        items = list()
        if items:
            dispatch(principal, request)
        items.append(request)
        if isinstance(items, list) and len(items) == 1:
            decision = permission(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return dispatch(principal, items[0])
    """)
    assert report["complete"], report


def test_dataclass_list_factory_allocates_a_mutable_dependency():
    report = record_check(
        """
        payload = request
        request = Request(principal)
        request.items.append(payload)
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            request.items.clear()
            return dispatch(principal, request)
    """,
        """
        @dataclass
        class Request:
            principal: object
            items: object = field(default_factory=list)
    """,
    )
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated", report
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_tuple_conversion_snapshots_list_outer_storage():
    report = check("""
        items = [request]
        snapshot = tuple(items)
        decision = permission(principal, snapshot)
        if decision.verdict is Verdict.ALLOW:
            items.clear()
            return dispatch(principal, snapshot)
    """)
    assert report["complete"], report


def test_list_members_are_unhashable_before_later_dispatch():
    report = check("frozenset([[]])\nreturn dispatch(principal, request)")
    assert report["entries"][0]["status"] == "verified", report
    assert not report["entries"][0]["dispatches"]


def test_custom_index_protocol_cannot_be_treated_as_an_inert_integer():
    report = check(
        """
        items = [request]
        selected = items[Index()]
        decision = permission(principal, selected)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, selected)
    """,
        """
        class Index:
            def __index__(self):
                return 0
    """,
    )
    assert not report["complete"]
    assert any(
        "list index requires an inert integer protocol" == i["reason"]
        for i in report["entries"][0]["issues"]
    )


def test_native_list_snapshot_contract():
    value = object()
    items = [value]
    copied = items[:]
    items.extend(items)
    assert len(items) == 2
    assert items.pop(-1) is value
    items.clear()
    assert copied[0] is value
