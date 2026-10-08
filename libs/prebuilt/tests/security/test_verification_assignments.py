"""Assignment-expression and local-annotation transfer checks; source only."""

import pytest

from tests.security.test_verification_continuations import AUTHORIZE, check


def test_named_decision_preserves_authorization_and_returned_identity():
    report = check("""
        if (d := permission(principal, request)).verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(principal, request)
    """)
    assert report["complete"], report


@pytest.mark.parametrize("comparison", ["is", "is not"])
def test_named_request_in_comparison_is_bound_for_subsequent_dispatch(comparison):
    report = check(f"""
        if (selected := request) {comparison} None:
            d = permission(principal, selected)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, selected)
    """)
    assert report["complete"], report


def test_named_assignment_cannot_replace_authorized_request():
    report = check(AUTHORIZE + "\nreturn dispatch(principal, (request := 'changed'))")
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_named_assignment_does_not_confer_permission_by_truthiness():
    report = check("""
        if d := permission(principal, request):
            return dispatch(principal, request)
    """)
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_named_assignment_preserves_false_branch_binding():
    report = check("""
        if selected := None:
            raise ValueError('unreachable')
        d = permission(principal, selected)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, selected)
    """)
    assert report["complete"], report


def test_short_circuit_does_not_perform_skipped_named_assignment():
    report = check("""
        selected = request
        skipped = False and (selected := 'changed')
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, selected)
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "declaration", ["selected: object", "selected: dispatch(principal, request)"]
)
def test_local_annotation_does_not_evaluate_or_clear_existing_value(declaration):
    report = check(
        "selected = request\n"
        + declaration
        + AUTHORIZE
        + "\nreturn dispatch(principal, selected)"
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_annotated_assignment_evaluates_value_but_not_annotation():
    report = check("""
        selected: dispatch(principal, request) = request
        d = permission(principal, selected)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, selected)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_annotated_value_cannot_hide_unchecked_effect():
    report = check("value: object = dispatch(principal, request)")
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_annotation_on_nonlocal_target_remains_unresolved():
    report = check(
        "request.field: object\n" + AUTHORIZE + "\ndispatch(principal, request)"
    )
    assert not report["complete"]
    assert any(
        "AnnAssign" in issue["reason"] for issue in report["entries"][0]["issues"]
    )
