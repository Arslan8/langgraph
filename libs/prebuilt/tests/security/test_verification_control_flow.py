"""Source-only safety checks for compound conditions, tuples and exceptions."""

from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import (
    VerificationSpec,
    installed_spec,
    verify,
)


def check(body: str, helpers: str = ""):
    source = (
        "from policy import permission, Verdict\nfrom legacy import dispatch\n"
        + dedent(helpers)
        + "class Tool:\n"
        + "    def invoke(self, principal, request, enabled=True):\n"
        + "\n".join("        " + line for line in dedent(body).strip().splitlines())
        + "\n"
    )
    return verify(
        VerificationSpec(
            sources={"example": source},
            surfaces=("example.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
        )
    )


@pytest.mark.parametrize(
    "condition",
    [
        "d.verdict is Verdict.ALLOW and enabled",
        "not (d.verdict is not Verdict.ALLOW or not enabled)",
    ],
)
def test_short_circuit_verdict_guards(condition):
    report = check(f"""
        d = permission(principal, request)
        allowed = {condition}
        if allowed:
            return dispatch(principal, request)
        raise PermissionError('denied')
    """)
    assert report["complete"], report


def test_disjunction_does_not_make_authorization_optional():
    report = check("""
        d = permission(principal, request)
        if enabled or d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        raise PermissionError('denied')
    """)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_short_circuit_rhs_is_visited_for_effects():
    report = check("return enabled or dispatch(principal, request)")
    assert report["entries"][0]["status"] == "violated"
    assert report["entries"][0]["dispatches"]


@pytest.mark.parametrize(
    "dispatch_args,complete", [("subject, call", True), ("call, subject", False)]
)
def test_helper_tuple_unpacking_preserves_bound_identities(dispatch_args, complete):
    report = check(
        f"""
        d, (subject, call) = prepare(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch({dispatch_args})
    """,
        """
        def prepare(principal, request):
            d = permission(principal, request)
            return d, (principal, request)
    """,
    )
    assert report["complete"] is complete, report


def test_tuple_projection_preserves_callable_effects():
    report = check("return (dispatch,)[0](principal, request)")
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "wrapper",
    [
        "return ((dispatch,),)",
        "return (dispatch,).__getitem__",
        "raise ValueError((dispatch,))",
        "return ValueError(dispatch)",
        "try:\n    raise ValueError(dispatch)\nexcept Exception as error:\n    return error",
        "try:\n    raise ValueError(dispatch)\nexcept Exception:\n    raise",
    ],
)
def test_aggregate_and_exception_paths_cannot_export_execution_capabilities(wrapper):
    report = check(wrapper)
    assert not report["complete"]
    assert report["entries"][0]["issues"]


def test_handler_may_reauthorize_after_failure():
    report = check("""
        try:
            raise ValueError('retry')
        except Exception:
            d = permission(principal, request)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
            return dispatch(principal, request)
        finally:
            pass
    """)
    assert report["complete"], report


@pytest.mark.parametrize("clause", ["except Exception:", "finally:"])
def test_error_path_requires_its_own_authorization(clause):
    report = check(f"""
        try:
            d = permission(principal, request)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
            return dispatch(principal, request)
        {clause}
            return dispatch(principal, request)
    """)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_finally_preserves_a_returned_authorization_tuple():
    report = check(
        """
        d, subject, call = prepare(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(subject, call)
    """,
        """
        def prepare(principal, request):
            try:
                return permission(principal, request), principal, request
            finally:
                'cleanup'
    """,
    )
    assert report["complete"], report


def test_failed_assignment_does_not_replace_request_before_finally():
    report = check(
        """
        try:
            request = fail()
        finally:
            if request is None:
                return None
            return dispatch(principal, request)
    """,
        """
        def fail():
            raise ValueError('failed')
    """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_raise_cause_is_analyzed_for_dispatch():
    report = check("raise PermissionError('denied') from dispatch(principal, request)")
    assert report["entries"][0]["status"] == "violated"


def test_exception_objects_are_not_conflated():
    report = check("""
        request = ValueError('first')
        d = permission(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(principal, ValueError('second'))
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "authorize, dispatch, complete",
    [
        (
            "call=request, principal=principal",
            "constraints=d.constraints, call=request, principal=principal",
            True,
        ),
        ("principal, request", "principal, request, d.constraints", True),
        (
            "call=request, principal=principal",
            "principal=request, call=principal, constraints=d.constraints",
            False,
        ),
        ("principal, call=request", "principal, request, None", False),
        (
            "principal, request, principal=principal",
            "principal, request, d.constraints",
            False,
        ),
        ("principal, typo=request", "principal, request, d.constraints", False),
        ("principal=principal", "principal, request, d.constraints", False),
        ("principal, request, None, None", "principal, request, d.constraints", False),
        ("principal, request", "principal, request", False),
    ],
)
def test_terminal_signatures_bind_exact_constraints(authorize, dispatch, complete):
    source = f"""
from policy import permission, Verdict
from legacy import dispatch
class Tool:
    def invoke(self, principal, request):
        d = permission({authorize})
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch({dispatch})
"""
    report = verify(
        VerificationSpec(
            sources={"example": source},
            surfaces=("example.Tool",),
            authorizers=(
                Authorizer(
                    "policy.permission", ("arg:0", "arg:1", "result:constraints")
                ),
            ),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1", "arg:2")),),
            terminal_parameters={
                "policy.permission": ("principal", "call", "approval"),
                "legacy.dispatch": ("principal", "call", "constraints"),
            },
        )
    )
    assert report["complete"] is complete, report


def test_keyword_terminal_requires_signature():
    report = check("""
        d = permission(principal=principal, call=request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert not report["complete"]


def test_installed_terminal_inventory_covers_both_host_paths():
    spec = installed_spec()
    guarded = "langgraph.prebuilt.security.guarded._GuardedExecutor"
    node = "langgraph.prebuilt.tool_node.ToolNode"
    assert {item.target for item in spec.operations} == {
        f"{prefix}.{method}"
        for prefix in (
            f"{guarded}.security.host_executor",
            f"{node}._security_host_executor",
        )
        for method in ("invoke", "ainvoke")
    }
    assert {item.target for item in spec.authorizers} == {
        f"{prefix}.{method}"
        for prefix in (f"{guarded}.stack", f"{node}._security_stack")
        for method in ("permission", "apermission")
    }
    assert all(item.bindings == ("arg:0", "arg:1", "arg:2") for item in spec.operations)
    assert all(
        item.bindings == ("arg:0", "arg:1", "result:constraints")
        for item in spec.authorizers
    )
    assert len(spec.async_terminals) == 4
    assert len(spec.terminal_parameters) == 8


def test_exceptional_local_cannot_hide_escaped_dispatch():
    report = check("""
        try:
            executable = dispatch
            raise ValueError('failure')
        except ValueError:
            return executable
    """)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"


@pytest.mark.parametrize("suite", ["else", "handler"])
def test_finally_covers_failure_prefixes_outside_try_body(suite):
    source = """
        executable = None
        try:
            pass
        except ValueError:
            BODY_HANDLER
        else:
            BODY_ELSE
        finally:
            return executable
    """
    prefix = "executable = dispatch\n            permission(principal, request)\n            executable = None"
    source = source.replace("BODY_HANDLER", prefix if suite == "handler" else "pass")
    source = source.replace("BODY_ELSE", prefix if suite == "else" else "pass")
    report = check(source)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"
