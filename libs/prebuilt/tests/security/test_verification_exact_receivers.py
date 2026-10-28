"""Exact receiver proofs require a layout that prevents method shadowing."""

from dataclasses import replace
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import (
    ReturnProtocol,
    VerificationSpec,
    verify,
)

ROUTER = """
class Router:
    __slots__ = ('value',)
    def execute(self, principal, request):
        decision = permission(principal, request)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(principal, request)
"""
BODY = """
if type(router) is not Router:
    raise PermissionError('unsupported receiver')
return router.execute(principal, request)
"""


def contract(body=BODY, router=ROUTER, *, asynchronous=False):
    prefix = "async " if asynchronous else ""
    if asynchronous:
        router = (
            router.replace("def execute", "async def execute")
            .replace("= permission(", "= await permission(")
            .replace("return dispatch(", "return await dispatch(")
        )
        body = body.replace("return router.execute(", "return await router.execute(")
    return VerificationSpec(
        sources={
            "sample": (
                "from policy import permission, Verdict\nfrom host import dispatch\n"
                + dedent(router)
                + f"class Tool:\n    {prefix}def invoke(self, router, principal, request):\n"
                + "\n".join(
                    "        " + line for line in dedent(body).strip().splitlines()
                )
                + "\n"
            )
        },
        surfaces=("sample.Tool",),
        authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
        operations=(Operation("host.dispatch", ("arg:0", "arg:1")),),
        async_terminals=("policy.permission", "host.dispatch") if asynchronous else (),
        return_protocols={"sample.Tool.invoke": ReturnProtocol(("host.dispatch",))},
    )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_guarded_receiver_enters_source_method_instead_of_trusting_a_helper(
    asynchronous,
):
    report = verify(contract(asynchronous=asynchronous))
    assert report["complete"], report
    entry = report["entries"][0]
    assert "sample.Router.execute" in entry["visited_functions"]
    assert entry["dispatches"] and all(
        site["authorized"] for site in entry["dispatches"]
    )
    assert all(
        outcome["kind"] == "authorized_operation"
        for outcome in entry["return_outcomes"]
    )


@pytest.mark.parametrize(
    "body",
    [
        BODY.replace("type(router) is not Router", "not isinstance(router, Router)"),
        BODY.replace("type(router)", "type(request)"),
        "return router.execute(principal, request)",
        BODY.replace(
            "return router.execute", "router = request\nreturn router.execute"
        ),
    ],
)
def test_missing_weak_or_wrong_object_guard_does_not_bind_source_methods(body):
    assert not verify(contract(body))["complete"]


@pytest.mark.parametrize(
    "guard",
    [
        "type(router) is not Router",
        "Router is not type(router)",
        "not (type(router) is Router)",
    ],
)
def test_native_identity_guard_forms_preserve_receiver_binding(guard):
    assert verify(contract(BODY.replace("type(router) is not Router", guard)))[
        "complete"
    ]


def test_dictionary_bearing_instance_can_shadow_methods_despite_exact_class():
    report = verify(contract(router=ROUTER.replace("    __slots__ = ('value',)\n", "")))
    assert not report["complete"]
    assert any(
        "unresolved call target" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "declaration",
    [
        "__slots__ = ('__dict__',)",
        "__slots__ = ('__weakref__',)",
        "__slots__ = ('execute',)",
        "__slots__ = ('value', 'value')",
        "__slots__ = ['value']",
        "__slots__ = dynamic()",
    ],
)
def test_unmodeled_or_shadowable_slot_layout_cannot_grant_a_receiver_model(declaration):
    report = verify(
        contract(router=ROUTER.replace("__slots__ = ('value',)", declaration))
    )
    assert not report["complete"]
    assert report["issues"]


def test_ordinary_base_can_reintroduce_instance_dictionary():
    router = "class Base:\n    pass\n" + ROUTER.replace(
        "class Router:", "class Router(Base):"
    )
    assert not verify(contract(router=router))["complete"]


def test_guard_is_not_a_permission_and_source_method_still_has_to_prove_dispatch():
    router = ROUTER.replace("if decision.verdict is not Verdict.ALLOW:", "if False:")
    report = verify(contract(router=router))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_type_query_aliases_preserve_identity():
    body = "alias = router\nquery = type(alias)\n" + BODY.replace(
        "type(router)", "query"
    )
    assert verify(contract(body))["complete"]


def test_same_class_alternate_instance_does_not_share_slot_values():
    router = ROUTER.replace(
        "permission(principal, request)", "permission(principal, self.value)"
    )
    report = verify(contract(router=router))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_input_slot_may_be_unset_but_present_value_is_bound_consistently():
    router = ROUTER.replace(
        "permission(principal, request)", "permission(principal, self.value)"
    ).replace("dispatch(principal, request)", "dispatch(principal, self.value)")
    report = verify(contract(router=router))
    assert report["complete"], report
    assert report["entries"][0]["dispatches"]


def test_distinct_input_names_may_alias_the_same_slot_storage():
    body = BODY.replace(
        "return router.execute(principal, request)",
        """if type(principal) is not Router:
    raise PermissionError('unsupported receiver')
decision = permission('actor', router.value)
principal.value = request
if decision.verdict is not Verdict.ALLOW:
    raise PermissionError('denied')
return dispatch('actor', router.value)""",
    )
    report = verify(contract(body))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_untyped_authorized_input_may_alias_a_mutated_typed_receiver():
    body = BODY.replace(
        "return router.execute(principal, request)",
        """decision = permission(principal, request)
router.value = None
if decision.verdict is not Verdict.ALLOW:
    raise PermissionError('denied')
return dispatch(principal, request)""",
    )
    report = verify(contract(body))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_unset_slot_handler_cannot_dispatch_without_permission():
    body = BODY.replace(
        "return router.execute(principal, request)",
        """try:
    value = router.value
except Exception:
    return dispatch(principal, request)
return router.execute(principal, request)""",
    )
    report = verify(contract(body))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_failed_method_shadowing_does_not_hide_exception_handler_effects():
    body = BODY.replace(
        "return router.execute(principal, request)",
        """try:
    router.execute = None
except Exception:
    return dispatch(principal, request)
return router.execute(principal, request)""",
    )
    report = verify(contract(body))
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_empty_slots_and_known_subclass_identity_do_not_grant_parent_identity():
    router = ROUTER.replace("__slots__ = ('value',)", "__slots__ = ()")
    assert verify(contract(router=router))["complete"]
    router += "\nclass Child(Router):\n    pass\n"
    report = verify(contract("router = Child()\n" + BODY, router=router))
    assert report["complete"], report
    assert not report["entries"][0]["dispatches"]


def test_runtime_type_objects_cannot_escape_as_inert_data():
    spec = contract(
        BODY.replace("return router.execute(principal, request)", "return type(router)")
    )
    report = verify(replace(spec, return_protocols={}))
    assert not report["complete"]
    assert any(
        "capability escapes" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )
