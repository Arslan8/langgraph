"""Static typing metadata must not grant runtime types or authorization."""

from dataclasses import replace
from textwrap import dedent
from typing import TYPE_CHECKING, cast

import pytest

from langgraph.prebuilt.security.mediation import Operation
from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec
from tests.security.test_verification_control_flow import check as check_source

_ALLOW = dedent("""
    decision = permission(principal, request)
    if decision.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
""")


def check(body, helpers=""):
    return check_source(body, dedent(helpers).rstrip() + "\n")


@pytest.mark.parametrize(
    ("imports", "expression"),
    [
        ("from typing import cast", 'cast("Request", request)'),
        (
            "from typing_extensions import cast as convert",
            'convert("Request", request)',
        ),
        ("import typing as t", 't.cast("Request", request)'),
        ("import typing_extensions as t", 't.cast(val=request, typ="Request")'),
    ],
)
def test_cast_preserves_authorized_value_identity(imports, expression):
    report = check(_ALLOW + f"\nreturn dispatch(principal, {expression})", imports)
    assert report["complete"], report


def test_cast_preserves_decision_identity_and_callable_authorization():
    report = check(
        """
        decision = cast('Decision', permission(principal, request))
        if decision.verdict is Verdict.ALLOW:
            operation = cast('Operation', dispatch)
            return operation(principal, request)
        """,
        "from typing import cast",
    )
    assert report["complete"], report


def test_cast_does_not_create_authorization():
    report = check(
        "return dispatch(principal, cast('Authorized', request))",
        "from typing import cast",
    )
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_cast_keeps_executable_escape_visible():
    report = check("return cast('str', dispatch)", "from typing import cast")
    assert not report["complete"]
    assert any(
        "capability escapes" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_cast_does_not_turn_unknown_input_into_a_native_mapping():
    report = check(
        """
        value = cast('dict', request).get('value')
        decision = permission(principal, value)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, value)
        """,
        "from typing import cast",
    )
    assert not report["complete"]
    assert any(
        "unresolved call target" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_cast_evaluates_type_argument_and_retains_its_effects():
    report = check(
        """
        box = {'value': request}
        decision = permission(principal, box)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, cast(change(box), box))
        """,
        """
        from typing import cast
        def change(box):
            box['value'] = 'changed'
            return None
        """,
    )
    assert not report["complete"]
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_cast_does_not_skip_a_call_in_its_type_argument():
    report = check(
        "return cast(dispatch(principal, request), None)",
        "from typing import cast",
    )
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "expression",
    [
        'cast("Request")',
        'cast("Request", request, request)',
        'cast("Request", request, val=request)',
        'cast(typ="Request", value=request)',
        "cast(val=request)",
    ],
)
def test_cast_binding_errors_prevent_later_dispatch(expression):
    report = check(
        expression + "\nreturn dispatch(principal, request)", "from typing import cast"
    )
    assert report["entries"][0]["status"] == "verified", report
    assert not report["entries"][0]["dispatches"]
    assert not report["complete"]  # No reachable dispatch obligation in this fixture.


def test_cast_binding_failure_cannot_hide_an_exception_handler():
    report = check(
        """
        try:
            cast('Request')
        except TypeError:
            return dispatch(principal, request)
        """,
        "from typing import cast",
    )
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_cast_open_keyword_forwarding_preserves_value_binding():
    report = verify(
        spec("""
from typing import cast
class Tool:
    def invoke(self, principal, **kwargs):
        request = kwargs['val']
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, cast('Request', **kwargs))
    """)
    )
    assert report["complete"], report


def test_cast_shadowing_uses_the_actual_source_function():
    report = check(
        _ALLOW + "\nreturn dispatch(principal, cast('Request', request))",
        """
        def cast(typ, val):
            return 'different'
        """,
    )
    assert report["entries"][0]["status"] == "violated"


def test_declared_terminal_named_cast_is_not_an_identity_operation():
    options = spec("""
from typing import cast
class Tool:
    def invoke(self, principal, request):
        return cast(principal, request)
    """)
    report = verify(
        replace(
            options,
            operations=(
                *options.operations,
                Operation("typing.cast", ("arg:0", "arg:1")),
            ),
        )
    )
    assert report["entries"][0]["status"] == "violated"


def test_cast_is_not_an_async_primitive():
    report = verify(
        spec("""
from typing import cast
class Tool:
    async def invoke(self, principal, request):
        return await cast('Request', request)
    """)
    )
    assert not report["complete"]
    assert any(
        "cannot be awaited" in i["reason"] for i in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    ("imports", "condition"),
    [
        ("from typing import TYPE_CHECKING", "TYPE_CHECKING"),
        ("from typing_extensions import TYPE_CHECKING as TC", "TC"),
        ("import typing as t", "t.TYPE_CHECKING"),
        ("import typing_extensions", "typing_extensions.TYPE_CHECKING"),
    ],
)
def test_type_only_definitions_do_not_supply_runtime_api_bindings(imports, condition):
    report = verify(
        spec(f"""
{imports}
if {condition}:
    from unavailable import something
    @unknown_decorator
    class Tool:
        def type_only(self):
            return something()
else:
    class Tool:
        def invoke(self, principal, request):
            decision = permission(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """)
    )
    assert report["complete"], report
    assert set(report["surfaces"]["example.Tool"]) == {"invoke"}


def test_type_only_import_does_not_override_runtime_helper():
    report = verify(
        spec("""
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from policy import permission as execute
else:
    from legacy import dispatch as execute
class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)
    """)
    )
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_function_type_checking_branch_is_not_runtime_authorization():
    report = check(
        """
        if TYPE_CHECKING:
            decision = permission(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
        return dispatch(principal, request)
        """,
        "from typing import TYPE_CHECKING",
    )
    assert report["entries"][0]["status"] == "violated"
    assert "policy.permission" not in report["entries"][0]["visited_functions"]


def test_runtime_branch_definitions_are_discovered_through_nested_conditions():
    options = spec("""
import typing as t
if not t.TYPE_CHECKING:
    if False or not t.TYPE_CHECKING:
        class Tool:
            def invoke(self, principal, request):
                decision = permission(principal, request)
                if decision.verdict is Verdict.ALLOW:
                    return dispatch(principal, request)
    """)
    assert verify(options)["complete"]


@pytest.mark.parametrize(
    "prefix",
    [
        "",  # Missing import.
        "from fake_typing import TYPE_CHECKING\n",
        "def TYPE_CHECKING():\n    return False\n",
        "from typing import TYPE_CHECKING\nTYPE_CHECKING = True\n",
    ],
)
def test_unknown_or_rebound_type_checking_never_hides_source(prefix):
    options = spec(
        prefix
        + """
if TYPE_CHECKING:
    unknown_initialization()
class Tool:
    def invoke(self, principal, request):
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """
    )
    assert not verify(options)["complete"]


def test_module_condition_cannot_use_a_later_import():
    report = verify(
        spec("""
if typing.TYPE_CHECKING:
    unknown_initialization()
import typing
class Tool:
    def invoke(self, principal, request):
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert not report["complete"]
    assert any("module initialization" in i["reason"] for i in report["issues"])


def test_standard_typing_module_override_invalidates_native_model():
    options = spec("""
from typing import TYPE_CHECKING
if not TYPE_CHECKING:
    class Tool:
        def invoke(self, principal, request):
            decision = permission(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """)
    options.sources["typing"] = "TYPE_CHECKING = True\n"
    assert not verify(options)["complete"]


def test_local_type_checking_parameter_is_not_the_typing_constant():
    report = verify(
        spec("""
from typing import TYPE_CHECKING
class Tool:
    def invoke(self, principal, request, TYPE_CHECKING):
        if TYPE_CHECKING:
            decision = permission(principal, request)
            if decision.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
        return dispatch(principal, request)
    """)
    )
    assert not report["complete"]
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_type_checking_boolean_short_circuit_does_not_evaluate_unknown_operand():
    report = verify(
        spec("""
from typing import TYPE_CHECKING
if TYPE_CHECKING and unknown_condition():
    unknown_initialization()
class Tool:
    def invoke(self, principal, request):
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert report["complete"], report


def test_unknown_left_operand_cannot_be_pruned_by_false_type_checking():
    report = verify(
        spec("""
from typing import TYPE_CHECKING
if unknown_condition() and TYPE_CHECKING:
    pass
class Tool:
    def invoke(self, principal, request):
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert not report["complete"]


def test_conditional_runtime_import_reexports_the_real_helper():
    options = spec("""
from facade import execute
class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)
    """)
    options.sources["facade"] = dedent("""
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from absent import execute
        else:
            from implementation import execute
    """)
    options.sources["implementation"] = dedent("""
        from policy import permission, Verdict
        from legacy import dispatch
        def execute(principal, request):
            decision = permission(principal, request)
            if decision.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """)
    report = verify(options)
    assert report["complete"], report
    assert "implementation.execute" in report["entries"][0]["visited_functions"]


def test_native_typing_contract_preserves_identity_without_inspection():
    class Opaque:
        def __bool__(self):
            raise AssertionError("cast must not inspect the value")

        def __repr__(self):
            raise AssertionError("cast must not inspect the type")

    value, annotation = Opaque(), Opaque()
    assert cast(annotation, value) is value
    assert cast(val=value, typ=annotation) is value
    assert TYPE_CHECKING is False
