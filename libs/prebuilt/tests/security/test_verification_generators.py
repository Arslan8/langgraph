"""Source-only immediate-generator analysis; no candidate body is executed."""

from itertools import product
from textwrap import dedent, indent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import VerificationSpec, verify


def check(body, helpers="", *, asynchronous=False):
    source = (
        "from __future__ import annotations\n"
        "import builtins\n"
        "from policy import permission, Verdict\n"
        "from legacy import dispatch\n"
        + dedent(helpers)
        + "\nclass Tool:\n"
        + ("    async def" if asynchronous else "    def")
        + " invoke(self, principal, request, alternate):\n"
        + indent(dedent(body).strip(), "        ")
        + "\n"
    )
    return verify(
        VerificationSpec(
            sources={"fixture": source},
            surfaces=("fixture.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
        )
    )


def iterable(shape, count):
    values = ", ".join("request" for _ in range(count))
    if shape == "tuple":
        return "(" + values + ("," if count else "") + ")"
    if shape == "list":
        return "[" + values + "]"
    if shape == "mapping_values":
        return "{" + ", ".join(f"'k{i}': request" for i in range(count)) + "}.values()"
    raise AssertionError(shape)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("consumer", ["tuple", "list"])
@pytest.mark.parametrize("callee_form", ["direct", "qualified", "alias"])
@pytest.mark.parametrize("shape", ["tuple", "list", "mapping_values"])
@pytest.mark.parametrize("count", range(4))
@pytest.mark.parametrize(
    "guard", ["allow_only", "missing", "deny_only", "wrong_binding"]
)
def test_immediate_consumer_permutation_matrix(
    asynchronous, consumer, callee_form, shape, count, guard
):
    callee = f"builtins.{consumer}" if callee_form == "qualified" else consumer
    setup = ""
    if callee_form == "alias":
        setup, callee = f"consume = {consumer}", "consume"
    checked_value = "alternate" if guard == "wrong_binding" else "value"
    guarded = ""
    if guard != "missing":
        condition = (
            "decision.verdict is Verdict.DENY"
            if guard == "deny_only"
            else "decision.verdict is not Verdict.ALLOW"
        )
        guarded = f"if {condition}:\n    raise PermissionError('denied')\n"
    helper = "def execute(principal, value, alternate):\n" + indent(
        f"decision = permission(principal, {checked_value})\n"
        + guarded
        + "return dispatch(principal, value)\n",
        "    ",
    )
    proof = check(
        f"""
        {setup}
        return {callee}(execute(principal, item, alternate) for item in {iterable(shape, count)})
        """,
        helper,
        asynchronous=asynchronous,
    )
    expected = "verified" if guard == "allow_only" or count == 0 else "violated"
    assert not proof["issues"], proof
    assert proof["entries"][0]["status"] == expected, proof
    # The entry can prove that an empty iterable has no effects. The existing
    # whole-spec gate also requires at least one dispatch obligation; preserve
    # that gate rather than treating an empty test case as coverage evidence.
    assert proof["complete"] is (expected == "verified" and count > 0), proof
    if count:
        assert proof["entries"][0]["dispatches"], proof
    else:
        assert not proof["entries"][0]["dispatches"], proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
@pytest.mark.parametrize("count", range(4))
def test_a_single_prior_grant_cannot_cover_multiple_generated_effects(consumer, count):
    proof = check(f"""
        decision = permission(principal, request)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return {consumer}(dispatch(principal, item) for item in {iterable("tuple", count)})
    """)
    expected = "verified" if count <= 1 else "violated"
    assert proof["entries"][0]["status"] == expected, proof
    assert [site["authorized"] for site in proof["entries"][0]["dispatches"]] == (
        [True] + [False] * (count - 1) if count else []
    )


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_first_iterable_is_evaluated_before_target_shadowing(consumer):
    proof = check(f"""
        item = (request,)
        values = {consumer}(item for item in item)
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, values[0])
    """)
    assert proof["complete"], proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_generator_targets_do_not_change_outer_authorization_bindings(consumer):
    proof = check(f"""
        values = {consumer}(principal for principal in (None,))
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert proof["complete"], proof
    assert proof["entries"][0]["dispatches"][0]["bindings"][1:] == [
        "input:principal",
        "input:request",
    ]


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_first_iterable_helper_runs_once_and_before_filter_and_element(consumer):
    proof = check(
        f"""
        order = []
        values = {consumer}(emit(order, item) for item in start(order, request) if accept(order))
        if len(order) != 3:
            return dispatch(principal, alternate)
        if order[0] != 'start' or order[1] != 'filter' or order[2] != 'element':
            return dispatch(principal, alternate)
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, values[0])
        """,
        """
        def start(order, value):
            order.append('start')
            return (value,)
        def accept(order):
            order.append('filter')
            return True
        def emit(order, value):
            order.append('element')
            return value
        """,
    )
    assert proof["complete"], proof
    assert len(proof["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_rejected_filter_still_requires_authorization_for_its_effect(consumer):
    proof = check(
        f"return {consumer}(None for item in (request,) if reject(principal, item))",
        """
        def reject(principal, request):
            dispatch(principal, request)
            return False
        """,
    )
    assert proof["entries"][0]["status"] == "violated", proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
@pytest.mark.parametrize("nested", [False, True])
def test_filters_skip_elements_and_later_iterables_in_source_order(consumer, nested):
    clauses = (
        "if False for inner in dispatch(principal, request)"
        if nested
        else "if False if dispatch(principal, request)"
    )
    proof = check(f"""
        values = {consumer}(dispatch(principal, request) for item in (request,) {clauses})
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert proof["complete"], proof
    assert len(proof["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("outer, inner", list(product(("tuple", "list"), repeat=2)))
def test_nested_immediate_generators_preserve_values(outer, inner):
    proof = check(f"""
        values = {outer}({inner}(value for value in (item,)) for item in (request,))
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, values[0][0])
    """)
    assert proof["complete"], proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_nested_aliases_remain_authorization_dependencies(consumer):
    proof = check(f"""
        nested = {{'value': request}}
        values = {consumer}(nested for item in (None,))
        decision = permission(principal, values)
        if decision.verdict is Verdict.ALLOW:
            nested['value'] = alternate
            return dispatch(principal, values)
    """)
    assert proof["entries"][0]["status"] == "violated", proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_failed_first_iterable_does_not_evaluate_body(consumer):
    proof = check(
        f"return {consumer}(dispatch(principal, request) for item in fail())",
        """
        def fail():
            raise ValueError('refused')
        """,
    )
    assert proof["entries"][0]["status"] == "verified", proof
    assert not proof["complete"]  # No dispatch obligation was reached.
    assert not proof["entries"][0]["dispatches"]


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_iteration_failure_still_analyzes_exception_handler(consumer):
    proof = check(
        f"""
        try:
            values = {consumer}(fail() for item in (request,))
        except:
            return dispatch(principal, request)
        """,
        """
        def fail():
            raise ValueError('refused')
        """,
    )
    assert proof["entries"][0]["status"] == "violated", proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_callee_resolution_precedes_the_first_iterable(consumer):
    proof = check(
        """
        box = {'value': alternate}
        values = choose(box, request)(item for item in (box['value'],))
        decision = permission(principal, request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, values[0])
        """,
        f"""
        def choose(box, request):
            box['value'] = request
            return {consumer}
        """,
    )
    assert proof["complete"], proof


@pytest.mark.parametrize(
    "body",
    [
        "values = (dispatch(principal, request) for item in (None,))\nreturn values",
        "values = (item for item in (request,))\nreturn tuple(values)",
        "return consume(item for item in (request,))",
        "return tuple(item for item in request)",
        "return tuple((saved := item) for item in (request,))",
        "return tuple(item async for item in request)",
        "return tuple(await execute(item) for item in (request,))",
        "return tuple((item for item in (request,)), unexpected=True)",
        "return tuple((item for item in (request,)), alternate)",
        "tuple = alternate\nreturn tuple(item for item in (request,))",
        "return frozenset(item for item in (request,))",
    ],
)
def test_deferred_unknown_or_unsupported_consumption_stays_unresolved(body):
    proof = check(body, asynchronous=True)
    assert not proof["complete"], proof
    assert proof["entries"][0]["status"] == "unresolved", proof


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_active_iterable_mutation_is_not_silently_snapshotted(consumer):
    proof = check(f"""
        source = [request]
        return {consumer}(source.append(alternate) for item in source)
    """)
    assert not proof["complete"], proof
    assert any(
        "list changed during active iteration" in issue["reason"]
        for issue in proof["entries"][0]["issues"]
    )


@pytest.mark.parametrize("consumer", ["tuple", "list"])
def test_generator_cannot_hide_executable_publication(consumer):
    proof = check(f"return {consumer}(dispatch for item in (None,))")
    assert not proof["complete"], proof
    assert any(
        "capability escapes" in issue["reason"]
        for issue in proof["entries"][0]["issues"]
    )


def test_native_immediate_consumption_order_with_benign_data():
    order = []

    def start():
        order.append("start")
        return ("first", "second")

    def emit(value):
        order.append(value)
        return value

    values = tuple(emit(item) for item in start())
    assert order == ["start", "first", "second"]
    assert values == ("first", "second")
