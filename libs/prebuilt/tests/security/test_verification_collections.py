"""Known immutable collection operations retain identity and mediation facts."""

from dataclasses import dataclass, field

import pytest

from tests.security.test_verification_continuations import AUTHORIZE
from tests.security.test_verification_control_flow import check
from tests.security.test_verification_records import check as record_check


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("frozenset()", False),
        ("frozenset(('read',))", True),
        ("len(frozenset(('read', 'read'))) == 1", True),
        ("len(frozenset((True, 1))) == 1", True),
        ("len(frozenset((True, 1, 'read'))) == 2", True),
        ("'read' in frozenset(('read',))", True),
        ("'write' in frozenset(('read',))", False),
        ("'write' not in frozenset(('read',))", True),
        ("frozenset(('read',)) <= frozenset(('read', 'write'))", True),
        ("frozenset(('read', 'write')) <= frozenset(('read',))", False),
        ("frozenset(('read',)) == frozenset(('read', 'read'))", True),
        ("frozenset(('read',)) == None", False),
        ("frozenset(('read',)) != None", True),
        ("isinstance(frozenset(), frozenset)", True),
        ("isinstance(frozenset(), Set)", True),
        ("isinstance(frozenset(), Sequence)", False),
        ("'read' in {'read': None}", True),
        ("'read' in {'read': None}.keys()", True),
        ("'read' in MappingProxyType({'read': None})", True),
        ("1 in {'read': None}", False),
        ("'read' in ('read', 'write')", True),
        ("frozenset(('read',)) in frozenset((frozenset(('read',)),))", True),
        ("('read', 1) in frozenset((('read', 1),))", True),
    ],
)
def test_inert_collection_predicates_choose_the_correct_branch(condition, expected):
    report = check(
        f"if {'not ' if expected else ''}({condition}):\n"
        "    dispatch(principal, request)\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        "from collections.abc import Set, Sequence\nfrom types import MappingProxyType\n",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("constructor", ["frozenset", "standard.frozenset", "frozen"])
def test_frozen_normalization_preserves_existing_identity(constructor):
    report = check(
        f"""
        request = frozenset(('read', 'write'))
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, {constructor}(request))
        """,
        "import builtins as standard\nfrom builtins import frozenset as frozen\n",
    )
    assert report["complete"], report


@pytest.mark.parametrize("factory", ["frozenset", "standard.frozenset"])
def test_frozen_default_factory_is_analyzed_and_inert(factory):
    report = record_check(
        """
        principal = Principal()
        if principal.roles:
            dispatch(None, None)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, request)
        """,
        f"""
        import builtins as standard
        @dataclass(frozen=True, slots=True)
        class Principal:
            roles: frozenset = field(default_factory={factory})
            def __post_init__(self):
                object.__setattr__(self, 'roles', frozenset(self.roles))
        """,
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "source",
    ["{'key': request}.values()", "MappingProxyType({'key': request}).values()"],
)
def test_tuple_conversion_of_live_mapping_values_preserves_bound_identity(source):
    report = check(
        f"calls = tuple({source})\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, calls[0])",
        "from types import MappingProxyType\n",
    )
    assert report["complete"], report


def test_tuple_conversion_of_items_preserves_names_and_values():
    report = check("""
        item = tuple({'key': request}.items())[0]
        name, value = item
        if name != 'key':
            return dispatch(None, None)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, value)
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "expression",
    ["len(())", "len({})", "len({}.items())", "len(frozenset())", "standard.len('')"],
)
def test_known_empty_collection_lengths_do_not_execute_dead_dispatches(expression):
    report = check(
        f"if {expression}:\n    dispatch(None, None)\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        "import builtins as standard\n",
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "expression",
    [
        "frozenset(({},))",
        "frozenset((({},),))",
        "frozenset(1)",
        "tuple(None)",
        "len(1)",
        "{} in frozenset()",
        "{} in {}",
    ],
)
def test_known_invalid_collection_operations_exit_before_later_dispatch(expression):
    report = check(
        AUTHORIZE
        + f"\ndispatch(principal, request)\n{expression}\ndispatch(None, None)"
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize(
    "expression",
    [
        "frozenset(request)",
        "frozenset((request,))",
        "request in frozenset()",
        "len(request)",
        "tuple(request)",
    ],
)
def test_unknown_iteration_hashing_equality_and_length_stay_unresolved(expression):
    report = check(
        f"value = {expression}\n" + AUTHORIZE + "\nreturn dispatch(principal, request)"
    )
    assert not report["complete"], report
    assert report["entries"][0]["issues"]


def test_candidate_hash_methods_are_never_assumed_inert():
    report = check(
        "frozenset((Key(),))\n" + AUTHORIZE + "\nreturn dispatch(principal, request)",
        """
        class Key:
            def __hash__(self):
                dispatch(None, None)
                return 1
        """,
    )
    assert not report["complete"]
    assert any(
        "hashing/equality" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


def test_function_shadowing_frozen_constructor_is_analyzed():
    report = check(
        "frozenset(principal, request)",
        """
        def frozenset(principal, request):
            return dispatch(principal, request)
    """,
    )
    assert report["entries"][0]["status"] == "violated", report


def test_constructor_argument_effects_are_not_hidden_by_hash_failure():
    report = check("frozenset(({}, dispatch(principal, request)))")
    assert report["entries"][0]["status"] == "violated", report


def test_multiple_frozen_members_do_not_gain_an_arbitrary_iteration_order():
    report = check("""
        first, second = tuple(frozenset(('read', 'write')))
        d = permission(principal, first)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, first)
    """)
    assert not report["complete"]
    assert any(
        "order model" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize("source", ["frozenset(('read',))", "'r'", "b'r'"])
def test_singleton_and_ordered_scalar_iteration_preserves_identity(source):
    report = check(f"""
        for scope in {source}:
            d = permission(principal, scope)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, scope)
    """)
    assert report["complete"], report


@pytest.mark.parametrize("source", ["frozenset()", "1"])
def test_empty_or_invalid_iteration_cannot_execute_body(source):
    report = check(
        AUTHORIZE
        + f"""
dispatch(principal, request)
for value in {source}:
    dispatch(None, None)
    """
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_native_frozen_contract_preserves_first_equal_member_and_identity():
    frozen = frozenset((True, 1))
    assert len(frozen) == 1
    assert next(iter(frozen)) is True
    assert frozenset(frozen) is frozen

    @dataclass
    class Record:
        roles: frozenset = field(default_factory=frozenset)

    assert Record().roles == frozenset()
