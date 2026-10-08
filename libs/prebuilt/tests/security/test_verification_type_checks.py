"""Standard type guards preserve mediation facts; candidate sources never run."""

import builtins
from collections import abc
from dataclasses import replace
from types import MappingProxyType, NoneType

import pytest

from langgraph.prebuilt.security.verification import _TYPE_BASES, _Program, verify
from tests.security.test_verification import spec
from tests.security.test_verification_continuations import AUTHORIZE, check


def test_standard_type_relationships_match_the_running_python_runtime():
    """Validate the primitive table against stdlib types, never candidate code."""
    standard = {
        name: getattr(builtins, name)
        for name in (
            "object",
            "bool",
            "int",
            "float",
            "complex",
            "str",
            "bytes",
            "list",
            "tuple",
            "dict",
            "frozenset",
            "BaseException",
            "Exception",
            "OSError",
            "PermissionError",
            "TimeoutError",
            "ValueError",
            "RuntimeError",
            "NotImplementedError",
            "TypeError",
            "LookupError",
            "KeyError",
        )
    }
    standard.update(
        {
            "types.MappingProxyType": MappingProxyType,
            "types.NoneType": NoneType,
            "collections.abc.Mapping": abc.Mapping,
            "collections.abc.MutableMapping": abc.MutableMapping,
            "collections.abc.Sequence": abc.Sequence,
            "collections.abc.Set": abc.Set,
        }
    )
    assert set(standard) == set(_TYPE_BASES)
    program = _Program(spec())
    for name, runtime_type in standard.items():
        lineage = program.type_lineage(name)
        assert lineage is not None
        for candidate, parent in standard.items():
            assert (candidate in lineage) == issubclass(runtime_type, parent), (
                name,
                candidate,
            )


@pytest.mark.parametrize(
    "value, classinfo, expected",
    [
        ("True", "int", True),
        ("1", "bool", False),
        ("None", "object", True),
        ("None", "NoneType", True),
        ("'text'", "str", True),
        ("'text'", "int", False),
        ("{}", "dict", True),
        ("{}", "Mapping", True),
        ("{}", "MutableMapping", True),
        ("{}", "Sequence", False),
        ("()", "Sequence", True),
        ("b'data'", "Sequence", True),
        ("MappingProxyType({})", "Mapping", True),
        ("MappingProxyType({})", "MutableMapping", False),
        ("MappingProxyType({})", "dict", False),
        ("Child()", "Base", True),
        ("Base()", "Child", False),
        ("Child()", "object", True),
        ("1", "(str, (bool, int))", True),
        ("1", "()", False),
        ("1", "(int, 7)", True),
    ],
)
def test_known_type_guards_follow_builtin_and_source_inheritance(
    value, classinfo, expected
):
    report = check(
        f"if isinstance({value}, {classinfo}) is {not expected}:\n"
        "    return dispatch(principal, request)\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        """
        from collections.abc import Mapping, MutableMapping, Sequence
        from types import MappingProxyType, NoneType
        class Base:
            pass
        class Child(Base):
            pass
        """,
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_unknown_type_guard_keeps_both_authorized_paths():
    report = check("""
        if isinstance(request, int):
            selected = request
        else:
            selected = principal
        d = permission(principal, selected)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, selected)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 2


def test_repeated_type_guards_retain_the_same_value_identity():
    report = check("""
        if isinstance(request, int):
            if not isinstance(request, int):
                return dispatch(principal, request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert report["complete"], report


def test_unknown_type_match_is_not_authorization():
    report = check("""
        if isinstance(request, int):
            return dispatch(principal, request)
    """)
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_type_tuple_can_match_before_a_later_invalid_item():
    report = check("""
        if isinstance(request, (int, 7)):
            return dispatch(principal, request)
    """)
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])
    assert report["entries"][0]["settled_exceptions"] > 0


@pytest.mark.parametrize(
    "call",
    [
        "isinstance(request, 7)",
        "isinstance(request)",
        "isinstance(request, int, extra=True)",
    ],
)
def test_invalid_type_call_terminates_its_path(call):
    report = check(
        AUTHORIZE
        + "\ndispatch(principal, request)\n"
        + call
        + "\ndispatch(principal, request)"
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_invalid_type_call_reaches_an_enclosing_handler():
    report = check("""
        try:
            isinstance(request, 7)
        except TypeError:
            return dispatch(principal, request)
    """)
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_all_classinfo_argument_expressions_are_evaluated_before_type_matching():
    report = check("""
        if isinstance(1, (int, dispatch(principal, request))):
            return None
    """)
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_positive_type_guard_does_not_trust_unknown_receiver_methods():
    report = check("""
        if isinstance(request, dict):
            request.get('value')
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert not report["complete"]
    assert any(
        "request.get" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize("type_name", ["Custom", "Child"])
def test_metaclass_checks_remain_unresolved(type_name):
    report = check(
        f"isinstance(request, {type_name})\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        """
        class Meta(type):
            def __instancecheck__(self, value):
                return value
        class Custom(metaclass=Meta):
            pass
        class Child(Custom):
            pass
        """,
    )
    assert not report["complete"]
    assert any(
        "metaclass" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


def test_type_query_aliases_keep_standard_semantics():
    report = check(
        """
        matches = standard.isinstance
        integer = int
        if matches('text', integer):
            return dispatch(principal, request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        "import builtins as standard\n",
    )
    assert report["complete"], report


def test_shadowed_type_query_is_analyzed_as_source():
    report = check(
        "return isinstance(principal, request)",
        """
        def isinstance(principal, request):
            return dispatch(principal, request)
        """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_shadowed_type_name_does_not_match_a_builtin():
    report = check(
        "if isinstance(1, int):\n    return dispatch(principal, request)\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        "class int:\n    pass\n",
    )
    assert report["complete"], report


def test_instance_checker_object_cannot_be_pruned_as_an_invalid_type():
    report = check(
        "if isinstance(request, Checker()):\n    return dispatch(principal, request)\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        """
        class Checker:
            def __instancecheck__(self, value):
                return True
        """,
    )
    assert not report["complete"]
    assert any(
        "instance-check protocol" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


@pytest.mark.parametrize(
    "module, name",
    [
        ("builtins", "int"),
        ("collections.abc", "Mapping"),
        ("types", "MappingProxyType"),
    ],
)
def test_supplied_source_cannot_replace_standard_type_semantics(module, name):
    original = spec(f"""
from {module} import {name} as ReplacedType
class Tool:
    def invoke(self, principal, request):
        if not isinstance({{}}, ReplacedType):
            return dispatch(principal, request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    report = verify(
        replace(
            original,
            sources={
                **original.sources,
                module: f"class {name}:\n    pass\n",
            },
        )
    )
    assert not report["complete"]
    assert any("type-model module" in issue["reason"] for issue in report["issues"])
