"""Method descriptors must preserve the actual receiver and authorization edge."""

from dataclasses import replace

import pytest
from typing_extensions import override

from langgraph.prebuilt.security.mediation import Operation
from langgraph.prebuilt.security.verification import _Program, verify
from tests.security.test_verification import spec
from tests.security.test_verification_control_flow import check
from tests.security.test_verification_records import check as record_check


def test_ordinary_receiver_binding_does_not_depend_on_parameter_spelling():
    report = verify(
        spec("""
class Tool:
    def invoke(receiver, principal, request):
        return receiver.run(principal, request)
    def run(arbitrary_name, principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("receiver", ["Tool", "self", "Tool()"])
def test_static_method_never_receives_an_implicit_instance(receiver):
    report = verify(
        spec(f"""
class Tool:
    def invoke(self, principal, request):
        return {receiver}.execute(principal, request)
    @staticmethod
    def execute(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert report["complete"], report


def test_static_parameter_named_self_remains_an_external_argument():
    report = verify(
        spec("""
class Tool:
    @staticmethod
    def invoke(self, request):
        d = permission(self, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(self, request)
    """)
    )
    assert report["complete"], report
    assert report["entries"][0]["dispatches"][0]["bindings"][1] == "input:self"


def test_inherited_classmethod_resolves_the_derived_class_override():
    report = verify(
        spec("""
class Tool:
    @classmethod
    def invoke(cls, principal, request):
        return cls.execute(principal, request)
    @staticmethod
    def execute(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
class Child(Tool):
    @staticmethod
    def execute(principal, request):
        return dispatch(principal, request)
    """)
    )
    assert not report["complete"]
    base = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    child = next(e for e in report["entries"] if e["entry"] == "example.Child.invoke")
    assert base["status"] == "verified", base
    assert child["status"] == "violated", child
    assert child["dispatches"][0]["call_path"][-1] == "example.Child.execute"


@pytest.mark.parametrize("receiver", ["Derived", "Derived()"])
def test_classmethod_lookup_on_a_helper_preserves_its_actual_class(receiver):
    report = check(
        f"return {receiver}.execute(principal, request)",
        """
        class Base:
            @classmethod
            def execute(cls, principal, request):
                return cls.finish(principal, request)
            @staticmethod
            def finish(principal, request):
                return None
        class Derived(Base):
            @staticmethod
            def finish(principal, request):
                return dispatch(principal, request)
    """,
    )
    assert report["entries"][0]["status"] == "violated", report
    assert (
        report["entries"][0]["dispatches"][0]["call_path"][-1]
        == "example.Derived.finish"
    )


def test_explicit_class_lookup_of_an_ordinary_method_remains_unbound():
    report = verify(
        spec("""
class Tool:
    def invoke(self, principal, request):
        return Tool.execute(self, principal, request)
    def execute(self, principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert report["complete"], report


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_async_descriptor_methods_keep_the_await_contract(decorator):
    prefix = "cls, " if decorator == "classmethod" else ""
    report = verify(
        spec(f"""
class Tool:
    async def ainvoke(self, principal, request):
        return await self.execute(principal, request)
    @{decorator}
    async def execute({prefix}principal, request):
        d = await apermission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return await adispatch(principal, request)
    """)
    )
    assert report["complete"], report


@pytest.mark.parametrize("decorator", ["standard.staticmethod", "static"])
def test_standard_decorator_import_aliases_are_resolved(decorator):
    report = verify(
        spec(f"""
import builtins as standard
from builtins import staticmethod as static
class Tool:
    @{decorator}
    def invoke(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert report["complete"], report


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_source_decorator_shadowing_remains_unresolved(decorator):
    report = verify(
        spec(f"""
def {decorator}(function):
    dispatch(None, None)
    return function
class Tool:
    @{decorator}
    def invoke(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert not report["complete"]
    assert any("definition-time" in issue["reason"] for issue in report["issues"])


def test_class_local_decorator_shadow_is_not_treated_as_a_builtin():
    candidate = spec("""
class Tool:
    def staticmethod(function):
        dispatch(None, None)
        return function
    @staticmethod
    def invoke(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert "example.Tool.invoke" not in _Program(candidate).method_kinds
    assert not verify(candidate)["complete"]


def test_decorator_import_must_exist_when_the_class_is_defined():
    report = verify(
        spec("""
class Tool:
    @standard.staticmethod
    def invoke(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
import builtins as standard
    """)
    )
    assert not report["complete"]
    assert report["issues"]


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_decorated_initializer_has_the_correct_implicit_arguments(decorator):
    prefix = "cls, " if decorator == "classmethod" else ""
    report = check(
        "Helper(principal, request)",
        f"""
        class Helper:
            @{decorator}
            def __init__({prefix}principal, request):
                d = permission(principal, request)
                if d.verdict is Verdict.ALLOW:
                    dispatch(principal, request)
    """,
    )
    assert report["complete"], report


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_method_descriptor_cannot_hide_an_executable_escape(decorator):
    prefix = "cls, " if decorator == "classmethod" else ""
    report = check(
        "return Helper.execute",
        f"""
        class Helper:
            @{decorator}
            def execute({prefix}principal, request):
                return dispatch(principal, request)
    """,
    )
    assert not report["complete"]
    assert any("escapes" in issue["reason"] for issue in report["entries"][0]["issues"])


@pytest.mark.parametrize("static", [False, True])
def test_bound_method_dependency_tracks_its_receiver_but_static_method_does_not(static):
    decorator = "    @staticmethod\n" if static else ""
    receiver = "" if static else "self"
    helper = (
        "class Holder:\n"
        + decorator
        + f"    def execute({receiver}):\n        return None\n"
    )
    report = check(
        """
        holder = Holder()
        alias = holder.execute
        d = permission(principal, alias)
        if d.verdict is Verdict.ALLOW:
            holder.changed = request
            return dispatch(principal, alias)
    """,
        helper,
    )
    assert report["complete"] is static, report
    if not static:
        assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "decorators,receiver",
    [
        ("@override", "this, "),
        ("@override\n@staticmethod", ""),
        ("@staticmethod\n@override", ""),
        ("@override\n@classmethod", "cls, "),
        ("@classmethod\n@override", "cls, "),
    ],
)
def test_override_metadata_preserves_method_binding(decorators, receiver):
    decorators = "\n".join("    " + line for line in decorators.splitlines())
    report = verify(
        spec(f"""
from typing_extensions import override
class Tool:
{decorators}
    def invoke({receiver}principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    )
    assert report["complete"], report


@pytest.mark.parametrize("module", ["typing", "typing_extensions"])
def test_override_does_not_exempt_a_helper_body(module):
    report = check(
        "execute(principal, request)",
        f"""
        from {module} import override
        @override
        def execute(principal, request):
            return dispatch(principal, request)
    """,
    )
    assert report["entries"][0]["status"] == "violated", report


def test_source_function_named_override_cannot_replace_standard_metadata():
    report = check(
        "execute(principal, request)",
        """
        def override(function):
            dispatch(None, None)
            return function
        @override
        def execute(principal, request):
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """,
    )
    assert not report["complete"]
    assert any("definition-time" in issue["reason"] for issue in report["issues"])


@pytest.mark.parametrize(
    "target", ["builtins.staticmethod", "typing_extensions.override"]
)
def test_declared_effect_terminal_cannot_be_skipped_as_decorator_metadata(target):
    original = spec(f"""
import builtins
import typing_extensions
class Tool:
    @{target}
    def invoke(self, principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    candidate = replace(
        original, operations=(*original.operations, Operation(target, ("arg:0",)))
    )
    assert "example.Tool.invoke" not in _Program(candidate).method_kinds
    assert not verify(candidate)["complete"]


@pytest.mark.parametrize(
    "decorator,receiver", [("staticmethod", ""), ("classmethod", "cls")]
)
def test_dataclass_post_initializer_uses_descriptor_binding(decorator, receiver):
    report = record_check(
        "Record()",
        f"""
        @dataclass
        class Record:
            value: object = None
            @{decorator}
            def __post_init__({receiver}):
                dispatch(None, None)
    """,
    )
    assert report["entries"][0]["status"] == "violated", report
    assert (
        report["entries"][0]["dispatches"][0]["call_path"][-1]
        == "example.Record.__post_init__"
    )


def test_native_descriptor_and_initializer_contracts_use_inert_objects_only():
    observed = []

    class Base:
        @classmethod
        def kind(cls):
            return cls

        @staticmethod
        def identity(value):
            return value

    class Derived(Base):
        @classmethod
        def __init__(cls, value):
            observed.append((cls, value))

    value = object()
    instance = Derived(value)
    assert instance.kind() is Derived
    assert Derived.kind() is Derived
    assert instance.identity(value) is value
    assert observed == [(Derived, value)]

    def inert(value):
        return value

    assert override(inert) is inert
    assert getattr(inert, "__override__") is True
    descriptor = classmethod(inert)
    assert override(descriptor) is descriptor
