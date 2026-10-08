"""Source method resolution follows C3 and super's actual receiver binding."""

import pytest

from langgraph.prebuilt.security.verification import _Program, verify
from tests.security.test_verification import spec
from tests.security.test_verification_control_flow import check
from tests.security.test_verification_records import check as record_check

GOOD_BASE = """
class Base:
    def execute(self, principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
"""


@pytest.mark.parametrize(
    "expression", ["super()", "super(Tool, self)", "super(__class__, self)"]
)
def test_super_follows_source_base_and_keeps_bindings(expression):
    report = verify(
        spec(
            GOOD_BASE
            + f"""
class Tool(Base):
    def invoke(self, principal, request):
        return {expression}.execute(principal, request)
    """
        )
    )
    assert report["complete"], report
    entry = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    assert entry["dispatches"][0]["call_path"] == [
        "example.Tool.invoke",
        "example.Base.execute",
    ]


def test_super_does_not_skip_a_diamond_sibling_override():
    report = verify(
        spec(
            GOOD_BASE
            + """
class Left(Base):
    def execute(self, principal, request):
        return super().execute(principal, request)
class Right(Base):
    def execute(self, principal, request):
        return dispatch(principal, request)
class Tool(Left, Right):
    def invoke(self, principal, request):
        return super().execute(principal, request)
    """
        )
    )
    assert not report["complete"]
    entry = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    assert entry["status"] == "violated", entry
    assert entry["dispatches"][0]["call_path"] == [
        "example.Tool.invoke",
        "example.Left.execute",
        "example.Right.execute",
    ]


def test_cooperative_diamond_reaches_fresh_base_authorization():
    report = verify(
        spec(
            GOOD_BASE
            + """
class Left(Base):
    def execute(self, principal, request):
        return super().execute(principal, request)
class Right(Base):
    def execute(self, principal, request):
        return super().execute(principal, request)
class Tool(Left, Right):
    def invoke(self, principal, request):
        return super().execute(principal, request)
    """
        )
    )
    assert report["complete"], report


def test_ordinary_method_lookup_uses_leftmost_override():
    report = verify(
        spec(
            GOOD_BASE
            + """
class Left(Base):
    def execute(self, principal, request):
        return dispatch(principal, request)
class Tool(Left, Base):
    def invoke(self, principal, request):
        return self.execute(principal, request)
    """
        )
    )
    assert not report["complete"]
    entry = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    assert entry["status"] == "violated"
    assert entry["dispatches"][0]["call_path"][-1] == "example.Left.execute"


def test_method_resolution_does_not_select_an_ancestor_before_a_sibling():
    report = verify(
        spec(
            GOOD_BASE
            + """
class Left(Base):
    pass
class Right(Base):
    def execute(self, principal, request):
        return dispatch(principal, request)
class Tool(Left, Right):
    def invoke(self, principal, request):
        return self.execute(principal, request)
    """
        )
    )
    entry = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    assert entry["status"] == "violated"
    assert entry["dispatches"][0]["call_path"][-1] == "example.Right.execute"


def test_super_classmethod_retains_most_derived_class():
    report = verify(
        spec("""
class Base:
    @classmethod
    def execute(cls, principal, request):
        return cls.finish(principal, request)
    @staticmethod
    def finish(principal, request):
        return None
class Tool(Base):
    @classmethod
    def invoke(cls, principal, request):
        return super().execute(principal, request)
    @staticmethod
    def finish(principal, request):
        return dispatch(principal, request)
    """)
    )
    entry = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    assert entry["status"] == "violated"
    assert entry["dispatches"][0]["call_path"][-1] == "example.Tool.finish"


def test_static_method_retrieved_through_super_has_no_implicit_receiver():
    report = verify(
        spec("""
class Base:
    @staticmethod
    def execute(principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
class Tool(Base):
    def invoke(self, principal, request):
        return super().execute(principal, request)
    """)
    )
    assert report["complete"], report


def test_ordinary_method_on_class_bound_super_is_unbound():
    report = verify(
        spec(
            GOOD_BASE
            + """
class Tool(Base):
    @classmethod
    def invoke(cls, principal, request):
        return super().execute(None, principal, request)
    """
        )
    )
    assert report["complete"], report


def test_async_super_call_preserves_terminal_await_modes():
    report = verify(
        spec("""
class Base:
    async def execute(self, principal, request):
        d = await apermission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return await adispatch(principal, request)
class Tool(Base):
    async def ainvoke(self, principal, request):
        return await super().execute(principal, request)
    """)
    )
    assert report["complete"], report


def test_explicit_super_arguments_are_evaluated_before_validation():
    report = check("return super(dispatch(principal, request), self)")
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_super_uses_reassigned_first_parameter():
    report = verify(
        spec(
            GOOD_BASE
            + """
class Other(Base):
    pass
class Tool(Base):
    def invoke(self, principal, request):
        self = Other()
        super().execute(principal, request)
        return dispatch(principal, request)
    """
        )
    )
    entry = next(e for e in report["entries"] if e["entry"] == "example.Tool.invoke")
    assert not entry["dispatches"]
    assert not entry["issues"]


def test_source_constructor_chain_can_reach_native_object_initializer():
    report = check(
        """
        helper = Child(request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, helper.value)
        """,
        """
        class Base:
            def __init__(self, value):
                super().__init__()
                self.value = value
        class Child(Base):
            def __init__(self, value):
                super().__init__(value)
        """,
    )
    assert report["complete"], report


def test_native_object_initializer_rejects_extra_arguments():
    report = check(
        "Helper(request)\nreturn dispatch(principal, request)",
        """
        class Helper:
            def __init__(self, value):
                super().__init__(value)
        """,
    )
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


@pytest.mark.parametrize("expression", ["super()", "super().__init__"])
def test_super_capability_cannot_escape(expression):
    report = check("return " + expression)
    assert report["entries"][0]["status"] == "unresolved"
    assert any(
        "capability escapes" in i["reason"] for i in report["entries"][0]["issues"]
    )


def test_super_method_mutation_retains_receiver_dependencies():
    report = check(
        """
        helper = Child()
        method = helper.operation()
        d = permission(principal, method)
        if d.verdict is Verdict.ALLOW:
            helper.value = request
            return dispatch(principal, method)
        """,
        """
        class Base:
            def update(self):
                return None
        class Child(Base):
            def operation(self):
                return super().update
        """,
    )
    assert report["entries"][0]["status"] == "violated"


def test_super_metadata_preserves_actual_receiver():
    report = check(
        """
        helper = Child(request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, helper.read())
        """,
        """
        class Child:
            def __init__(self, value):
                self.value = value
            def read(self):
                return super().__self__.value
        """,
    )
    assert report["complete"], report


@pytest.mark.parametrize("bases", ["Left, Left", "object, Left", "Left, Missing"])
def test_invalid_or_unknown_base_order_remains_unresolved(bases):
    report = verify(
        spec(
            GOOD_BASE
            + f"""
class Left(Base):
    pass
class Tool({bases}):
    def invoke(self, principal, request):
        return super().execute(principal, request)
    """
        )
    )
    assert not report["complete"]
    assert any("base-class order" in i["reason"] for i in report["issues"])


def test_inconsistent_c3_order_cannot_be_certified():
    original = spec(
        GOOD_BASE
        + """
class A(Base): pass
class B(Base): pass
class Left(A, B): pass
class Right(B, A): pass
class Tool(Left, Right):
    def invoke(self, principal, request):
        return super().execute(principal, request)
    """
    )
    assert _Program(original).linearization("example.Tool") is None
    assert not verify(original)["complete"]


def test_explicit_builtin_object_alias_has_native_order():
    original = spec("""
import builtins as standard
class Tool(standard.object):
    def invoke(self, principal, request):
        super().__init__()
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert verify(original)["complete"]


def test_late_base_binding_does_not_create_a_valid_class():
    report = verify(
        spec(
            """
class Tool(Base):
    def invoke(self, principal, request):
        return super().execute(principal, request)
"""
            + GOOD_BASE
        )
    )
    assert not report["complete"]
    assert report["issues"]


def test_class_decorator_and_custom_metaclass_are_not_exempted():
    for declaration in [
        "@decorate\nclass Tool(Base):",
        "class Tool(Base, metaclass=Custom):",
    ]:
        report = verify(
            spec(
                GOOD_BASE
                + declaration
                + "\n    def invoke(self, principal, request):\n        return super().execute(principal, request)\n"
            )
        )
        assert not report["complete"]
        assert report["issues"]


def test_no_argument_super_outside_method_raises():
    report = check(
        "helper()\nreturn dispatch(principal, request)",
        "def helper():\n    return super()\n",
    )
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_alias_without_class_cell_has_no_successful_route():
    original = spec(
        GOOD_BASE
        + """
from builtins import super as parent
class Tool(Base):
    def invoke(self, principal, request):
        return parent().execute(principal, request)
    """
    )
    entry = next(
        e for e in verify(original)["entries"] if e["entry"] == "example.Tool.invoke"
    )
    assert not entry["dispatches"]
    assert not entry["issues"]


def test_explicit_super_alias_does_not_need_a_class_cell():
    original = spec(
        GOOD_BASE
        + """
from builtins import super as parent
class Tool(Base):
    def invoke(self, principal, request):
        return parent(Tool, self).execute(principal, request)
    """
    )
    assert verify(original)["complete"]


def test_unbound_super_descriptor_remains_unresolved():
    original = spec(
        GOOD_BASE
        + """
class Tool(Base):
    def invoke(self, principal, request):
        return super(Tool).execute(principal, request)
    """
    )
    assert not verify(original)["complete"]


def test_generated_slots_dataclass_class_cell_is_not_assumed_unchanged():
    report = record_check(
        "Record().run()",
        """
        @dataclass(slots=True)
        class Record:
            def run(self):
                return super().__init__()
        """,
    )
    assert report["entries"][0]["status"] == "unresolved"
    assert any("class cell" in i["reason"] for i in report["entries"][0]["issues"])


def test_native_c3_order_and_class_super_binding():
    class Base:
        def run(self):
            return ["base"]

        @classmethod
        def bound(cls):
            return cls

    class Left(Base):
        def run(self):
            return ["left", *super().run()]

    class Right(Base):
        def run(self):
            return ["right", *super().run()]

    class Child(Left, Right):
        pass

    assert Child().run() == ["left", "right", "base"]
    assert super(Child, Child).run is Left.run
    assert super(Child, Child).bound() is Child
