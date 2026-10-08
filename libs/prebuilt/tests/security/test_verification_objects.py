"""Source-only object allocation, field aliasing and service dispatch checks."""

from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import VerificationSpec, verify

HOLDER = """
class Holder:
    def __init__(self, principal, request):
        self.principal = principal
        self.request = request
    def permit(self):
        return permission(self.principal, self.request)
    def execute(self):
        return dispatch(self.principal, self.request)
"""


def check(body, helpers=HOLDER):
    source = (
        "from policy import permission, Verdict\nfrom legacy import dispatch\n"
        + dedent(helpers)
        + "class Tool:\n    def invoke(self, principal, request):\n"
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
    "operation", ["holder.execute()", "alias.execute()", "callback()"]
)
def test_object_fields_and_bound_methods_preserve_authorization(operation):
    report = check(f"""
        holder = Holder(principal, request)
        alias = holder
        callback = holder.execute
        d = holder.permit()
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return {operation}
    """)
    assert report["complete"], report


def test_separate_objects_are_not_conflated_by_class_identity():
    report = check("""
        first = Holder(principal, request)
        second = Holder(request, principal)
        d = first.permit()
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return second.execute()
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "change",
    [
        "alias.request = principal",
        "alias.principal = request",
        "rewrite(alias, principal)",
    ],
)
@pytest.mark.parametrize("recheck", [False, True])
def test_object_field_writes_revoke_authority_through_aliases(change, recheck):
    reauthorization = (
        """d = holder.permit()\n        if d.verdict is not Verdict.ALLOW:\n            raise PermissionError('denied')"""
        if recheck
        else "pass"
    )
    report = check(
        f"""
        holder = Holder(principal, request)
        alias = holder
        d = holder.permit()
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        {change}
        {reauthorization}
        return holder.execute()
    """,
        HOLDER
        + dedent("""
        def rewrite(holder, value):
            holder.request = value
    """),
    )
    assert report["complete"] is recheck, report
    assert report["entries"][0]["status"] == ("verified" if recheck else "violated")


def test_initializers_are_analyzed_for_dispatch_effects():
    report = check(
        "return Holder(principal, request)",
        """
        class Holder:
            def __init__(self, principal, request):
                dispatch(principal, request)
    """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_instance_callable_fields_are_not_implicitly_bound_methods():
    report = check(
        """
        holder = Holder(permission, dispatch)
        d = holder.authorize(principal, request)
        if d.verdict is Verdict.ALLOW:
            return holder.execute(principal, request)
    """,
        """
        class Holder:
            def __init__(self, authorize, execute):
                self.authorize = authorize
                self.execute = execute
    """,
    )
    assert report["complete"], report


def test_object_stores_cannot_keep_pending_authority_alive():
    report = check("""
        holder = Holder(principal, request)
        d = holder.permit()
        holder.request = principal
        if d.verdict is Verdict.ALLOW:
            return holder.execute()
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize("value", ["holder", "holder.execute", "{'holder': holder}"])
def test_object_and_bound_method_escapes_require_interface_verification(value):
    report = check(f"""
        holder = Holder(principal, request)
        return {value}
    """)
    assert report["entries"][0]["status"] == "unresolved"


@pytest.mark.parametrize(
    "definition",
    [
        "class Unused:\n    exposed = dispatch(None, None)",
        "@dispatch(None, None)\nclass Unused:\n    pass",
        "class Unused(dispatch(None, None)):\n    pass",
        "class Unused(metaclass=dispatch(None, None)):\n    pass",
    ],
)
def test_unused_class_initialization_cannot_hide_effects(definition):
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        definition,
    )
    assert not report["complete"]
    assert report["issues"]


@pytest.mark.parametrize(
    "protocol",
    [
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__new__",
        "__init_subclass__",
        "__bool__",
        "__len__",
        "__del__",
    ],
)
def test_custom_object_protocols_are_not_silently_ignored(protocol):
    report = check(
        """
        holder = Holder()
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        f"""
        class Holder:
            def {protocol}(self, *args):
                return dispatch(None, None)
    """,
    )
    assert not report["complete"]
    assert any("object protocol" in issue["reason"] for issue in report["issues"])


def test_exception_prefixes_do_not_assume_original_object_fields():
    report = check("""
        holder = Holder(principal, request)
        try:
            holder.request = principal
            raise ValueError()
        except Exception:
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return holder.execute()
    """)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"


def test_exception_payload_cannot_hide_constructed_object():
    report = check("""
        try:
            raise ValueError(Holder(principal, request))
        except ValueError as error:
            return error
    """)
    assert report["entries"][0]["status"] == "unresolved"


def test_inherited_initializer_and_method_keep_concrete_receiver():
    report = check(
        """
        holder = Derived(principal, request)
        d = holder.permit()
        if d.verdict is Verdict.ALLOW:
            return holder.execute()
    """,
        HOLDER + "\nclass Derived(Holder):\n    pass\n",
    )
    assert report["complete"], report


def test_field_deleted_before_use_does_not_hide_earlier_dispatch():
    report = check("""
        holder = Holder(principal, request)
        holder.execute()
        del holder.request
        return holder.execute()
    """)
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


@pytest.mark.parametrize("attribute", ["__dict__", "__class__", "__repr__"])
def test_implicit_object_attributes_are_not_treated_as_absent(attribute):
    report = check(f"""
        holder = Holder(principal, request)
        d = holder.permit()
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        holder.execute()
        reflected = holder.{attribute}
        return reflected
    """)
    assert report["entries"][0]["status"] == "unresolved"
    assert any(
        "object protocol attribute" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


def test_constructor_non_none_return_is_not_accepted():
    report = check(
        "return Holder(principal, request)",
        """
        class Holder:
            def __init__(self, principal, request):
                return principal
    """,
    )
    assert report["entries"][0]["status"] == "unresolved"
    assert any(
        "initializer must return None" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


def test_field_can_shadow_method_but_does_not_gain_authority():
    report = check("""
        holder = Holder(principal, request)
        holder.execute = dispatch
        return holder.execute(principal, request)
    """)
    assert report["entries"][0]["status"] == "violated"
