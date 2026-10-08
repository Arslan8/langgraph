"""Dataclass factories are executable constructor edges, not trusted metadata."""

from dataclasses import _HAS_DEFAULT_FACTORY, dataclass, field, replace
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec
from tests.security.test_verification_continuations import AUTHORIZE
from tests.security.test_verification_records import check


def test_standard_factory_sentinel_matches_the_running_python_runtime():
    """Check stdlib behavior with inert values; no candidate source is executed."""
    created = []

    def make_value():
        value = object()
        created.append(value)
        return value

    @dataclass
    class StandardRecord:
        value: object = field(default_factory=make_value)

    first = StandardRecord()
    supplied = object()
    explicit = StandardRecord(supplied)
    sentinel = StandardRecord(_HAS_DEFAULT_FACTORY)
    assert len(created) == 2
    assert explicit.value is supplied
    assert first.value is created[0]
    assert sentinel.value is created[1]
    assert first.value is not sentinel.value


@pytest.mark.parametrize(
    "factory", ["dict", "tuple", "standard.dict", "dictionary", "build"]
)
def test_empty_factories_preserve_identity_and_do_not_inherit_caller_locals(factory):
    report = check(
        """
        dict = dispatch
        build = dispatch
        box = Request()
        if box.value:
            return dispatch(principal, request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        f"""
        import builtins as standard
        from builtins import dict as dictionary
        def build():
            return {{}}
        @dataclass(frozen=True, slots=True)
        class Request:
            value: object = field(default_factory={factory}, compare=False, repr=False)
        """,
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("mutated", ["first", "second"])
def test_factory_results_are_fresh_but_mutation_of_an_authorized_owner_revokes_it(
    mutated,
):
    report = check(
        f"""
        first = Request()
        second = Request()
        d = permission(principal, first)
        if d.verdict is Verdict.ALLOW:
            {mutated}.value['changed'] = request
            return dispatch(principal, first)
        """,
        """
        @dataclass
        class Request:
            value: dict = field(default_factory=dict)
        """,
    )
    assert report["complete"] is (mutated == "second"), report
    assert report["entries"][0]["dispatches"][0]["authorized"] is (mutated == "second")


@pytest.mark.parametrize("provided", [False, True])
def test_factory_body_executes_only_when_the_field_was_omitted(provided):
    argument = "{'provided': request}" if provided else ""
    report = check(
        f"box = Request({argument})\n"
        + AUTHORIZE
        + "\nreturn dispatch(principal, request)",
        """
        def build():
            return dispatch(None, None)
        @dataclass
        class Request:
            value: object = field(default_factory=build)
        """,
    )
    assert report["complete"] is provided, report
    assert (
        "example.build" in report["entries"][0]["visited_functions"]
    ) is not provided
    if not provided:
        assert any(
            not site["authorized"] for site in report["entries"][0]["dispatches"]
        )


def test_factory_uses_its_defining_module_and_restores_callers_environment():
    original = spec("""
from records import Request
class Tool:
    def invoke(self, principal, request):
        build = permission
        box = Request()
        d = build(principal, box.value['key'])
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, 'factory-value')
    """)
    report = verify(
        replace(
            original,
            sources={
                **original.sources,
                "records": dedent("""
            from __future__ import annotations
            from dataclasses import dataclass, field
            def build():
                return {'key': 'factory-value'}
            @dataclass
            class Request:
                value: dict = field(default_factory=build)
        """),
            },
        )
    )
    assert report["complete"], report
    assert "records.build" in report["entries"][0]["visited_functions"]


def test_factory_class_constructor_is_analyzed():
    report = check(
        """
        box = Request()
        d = permission(principal, box.value.item)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, 'factory-value')
        """,
        """
        class Holder:
            def __init__(self):
                self.item = 'factory-value'
        @dataclass
        class Request:
            value: object = field(default_factory=Holder)
        """,
    )
    assert report["complete"], report
    assert "example.Holder.__init__" in report["entries"][0]["visited_functions"]


def test_factory_exception_skips_later_factories_and_post_initializer():
    report = check(
        AUTHORIZE + "\ndispatch(principal, request)\nRequest()",
        """
        def fail():
            raise ValueError('failed')
        def later():
            return dispatch(None, None)
        @dataclass
        class Request:
            first: object = field(default_factory=fail)
            second: object = field(default_factory=later)
            def __post_init__(self):
                dispatch(None, None)
        """,
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1
    assert "example.later" not in report["entries"][0]["visited_functions"]


def test_factory_failure_reaches_callers_exception_handler():
    report = check(
        """
        try:
            Request()
        except ValueError:
            return dispatch(principal, request)
        """,
        """
        def fail():
            raise ValueError('failed')
        @dataclass
        class Request:
            value: object = field(default_factory=fail)
        """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_factory_exception_payload_is_checked_before_retirement():
    report = check(
        AUTHORIZE + "\ndispatch(principal, request)\nRequest()",
        """
        def fail():
            raise ValueError(dispatch)
        @dataclass
        class Request:
            value: object = field(default_factory=fail)
        """,
    )
    assert not report["complete"]
    assert any("escapes" in issue["reason"] for issue in report["entries"][0]["issues"])


def test_factory_result_carries_only_authority_that_was_actually_requested():
    report = check(
        """
        box = Request()
        if box.value.verdict is Verdict.ALLOW:
            return dispatch(None, None)
        """,
        """
        def build():
            return permission(None, None)
        @dataclass
        class Request:
            value: object = field(default_factory=build)
        """,
    )
    assert report["complete"], report


def test_factory_cannot_forge_allow_by_constructing_a_record():
    report = check(
        """
        box = Request()
        if box.value.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        """
        @dataclass
        class FakeDecision:
            verdict: object
        def build():
            return FakeDecision(Verdict.ALLOW)
        @dataclass
        class Request:
            value: object = field(default_factory=build)
        """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


@pytest.mark.parametrize(
    "default", ["field()", "field(default=None)", "field(default='default')"]
)
def test_field_metadata_preserves_explicit_constructor_arguments(default):
    report = check(
        """
        box = Request(request)
        d = permission(principal, box.value)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        f"@dataclass\nclass Request:\n    value: object = {default}\n",
    )
    assert report["complete"], report


def test_deleted_factory_field_does_not_become_a_class_default():
    report = check(
        AUTHORIZE
        + "\ndispatch(principal, request)\nbox = Request()\ndel box.value\nbox.value\ndispatch(principal, request)",
        "@dataclass\nclass Request:\n    value: dict = field(default_factory=dict)\n",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize(
    "definition",
    [
        "@dataclass\nclass Request:\n    value: object = field(default_factory=lambda: {})",
        "@dataclass\nclass Request:\n    value: object = field(default_factory=unknown)",
        "@dataclass\nclass Request:\n    value: object = field(default_factory=dict, default=None)",
        "@dataclass\nclass Request:\n    value: object = field(default_factory=dict, init=False)",
        "@dataclass\nclass Request:\n    value: object = field(default_factory=dict, compare=compute())",
        "@dataclass\nclass Request:\n    dict: object = None\n    value: object = field(default_factory=dict)",
        "@dataclass\nclass Request:\n    field: object = None\n    value: object = field(default_factory=dict)",
        "@dataclass\nclass Request:\n    value: object = field(default_factory=build)\ndef build():\n    return {}",
    ],
)
def test_unsupported_or_unbound_factory_metadata_cannot_receive_certificate(definition):
    report = check(
        AUTHORIZE + "\nreturn dispatch(principal, request)", definition + "\n"
    )
    assert not report["complete"]
    assert report["issues"]


@pytest.mark.parametrize(
    "argument", ["request", "FACTORY", "standard._HAS_DEFAULT_FACTORY"]
)
def test_factory_sentinel_may_run_factory_even_when_argument_is_supplied(argument):
    report = check(
        f"Request({argument})\n" + AUTHORIZE + "\nreturn dispatch(principal, request)",
        """
        import dataclasses as standard
        from dataclasses import _HAS_DEFAULT_FACTORY as FACTORY
        def build():
            return dispatch(None, None)
        @dataclass
        class Request:
            value: object = field(default_factory=build)
        """,
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_explicit_guard_excludes_factory_sentinel_for_unknown_argument():
    report = check(
        """
        if request is FACTORY:
            raise ValueError('sentinel excluded')
        box = Request(request)
        d = permission(principal, box.value)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        """
        from dataclasses import _HAS_DEFAULT_FACTORY as FACTORY
        def build():
            return dispatch(None, None)
        @dataclass
        class Request:
            value: object = field(default_factory=build)
        """,
    )
    assert report["complete"], report
    assert "example.build" not in report["entries"][0]["visited_functions"]


def test_factory_may_return_the_sentinel_without_being_called_again():
    report = check(
        """
        box = Request()
        d = permission(principal, box.value)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, FACTORY)
        """,
        """
        from dataclasses import _HAS_DEFAULT_FACTORY as FACTORY
        def build():
            return FACTORY
        @dataclass
        class Request:
            value: object = field(default_factory=build)
        """,
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_factory_failure_preserves_caller_finalizer_without_running_post_init():
    report = check(
        """
        try:
            Request()
        finally:
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                dispatch(principal, request)
        """,
        """
        def fail():
            raise ValueError('failed')
        @dataclass
        class Request:
            value: object = field(default_factory=fail)
            def __post_init__(self):
                dispatch(None, None)
        """,
    )
    assert report["complete"], report
    assert (
        "example.Request.__post_init__" not in report["entries"][0]["visited_functions"]
    )
