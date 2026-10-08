"""Dataclass constructor and immutable-view models for source verification."""

import inspect
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.types import Decision, ToolCall
from langgraph.prebuilt.security.verification import VerificationSpec, verify

RECORD = """
@dataclass(frozen=True, slots=True)
class Request:
    value: object
    metadata: tuple = ()
    def __post_init__(self):
        object.__setattr__(self, 'metadata', tuple(self.metadata))
"""


def check(body, helpers=RECORD):
    source = (
        "from __future__ import annotations\nfrom dataclasses import dataclass, field, InitVar\n"
        "from types import MappingProxyType\nfrom typing import ClassVar\n"
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
    "construction",
    [
        "Request(request)",
        "Request(value=request)",
        "Request(request, ())",
        "Request(metadata=(), value=request)",
    ],
)
def test_record_constructor_fields_preserve_exact_call_identity(construction):
    report = check(f"""
        call = {construction}
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, call)
    """)
    assert report["complete"], report


def test_post_initializer_is_analyzed_instead_of_trusted():
    report = check(
        "return Request(principal, request)",
        """
        @dataclass(frozen=True, slots=True)
        class Request:
            principal: object
            request: object
            def __post_init__(self):
                dispatch(self.principal, self.request)
    """,
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_actual_decision_constructor_preserves_unrelated_authority():
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        audit = Decision(Verdict.ALLOW, 'dispatch:reserved')
        return dispatch(principal, request)
    """,
        inspect.getsource(Decision),
    )
    assert report["complete"], report
    assert any(
        name.endswith("Decision.__post_init__")
        for name in report["entries"][0]["visited_functions"]
    )


def test_constructing_allow_record_cannot_forge_permission():
    report = check(
        """
        d = Decision(Verdict.ALLOW, 'forged')
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        inspect.getsource(Decision),
    )
    assert report["entries"][0]["status"] == "violated"


def test_actual_decision_transform_copies_arguments_into_readonly_view():
    report = check(
        """
        args = {'value': request}
        d = Decision(Verdict.TRANSFORM, 'transform', new_args=args)
        args['value'] = principal
        authorized = permission(principal, request)
        if authorized.verdict is Verdict.ALLOW:
            return dispatch(principal, d.new_args['value'])
    """,
        inspect.getsource(Decision),
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "write",
    [
        "object.__setattr__(call, 'value', principal)",
        "call.value['nested'] = principal",
    ],
)
def test_mutating_authorized_record_graph_revokes_grant(write):
    report = check(f"""
        call = Request({{'nested': request}})
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        {write}
        return dispatch(principal, call)
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize("mutation", ["call.value = principal", "del call.value"])
def test_frozen_record_writes_raise_and_cannot_reach_dispatch(mutation):
    report = check(f"""
        call = Request(request)
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        dispatch(principal, call)
        {mutation}
        dispatch(principal, call)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_unrelated_object_and_mapping_writes_preserve_bound_grants():
    report = check("""
        call = Request(request)
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        unrelated = {}
        unrelated['marker'] = principal
        unrelated_object = Request(principal)
        object.__setattr__(unrelated_object, 'value', None)
        return dispatch(principal, call)
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "wrapper",
    [
        "backing",
        "MappingProxyType(backing)",
        "MappingProxyType(MappingProxyType(backing))",
    ],
)
def test_readonly_views_depend_on_live_backing_dictionary(wrapper):
    report = check(f"""
        backing = {{'value': request}}
        call = {wrapper}
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        backing['value'] = principal
        return dispatch(principal, call)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_copying_readonly_view_detaches_top_level_backing_storage():
    report = check("""
        backing = {'value': request}
        call = dict(MappingProxyType(backing))
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        backing['value'] = principal
        return dispatch(principal, call)
    """)
    assert report["complete"], report


def test_nested_alias_through_proxy_copy_still_revokes():
    report = check("""
        nested = {'value': request}
        backing = {'nested': nested}
        call = dict(MappingProxyType(backing))
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        nested['value'] = principal
        return dispatch(principal, call)
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize("mutation", ["call['value'] = principal", "del call['value']"])
def test_proxy_mutation_raises_without_mutating_backing(mutation):
    report = check(f"""
        call = MappingProxyType({{'value': request}})
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        dispatch(principal, call)
        {mutation}
        dispatch(principal, call)
    """)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize(
    "unsupported",
    [
        "@dataclass\nclass Request:\n    value: object = field(default_factory=dispatch)",
        "@dataclass(kw_only=True)\nclass Request:\n    value: object",
        "@dataclass\nclass Request:\n    value: ClassVar[object] = None",
        "@dataclass\nclass Request:\n    value: InitVar[object]",
        "@dataclass\nclass Request:\n    value: object = None\n    def value(self):\n        return dispatch",
        "@dataclass\nclass Request:\n    value: object\n    def __init__(self):\n        dispatch(None,None)",
    ],
)
def test_unsupported_dataclass_definition_cannot_receive_certificate(unsupported):
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        unsupported,
    )
    assert not report["complete"]
    assert report["issues"]


def test_deletion_on_mutable_record_restores_class_default():
    report = check(
        """
        call = Request(principal)
        del call.value
        d = permission(principal, None)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, call.value)
    """,
        """
        @dataclass
        class Request:
            value: object = None
    """,
    )
    assert report["complete"], report


def test_record_verdict_reassignment_does_not_keep_old_branch_facts():
    report = check(
        """
        decision = Decision(Verdict.DENY, 'initial')
        if decision.verdict is Verdict.DENY:
            object.__setattr__(decision, 'verdict', Verdict.ALLOW)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        inspect.getsource(Decision),
    )
    assert report["entries"][0]["status"] == "violated"


def test_pruning_one_helper_context_does_not_hide_other_contexts():
    report = check(
        """
        decide(False, principal, request)
        return decide(True, principal, request)
    """,
        """
        def decide(enabled, principal, request):
            if enabled:
                return dispatch(principal, request)
    """,
    )
    assert report["entries"][0]["status"] == "violated"


def test_bound_receiver_graph_is_not_truncated_at_qualified_class_name():
    report = check("""
        self.nested = {'value': request}
        d = permission(principal, self)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        self.nested['value'] = principal
        return dispatch(principal, self)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_pending_authorization_depends_on_nested_record_aliases():
    report = check("""
        nested = {'value': request}
        call = Request(nested)
        d = permission(principal, call)
        nested['value'] = principal
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, call)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_dataclass_with_generated_interface_is_not_silently_underinventoried():
    source = """
from __future__ import annotations
from dataclasses import dataclass
from policy import permission, Verdict
from legacy import dispatch
@dataclass
class Tool:
    label: str
    def invoke(self, principal, request):
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
"""
    report = verify(
        VerificationSpec(
            sources={"example": source},
            surfaces=("example.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
        )
    )
    assert not report["complete"]
    assert any("generated-method" in issue["reason"] for issue in report["issues"])


def test_dataclass_inheritance_is_explicitly_unresolved():
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        RECORD + "\nclass Derived(Request):\n    pass\n",
    )
    assert not report["complete"]
    assert any("dataclass inheritance" in issue["reason"] for issue in report["issues"])


def test_actual_tool_call_constructor_snapshots_argument_mappings():
    report = check(
        """
        args = {'value': request}
        call = ToolCall(request, args, {}, 'call-1', 0)
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        args['value'] = principal
        return dispatch(principal, call)
    """,
        inspect.getsource(ToolCall),
    )
    assert report["complete"], report
    assert any(
        name.endswith("ToolCall.__post_init__")
        for name in report["entries"][0]["visited_functions"]
    )


def test_actual_tool_call_nested_argument_alias_revokes_permission():
    report = check(
        """
        nested = {'value': request}
        call = ToolCall(request, {'nested': nested}, {}, 'call-1', 0)
        d = permission(principal, call)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        nested['value'] = principal
        return dispatch(principal, call)
    """,
        inspect.getsource(ToolCall),
    )
    assert report["entries"][0]["status"] == "violated"


def test_unresolved_annotation_reexport_cannot_hide_initvar_layout():
    report = check(
        """
        call = Request(request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        """
        from external import MaybeInitVar
        @dataclass
        class Request:
            value: MaybeInitVar[object] = None
            def __post_init__(self, value=None):
                if value is not None:
                    dispatch(None, value)
    """,
    )
    assert not report["complete"]
    assert report["issues"]
