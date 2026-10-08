"""Source-only forwarding and mutable-alias checks for the proof engine."""

from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import VerificationSpec, verify


def check(body, helpers="", signature="self, principal, request"):
    source = (
        "from policy import permission, Verdict\nfrom legacy import dispatch\n"
        + dedent(helpers)
        + f"class Tool:\n    def invoke({signature}):\n"
        + "\n".join("        " + line for line in dedent(body).strip().splitlines())
        + "\n"
    )
    return verify(
        VerificationSpec(
            sources={"example": source},
            surfaces=("example.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
            terminal_parameters={
                "policy.permission": ("principal", "request"),
                "legacy.dispatch": ("principal", "request"),
            },
        )
    )


@pytest.mark.parametrize(
    "forward",
    [
        "relay(dispatch, principal, request)",
        "relay(dispatch, *(principal, request))",
        "relay(dispatch, principal, **{'request': request})",
        "relay(dispatch, **{'request': request, 'principal': principal})",
    ],
)
def test_variadic_helpers_preserve_call_bindings(forward):
    report = check(
        f"""
        d = relay(permission, principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return {forward}
    """,
        """
        def relay(function, *args, **kwargs):
            return function(*args, **kwargs)
    """,
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "copy", ["packet", "packet.copy()", "dict(packet)", "dict(**packet)", "{**packet}"]
)
def test_mapping_copies_preserve_values_and_call_targets(copy):
    report = check(f"""
        packet = {{'principal': principal, 'request': request}}
        forwarded = {copy}
        d = permission(**forwarded)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(forwarded.get('principal'), forwarded['request'])
    """)
    assert report["complete"], report


@pytest.mark.parametrize(
    "overwrite", ["{'principal': request}", "{'request': principal}"]
)
def test_dictionary_merge_cannot_substitute_authorized_arguments(overwrite):
    report = check(f"""
        packet = {{'principal': principal, 'request': request}}
        d = permission(**packet)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(**{{**packet, **{overwrite}}})
    """)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "mutation",
    [
        "alias['key'] = principal",
        "del alias['key']",
        "rewrite(alias, principal)",
    ],
)
@pytest.mark.parametrize("recheck", [False, True])
def test_mapping_mutation_revokes_authority_through_aliases(mutation, recheck):
    report = check(
        f"""
        request = {{'key': request}}
        alias = request
        d = permission(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        {mutation}
        {"d = permission(principal, request)" if recheck else "pass"}
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(principal, request)
    """,
        """
        def rewrite(mapping, value):
            mapping['key'] = value
    """,
    )
    assert report["complete"] is recheck, report


def test_mutation_before_allow_guard_also_revokes_pending_decision():
    report = check("""
        request = {'key': request}
        d = permission(principal, request)
        request['key'] = principal
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_copied_mappings_do_not_alias_their_top_level_keys():
    report = check("""
        packet = {'principal': principal, 'request': request}
        copied = packet.copy()
        copied['principal'] = request
        d = permission(**packet)
        if d.verdict is Verdict.ALLOW:
            return dispatch(**packet)
    """)
    assert report["complete"], report


def test_copied_mappings_keep_nested_mutable_aliases():
    report = check("""
        request = {'value': request}
        packet = {'request': request}
        copied = dict(packet)
        d = permission(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        copied['request']['value'] = principal
        return dispatch(principal, request)
    """)
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "body",
    [
        "return {'call': dispatch}",
        "return dict(call=dispatch)",
        "return {'call': dispatch}.copy()",
        "return {'call': dispatch}.get('call')",
        "return {'call': dispatch}.get",
        "raise ValueError({'call': dispatch})",
        "try:\n    raise ValueError({'call': dispatch})\nexcept ValueError as e:\n    return e",
        "packet = {}\npacket['cycle'] = packet\npacket['call'] = dispatch\nreturn packet",
        "packet = {}\ntry:\n    packet['call'] = dispatch\n    raise ValueError()\nexcept ValueError:\n    return packet",
    ],
)
def test_mappings_cannot_hide_execution_capability_escapes(body):
    report = check(body)
    assert not report["complete"]
    assert report["entries"][0]["issues"]


def test_mapping_projection_tracks_execution_capability_calls():
    report = check("return {'call': dispatch}['call'](principal, request)")
    assert report["entries"][0]["status"] == "violated"


def test_mapping_constructor_shadowing_is_not_treated_as_pure():
    report = check(
        "return dict(principal, request)",
        """
        def dict(principal, request):
            return dispatch(principal, request)
    """,
    )
    assert report["entries"][0]["status"] == "violated"


def test_duplicate_keyword_does_not_hide_argument_evaluation():
    report = check(
        "return permission(**{'principal': principal}, **{'principal': dispatch(principal, request)})"
    )
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_positional_only_names_can_also_appear_in_kwargs():
    report = check(
        "return relay(principal, principal=request, request=request)",
        """
        def relay(principal, /, **kwargs):
            request = kwargs['request']
            d = permission(principal, request)
            if d.verdict is not Verdict.ALLOW:
                raise PermissionError('denied')
            return dispatch(principal, request)
    """,
    )
    assert report["complete"], report


def test_arbitrary_variadic_entry_is_not_analyzed_as_empty_arguments():
    report = check(
        "return relay(*args, **kwargs)",
        """
        def relay(*args, **kwargs):
            return dispatch(*args, **kwargs)
    """,
        signature="self, *args, **kwargs",
    )
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"


def test_unused_variadic_inputs_do_not_prevent_bound_dispatch():
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        signature="self, principal, request, *args, **kwargs",
    )
    assert report["complete"], report


def test_keyword_forwarding_still_consumes_one_grant_per_dispatch():
    report = check("""
        packet = {'principal': principal, 'request': request}
        d = permission(**packet)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        dispatch(**packet)
        return dispatch(**packet)
    """)
    assert report["entries"][0]["status"] == "violated"


def test_missing_get_default_retains_callable_identity():
    report = check("return {}.get('call', dispatch)(principal, request)")
    assert report["entries"][0]["status"] == "violated"


def test_inert_cyclic_mapping_escape_terminates_without_hiding_dispatch():
    report = check("""
        packet = {}
        packet['cycle'] = packet
        d = permission(principal, request)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        dispatch(principal, request)
        return packet
    """)
    assert report["complete"], report


@pytest.mark.parametrize("parameter", ["*args", "**kwargs"])
def test_variadic_annotations_cannot_hide_definition_time_effects(parameter):
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        f"""
        def unused({parameter}: dispatch(None, None)):
            pass
    """,
    )
    assert not report["complete"]
    assert any("definition-time" in issue["reason"] for issue in report["issues"])


def test_assignment_target_evaluation_cannot_hide_effects():
    report = check("""
        packet = {}
        packet[dispatch(principal, request)] = None
    """)
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_async_forwarding_preserves_awaited_terminal_contracts():
    source = """
from policy import permission, Verdict
from legacy import dispatch
async def relay(function, *args, **kwargs):
    return await function(*args, **kwargs)
class Tool:
    async def ainvoke(self, principal, request):
        packet = {'principal': principal, 'request': request}
        d = await relay(permission, **packet)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return await relay(dispatch, **packet)
"""
    spec = VerificationSpec(
        sources={"example": source},
        surfaces=("example.Tool",),
        authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
        operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
        terminal_parameters={
            "policy.permission": ("principal", "request"),
            "legacy.dispatch": ("principal", "request"),
        },
        async_terminals=("policy.permission", "legacy.dispatch"),
    )
    assert verify(spec)["complete"]
