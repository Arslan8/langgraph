"""Source-only context propagation proofs and native inert contract checks."""

from contextvars import Context, ContextVar
from dataclasses import replace

import pytest

from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec
from tests.security.test_verification_records import check

CONTEXT = """
from contextvars import ContextVar
current = ContextVar('current', default=None)
"""


@pytest.mark.parametrize("setup", ["", "current = ContextVar('local', default=None)"])
def test_set_get_retains_authorized_request_identity(setup):
    report = check(
        f"""
        {setup}
        current.set(request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, current.get())
        """,
        CONTEXT,
    )
    assert report["complete"], report


def test_decision_keeps_identity_within_current_invocation():
    report = check(
        """
        decision = permission(principal, request)
        current.set(decision)
        if current.get().verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        CONTEXT,
    )
    assert report["complete"], report


def test_inherited_decision_does_not_supply_fresh_authority():
    report = check(
        """
        decision = current.get()
        if decision is not None and decision.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
        """,
        CONTEXT,
    )
    assert not report["complete"]
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_stored_decision_does_not_survive_a_later_denial():
    report = check(
        """
        decision = permission(principal, request)
        current.set(decision)
        replacement = permission(principal, request)
        if replacement.verdict is Verdict.DENY:
            if current.get().verdict is Verdict.ALLOW:
                return dispatch(principal, request)
        """,
        CONTEXT,
    )
    assert not report["complete"]
    assert any(not d["authorized"] for d in report["entries"][0]["dispatches"])


def test_module_context_is_not_assumed_empty():
    report = check(
        """
        value = current.get()
        if value is not None:
            return dispatch(principal, value)
        """,
        CONTEXT,
    )
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize("default", [", default=None", ""])
def test_repeated_reads_preserve_inherited_value_identity(default):
    report = check(
        """
        value = current.get()
        d = permission(principal, value)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, current.get())
        """,
        CONTEXT.replace(", default=None", default),
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    ("setup", "read", "value"),
    [
        ("current = ContextVar('local', default=request)", "current.get()", "request"),
        (
            "current = ContextVar('local', default=None)",
            "current.get(request)",
            "request",
        ),
        ("current.set(request)", "current.get(None)", "request"),
    ],
)
def test_default_precedence(setup, read, value):
    report = check(
        f"""
        {setup}
        d = permission(principal, {value})
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, {read})
        """,
        CONTEXT,
    )
    assert report["complete"], report


def test_setting_new_value_does_not_authorize_it():
    report = check(
        """
        current.set(request)
        d = permission(principal, current.get())
        if d.verdict is Verdict.ALLOW:
            current.set(None)
            return dispatch(principal, current.get())
        """,
        CONTEXT,
    )
    assert report["entries"][0]["status"] == "violated"


def test_context_mutation_revokes_grant_on_variable():
    report = check(
        """
        current.set(request)
        d = permission(principal, current)
        if d.verdict is Verdict.ALLOW:
            current.set(None)
            return dispatch(principal, current)
        """,
        CONTEXT,
    )
    assert report["entries"][0]["status"] == "violated"


def test_rebinding_context_does_not_mutate_saved_request():
    report = check(
        """
        current.set(request)
        saved = current.get()
        d = permission(principal, saved)
        if d.verdict is Verdict.ALLOW:
            current.set(None)
            return dispatch(principal, saved)
        """,
        CONTEXT,
    )
    assert report["complete"], report


def test_context_keeps_nested_aliases_live():
    report = check(
        """
        box = {'value': request}
        current.set(box)
        d = permission(principal, box)
        if d.verdict is Verdict.ALLOW:
            current.get()['value'] = None
            return dispatch(principal, box)
        """,
        CONTEXT,
    )
    assert report["entries"][0]["status"] == "violated"


def test_reset_restores_exact_previous_value():
    report = check(
        """
        current.set(request)
        token = current.set(None)
        current.reset(token)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, current.get())
        """,
        CONTEXT,
    )
    assert report["complete"], report


def test_reset_of_initial_binding_preserves_inherited_value():
    report = check(
        """
        saved = current.get()
        token = current.set(request)
        current.reset(token)
        d = permission(principal, saved)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, current.get())
        """,
        CONTEXT,
    )
    assert report["complete"], report


def test_restored_value_does_not_inherit_replacement_grant():
    report = check(
        """
        current.set(None)
        token = current.set(request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            current.reset(token)
            return dispatch(principal, current.get())
        """,
        CONTEXT,
    )
    assert report["entries"][0]["status"] == "violated"


def test_tokens_need_not_be_reset_in_stack_order():
    report = check(
        """
        local = ContextVar('local', default=None)
        first = local.set(request)
        second = local.set(None)
        local.reset(first)
        local.reset(second)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, local.get())
        """,
        CONTEXT,
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "body",
    [
        "local = ContextVar('local')\nlocal.get()",
        "local = ContextVar('local')\ntoken = local.set(request)\nlocal.reset(token)\nlocal.get()",
        "token = current.set(request)\ncurrent.reset(token)\ncurrent.reset(token)",
        "local = ContextVar('local')\ntoken = current.set(request)\nlocal.reset(token)",
        "current.get(default=request)",
        "current.set()",
        "current.set(request, None)",
        "current.reset()",
        "current.get(None, None)",
    ],
)
def test_native_error_has_no_successful_dispatch_continuation(body):
    report = check(body + "\nreturn dispatch(principal, request)", CONTEXT)
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_reset_with_unknown_token_remains_unresolved():
    report = check("current.reset(request)", CONTEXT)
    assert report["entries"][0]["status"] == "unresolved"


def test_default_argument_is_evaluated_even_when_value_is_bound():
    report = check(
        "current.set(None)\nreturn current.get(dispatch(principal, request))", CONTEXT
    )
    assert report["entries"][0]["status"] == "violated"


@pytest.mark.parametrize(
    "body",
    [
        "return current",
        "return current.get",
        "return current.set(request)",
        "return current.get()",
        "current.set(dispatch)",
        "current.set({'operation': dispatch})",
        "current.set(self)",
    ],
)
def test_context_capabilities_and_inherited_unknown_values_cannot_escape(body):
    report = check(body, CONTEXT)
    assert report["entries"][0]["status"] == "unresolved"


def test_global_context_through_module_alias_preserves_identity():
    original = spec("""
        import config
        class Tool:
            def invoke(self, principal, request):
                config.current.set(request)
                d = permission(principal, request)
                if d.verdict is Verdict.ALLOW:
                    return dispatch(principal, config.current.get())
    """)
    report = verify(replace(original, sources={**original.sources, "config": CONTEXT}))
    assert report["complete"], report


def test_native_constructor_through_module_alias():
    report = check(
        """
        local = cv.ContextVar('local', default=request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, local.get())
        """,
        "import contextvars as cv\n",
    )
    assert report["complete"], report


def test_parameterized_module_annotation_is_inert_when_postponed():
    report = check(
        """
        current.set(request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, current.get())
        """,
        CONTEXT.replace("current =", "current: ContextVar[object] ="),
    )
    assert report["complete"], report


def test_eager_module_annotation_is_not_skipped():
    original = spec(
        CONTEXT.replace("current =", "current: effect() =")
        + "\nclass Tool:\n    def invoke(self):\n        pass\n"
    )
    report = verify(original)
    assert not report["complete"]
    assert report["issues"]


def test_async_source_calls_keep_same_current_context():
    original = spec("""
        from contextvars import ContextVar
        current = ContextVar('current', default=None)
        async def helper(value):
            current.set(value)
        class Tool:
            async def invoke(self, principal, request):
                await helper(request)
                d = await apermission(principal, request)
                if d.verdict is Verdict.ALLOW:
                    return await adispatch(principal, current.get())
    """)
    report = verify(original)
    assert report["complete"], report


def test_awaiting_synchronous_context_method_is_unresolved():
    original = spec("""
        from contextvars import ContextVar
        current = ContextVar('current', default=None)
        class Tool:
            async def invoke(self, principal, request):
                await current.set(request)
    """)
    report = verify(original)
    assert report["entries"][0]["status"] == "unresolved"


def test_exceptional_prefix_does_not_keep_stale_context_binding():
    report = check(
        """
        current.set(request)
        try:
            current.set(None)
            raise ValueError('failed')
        except ValueError:
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, current.get())
        """,
        CONTEXT,
    )
    assert not report["complete"]
    assert any(
        "exceptional context state" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "definition",
    [
        "current = ContextVar('current', default=dispatch(None, None))",
        "current = ContextVar(make_name())",
        "current = ContextVar('current', extra=None)",
        "current = ContextVar('current', None)",
        "current = ContextVar('current', **options)",
    ],
)
def test_effectful_or_unknown_module_construction_is_not_exempted(definition):
    report = check(
        "return None", "from contextvars import ContextVar\n" + definition + "\n"
    )
    assert report["issues"]
    assert not report["complete"]


def test_native_context_token_contract():
    variable = ContextVar("verification-test", default=None)
    marker = object()
    context = Context()
    first = context.run(variable.set, marker)
    second = context.run(variable.set, None)
    context.run(variable.reset, first)
    assert context.run(variable.get) is None
    context.run(variable.reset, second)
    assert context.run(variable.get) is marker
    with pytest.raises(RuntimeError):
        context.run(variable.reset, second)
    assert variable.get() is None


def test_native_inherited_value_and_get_default_precedence():
    variable = ContextVar("verification-test", default=None)
    context = Context()
    marker = object()
    assert context.run(variable.get, marker) is marker
    context.run(variable.set, None)
    assert context.run(variable.get, marker) is None
    inherited = context.copy()
    assert inherited.run(variable.get, marker) is None
