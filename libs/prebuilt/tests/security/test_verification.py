"""Source-only proofs and counterexamples; no fixture source is executed."""

import json
from dataclasses import replace
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import VerificationSpec, load_spec, verify

_PREFIX = """
from policy import permission, apermission, Verdict
from legacy import dispatch, adispatch
"""
_GOOD = """
def decision_for(principal, request):
    return permission(principal, request)

def execute(principal, request):
    decision = decision_for(principal, request)
    if decision.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
    return dispatch(principal, request)

class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)

    def run(self, principal, request):
        alias = self.invoke
        return alias(principal, request)

    async def ainvoke(self, principal, request):
        decision = await apermission(principal, request)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return await adispatch(principal, request)

class Child(Tool):
    async def arun(self, principal, request):
        return await self.ainvoke(principal, request)
"""


def spec(body: str = _GOOD) -> VerificationSpec:
    return VerificationSpec(
        sources={"example": dedent(_PREFIX) + dedent(body)},
        surfaces=("example.Tool",),
        async_terminals=("policy.apermission", "legacy.adispatch"),
        authorizers=tuple(
            Authorizer(f"policy.{name}", ("arg:0", "arg:1"))
            for name in ["permission", "apermission"]
        ),
        operations=tuple(
            Operation(f"legacy.{name}", ("arg:0", "arg:1"))
            for name in ["dispatch", "adispatch"]
        ),
    )


def test_interprocedural_complete_proof_includes_inherited_apis() -> None:
    report = verify(spec())
    assert report["complete"], report
    assert report["summary"]["entries"] == 7
    run = next(
        entry for entry in report["entries"] if entry["entry"] == "example.Child.run"
    )
    assert run["dispatches"][0]["call_path"] == [
        "example.Tool.run",
        "example.Tool.invoke",
        "example.execute",
    ]
    assert "example.decision_for" in run["visited_functions"]


def test_reexported_base_class_cannot_hide_a_new_tool_api() -> None:
    original = spec()
    sources = {
        **original.sources,
        "facade": "from example import Tool as PublicTool\n",
        "second_facade": "from facade import PublicTool as Tool\n",
        "extension": dedent("""
            from second_facade import Tool
            from legacy import dispatch
            class PluginTool(Tool):
                def execute_new(self, principal, request):
                    return dispatch(principal, request)
        """),
    }
    report = verify(replace(original, sources=sources))
    assert not report["complete"]
    assert "extension.PluginTool" in report["surfaces"]
    entry = next(
        item
        for item in report["entries"]
        if item["entry"] == "extension.PluginTool.execute_new"
    )
    assert entry["status"] == "violated"


def test_cyclic_reexports_cannot_receive_a_certificate() -> None:
    original = spec()
    sources = {
        **original.sources,
        "one": "from two import Tool\n",
        "two": "from one import Tool\n",
        "extension": "from one import Tool\nclass Plugin(Tool):\n    pass\n",
    }
    report = verify(replace(original, sources=sources))
    assert not report["complete"]
    assert any("cyclic import alias" in issue["reason"] for issue in report["issues"])


def test_expanding_import_alias_is_bounded_and_unresolved() -> None:
    original = spec()
    report = verify(
        replace(
            original,
            sources={
                **original.sources,
                "cycle": "from cycle.Tool import Tool\n",
                "extension": "from cycle import Tool\nclass Plugin(Tool):\n    pass\n",
            },
        )
    )
    assert not report["complete"]
    assert any(
        "alias resolution budget" in issue["reason"] for issue in report["issues"]
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda text: text.replace(
            "return execute(principal, request)", "return dispatch(principal, request)"
        ),
        lambda text: text.replace(
            "decision = decision_for(principal, request)",
            "decision = decision_for(principal, 'other')",
        ),
        lambda text: text.replace(
            "decision.verdict is not Verdict.ALLOW", "decision.verdict is Verdict.ALLOW"
        ),
        lambda text: text.replace(
            "return dispatch(principal, request)",
            "dispatch(principal, request)\n    return dispatch(principal, request)",
        ),
        lambda text: text.replace(
            "return dispatch(principal, request)", "return dispatch('other', request)"
        ),
        lambda text: text.replace(
            "return dispatch(principal, request)",
            "permission(principal, request)\n    return dispatch(principal, request)",
        ),
    ],
)
def test_invalid_authority_has_a_counterexample(change) -> None:
    report = verify(spec(change(_GOOD)))
    assert not report["complete"]
    failures = [
        site
        for entry in report["entries"]
        for site in entry["dispatches"]
        if not site["authorized"]
    ]
    assert failures, report
    assert failures[0]["call_path"]


def test_new_api_is_discovered_without_editing_a_catalog() -> None:
    report = verify(
        spec(
            _GOOD
            + """
class NewTool(Tool):
    def newly_added_api(self, principal, request):
        return dispatch(principal, request)
"""
        )
    )
    assert not report["complete"]
    entry = next(
        item
        for item in report["entries"]
        if item["entry"] == "example.NewTool.newly_added_api"
    )
    assert entry["status"] == "violated"


def _nested_decision_spec(body: str) -> VerificationSpec:
    return VerificationSpec(
        sources={
            "nested": dedent(_PREFIX) + dedent(body),
        },
        surfaces=("nested.Router",),
        authorizers=(
            Authorizer(
                "policy.permission",
                ("arg:0", "result:request"),
                decision="decision",
            ),
        ),
        operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
    )


_NESTED_DECISION = """
class Router:
    def route(self, principal, request):
        authorization = permission(principal, request)
        if authorization.decision.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return dispatch(principal, authorization.request)
"""


def test_nested_authorization_decision_binds_effective_request() -> None:
    report = verify(_nested_decision_spec(_NESTED_DECISION))
    assert report["complete"], report


@pytest.mark.parametrize(
    "change",
    [
        lambda source: source.replace(
            "authorization.decision.verdict", "authorization.verdict"
        ),
        lambda source: source.replace("authorization.request", "request"),
        lambda source: source.replace(
            "authorization.decision.verdict is not Verdict.ALLOW",
            "authorization.decision.verdict is Verdict.ALLOW",
        ),
    ],
)
def test_nested_authorization_mutations_are_rejected(change) -> None:
    report = verify(_nested_decision_spec(change(_NESTED_DECISION)))
    assert not report["complete"]


@pytest.mark.parametrize(
    "body",
    [
        "return dynamic(principal, request)",
        "return self.invoke(principal, request)",
        "return getattr(self, 'invoke')(principal, request)",
        "self.request = request\n        return execute(principal, request)",
        "for item in request:\n            execute(principal, item)",
        "try:\n            return execute(principal, request)\n        except Exception:\n            return dispatch(principal, request)",
        "assert permission(principal, request)\n        return dispatch(principal, request)",
        "return execute(*request)",
    ],
)
def test_unknown_behavior_never_produces_a_certificate(body: str) -> None:
    text = (
        "class Tool:\n    def invoke(self, principal, request):\n        " + body + "\n"
    )
    report = verify(spec(text))
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"


@pytest.mark.parametrize("budget", ["max_steps", "max_paths", "max_depth"])
def test_resource_exhaustion_is_unresolved(budget: str) -> None:
    candidate = spec()
    if budget == "max_paths":
        candidate = spec(
            _GOOD.replace(
                "    decision = decision_for(principal, request)",
                "    if principal:\n        alias = principal\n    else:\n        alias = request\n    decision = decision_for(principal, request)",
            )
        )
    report = verify(replace(candidate, **{budget: 1}))
    assert not report["complete"]
    assert any(
        "budget" in issue["reason"]
        for entry in report["entries"]
        for issue in entry["issues"]
    )


def test_external_base_does_not_hide_inherited_apis() -> None:
    report = verify(spec(_GOOD.replace("class Tool:", "class Tool(UnknownBase):")))
    assert not report["complete"]
    assert any("base class" in item["reason"] for item in report["issues"])


def test_keyword_binding_and_cross_module_helper() -> None:
    original = spec()
    sources = {
        "example": dedent(_PREFIX)
        + "from helpers import execute\nclass Tool:\n    def invoke(self, principal, request):\n        return execute(request=request, principal=principal)\n",
        "helpers": dedent(_PREFIX)
        + "def execute(principal, request):\n    d = permission(principal, request)\n    if d.verdict is Verdict.ALLOW:\n        return dispatch(principal, request)\n    raise PermissionError('denied')\n",
    }
    report = verify(replace(original, sources=sources))
    assert report["complete"], report


def test_helper_exception_does_not_resume_caller_dispatch() -> None:
    text = """
def denied(principal, request):
    raise PermissionError('denied')
class Tool:
    def invoke(self, principal, request):
        denied(principal, request)
        return dispatch(principal, request)
"""
    report = verify(spec(text))
    assert not report["complete"]  # Unvisited sink stays an explicit obligation.
    assert not report["entries"][0]["dispatches"]


def test_callable_alias_cannot_mask_an_unmediated_terminal() -> None:
    text = """
class Tool:
    def invoke(self, principal, request):
        alias = dispatch
        return alias(principal, request)
"""
    report = verify(spec(text))
    assert report["entries"][0]["status"] == "violated"


def test_module_rebinding_is_not_silently_ignored() -> None:
    report = verify(spec(_GOOD + "\npermission = dispatch\n"))
    assert not report["complete"]
    assert report["issues"]


@pytest.mark.parametrize("value", ["dispatch", "self", "self.invoke", "Tool"])
def test_executable_capability_cannot_escape_as_api_output(value: str) -> None:
    report = verify(
        spec(
            _GOOD
            + f"\nclass Escape(Tool):\n    def unwrap(self):\n        return {value}\n"
        )
    )
    assert not report["complete"]
    assert any(
        "escapes" in issue["reason"]
        for entry in report["entries"]
        for issue in entry["issues"]
    )


def test_custom_attribute_resolution_is_not_treated_as_plain_python() -> None:
    report = verify(
        spec(
            _GOOD
            + "\nclass Special(Tool):\n    def __getattribute__(self, name):\n        return dispatch\n"
        )
    )
    assert not report["complete"]
    assert any("object protocol" in item["reason"] for item in report["issues"])


def test_unscheduled_coroutine_does_not_establish_authority() -> None:
    report = verify(spec(_GOOD.replace("await apermission", "apermission")))
    assert not report["complete"]
    assert any(
        "await mode" in issue["reason"]
        for entry in report["entries"]
        for issue in entry["issues"]
    )


def test_new_source_file_is_discovered_by_source_root(tmp_path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    (root / "gateway.py").write_text(dedent(_PREFIX) + dedent(_GOOD))
    payload = {
        "source_roots": {"package": "package"},
        "surfaces": ["package.gateway.Tool"],
        "authorizers": [
            {"target": f"policy.{name}", "bindings": ["arg:0", "arg:1"]}
            for name in ["permission", "apermission"]
        ],
        "operations": [
            {"target": f"legacy.{name}", "bindings": ["arg:0", "arg:1"]}
            for name in ["dispatch", "adispatch"]
        ],
        "async_terminals": ["policy.apermission", "legacy.adispatch"],
    }
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(payload))
    assert verify(load_spec(path))["complete"]
    (root / "new.py").write_text(
        "from package.gateway import Tool\nfrom legacy import dispatch\nclass New(Tool):\n    def invoke(self, p, r):\n        return dispatch(p, r)\n"
    )
    report = verify(load_spec(path))
    assert not report["complete"]
    assert "package.new.New" in report["surfaces"]


def test_authority_crosses_helpers_with_exact_returned_request_identity() -> None:
    body = """
def checked(principal, request):
    d = permission(principal, request)
    if d.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
    return request
class Tool:
    def invoke(self, principal, request):
        bound_request = checked(principal, request)
        return dispatch(principal, bound_request)
"""
    report = verify(spec(body))
    assert report["complete"], report
    changed = verify(spec(body.replace("return request", "return 'different'")))
    assert not changed["complete"]
    assert changed["entries"][0]["status"] == "violated"


def test_different_permission_domains_cannot_substitute_for_each_other() -> None:
    original = spec()
    report = verify(
        replace(
            original,
            operations=(
                Operation("legacy.dispatch", ("arg:0", "arg:1"), permission="publish"),
                original.operations[1],
            ),
        )
    )
    assert not report["complete"]
    assert any(
        not site["authorized"]
        for entry in report["entries"]
        for site in entry["dispatches"]
    )


@pytest.mark.parametrize(
    "definition",
    [
        "def unused(value=dispatch(None, None)):\n    pass\n",
        "@dispatch(None, None)\ndef unused():\n    pass\n",
        "def unused(value: dispatch(None, None)):\n    pass\n",
    ],
)
def test_definition_time_effects_cannot_hide_in_unused_helpers(definition: str) -> None:
    report = verify(spec(_GOOD + definition))
    assert not report["complete"]
    assert any("definition-time" in item["reason"] for item in report["issues"])
