"""Positive boundary proofs and source-only negative variants."""

import ast
import types
from pathlib import Path

import pytest

from langgraph.prebuilt.security import host_router
from langgraph.prebuilt.security.boundary_verification import (
    verify_host_router,
    verify_router_source,
)
from langgraph.prebuilt.security.host_boundary import make_host_router


def _source() -> str:
    return Path(host_router.__file__).read_text()


def test_entire_runtime_router_surface_is_verified() -> None:
    report = verify_host_router()
    assert report["complete"], report
    assert report["runtime_binding"]["verified"]
    assert all(item["entry_protocol_verified"] for item in report["coverage"])
    assert report["summary"] == {
        "discovered": 21,
        "verified": 21,
        "dispatch_obligations": 21,
    }
    for entry in report["source_proof"]["entries"]:
        for site in entry["dispatches"]:
            domains = {item["permission"] for item in site["requirements"]}
            name = entry["entry"].rsplit(".", 1)[-1]
            if entry["entry"].endswith("invoke_from"):
                assert domains == {
                    "tool_call",
                    "authenticated_origin",
                    "delegation",
                    "tool_transition",
                }
            elif name in {"invoke", "ainvoke", "run", "arun", "__call__"}:
                assert domains == {"tool_call"}
            else:
                assert domains == {"framework_object"}
            assert all(item["authorized"] for item in site["requirements"])


@pytest.mark.parametrize("gate", ["identity", "delegation", "transition", "decision"])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_each_cross_tool_guard_is_necessary(gate: str, asynchronous: bool) -> None:
    tree = ast.parse(_source())
    name = "ainvoke_from" if asynchronous else "invoke_from"
    method = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    method.body = [
        node
        for node in method.body
        if not (
            isinstance(node, ast.If)
            and ast.unparse(node.test).startswith(gate + ".verdict")
        )
    ]
    report = verify_router_source(ast.unparse(tree))
    assert not report["complete"]
    entry = next(
        item
        for item in report["source_proof"]["entries"]
        if item["entry"].endswith("." + name)
    )
    assert entry["status"] == "violated"


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.replace("delegation.constraints,", "transition.constraints,"),
        lambda s: s.replace("decision.constraints", "call.normalized"),
        lambda s: s.replace(
            "return self.host.invoke(principal, call, decision.constraints)",
            "self.host.invoke(principal, call, decision.constraints)\n        return self.host.invoke(principal, call, decision.constraints)",
        ),
        lambda s: s.replace(
            "return self.host.invoke(principal, call, decision.constraints)",
            "self.policy.permission(principal, call)\n        return self.host.invoke(principal, call, decision.constraints)",
        ),
        lambda s: s.replace(
            "return self.host.invoke(principal, call, decision.constraints)",
            "return self.host.invoke('other', call, decision.constraints)",
        ),
        lambda s: s.replace(
            "return self.host.invoke(principal, call, decision.constraints)",
            "return self.host.invoke",
        ),
    ],
)
def test_bindings_constraints_freshness_and_capability_escape(change) -> None:
    original = _source()
    changed = change(original)
    assert changed != original
    assert not verify_router_source(changed)["complete"]


def test_cross_tool_entry_cannot_switch_to_root_dispatch() -> None:
    tree = ast.parse(_source())
    method = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "invoke_from"
    )
    method.body[-1] = ast.parse(
        "return self.host.invoke(child, call, decision.constraints)"
    ).body[0]
    report = verify_router_source(ast.unparse(tree))
    # Tool permission holds, but the return protocol now rejects the wrong
    # operation in the transfer engine as well as in the coverage check.
    assert not report["source_proof"]["complete"]
    assert not report["complete"]
    assert any("wrong root/cross-tool" in issue for issue in report["issues"])


def test_added_api_cannot_hide_outside_the_inventory() -> None:
    source = (
        _source()
        + "\n    def new_api(self, principal, call):\n        return self.invoke(principal, call)\n"
    )
    report = verify_router_source(source)
    assert not report["complete"]
    assert report["summary"]["discovered"] == 22


def test_runtime_monkeypatch_invalidates_source_certificate(monkeypatch) -> None:
    monkeypatch.setattr(
        host_router.HostRouter, "invoke", lambda self, principal, call: None
    )
    report = verify_host_router()
    assert not report["complete"]
    assert not report["runtime_binding"]["verified"]
    with pytest.raises(ValueError, match="unresolved"):
        make_host_router(None, None)


def test_added_runtime_attribute_invalidates_admission(monkeypatch) -> None:
    monkeypatch.setattr(
        host_router.HostRouter, "hidden_service", object(), raising=False
    )
    assert not verify_host_router()["complete"]


@pytest.mark.parametrize("name", ["route", "invoke", "output_emit", "state"])
def test_router_instances_cannot_shadow_verified_methods(name):
    router = make_host_router(None, None)
    assert not hasattr(router, "__dict__")
    with pytest.raises(AttributeError):
        setattr(router, name, lambda *args: "unmediated")


@pytest.mark.parametrize("name", ["policy", "host"])
def test_replaced_slot_descriptor_is_not_an_admitted_router(monkeypatch, name):
    monkeypatch.setattr(host_router.HostRouter, name, None)
    report = verify_host_router()
    assert not report["complete"]
    assert any(
        "slot descriptor changed" in issue
        for issue in report["runtime_binding"]["issues"]
    )
    with pytest.raises(ValueError, match="unresolved mediation"):
        make_host_router(None, None)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "change", ["ordinary_permission", "approval", "request", "principal"]
)
def test_resume_requires_its_own_protocol_and_original_inputs(asynchronous, change):
    tree = ast.parse(_source())
    name = "aresume" if asynchronous else "resume"
    method = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    call = next(
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.endswith("object_resume_permission")
    )
    if change == "ordinary_permission":
        call.func.attr = "aobject_permission" if asynchronous else "object_permission"
        call.args.pop()
    else:
        index = {"principal": 0, "request": 1, "approval": 2}[change]
        call.args[index] = ast.Constant(None)
    report = verify_router_source(ast.unparse(tree))
    assert not report["complete"]
    entry = next(
        item for item in report["coverage"] if item["entry"].endswith("." + name)
    )
    assert not entry["entry_protocol_verified"]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "change", ["guard", "effective_request", "principal", "repeat"]
)
def test_framework_routes_require_fresh_exact_effective_authorization(
    asynchronous, change
):
    tree = ast.parse(_source())
    name = "aroute" if asynchronous else "route"
    method = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    call = next(
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and ast.unparse(node.func).startswith("self.host.")
    )
    if change == "guard":
        method.body = [node for node in method.body if not isinstance(node, ast.If)]
    elif change == "effective_request":
        call.args[1] = ast.Name(id="request", ctx=ast.Load())
    elif change == "principal":
        call.args[0] = ast.Constant(None)
    else:
        method.body.insert(-1, ast.Expr(value=method.body[-1].value))
    report = verify_router_source(ast.unparse(ast.fix_missing_locations(tree)))
    assert not report["complete"]


def test_authorizer_inputs_cannot_be_rebound_before_checking():
    source = _source().replace(
        "decision = self.policy.permission(principal, call)",
        "principal = None\n        decision = self.policy.permission(principal, call)",
        1,
    )
    report = verify_router_source(source)
    # The shared transfer engine now checks original entry identities too,
    # rather than relying only on the router-specific report wrapper.
    assert not report["source_proof"]["complete"]
    assert any(
        not authorization["entry_bound"]
        for entry in report["source_proof"]["entries"]
        for authorization in entry["authorizations"]
    )
    assert not report["complete"]


def test_router_returns_prove_dispatch_or_pending_approval_without_conflating_them():
    report = verify_host_router()
    assert report["complete"]
    for entry in report["source_proof"]["entries"]:
        name = entry["entry"].rsplit(".", 1)[-1]
        kinds = {outcome["kind"] for outcome in entry["return_outcomes"]}
        expected = {"authorized_operation"}
        if name in {
            "route",
            "aroute",
            "dispatch",
            "adispatch",
            "register",
            "aregister",
            "state",
            "astate",
            "model_invoke",
            "amodel_invoke",
            "output_emit",
            "aoutput_emit",
        }:
            expected.add("escalated_authorization")
        assert kinds == expected
        assert all(outcome["verified"] for outcome in entry["return_outcomes"])
    # Provenance evidence does not silently become a publication permission.
    assert not report["source_proof"]["return_requirements"]
    assert not report["source_proof"]["refusing_authorizers"]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "replacement", ["request", "authorization.request", "None", "(value, request)"]
)
def test_authorized_dispatch_does_not_license_a_different_return(
    asynchronous, replacement
):
    source = _source()
    await_prefix = "await " if asynchronous else ""
    method = "adispatch" if asynchronous else "dispatch"
    old = f"return {await_prefix}self.host.{method}(principal, authorization.request)"
    new = f"value = {await_prefix}self.host.{method}(principal, authorization.request)\n        return {replacement}"
    assert old in source
    report = verify_router_source(source.replace(old, new, 1))
    assert not report["complete"]
    assert any(
        not outcome["verified"]
        for entry in report["source_proof"]["entries"]
        for outcome in entry["return_outcomes"]
    )


@pytest.mark.parametrize(
    "condition", ["Verdict.DENY", "Verdict.ALLOW", "Verdict.REDACT"]
)
def test_only_escalated_authorization_may_return_without_dispatch(condition):
    report = verify_router_source(
        _source().replace("is Verdict.ESCALATE:", f"is {condition}:")
    )
    assert not report["complete"]
    assert any(
        not outcome["verified"]
        for entry in report["source_proof"]["entries"]
        for outcome in entry["return_outcomes"]
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "return authorization.request",
        "return request",
        "authorization.request = request\n            return authorization",
        "authorization.decision.verdict = Verdict.ALLOW\n            return authorization",
    ],
)
def test_pending_approval_must_be_the_unchanged_authorizer_result(replacement):
    source = _source().replace("return authorization", replacement)
    assert not verify_router_source(source)["complete"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_matching_loaded_source_is_refused_when_return_protocol_is_unprovable(
    monkeypatch, tmp_path, asynchronous
):
    method = "aroute" if asynchronous else "route"
    dispatch = "await self.host.adispatch" if asynchronous else "self.host.dispatch"
    source = _source().replace(
        f"return {dispatch}(principal, authorization.request)",
        f"{dispatch}(principal, authorization.request)\n        return request",
        1,
    )
    path = tmp_path / "host_router.py"
    path.write_text(source)
    # Compile for code-shape binding only. Never execute the candidate module or
    # its violating method; the admission check must stop before construction.
    compiled = compile(source, str(path), "exec", dont_inherit=True)
    class_code = next(
        item
        for item in compiled.co_consts
        if isinstance(item, types.CodeType) and item.co_name == "HostRouter"
    )
    method_code = next(
        item
        for item in class_code.co_consts
        if isinstance(item, types.CodeType) and item.co_name == method
    )
    monkeypatch.setattr(host_router, "__file__", str(path))
    monkeypatch.setattr(
        getattr(host_router.HostRouter, method), "__code__", method_code
    )
    report = verify_host_router()
    assert report["runtime_binding"]["verified"], report
    assert not report["complete"]
    assert any(
        not outcome["verified"]
        for entry in report["source_proof"]["entries"]
        for outcome in entry["return_outcomes"]
    )
    with pytest.raises(ValueError, match="unresolved mediation obligations"):
        make_host_router(None, None)
