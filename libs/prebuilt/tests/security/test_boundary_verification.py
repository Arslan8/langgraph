"""Positive boundary proofs and source-only negative variants."""

import ast
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
    assert report["source_proof"]["complete"]  # Tool permission alone holds.
    assert not report["complete"]  # But the cross-tool protocol was bypassed.
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
