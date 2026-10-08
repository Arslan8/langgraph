"""Completeness certificates for the host-only routing boundary.

Kernel MAC and the atomic host activation contract are premises. The checked
property is complete routing and inter-tool mediation, not tool-body semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import platform
import types
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.types import Verdict
from langgraph.prebuilt.security.verification import (
    Requirement,
    VerificationSpec,
    verify,
)

_MODULE = "langgraph.prebuilt.security.host_router"
_CLASS = _MODULE + ".HostRouter"
# This is an admission classification, not the source of inventory. Discovery
# finds every actual method; any additional method fails until classified.
_ENTRY_KINDS = {
    "invoke": "root",
    "ainvoke": "root",
    "run": "root",
    "arun": "root",
    "__call__": "root",
    "invoke_from": "cross_tool",
    "ainvoke_from": "cross_tool",
    "route": "framework",
    "aroute": "framework",
    "dispatch": "framework",
    "adispatch": "framework",
    "register": "framework",
    "aregister": "framework",
    "state": "framework",
    "astate": "framework",
    "model_invoke": "framework",
    "amodel_invoke": "framework",
    "output_emit": "framework",
    "aoutput_emit": "framework",
    "resume": "framework",
    "aresume": "framework",
}


def _entry_protocol(name: str, kind: str | None, prefix: str) -> dict[str, list[str]]:
    """Require the entry's actual authorization protocol and original inputs.

    Effective object requests may change inside the trusted policy primitive.
    Its input must still be the entry request. Resume additionally must submit
    the entry approval to the resume primitive, never ordinary permission.
    """
    policy = f"{_CLASS}.policy.{prefix}"
    if kind == "root":
        return {policy + "permission": ["input:principal", "input:call"]}
    if kind == "cross_tool":
        origin = ["input:origin", "input:parent", "input:child", "input:call"]
        return {
            f"{_CLASS}.host.{prefix}origin_permission": origin,
            policy + "delegation_permission": origin,
            policy + "transition_permission": origin,
            policy + "permission": ["input:child", "input:call"],
        }
    if kind == "framework":
        if name in {"resume", "aresume"}:
            return {
                policy + "object_resume_permission": [
                    "input:principal",
                    "input:request",
                    "input:approval",
                ]
            }
        return {policy + "object_permission": ["input:principal", "input:request"]}
    return {}


def router_spec(source: str) -> VerificationSpec:
    """Describe only the policy and atomic host boundary primitive contracts."""
    authorizers: list[Authorizer] = []
    operations: list[Operation] = []
    requirements: dict[str, tuple[Requirement, ...]] = {}
    asynchronous: list[str] = []
    for prefix in ("", "a"):
        permission = f"{_CLASS}.policy.{prefix}permission"
        origin = f"{_CLASS}.host.{prefix}origin_permission"
        delegation = f"{_CLASS}.policy.{prefix}delegation_permission"
        transition = f"{_CLASS}.policy.{prefix}transition_permission"
        root = f"{_CLASS}.host.{prefix}invoke"
        cross = f"{root}_from"
        object_permission = f"{_CLASS}.policy.{prefix}object_permission"
        object_resume = f"{_CLASS}.policy.{prefix}object_resume_permission"
        framework = f"{_CLASS}.host.{prefix}dispatch"
        authorizers.extend(
            (
                Authorizer(permission, ("arg:0", "arg:1", "result:constraints")),
                Authorizer(
                    origin,
                    ("arg:0", "arg:1", "arg:2", "arg:3"),
                    permission="authenticated_origin",
                ),
                Authorizer(
                    delegation,
                    ("arg:0", "arg:1", "arg:2", "arg:3", "result:constraints"),
                    permission="delegation",
                ),
                Authorizer(
                    transition,
                    ("arg:0", "arg:1", "arg:2", "arg:3", "result:constraints"),
                    permission="tool_transition",
                ),
                Authorizer(
                    object_permission,
                    ("arg:0", "result:request"),
                    decision="decision",
                    permission="framework_object",
                ),
                Authorizer(
                    object_resume,
                    ("arg:0", "result:request"),
                    decision="decision",
                    permission="framework_object",
                ),
            )
        )
        operations.extend(
            (
                Operation(root, ("arg:0", "arg:1", "arg:2")),
                Operation(cross, ("arg:2", "arg:3", "arg:4")),
                Operation(
                    framework,
                    ("arg:0", "arg:1"),
                    permission="framework_object",
                ),
            )
        )
        requirements[cross] = (
            Requirement("authenticated_origin", ("arg:0", "arg:1", "arg:2", "arg:3")),
            Requirement("delegation", ("arg:0", "arg:1", "arg:2", "arg:3", "arg:5")),
            Requirement(
                "tool_transition", ("arg:0", "arg:1", "arg:2", "arg:3", "arg:6")
            ),
        )
        if prefix:
            asynchronous.extend(
                (
                    permission,
                    origin,
                    delegation,
                    transition,
                    object_permission,
                    object_resume,
                    root,
                    cross,
                    framework,
                )
            )
    return VerificationSpec(
        sources={_MODULE: source},
        surfaces=(_CLASS,),
        authorizers=tuple(authorizers),
        operations=tuple(operations),
        requirements=requirements,
        async_terminals=tuple(asynchronous),
    )


def verify_router_source(source: str) -> dict[str, Any]:
    """Check a source candidate; this alone does not certify loaded bytecode."""
    proof = verify(router_spec(source))
    issues: list[str] = []
    coverage = []
    discovered = proof["surfaces"].get(_CLASS, {})
    if set(discovered) != set(_ENTRY_KINDS) or set(proof["surfaces"]) != {_CLASS}:
        issues.append(
            "entry-point surface differs from the admitted root/cross-tool interface"
        )
    for entry in proof["entries"]:
        name = entry["entry"].rsplit(".", 1)[-1]
        kind = _ENTRY_KINDS.get(name)
        # Await mode is also checked by the transfer engine; aliases keep the
        # same route classification as their externally visible entry point.
        prefix = (
            "a"
            if name
            in {
                "ainvoke",
                "arun",
                "ainvoke_from",
                "aroute",
                "adispatch",
                "aregister",
                "astate",
                "amodel_invoke",
                "aoutput_emit",
                "aresume",
            }
            else ""
        )
        expected = (
            f"{_CLASS}.host.{prefix}dispatch"
            if kind == "framework"
            else f"{_CLASS}.host.{prefix}invoke"
            + ("_from" if kind == "cross_tool" else "")
        )
        routed = bool(entry["dispatches"]) and all(
            site["target"] == expected for site in entry["dispatches"]
        )
        protocol = _entry_protocol(name, kind, prefix)
        authorizations = entry["authorizations"]
        protocol_verified = (
            bool(protocol)
            and {site["target"] for site in authorizations} == set(protocol)
            and all(
                site["arguments"] == protocol.get(site["target"])
                for site in authorizations
            )
        )
        if not protocol_verified:
            issues.append(
                f"{entry['entry']}: authorization protocol or entry inputs differ"
            )
        if not routed:
            issues.append(
                f"{entry['entry']}: missing host route or wrong root/cross-tool dispatch"
            )
        coverage.append(
            {
                "entry": entry["entry"],
                "kind": kind,
                "status": entry["status"],
                "host_only": routed,
                "entry_protocol_verified": protocol_verified,
                "required_authorizers": protocol,
                "dispatch_obligations": len(entry["dispatches"]),
            }
        )
    return {
        "schema_version": 2,
        "complete": proof["complete"] and not issues,
        "claim": "Every admitted HostRouter entry authorizes the identical effective request before atomic dispatch; tool calls preserve constraints, and cross-tool entries additionally require fresh authenticated-origin, delegation and tool-transition decisions.",
        "scope": "HostRouter's entire discovered method surface, including the generic framework-object route. Host-confined ToolNode and guarded_tool calls enter the tool-call surface through a separately tested exact-decision bridge.",
        "trusted_boundary": [
            "Host MAC/LSM correctly enforces installed policy for every resource access.",
            "The host adapter binds principal, request, tool and all constraints, activates confinement before tool imports/initialization/execution, and never falls back to control-process execution.",
            "The host authenticates origin against a live worker channel and binds it again at nested dispatch; caller-supplied origin strings are not credentials.",
            "Workers cannot use root admission or acquire another registered tool's authority through a raw callable, direct service channel, or unmediated host API.",
            "Policy decisions implement the intended policy; inputs and service bindings are immutable throughout a call; the Python control plane and construction are trusted.",
        ],
        "source_proof": proof,
        "coverage": coverage,
        "issues": issues,
        "summary": {
            "discovered": len(coverage),
            "verified": sum(
                item["status"] == "verified"
                and item["host_only"]
                and item["entry_protocol_verified"]
                and item["kind"] is not None
                for item in coverage
            ),
            "dispatch_obligations": proof["summary"]["dispatch_obligations"],
        },
    }


def _code_shape(code: types.CodeType) -> Any:
    """Compare executable structure without location-only/debug metadata."""
    return (
        code.co_code.hex(),
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_flags,
        tuple(
            _code_shape(value) if isinstance(value, types.CodeType) else repr(value)
            for value in code.co_consts
        ),
        getattr(code, "co_exceptiontable", b"").hex(),
    )


def verify_host_router() -> dict[str, Any]:
    """Bind the proof to the actual loaded class and its executable methods."""
    from langgraph.prebuilt.security import host_router

    path = Path(host_router.__file__)
    source = path.read_text(encoding="utf-8")
    report = verify_router_source(source)
    namespace = host_router.HostRouter.__dict__
    loaded = {
        name: value for name, value in namespace.items() if inspect.isfunction(value)
    }
    module_code = compile(source, str(path), "exec", dont_inherit=True)
    class_code = next(
        value
        for value in module_code.co_consts
        if isinstance(value, types.CodeType) and value.co_name == "HostRouter"
    )
    compiled = {
        value.co_name: value
        for value in class_code.co_consts
        if isinstance(value, types.CodeType)
    }
    mismatches = []
    if set(loaded) != set(_ENTRY_KINDS) or set(compiled) != set(loaded):
        mismatches.append("loaded callable inventory differs from the source proof")
    for name, method in loaded.items():
        if name not in compiled or _code_shape(method.__code__) != _code_shape(
            compiled[name]
        ):
            mismatches.append(f"loaded method differs from source: {name}")
        if method.__defaults__ or method.__kwdefaults__ or method.__closure__:
            mismatches.append(f"unexpected defaults/closure: {name}")
        if method.__globals__ is not vars(host_router):
            mismatches.append(f"unexpected method namespace: {name}")
    if vars(host_router).get("Verdict") is not Verdict or "PermissionError" in vars(
        host_router
    ):
        mismatches.append("trusted verdict/exception bindings changed")
    if type(host_router.HostRouter) is not type:
        mismatches.append("unexpected runtime metaclass")
    if host_router.HostRouter.__bases__ != (object,):
        mismatches.append("unexpected runtime inheritance")
    allowed = {
        *_ENTRY_KINDS,
        "__module__",
        "__annotations__",
        "__dict__",
        "__weakref__",
        "__doc__",
        "__firstlineno__",
        "__static_attributes__",
        "__annotate__",
    }
    if set(namespace) - allowed:
        mismatches.append("unclassified runtime class attributes")
    report["runtime_binding"] = {
        "verified": not mismatches,
        "issues": mismatches,
        "python_implementation": platform.python_implementation(),
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
    }
    report["complete"] = report["complete"] and not mismatches
    report["certificate_checker_sha256"] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    return report


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = verify_host_router()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
