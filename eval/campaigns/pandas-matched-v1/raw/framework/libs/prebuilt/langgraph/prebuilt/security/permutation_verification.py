"""Finite non-bypassability matrices, not a system-completeness certificate.

Negative binding candidates are parsed only, never imported or executed. Runtime
cases exercise the admitted router with in-memory policy/effect observers; no
tool body, filesystem, network or subprocess effect is requested.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import itertools
import json
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.boundary_verification import verify_host_router
from langgraph.prebuilt.security.descriptor import ToolDac
from langgraph.prebuilt.security.host_boundary import ToolOrigin, make_host_router
from langgraph.prebuilt.security.host_router import HostRouter
from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.objects import (
    DispatchKind,
    DispatchRequest,
    ModelInvocationRequest,
    ObjectAuthorization,
    OutputRequest,
    SecurityLabels,
    StateOperation,
    StateRequest,
    ToolRegistryRequest,
)
from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    EscalationRequest,
    Principal,
    Tool,
    ToolCall,
    Verdict,
)
from langgraph.prebuilt.security.verification import VerificationSpec, verify

FORMS = ("direct", "aliases", "helper", "inherited", "branch")
GUARDS = ("allow_only", "missing", "inverted", "partial", "deny_only")
SLOTS = ("principal", "resource", "operation", "call")
ROOT_APIS = ("invoke", "ainvoke", "run", "arun", "__call__")
CROSS_APIS = ("invoke_from", "ainvoke_from")
FRAMEWORK_APIS = (
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
    "resume",
    "aresume",
)


def binding_spec(
    authorization: tuple[str, ...],
    effect: tuple[str, ...],
    form: str,
    asynchronous: bool,
    guard: str = "allow_only",
) -> VerificationSpec:
    """Generate an inert source fixture and an independently fixed contract."""
    if (
        form not in FORMS
        or guard not in GUARDS
        or sorted(authorization) != sorted(SLOTS)
        or sorted(effect) != sorted(SLOTS)
    ):
        raise ValueError("unknown form or invalid binding permutation")
    prefix, wait = ("async ", "await ") if asynchronous else ("", "")
    method = "ainvoke" if asynchronous else "invoke"
    body: list[str] = []
    authorize, dispatch = "authorize", "dispatch"
    if form == "aliases":
        body.extend(("check = authorize", "apply = dispatch"))
        authorize, dispatch = "check", "apply"
    body.append(f"decision = {wait}{authorize}({', '.join(authorization)})")
    if guard != "missing":
        condition = {
            "allow_only": "decision.verdict is not Verdict.ALLOW",
            "inverted": "decision.verdict is Verdict.ALLOW",
            "partial": "decision.verdict is not Verdict.ALLOW",
            "deny_only": "decision.verdict is Verdict.DENY",
        }[guard]
        if guard == "partial":
            body.extend(
                (
                    "if flag:",
                    f"    if {condition}:",
                    "        raise PermissionError('denied')",
                )
            )
        else:
            body.extend((f"if {condition}:", "    raise PermissionError('denied')"))
    invocation = f"return {wait}{dispatch}({', '.join(effect)})"
    if form == "branch":
        body.extend(("if flag:", "    " + invocation))
    body.append(invocation)
    source = "from policy import authorize, Verdict\nfrom backend import dispatch\n"
    parameters = ", ".join((*SLOTS, "flag"))
    if form == "helper":
        source += (
            f"{prefix}def checked({parameters}):\n"
            + "\n".join("    " + line for line in body)
            + "\n"
        )
        body = [f"return {wait}checked({parameters})"]
    owner = "Parent" if form == "inherited" else "Entry"
    source += f"class {owner}:\n    {prefix}def {method}(self, {parameters}):\n"
    source += "\n".join("        " + line for line in body) + "\n"
    if form == "inherited":
        source += "class Entry(Parent):\n    pass\n"
    selectors = tuple(f"arg:{index}" for index in range(4))
    return VerificationSpec(
        sources={"fixture": source},
        surfaces=("fixture.Entry",),
        authorizers=(Authorizer("policy.authorize", selectors),),
        operations=(Operation("backend.dispatch", selectors),),
        async_terminals=("policy.authorize", "backend.dispatch")
        if asynchronous
        else (),
        entry_bindings={
            f"fixture.Entry.{method}": {
                "policy.authorize": tuple(f"arg:{index}" for index in range(1, 5)),
            },
        },
    )


def _summary(ids: list[str], failures: list[dict[str, Any]]) -> dict[str, Any]:
    unique = len(set(ids)) == len(ids)
    return {
        "passed": bool(ids) and unique and not failures,
        "cases": len(ids),
        "unique_case_ids": unique,
        "case_ids_sha256": hashlib.sha256(
            json.dumps(ids, separators=(",", ":")).encode()
        ).hexdigest(),
        "failures": failures,
    }


def verify_binding_permutations() -> dict[str, Any]:
    ids, failures = [], []
    permutations = tuple(itertools.permutations(SLOTS))
    for asynchronous, form, guard, authorization, effect in itertools.product(
        (False, True), FORMS, GUARDS, permutations, permutations
    ):
        case_id = f"{'async' if asynchronous else 'sync'}/{form}/{guard}/{'-'.join(authorization)}/{'-'.join(effect)}"
        ids.append(case_id)
        proof = verify(binding_spec(authorization, effect, form, asynchronous, guard))
        expected = (
            "verified"
            if authorization == effect == SLOTS and guard == "allow_only"
            else "violated"
        )
        entries = proof["entries"]
        if (
            proof["issues"]
            or len(entries) != 1
            or entries[0]["status"] != expected
            or not entries[0]["dispatches"]
            or proof["complete"] != (expected == "verified")
        ):
            failures.append(
                {
                    "case": case_id,
                    "expected": expected,
                    "actual": [entry["status"] for entry in entries],
                    "issues": proof["issues"][:3],
                    "entry_issues": [entry["issues"][:3] for entry in entries],
                }
            )
    return {
        **_summary(ids, failures),
        "dimensions": {
            "modes": 2,
            "forms": list(FORMS),
            "guards": list(GUARDS),
            "binding_slots": list(SLOTS),
            "authorization_permutations": 24,
            "effect_permutations": 24,
        },
        "claim": "All combinations of these finite source dimensions; unsupported analysis fails the test, including for negative fixtures.",
    }


class _Observer:
    """Trusted test instrumentation; it is not a host-enforcement backend."""

    def __init__(self) -> None:
        self.verdicts: dict[str, Verdict] = {}
        self.events: list[tuple[str, tuple[Any, ...]]] = []
        self.effects: list[tuple[Any, ...]] = []
        self.authorization: ObjectAuthorization | None = None

    def decision(self, stage: str, args: tuple[Any, ...]) -> Decision:
        self.events.append((stage, args))
        verdict = self.verdicts[stage]
        reason = f"matrix:{stage}:{verdict.value}"
        if verdict in (Verdict.TRANSFORM, Verdict.REDACT):
            return Decision(verdict, reason, new_args={"value": "effective"})
        if verdict is Verdict.ESCALATE:
            return Decision(
                verdict,
                reason,
                escalation=EscalationRequest("approval", reason, "fixture", "call"),
            )
        return Decision(verdict, reason)

    def permission(self, *args: Any) -> Decision:
        return self.decision("tool", args)

    async def apermission(self, *args: Any) -> Decision:
        return self.permission(*args)

    def origin_permission(self, *args: Any) -> Decision:
        return self.decision("origin", args)

    async def aorigin_permission(self, *args: Any) -> Decision:
        return self.origin_permission(*args)

    def delegation_permission(self, *args: Any) -> Decision:
        return self.decision("delegation", args)

    async def adelegation_permission(self, *args: Any) -> Decision:
        return self.delegation_permission(*args)

    def transition_permission(self, *args: Any) -> Decision:
        return self.decision("transition", args)

    async def atransition_permission(self, *args: Any) -> Decision:
        return self.transition_permission(*args)

    def object_permission(self, *args: Any) -> ObjectAuthorization:
        self.authorization = ObjectAuthorization(self.decision("object", args), args[1])
        return self.authorization

    async def aobject_permission(self, *args: Any) -> ObjectAuthorization:
        return self.object_permission(*args)

    def object_resume_permission(self, *args: Any) -> ObjectAuthorization:
        self.authorization = ObjectAuthorization(self.decision("resume", args), args[1])
        return self.authorization

    async def aobject_resume_permission(self, *args: Any) -> ObjectAuthorization:
        return self.object_resume_permission(*args)

    def invoke(self, *args: Any) -> Any:
        self.effects.append(args)
        return None

    async def ainvoke(self, *args: Any) -> Any:
        return self.invoke(*args)

    invoke_from = invoke
    ainvoke_from = ainvoke
    dispatch = invoke
    adispatch = ainvoke


def _requests(principal: Principal, tool: Tool) -> list[tuple[str, Any]]:
    requests: list[tuple[str, Any]] = [
        (
            f"state:{operation.value}",
            StateRequest(operation, "resource", principal.user_id, value="value"),
        )
        for operation in StateOperation
    ]
    requests += [
        (
            f"dispatch:{kind.value}",
            DispatchRequest(kind, principal, principal, "dispatch"),
        )
        for kind in DispatchKind
    ]
    requests += [
        (f"registry:{dynamic}:{override}", ToolRegistryRequest(tool, dynamic, override))
        for dynamic, override in itertools.product((False, True), repeat=2)
    ]
    requests += [
        (f"model:{model}", ModelInvocationRequest(model, (), "invocation"))
        for model in ("model-a", "model-b")
    ]
    requests += [
        (
            f"output:{destination}",
            OutputRequest(
                destination, "value", SecurityLabels(), frozenset(), "output"
            ),
        )
        for destination in ("user", "callback")
    ]
    return requests


async def verify_denial_permutations() -> dict[str, Any]:
    certificate = verify_host_router()
    discovered = {name for name, member in vars(HostRouter).items() if callable(member)}
    expected_apis = set((*ROOT_APIS, *CROSS_APIS, *FRAMEWORK_APIS))
    if not certificate["complete"] or discovered != expected_apis:
        return {
            "passed": False,
            "cases": 0,
            "failures": [
                {
                    "reason": "Router admission or API inventory changed",
                    "unclassified": sorted(discovered - expected_apis),
                    "missing": sorted(expected_apis - discovered),
                }
            ],
        }
    observer = _Observer()
    router = make_host_router(observer, observer)
    principal = Principal(
        "alice", frozenset({"operator"}), frozenset({"read"}), "session"
    )
    child = Principal(
        "alice", principal.roles, principal.scopes, "session", delegated_by="alice"
    )
    tool = Tool("fixture", ToolDac("operator", {"operator": "x"}), frozenset(), ())
    call = ToolCall(tool, {"value": "inert"}, {}, "call", 0)
    origin = ToolOrigin("parent-tool", "parent-call", object())
    approval = Approval("approval", True, "reviewer")
    nonallow = tuple(verdict for verdict in Verdict if verdict is not Verdict.ALLOW)
    ids: list[str] = []
    failures: list[dict[str, Any]] = []

    async def check(
        case_id: str,
        api: str,
        args: tuple[Any, ...],
        verdicts: dict[str, Verdict],
        stages: tuple[str, ...],
        stage_args: dict[str, tuple[Any, ...]],
        escalation: bool = False,
    ) -> None:
        ids.append(case_id)
        observer.verdicts = verdicts
        observer.events.clear()
        observer.effects.clear()
        observer.authorization = None
        first = next(stage for stage in stages if verdicts[stage] is not Verdict.ALLOW)
        expected_events = stages[: stages.index(first) + 1]
        outcome = "return"
        result = None
        try:
            result = getattr(router, api)(*args)
            if inspect.isawaitable(result):
                result = await result
        except PermissionError as exc:
            outcome = str(exc)
        except Exception as exc:
            outcome = f"unexpected:{type(exc).__name__}"
        expected_outcome = (
            "return" if escalation else f"matrix:{first}:{verdicts[first].value}"
        )
        bound = all(
            len(values) == len(stage_args[stage])
            and all(
                actual is expected
                for actual, expected in zip(values, stage_args[stage])
            )
            for stage, values in observer.events
            if stage in stage_args
        )
        if (
            outcome != expected_outcome
            or observer.effects
            or not bound
            or tuple(stage for stage, _ in observer.events) != expected_events
            or (
                escalation
                and (
                    observer.authorization is None
                    or result is not observer.authorization
                )
            )
        ):
            failures.append(
                {
                    "case": case_id,
                    "expected": expected_outcome,
                    "actual": outcome,
                    "effects": len(observer.effects),
                    "events": [stage for stage, _ in observer.events],
                    "exact_bindings": bound,
                }
            )

    for api, verdict in itertools.product(ROOT_APIS, nonallow):
        await check(
            f"root/{api}/{verdict.value}",
            api,
            (principal, call),
            {"tool": verdict},
            ("tool",),
            {"tool": (principal, call)},
        )
    stages = ("origin", "delegation", "transition", "tool")
    cross_args = (origin, principal, child, call)
    for api, values in itertools.product(
        CROSS_APIS, itertools.product(Verdict, repeat=4)
    ):
        if all(value is Verdict.ALLOW for value in values):
            continue
        await check(
            f"cross/{api}/{'-'.join(value.value for value in values)}",
            api,
            cross_args,
            dict(zip(stages, values)),
            stages,
            {
                stage: (child, call) if stage == "tool" else cross_args
                for stage in stages
            },
        )
    requests = _requests(principal, tool)
    for api, (name, request), verdict in itertools.product(
        FRAMEWORK_APIS, requests, nonallow
    ):
        resume = api in {"resume", "aresume"}
        stage = "resume" if resume else "object"
        args = (principal, request, approval) if resume else (principal, request)
        await check(
            f"framework/{api}/{name}/{verdict.value}",
            api,
            args,
            {stage: verdict},
            (stage,),
            {stage: args},
            escalation=not resume and verdict is Verdict.ESCALATE,
        )
    return {
        **_summary(ids, failures),
        "apis": sorted(discovered),
        "request_variants": len(requests),
        "verdicts": [verdict.value for verdict in Verdict],
        "router_runtime_binding": certificate["runtime_binding"],
        "claim": "Every combination in the declared router matrix that contains a non-ALLOW decision produces zero observed terminal host effects and preserves original authorization argument identities. Synthetic observers do not prove adapter or kernel integration.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = verify_binding_permutations()
    runtime = asyncio.run(verify_denial_permutations())
    report = {
        "schema_version": 1,
        "kind": "non-bypassability-permutation-tests",
        "suite_passed": source["passed"] and runtime["passed"],
        "system_complete": False,
        "source_bindings": source,
        "runtime_denial": runtime,
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "transfer_engine_sha256": hashlib.sha256(
            Path(inspect.getfile(verify)).read_bytes()
        ).hexdigest(),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"Source binding cases: {source['cases']}; runtime denial cases: {runtime['cases']}; suite passed: {report['suite_passed']}. This is not a system completeness certificate."
    )
    return 0 if report["suite_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
