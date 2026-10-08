"""Verify complete execution-API conformance for secured tool objects.

Unlike the bounded source analysis, this command inventories the installed API
surface independently and executes a finite, explicit allow/deny matrix. Its
completeness claim is about that API contract, not arbitrary Python programs or
all possible arguments, policy implementations, or adapter compositions.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import json
import platform
import warnings
from collections import Counter
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path
from threading import RLock
from typing import Any, cast

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda
from langchain_core.runnables.utils import ConfigurableField
from langchain_core.tools import StructuredTool
from langchain_core.tools import Tool as SimpleTool
from langgraph.runtime import Runtime

from langgraph.prebuilt.security._mediation_catalog import framework_report
from langgraph.prebuilt.security.binding import with_principal
from langgraph.prebuilt.security.config import SecurityConfig
from langgraph.prebuilt.security.descriptor import Effect, dac, effects
from langgraph.prebuilt.security.enforcement import ActivationReceipt, EnforcementMode
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.guarded import _GuardedExecutor, guarded_tool
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.types import (
    Decision,
    ForbidConstraint,
    PolicyConstraint,
    Principal,
    RulePredicate,
    ToolCall,
    Verdict,
)
from langgraph.prebuilt.tool_node import ToolNode

# No wildcard/default classification: a newly installed API fails discovery.
EXECUTION_APIS = frozenset(
    {
        "invoke",
        "ainvoke",
        "run",
        "arun",
        "batch",
        "abatch",
        "batch_as_completed",
        "abatch_as_completed",
        "stream",
        "astream",
        "stream_events",
        "astream_events",
        "astream_log",
        "transform",
        "atransform",
        "_run",
        "_arun",
        "__call__",
        "func",
        "afunc",
        "coroutine",
    }
)
FACTORY_APIS = frozenset(
    {
        "bind",
        "with_config",
        "with_retry",
        "with_fallbacks",
        "with_types",
        "with_listeners",
        "with_alisteners",
        "pipe",
        "__or__",
        "__ror__",
        "map",
        "pick",
        "assign",
        "as_tool",
        "copy",
        "model_copy",
        "configurable_fields",
        "configurable_alternatives",
        "prepare",
    }
)
INSPECTION_APIS = frozenset(
    {
        "config_schema",
        "dict",
        "json",
        "get_config_jsonschema",
        "get_graph",
        "get_input_jsonschema",
        "get_input_schema",
        "get_name",
        "get_output_jsonschema",
        "get_output_schema",
        "get_prompts",
        "model_dump",
        "model_dump_json",
        "to_json",
        "to_json_not_implemented",
        "get_lc_namespace",
        "is_lc_serializable",
        "lc_id",
        "model_json_schema",
        "model_parametrized_name",
        "schema",
        "schema_json",
    }
)
CONSTRUCTION_APIS = frozenset(
    {
        "construct",
        "from_function",
        "from_orm",
        "model_construct",
        "model_post_init",
        "model_rebuild",
        "model_validate",
        "model_validate_json",
        "model_validate_strings",
        "parse_file",
        "parse_obj",
        "parse_raw",
        "update_forward_refs",
        "validate",
    }
)
_MODES = ("allow", "deny", "missing_principal", "missing_scope")
_FAMILIES = ("guarded_structured", "guarded_simple", "node_structured", "node_simple")
_BACKENDS = ("in_process", "host", "host_denied")


def inventory(cls: Any) -> list[dict[str, Any]]:
    """Discover inherited public methods and executable low-level hooks."""
    entries = []
    for name in sorted(dir(cls)):
        if name.startswith("_") and name not in EXECUTION_APIS | FACTORY_APIS:
            continue
        method = inspect.getattr_static(cls, name)
        if isinstance(method, (classmethod, staticmethod)):
            method = method.__func__
        if not callable(method) or isinstance(method, type):
            continue
        kind = (
            "execution"
            if name in EXECUTION_APIS
            else "factory"
            if name in FACTORY_APIS
            else "inspection"
            if name in INSPECTION_APIS
            else "trusted_construction"
            if name in CONSTRUCTION_APIS
            else "unclassified"
        )
        try:
            source = inspect.getsource(method)
        except (OSError, TypeError):
            source = ""
            kind = "unclassified"
        entries.append(
            {
                "name": name,
                "owner": f"{method.__module__}.{method.__qualname__}",
                "parameters": list(inspect.signature(method).parameters),
                "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "classification": kind,
            }
        )
    return entries


class _ProbePolicy(SecurityModule):
    """Track the subject and arguments at each physical execution in fixtures."""

    name = "api_conformance"

    def __init__(self, mode: str, backend: str = "in_process") -> None:
        self.mode = mode
        self.backend = backend
        self.lock = RLock()
        self.approvals: Counter[str] = Counter()
        self.attempts = 0
        self.executions = 0
        self.errors: list[str] = []
        self.host_attempts = 0
        self.local_attempts = 0
        self.host_calls: dict[str, tuple[Principal, ToolCall]] = {}
        self.constraints = (
            (
                ForbidConstraint(
                    "probe-network",
                    RulePredicate(domain="network"),
                    "fixture restriction",
                ),
            )
            if backend != "in_process"
            else ()
        )

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        with self.lock:
            self.attempts += 1
            if principal.user_id != "verifier" or call.tool.name != "probe":
                self.errors.append("subject or tool identity changed")
            if self.mode == "deny":
                return Decision(Verdict.DENY, "api_probe_denied")
            self.approvals[str(call.args.get("value"))] += 1
            self.host_calls[call.call_id] = (principal, call)
        return Decision(
            Verdict.ALLOW, "api_probe_allowed", constraints=self.constraints
        )

    def execute(self, value: str, *, hosted: bool = False) -> dict[str, str]:
        with self.lock:
            if not hosted:
                self.local_attempts += 1
                if self.backend != "in_process":
                    self.errors.append("host execution fell back to the local tool")
            self.executions += 1
            if self.approvals[value] <= 0:
                self.errors.append("execution lacked matching fresh authorization")
            else:
                self.approvals[value] -= 1
        return {"value": value}


class _ProbeHost:
    """Pure routing oracle, not evidence of real kernel confinement."""

    def __init__(self, policy: _ProbePolicy) -> None:
        self.policy = policy

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        if set(tool_names) != {"probe"}:
            raise ValueError("unexpected fixture tool registry")

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        policy = self.policy
        with policy.lock:
            policy.host_attempts += 1
            expected = policy.host_calls.pop(call.call_id, None)
            if (
                expected is None
                or expected[0] is not principal
                or expected[1] is not call
            ):
                policy.errors.append("host dispatch changed authorized subject/request")
            if tuple(constraints) != tuple(
                replace(item, module=policy.name) for item in policy.constraints
            ):
                policy.errors.append(
                    "host dispatch dropped or changed policy constraints"
                )
            if policy.backend == "host_denied":
                input_value = str(call.args.get("value"))
                if policy.approvals[input_value] <= 0:
                    policy.errors.append("host dispatch lacked fresh authorization")
                else:
                    policy.approvals[input_value] -= 1
                raise HostExecutionDenied("api_host_activation_denied")
        value = policy.execute(str(call.args.get("value")), hosted=True)
        receipt = ActivationReceipt(
            "fixture-grant",
            "fixture-plan",
            "fixture-host",
            "fixture-context",
            call.call_id,
            EnforcementMode.ENFORCED,
            (),
            frozenset(),
            1.0,
        )
        return HostExecutionResult(value, receipt)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        return self.invoke(principal, call, constraints)

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        raise AssertionError("the pure fixture does not create workers")


class _Fixture:
    def __init__(self, family: str, mode: str, backend: str = "in_process") -> None:
        self.base: Any
        self.family = family
        self.policy = _ProbePolicy(mode, backend)

        def probe(value: str) -> dict[str, str]:
            """Return fixture data; no files, network, or subprocess effects."""
            return self.policy.execute(value)

        async def aprobe(value: str) -> dict[str, str]:
            return self.policy.execute(value)

        target: SimpleTool | StructuredTool
        if family.endswith("simple"):
            target = SimpleTool(
                name="probe",
                func=probe,
                coroutine=aprobe,
                description="Pure verifier fixture",
            )
        else:
            target = StructuredTool.from_function(probe, coroutine=aprobe, name="probe")
        effects(Effect.READ)(target)
        dac(
            owner="operator",
            grants={"tester": "x", "*": "-"},
            required_scopes=["probe:read"],
        )(target)
        security = SecurityConfig(
            modules=(self.policy,),
            host_executor=_ProbeHost(self.policy) if backend != "in_process" else None,
        )
        self.runtime = Runtime()
        if family.startswith("guarded"):
            self.base = guarded_tool(target, security=security)
            # The verifier owns the wrapper and closes its executor after probes.
            assert self.base.func is not None
            executor = next(
                cell.cell_contents
                for cell in self.base.func.__closure__ or ()
                if isinstance(cell.cell_contents, _GuardedExecutor)
            )
            self.stack = executor.stack
        else:
            self.base = ToolNode([target], security=security, handle_tool_errors=False)
            self.stack = self.base._security_stack
        config: dict[str, Any] = {"configurable": {"__pregel_runtime": self.runtime}}
        if mode != "missing_principal":
            principal = Principal(
                "verifier",
                frozenset({"tester"}),
                frozenset() if mode == "missing_scope" else frozenset({"probe:read"}),
                "api-verification",
            )
            config = dict(
                with_principal(
                    cast(RunnableConfig, config), principal, modules=security.modules
                )
            )
        self.config = config

    def input(self, suffix: str = "A") -> dict[str, Any]:
        args = {"value": f"fixture-{suffix}"}
        if self.family.startswith("guarded"):
            return args
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "probe",
                            "args": args,
                            "id": f"probe-{suffix}",
                        }
                    ],
                )
            ]
        }

    def close(self) -> None:
        if self.stack is not None:
            self.stack.close()


def _adapt(fixture: _Fixture, factory: str) -> tuple[Any, Callable[[Any], Any]]:
    base = fixture.base

    def identity(value: Any) -> Any:
        return value

    if factory.endswith(".prepare"):
        wrapped, _ = _adapt(fixture, factory.removesuffix(".prepare"))
        prepared, config = wrapped.prepare(fixture.config)
        fixture.config = config
        return prepared, identity
    if factory == "identity":
        return base, identity
    if factory == "bind":
        return base.bind(), identity
    if factory == "with_config":
        return base.with_config(metadata={"api_verifier": True}), identity
    if factory == "with_retry":
        return base.with_retry(
            stop_after_attempt=2, wait_exponential_jitter=False
        ), identity
    if factory == "with_fallbacks":
        return base.with_fallbacks([base]), identity
    if factory == "with_types":
        return base.with_types(input_type=dict, output_type=dict), identity
    if factory in {
        "with_listeners",
        "with_alisteners",
        "configurable_fields",
        "copy",
        "model_copy",
    }:
        return getattr(base, factory)(), identity
    if factory == "configurable_alternatives":
        return base.configurable_alternatives(
            ConfigurableField(id="secured_choice"),
            secured=base,
        ).with_config(configurable={"secured_choice": "secured"}), identity
    if factory in {"pipe", "__or__"}:
        return getattr(base, factory)(RunnableLambda(identity)), identity
    if factory == "__ror__":
        return base.__ror__(RunnableLambda(identity)), identity
    if factory == "map":
        return base.map(), lambda value: [value]
    if factory == "pick":
        return base.pick(
            "value" if fixture.family.startswith("guarded") else "messages"
        ), identity
    if factory == "assign":
        return base.assign(verification=RunnableLambda(lambda value: True)), identity
    if factory == "as_tool":
        args = (
            {"value": str}
            if fixture.family.startswith("guarded")
            else {"messages": list}
        )
        return base.as_tool(
            name="secured_adapter", description="Verifier adapter", arg_types=args
        ), identity
    raise ValueError(f"factory has no exercise: {factory}")


async def _execute(
    fixture: _Fixture,
    target: Any,
    api: str,
    convert: Callable[[Any], Any],
    *,
    event_version: str = "v2",
) -> Any:
    value, second = convert(fixture.input()), convert(fixture.input("B"))
    config = fixture.config
    method = getattr(target, api)
    if api == "ainvoke":
        return await method(value, config=config)
    if api == "arun":
        return await method(value, config=config)
    if api == "abatch":
        return await method([value, second], config=config, return_exceptions=True)
    if api == "abatch_as_completed":
        return [
            item
            async for item in method(
                [value, second], config=config, return_exceptions=True
            )
        ]
    if api in {"astream", "astream_log", "astream_events", "atransform"}:

        async def values() -> AsyncIterator[Any]:
            yield value

        stream = method(
            values() if api == "atransform" else value,
            config=config,
            **({"version": event_version} if api == "astream_events" else {}),
        )
        if inspect.isawaitable(stream):
            stream = await stream
        try:
            return [item async for item in stream]
        finally:
            if hasattr(stream, "aclose"):
                await stream.aclose()
    callback_args = dict(value) if isinstance(value, dict) else {}
    if (
        api in {"func", "coroutine"}
        and "callbacks" in inspect.signature(method).parameters
    ):
        callback_args["callbacks"] = None
    if api in {"_arun", "coroutine"}:
        return await method(**callback_args, config=config)
    if api == "afunc":
        return await method(value, config, fixture.runtime)

    def sync() -> Any:
        if api in {"batch", "batch_as_completed"}:
            result = method([value, second], config=config, return_exceptions=True)
            return list(result)
        if api in {"stream", "stream_events", "transform"}:
            return list(
                method(
                    iter([value]) if api == "transform" else value,
                    config=config,
                    **({"version": event_version} if api == "stream_events" else {}),
                )
            )
        if api == "_run" or (api == "func" and not isinstance(target, ToolNode)):
            return method(**callback_args, config=config)
        if api == "func":
            return method(value, config, fixture.runtime)
        return method(value, config=config)

    return await asyncio.to_thread(sync)


async def _case(
    family: str,
    factory: str,
    api: str,
    mode: str,
    event_version: str,
    backend: str = "in_process",
) -> dict[str, Any]:
    fixture = _Fixture(family, mode, backend)
    exception: Exception | None = None
    result: Any = None
    try:
        try:
            target, convert = _adapt(fixture, factory)
            result = await asyncio.wait_for(
                _execute(fixture, target, api, convert, event_version=event_version),
                15,
            )
        except Exception as exc:
            exception = exc
        policy = fixture.policy
        blocked_api = api == "stream_events" or (
            api == "astream_events" and (event_version == "v3" or factory == "map")
        )
        if blocked_api:
            passed = (
                isinstance(exception, NotImplementedError) and policy.executions == 0
            )
        elif mode == "allow" and backend == "host_denied":
            passed = (
                policy.executions == 0
                and policy.host_attempts > 0
                and "api_host_activation_denied"
                in str(exception if exception is not None else result)
            )
        elif mode == "allow":
            expected = (
                2
                if api
                in {"batch", "abatch", "batch_as_completed", "abatch_as_completed"}
                else 1
            )
            passed = (
                exception is None
                and policy.executions == expected
                and policy.attempts == expected
            )
        else:
            reason = {
                "deny": "api_probe_denied",
                "missing_principal": "no_principal",
                "missing_scope": "dac:scope",
            }[mode]
            passed = policy.executions == 0 and reason in str(
                exception if exception is not None else result
            )
            if mode == "deny":
                passed = passed and policy.attempts > 0
        passed = passed and not policy.errors and not any(policy.approvals.values())
        if backend != "in_process":
            passed = passed and policy.local_attempts == 0
            if mode != "allow" or blocked_api:
                passed = passed and policy.host_attempts == 0
            elif backend == "host":
                passed = passed and policy.host_attempts == policy.executions
        return {
            "backend": backend,
            "family": family,
            "factory": factory,
            "api": api,
            "mode": mode,
            "event_version": event_version if "events" in api else None,
            "status": "passed" if passed else "failed",
            "execution_count": policy.executions,
            "permission_count": policy.attempts,
            "host_dispatch_count": policy.host_attempts,
            "local_dispatch_count": policy.local_attempts,
            "errors": policy.errors,
            "exception": type(exception).__name__ if exception else None,
            "diagnostic": str(exception if exception is not None else result)[:300]
            if not passed
            else "",
            "unused_authorizations": sum(policy.approvals.values()),
            "expected_unavailable": blocked_api,
        }
    finally:
        fixture.close()


async def _verify_tool_apis(*, source_root: Path | None = None) -> dict[str, Any]:
    """Run all discovered execution APIs, adapters and denial modes on fixtures."""
    source_root = source_root or Path(__file__).parents[1]
    source_report = framework_report(source_root)
    surfaces: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for family in _FAMILIES:
        initial = _Fixture(family, "allow")
        try:
            entries = inventory(initial.base)
            factories = ["identity"] + [
                item["name"] for item in entries if item["classification"] == "factory"
            ]
            factories += [
                name + ".prepare"
                for name in factories
                if name in {"configurable_fields", "configurable_alternatives"}
            ]
        finally:
            initial.close()
        for factory in factories:
            sample = _Fixture(family, "allow")
            try:
                target, _ = _adapt(sample, factory)
                surface = inventory(target)
                # Include inherited methods and exposed callback fields on every
                # returned object, including adapters.
                apis = [
                    item["name"]
                    for item in surface
                    if item["classification"] == "execution"
                ]
                surfaces.append(
                    {
                        "family": family,
                        "factory": factory,
                        "class": f"{type(target).__module__}.{type(target).__qualname__}",
                        "methods": surface,
                        "exercised_apis": apis,
                    }
                )
            except Exception as exc:
                surfaces.append(
                    {
                        "family": family,
                        "factory": factory,
                        "class": None,
                        "methods": [],
                        "exercised_apis": [],
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                apis = []
            finally:
                sample.close()
            for api in apis:
                versions = ("v1", "v2", "v3") if "events" in api else ("v2",)
                for event_version in versions:
                    for mode in _MODES:
                        for backend in _BACKENDS:
                            cases.append(
                                await _case(
                                    family, factory, api, mode, event_version, backend
                                )
                            )
    coverage_complete = bool(surfaces) and all(
        not surface.get("error")
        and all(item["classification"] != "unclassified" for item in surface["methods"])
        for surface in surfaces
    )
    conformance_passed = bool(cases) and all(
        case["status"] == "passed" for case in cases
    )
    evidence_ready = all(
        item["status"] == "source_bound" for item in source_report["source_evidence"]
    )
    complete = (
        coverage_complete
        and conformance_passed
        and evidence_ready
        and source_report["claims_passed"]
    )
    return {
        "schema_version": 1,
        "claim": "Complete installed secured-tool execution API coverage and allow/deny conformance for the enumerated matrix.",
        "complete": complete,
        "inventory_complete": coverage_complete,
        "conformance_passed": conformance_passed,
        "source_claims_passed": source_report["claims_passed"],
        "source_evidence_ready": evidence_ready,
        "whole_framework_mac_complete": source_report["complete"],
        "versions": {
            "python": platform.python_version(),
            "langchain-core": version("langchain-core"),
            "langgraph-prebuilt": version("langgraph-prebuilt"),
        },
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_checks": source_report["checks"],
        "scope": {
            "families": list(_FAMILIES),
            "modes": list(_MODES),
            "backends": list(_BACKENDS),
            "host_oracle": "Synthetic host checks exact authorized subject/request/constraints and absence of local fallback, including activation denial; real kernel activation is tested separately.",
            "factory_parameters": "Identity-preserving adapters and secured fallbacks/alternatives; no replacement executable supplied by untrusted code.",
            "construction_and_inspection": "Inventoried separately; trusted application construction/schema/serialization APIs are not tool-execution entry points.",
            "limits": [
                "Finite API conformance, not a proof for all arguments or arbitrary adapter compositions.",
                "Original unguarded aliases, hostile object mutation, policy semantics and effects inside trusted in-process tools are outside this contract.",
                "No claim of complete confidentiality, concurrency/lifetime correctness, or publication mediation.",
            ],
        },
        "surfaces": surfaces,
        "cases": cases,
        "summary": {
            "surfaces": len(surfaces),
            "cases": len(cases),
            "passed": sum(item["status"] == "passed" for item in cases),
            "failed": sum(item["status"] != "passed" for item in cases),
        },
    }


async def verify_tool_apis(*, source_root: Path | None = None) -> dict[str, Any]:
    """Run in a dedicated event loop; unhandled stream errors also fail the gate."""
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    background_errors: list[dict[str, str]] = []

    def record_error(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        error = context.get("exception")
        background_errors.append(
            {
                "message": str(context.get("message", "")),
                "exception": type(error).__name__,
                "diagnostic": str(error)[:300],
            }
        )

    loop.set_exception_handler(record_error)
    try:
        report = await _verify_tool_apis(source_root=source_root)
        await loop.shutdown_asyncgens()
        await asyncio.sleep(0)
        report["background_errors"] = background_errors
        report["complete"] = report["complete"] and not background_errors
        return report
    finally:
        loop.set_exception_handler(previous_handler)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        report = asyncio.run(verify_tool_apis())
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
