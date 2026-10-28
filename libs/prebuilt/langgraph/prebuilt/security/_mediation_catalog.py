"""Reviewed, bounded framework contracts for authorization coverage.

The inventory is intentionally broader than the currently verified claims.
Trusting a call summary is never represented as verifying its implementation.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.mediation import (
    Authorizer,
    Contract,
    Operation,
    analyze_function,
)

_ASSUMPTIONS = (
    "Security is configured and its configuration is controlled by the application.",
    "Authorizer summaries authenticate the principal and return decisions for exactly the selected request.",
    "Request/principal identities and their security-relevant contents remain stable across reviewed calls and awaits.",
    "Reviewed calls preserve authorization inputs; their implementations and hidden effects are not verified here.",
    "Python builtins, Verdict enum identity, attribute reads and call-target resolution behave as declared; no monkeypatching or hostile descriptors.",
    "In-process dispatch and its argument/target projection are inventoried separately as unresolved.",
)

_GUARDED_TRUST = (
    "Decision",
    "SecurityDeniedError",
    "SecurityIndeterminateError",
    "dict",
    "str",
    "exc.receipt.audit_reason",
    "host_result.receipt.audit_reason",
    "self._acquire_flow",
    "self._analysis_result",
    "self._aanalysis_result",
    "self._finalize_flow",
    "self._prepare",
    "self._release_flow",
    "self.stack.post",
    "self.stack.apost",
    "self.stack.prepare",
    "self.stack.aprepare",
    "self.stack.record_framework_event",
    "self.target.invoke",
    "self.target.ainvoke",
)

_NODE_TRUST = (
    "Decision",
    "SecurityIndeterminateError",
    "ToolInvocationError",
    "ToolMessage",
    "TypeError",
    "_filter_validation_errors",
    "_handle_tool_error",
    "_infer_handled_types",
    "callable",
    "cast",
    "exc.receipt.audit_reason",
    "host_result.receipt.audit_reason",
    "isinstance",
    "issubclass",
    "msg_content_output",
    "self._acquire_security_flow",
    "self._audit_security",
    "self._finalize_security_flow",
    "self._inject_tool_args",
    "self._injected_args.get",
    "self._normalize_tool_response",
    # Lifecycle callbacks receive a fresh name/id dict, never authorization objects.
    "self._notify_tool_phase",
    "self._anotify_tool_phase",
    "self._release_security_flow",
    "self._security_denial",
    "self._security_trace_config",
    "self._validate_tool_call",
    "stack.post",
    "stack.apost",
    "str",
    "tool.invoke",
    "tool.ainvoke",
)

# Updating one of these values is an explicit review action. A changed helper
# body makes dependent obligations unresolved until its summary is re-reviewed.
_REVIEWED_DIGESTS = {
    "authorization-stack": "465eeff9d5953752738be9fe2e5aeb93cbee606df27e7063ebe85b27e7ed246f",
    "guarded-request-binding": "618de901277adc73396c1e08ab27562560a8f010e0aa7a2ec6763a7052144717",
    "toolnode-request-binding": "96d570d9470e7155270ea07662505ca913245560196678c66b66ea476e572a61",
    "in-process-dispatch-binding": "b4e3816578032535a10fc9b87e24536b7bd0defbb23b925ba91fb1cc5c9d1cc7",
    "guarded-in-process-dispatch": "e8297c70f9e05987e8d3be3ddf7cca4bc6bc69d6531ba11824aea91553df01e6",
    "linux-grant-activation": "ce921b3854f9f5f45ddaaf4762faa2c9cbd7198218f052f58399fa97118abbd5",
    "enforcement-receipt": "9a17cd15c3cb9b68fc84d00e8dc06333d2eff0bcb993d32a85de41b0727a88f8",
    "flow-lifecycle": "455dc915f2de6497930122596f1af5cc72b0a2ec0731fdec9dea3259922ec48f",
    "delegation-transfer": "b275e7e857ae259c20b0b5c07619bda9089c946239ea86f641a9efd94041371f",
    "publication-boundaries": "db2150a7e8eaba1baba53ee9860fd48e455ec42841dc65ebef8167ac9680539d",
}


def contracts() -> tuple[tuple[str, Contract], ...]:
    """Enumerate secured host and in-process dispatch entry points."""
    entries = []
    for asynchronous in (False, True):
        invoke = "ainvoke" if asynchronous else "invoke"
        permission = "apermission" if asynchronous else "permission"
        resume = "_aresume" if asynchronous else "_resume"
        entries.append(
            (
                "security/guarded.py",
                Contract(
                    f"_GuardedExecutor.{invoke}",
                    (
                        Authorizer(f"self.stack.{permission}", ("arg:0", "arg:1")),
                        Authorizer(f"self.{resume}", ("arg:0", "arg:1")),
                    ),
                    (
                        Operation(f"self.host_router.{invoke}", ("arg:0", "arg:1")),
                        Operation(
                            f"self._{'a' if asynchronous else ''}invoke_in_process",
                            ("arg:0", "arg:1"),
                        ),
                    ),
                    _GUARDED_TRUST,
                    _ASSUMPTIONS,
                ),
            )
        )
        execution = "_execute_tool_async" if asynchronous else "_execute_tool_sync"
        resume = "_aresume_security" if asynchronous else "_resume_security"
        entries.append(
            (
                "tool_node.py",
                Contract(
                    f"ToolNode.{execution}",
                    (
                        Authorizer(
                            "self._prepare_security_request",
                            ("result:1.principal", "result:2"),
                            decision="0",
                        ),
                        *(
                            (
                                Authorizer(
                                    "self._aprepare_security_request",
                                    ("result:1.principal", "result:2"),
                                    decision="0",
                                ),
                            )
                            if asynchronous
                            else ()
                        ),
                        Authorizer(f"self.{resume}", ("arg:0", "arg:1")),
                    ),
                    (
                        Operation(
                            f"self._security_host_router.{invoke}",
                            ("arg:0", "arg:1"),
                        ),
                        Operation(
                            f"self._invoke_secured_tool_{'async' if asynchronous else 'sync'}",
                            ("arg:0", "arg:1"),
                        ),
                    ),
                    _NODE_TRUST,
                    _ASSUMPTIONS,
                ),
            )
        )
    return tuple(entries)


def _source_evidence(
    source_root: Path, evidence_id: str, path: str, symbols: tuple[str, ...]
) -> dict[str, Any]:
    """Bind a reviewed claim to exact function bodies without importing them."""
    result: dict[str, Any] = {
        "id": evidence_id,
        "path": path,
        "symbols": list(symbols),
        "status": "unresolved",
        "items": [],
    }
    try:
        source = (source_root / path).read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeError, SyntaxError) as exc:
        result["reason"] = f"input unavailable: {type(exc).__name__}"
        return result
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def visit(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[prefix + node.name] = node

    visit(tree.body)
    for symbol in symbols:
        node = found.get(symbol)
        if node is None:
            result["reason"] = f"reviewed symbol missing: {symbol}"
            return result
        segment = ast.get_source_segment(source, node)
        if segment is None:
            result["reason"] = f"source unavailable for: {symbol}"
            return result
        result["items"].append(
            {
                "symbol": symbol,
                "line": node.lineno,
                "sha256": hashlib.sha256(segment.encode()).hexdigest(),
            }
        )
    manifest = "|".join(
        f"{item['symbol']}:{item['sha256']}" for item in result["items"]
    )
    result["reviewed_digest"] = _REVIEWED_DIGESTS.get(evidence_id, "")
    result["observed_digest"] = hashlib.sha256(manifest.encode()).hexdigest()
    if result["observed_digest"] != result["reviewed_digest"]:
        result["reason"] = "reviewed source digest changed"
        return result
    result["status"] = "source_bound"
    return result


def _evidence(source_root: Path) -> list[dict[str, Any]]:
    specifications = (
        (
            "authorization-stack",
            "security/stack.py",
            (
                "SecurityStack.prepare",
                "SecurityStack.aprepare",
                "SecurityStack.permission",
                "SecurityStack.resume_permission",
                "SecurityStack.apermission",
                "SecurityStack.aresume_permission",
            ),
        ),
        (
            "guarded-request-binding",
            "security/guarded.py",
            (
                "_GuardedExecutor._prepare",
                "_GuardedExecutor._resume",
                "_GuardedExecutor._aresume",
            ),
        ),
        (
            "toolnode-request-binding",
            "tool_node.py",
            (
                "ToolNode._prepare_security_request",
                "ToolNode._aprepare_security_request",
                "ToolNode._resume_security",
                "ToolNode._aresume_security",
                "ToolNode._notify_tool_phase",
                "ToolNode._anotify_tool_phase",
            ),
        ),
        (
            "in-process-dispatch-binding",
            "tool_node.py",
            (
                "ToolNode._invoke_secured_tool_sync",
                "ToolNode._invoke_secured_tool_async",
            ),
        ),
        (
            "guarded-in-process-dispatch",
            "security/guarded.py",
            (
                "_GuardedExecutor._invoke_in_process",
                "_GuardedExecutor._ainvoke_in_process",
                "_GuardedExecutor._analysis_result",
                "_GuardedExecutor._aanalysis_result",
            ),
        ),
        (
            "linux-grant-activation",
            "security/linux.py",
            (
                "LinuxSandboxExecutor._invoke",
                "LinuxSandboxExecutor._compile_grant",
                "LinuxSandboxExecutor._run_worker",
                "LinuxSandboxExecutor._cleanup_worker",
            ),
        ),
        (
            "enforcement-receipt",
            "security/enforcement.py",
            (
                "EnforcementCoordinator.negotiate",
                "EnforcementCoordinator.activate",
                "EnforcementCoordinator.validate_receipt",
            ),
        ),
        (
            "flow-lifecycle",
            "security/flow.py",
            (
                "SessionFlowPolicy.acquire",
                "SessionFlowPolicy.release",
                "SessionFlowPolicy.retain",
                "SessionFlowPolicy.recover_termination",
            ),
        ),
        (
            "delegation-transfer",
            "security/guarded.py",
            (
                "_DelegatedRunnable._principals",
                "_DelegatedRunnable._child_config",
                "_DelegatedRunnable._achild_config",
            ),
        ),
        (
            "publication-boundaries",
            "security/flow.py",
            (
                "SessionFlowPolicy.transfer_session",
                "SessionFlowPolicy.guard_operation",
            ),
        ),
    )
    return [
        _source_evidence(source_root, evidence_id, path, symbols)
        for evidence_id, path, symbols in specifications
    ]


def framework_report(source_root: Path) -> dict[str, Any]:
    """Produce reproducible source-bound evidence, including unresolved coverage."""
    checks: list[dict[str, Any]] = []
    constraint_checks: list[dict[str, Any]] = []
    constraints = []
    for relative, contract in contracts():
        host_operations = tuple(
            replace(item, bindings=(*item.bindings, "arg:2.constraints"))
            for item in contract.operations
            if "host_router" in item.target
        )
        constraints.append(
            (
                relative,
                replace(
                    contract,
                    authorizers=tuple(
                        replace(
                            item,
                            bindings=(
                                *item.bindings,
                                "result:0.constraints"
                                if item.decision == "0"
                                else "result:constraints",
                            ),
                        )
                        for item in contract.authorizers
                    ),
                    operations=host_operations,
                    trusted_calls=(
                        *contract.trusted_calls,
                        *(
                            item.target
                            for item in contract.operations
                            if "host_router" not in item.target
                        ),
                    ),
                ),
            )
        )
    for index, (relative, contract) in enumerate((*contracts(), *constraints)):
        try:
            source = (source_root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            check: dict[str, Any] = {
                "function": contract.function,
                "status": "unresolved",
                "issues": [
                    {"line": 0, "reason": f"input unavailable: {type(exc).__name__}"}
                ],
            }
        else:
            check = analyze_function(source, contract)
        check["path"] = relative
        for summary in check.get("authorizer_summaries", []):
            summary["source_evidence"] = [
                "toolnode-request-binding"
                if summary["target"]
                in {
                    "self._prepare_security_request",
                    "self._aprepare_security_request",
                    "self._resume_security",
                    "self._aresume_security",
                }
                else "guarded-request-binding"
                if summary["target"].startswith("self._")
                else "authorization-stack"
            ]
        (checks if index < len(contracts()) else constraint_checks).append(check)
    evidence = _evidence(source_root)
    evidence_ready = {item["id"]: item["status"] for item in evidence}
    # Reviewed helper drift invalidates the claim gate as well as obligations.
    for check in (*checks, *constraint_checks):
        required = {
            evidence_id
            for summary in check.get("authorizer_summaries", [])
            for evidence_id in summary["source_evidence"]
        }
        required.add(
            "in-process-dispatch-binding"
            if check["path"] == "tool_node.py"
            else "guarded-in-process-dispatch"
        )
        missing = sorted(
            key for key in required if evidence_ready.get(key) != "source_bound"
        )
        if missing:
            check["status"] = "unresolved"
            check.setdefault("issues", []).append(
                {
                    "line": 0,
                    "reason": "unresolved source evidence: " + ", ".join(missing),
                }
            )
    obligations = [
        {
            "id": "authorization-helper-validation",
            "property": "Policy summaries bind a decision to the principal and immutable ToolCall returned by the reviewed prepare/resume path.",
            "supported_scope": "SecurityStack, guarded_tool, and security-enabled ToolNode authorization and approval helpers.",
            "status": "source_bound",
            "source_evidence": [
                "authorization-stack",
                "guarded-request-binding",
                "toolnode-request-binding",
            ],
            "regression_tests": [
                "tests/security/test_stack.py",
                "tests/security/test_guarded.py",
                "tests/security/test_tool_node_security.py",
            ],
            "assumptions": [
                "Configured module implementations correctly implement their declared policy.",
                "Nested argument values are not mutated concurrently after ToolCall construction.",
            ],
            "unresolved": [
                "This is source-bound review evidence, not an interprocedural proof of arbitrary module code."
            ],
        },
        {
            "id": "in-process-execution",
            "property": "A secured in-process dispatch uses the registered executable and the principal, call id, tool name, and full injected argument mapping authorized for that dispatch.",
            "supported_scope": "guarded_tool and security-enabled ToolNode sync/async dispatch; wrapper-supplied executable replacement is rejected.",
            "status": "verified_under_contract",
            "source_evidence": [
                "guarded-in-process-dispatch",
                "in-process-dispatch-binding",
            ],
            "regression_tests": ["tests/security/test_tool_node_security.py"],
            "assumptions": [
                "In-process Python remains trusted not to monkeypatch the stack or mutate shared nested objects."
            ],
            "unresolved": [
                "Effects performed inside an in-process tool are not mediated per resource access."
            ],
        },
        {
            "id": "confinement-activation",
            "property": "The filtered grant and mandatory restrictions determine the negotiated plan, whose digest and complete obligation set are revalidated against the activated worker before GO.",
            "supported_scope": "LinuxSandboxExecutor authority domains implemented by the Linux adapter.",
            "status": "verified_under_contract",
            "source_evidence": ["linux-grant-activation", "enforcement-receipt"],
            "regression_tests": [
                "tests/security/test_enforcement.py",
                "tests/security/test_linux_execution.py",
                "tests/security/test_resource_boundary.py",
            ],
            "assumptions": [
                "Kernel, bubblewrap, libseccomp, interpreter, worker shim, and attested host behavior satisfy the adapter contract."
            ],
            "unresolved": [
                "Unsupported authority domains are rejected; this does not establish process-wide MAC."
            ],
        },
        {
            "id": "execution-lifetime",
            "property": "A flow reservation is acquired before dispatch and is released only after ordinary completion or retained with a process recovery identity until termination is confirmed.",
            "supported_scope": "Configured SessionFlowPolicy and LinuxSandboxExecutor worker processes.",
            "status": "partially_verified",
            "source_evidence": ["flow-lifecycle", "linux-grant-activation"],
            "regression_tests": [
                "tests/security/test_linux_execution.py::test_unconfirmed_termination_retains_durable_flow_reservation",
                "tests/security/test_linux_execution.py::test_cancellation_waits_for_confirmed_linux_termination",
            ],
            "assumptions": [
                "Process identity checks and the durable reservation store remain available."
            ],
            "unresolved": [
                "In-process tools can create background work whose termination is not observable by this framework.",
                "Policy-hook threads that time out may continue until their callable returns.",
            ],
        },
        {
            "id": "delegation-and-transfer",
            "property": "Delegated scopes cannot grow, module slots are copied then restricted, and explicit session transfers propagate flow labels atomically.",
            "supported_scope": "delegate() with one inherited SecurityConfig and explicit SessionFlowPolicy.transfer_session calls.",
            "status": "partially_verified",
            "source_evidence": ["delegation-transfer", "publication-boundaries"],
            "regression_tests": [
                "tests/security/test_guarded.py",
                "tests/security/test_flow.py::test_session_transfer_propagates_label_and_blocks_lower_sink",
            ],
            "assumptions": [
                "All child entry and cross-session publication paths use these APIs."
            ],
            "unresolved": [
                "Live reservations and numeric budgets are not transferable between sessions.",
                "Arbitrary graph Send operations are not automatically treated as authority transfers.",
            ],
        },
        {
            "id": "publication-inventory",
            "property": "Every named publication boundary is classified as automatic mediation, explicit opt-in mediation, trust assumption, or unsupported.",
            "supported_scope": "The documented boundary inventory below; not arbitrary application callbacks or dependencies.",
            "status": "partially_verified",
            "source_evidence": ["publication-boundaries"],
            "regression_tests": ["tests/security/test_flow.py"],
            "assumptions": [
                "Applications identify non-tool sinks and keep guard_operation open for the complete effect lifetime."
            ],
            "unresolved": [
                "There is no framework-wide automatic interception of every model, checkpoint, artifact, callback, or external-effect API."
            ],
        },
    ]
    for obligation in obligations:
        if any(
            evidence_ready.get(evidence_id) != "source_bound"
            for evidence_id in obligation["source_evidence"]
        ):
            obligation["status"] = "unresolved"
    obligation_status = {item["id"]: item["status"] for item in obligations}
    claims_passed = all(
        check["status"] == "verified_under_contract"
        for check in (*checks, *constraint_checks)
    )
    return {
        "schema_version": 2,
        "analysis": "bounded-authorization-state-v2",
        "checker_sha256": hashlib.sha256(
            Path(__file__).with_name("mediation.py").read_bytes()
        ).hexdigest(),
        "catalog_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "property": "Every modelled secured host or in-process dispatch has a preceding successful decision for the same principal and request, not consumed by an earlier dispatch.",
        "claims_passed": claims_passed,
        "complete": False,
        "checks": checks,
        "constraint_checks": constraint_checks,
        "source_evidence": evidence,
        "obligations": obligations,
        "publication_inventory": [
            {
                "boundary": "model requests",
                "status": "explicit_opt_in",
                "mechanism": "SessionFlowPolicy.guard_operation",
            },
            {
                "boundary": "returned tool results",
                "status": "automatic_hook_notification",
                "mechanism": "SecurityStack.post/apost before ToolNode publication",
            },
            {
                "boundary": "checkpoints and artifacts",
                "status": "explicit_opt_in",
                "mechanism": "SessionFlowPolicy.transfer_session",
            },
            {
                "boundary": "callbacks and tracing",
                "status": "explicit_opt_in",
                "mechanism": "SessionFlowPolicy.guard_operation",
            },
            {
                "boundary": "Linux worker external effects",
                "status": "grant_confined",
                "mechanism": "filtered Grant plus activated EnforcementPlan",
            },
            {
                "boundary": "in-process tool external effects",
                "status": "trusted",
                "mechanism": "no per-access mediation after dispatch",
            },
        ],
        "coverage": [
            {
                "operation": "secured host and in-process dispatch",
                "status": "analyzed" if claims_passed else "unresolved",
                "evidence": "checks",
            },
            {
                "operation": "policy and principal helper semantics",
                "status": obligation_status["authorization-helper-validation"],
                "reason": "Summaries link to hashed reviewed function bodies and explicit assumptions.",
            },
            {
                "operation": "grant lowering and worker activation",
                "status": obligation_status["confinement-activation"],
                "reason": "Grant, plan, receipt, and pre-GO activation bindings have source and regression evidence.",
            },
            {
                "operation": "reservation, cancellation and termination lifetime",
                "status": obligation_status["execution-lifetime"],
                "reason": "Linux worker recovery is covered; in-process background work is unsupported.",
            },
            {
                "operation": "delegation, transfers and publication",
                "status": obligation_status["delegation-and-transfer"],
                "reason": "Attenuation and explicit transfer APIs are covered; arbitrary application paths are not intercepted.",
            },
            {
                "operation": "dynamic Python, dependencies and original tool aliases",
                "status": "unsupported",
                "reason": "Use escape analysis and confinement; not covered by this source model.",
            },
        ],
    }
