"""Deterministic restricted-runtime manifest/MAC probes in fresh processes."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from evidence_utils import serial
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Principal,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.inprocess import read_text


@tool
def read_allowed(path: str) -> str:
    """Read the declared file through the granted terminal."""
    return read_text(path)


@tool
def undeclared_read(path: str, other: str) -> str:
    """Attempt an additional read omitted from the supplied manifest."""
    read_text(other)
    return read_text(path)


CASES = [
    "correct",
    "omitted_read",
    "overdeclared",
    "dac_vs_operator_forbid",
    "local_override",
    "rpc_identity",
    "resource_change",
    "missing_enforcer",
    "runtime_waiver",
]


def child(case):
    with tempfile.TemporaryDirectory(prefix="slg-manifest-") as tmp:
        alice = Path(tmp) / "alice"
        bob = Path(tmp) / "bob"
        alice.write_text("ALICE_ALLOWED")
        bob.write_text("BOB_PRIVATE_CANARY")
        # Principal DAC is deliberately broad; only the fixed operator forbid denies Bob.
        policy = "permit(principal, action, resource);"
        forbid = f'''forbid(principal, action == slangGraph::Action::"fs::read", resource)
when {{ resource.selector == "{bob}" }};'''
        install_mac_policy(forbid)
        base = "runs inprocess\nfs read @{path} need"
        principal = Principal("alice", frozenset(), frozenset(), "fixed-session")
        results = []
        for control in [True, False]:
            selected = read_allowed
            manifest = base
            arguments = {"path": str(alice)}
            if not control:
                if case == "omitted_read":
                    selected = undeclared_read
                    arguments["other"] = str(bob)
                elif case == "overdeclared":
                    manifest += f"\nfs read {bob} need"
                elif case in {"dac_vs_operator_forbid", "local_override"}:
                    arguments["path"] = str(bob)
                elif case == "missing_enforcer":
                    manifest = "runs linux\nfs read @{path} need"
            start = time.perf_counter()
            security = None
            error = None
            value = None
            phase = "admission"
            override = None
            try:
                if not control and case == "rpc_identity":
                    results.append(
                        dict(
                            control=False,
                            status="unsupported",
                            reason="restricted runtime exposes no worker RPC identity payload",
                        )
                    )
                    continue
                if not control and case == "local_override":
                    try:
                        install_mac_policy("forbid(principal, action, resource) when { false };")
                    except RuntimeError as exc:
                        override = str(exc)
                security = cedar_security(
                    selected, manifest=manifest, policy=policy, mac_forbids=""
                )
                if not control and case == "runtime_waiver":
                    from langgraph.prebuilt.security import (
                        CedarObjectAuthorizer,
                        ObjectPolicyHostExecutor,
                    )

                    existing = security.host_executor
                    authorizer = CedarObjectAuthorizer(
                        existing.authorizer.manifest,
                        existing.authorizer.policies,
                        enforcement_waivers={"fs": "requested compatibility"},
                    )
                    security = replace(
                        security,
                        host_executor=ObjectPolicyHostExecutor(
                            authorizer, existing.dispatcher, tool_owners=existing.tool_owners
                        ),
                    )
                if not control and case == "resource_change":
                    dispatcher = security.host_executor.dispatcher
                    original = dispatcher.invoke

                    def changed(principal, call, grant, original=original):
                        return original(
                            principal, replace(call, args={"path": str(bob)}, normalized={}), grant
                        )

                    dispatcher.invoke = changed
                builder = StateGraph(MessagesState)
                builder.add_node("tools", ToolNode([selected]))
                builder.add_edge(START, "tools")
                graph = builder.compile(security=security)
                phase = "invocation"
                output = graph.invoke(
                    {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[dict(name=selected.name, args=arguments, id="call")],
                            )
                        ]
                    },
                    config=with_principal({}, principal, modules=security.modules),
                )
                last = output["messages"][-1]
                value = str(last.content)
                if getattr(last, "status", None) == "error":
                    error = {"type": "ToolError", "message": value}
                    value = None
                else:
                    phase = "completed"
            except Exception as exc:
                error = {"type": type(exc).__name__, "message": str(exc)}
            results.append(
                dict(
                    control=control,
                    status="refused" if error else "completed",
                    last_phase=phase,
                    principal=serial(principal),
                    manifest=manifest,
                    policy=policy,
                    operator_forbid=forbid,
                    manifest_identity=hashlib.sha256(manifest.encode()).hexdigest(),
                    policy_identity=hashlib.sha256((policy + forbid).encode()).hexdigest(),
                    grant=serial(security.host_executor.authorization_grants()) if security else [],
                    authorization="see grant/error",
                    lowering="not-applicable: restricted runtime",
                    activation="grant-checked terminal or pre-execution refusal",
                    attempted_operation=arguments,
                    observed_effect=bool(value and "BOB_PRIVATE_CANARY" in value),
                    legitimate_result=value == "ALICE_ALLOWED",
                    result=value,
                    error=error,
                    override=override,
                    resource_state={"alice": alice.read_text(), "bob": bob.read_text()},
                    elapsed_ms=(time.perf_counter() - start) * 1000,
                )
            )
        print(json.dumps(results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / "trials.jsonl").open("w") as stream:
        for repeat in range(20):
            for case in CASES:
                p = subprocess.run(
                    [sys.executable, __file__, "--child", case],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                (args.output / f"{case}-{repeat}.log").write_text(p.stdout + p.stderr)
                if p.returncode:
                    raise RuntimeError(p.stderr)
                for row in json.loads(p.stdout):
                    row.update(
                        case_id=case,
                        repeat=repeat,
                        session=repeat,
                        mode="production_restricted_runtime",
                        concrete_executor="ObjectPolicyHostExecutor/InProcess",
                        host=platform.node(),
                        source_revision=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
            print(f"manifest repeat {repeat} complete", flush=True)


if __name__ == "__main__":
    main()
