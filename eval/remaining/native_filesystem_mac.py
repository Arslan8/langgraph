"""Manifest matrix for direct native filesystem access, without resource RPC."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from evidence_utils import serial
from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    install_mac_policy,
)

CASES = [
    "correct",
    "omitted_read",
    "overdeclared",
    "dac_vs_operator_forbid",
    "local_override",
    "rpc_identity",
    "resource_change",
    "missing_enforcer",
]
SOURCE = """from pathlib import Path

def run(path, other, attack):
    allowed = Path(path).read_text()
    if attack == "omitted_read":
        try:
            return {"allowed": allowed, "other": Path(other).read_text(), "attempted": True}
        except PermissionError as error:
            return {"allowed": allowed, "denied": type(error).__name__, "attempted": True}
    return {"allowed": allowed, "attempted": False}
"""


@tool
def native_read(path: str, other: str, attack: str) -> dict:
    """Read a declared file in the isolated worker."""
    raise RuntimeError("Coordinator must not execute this schema tool")


def child(case):
    with tempfile.TemporaryDirectory(prefix="slg-native-matrix-") as tmp:
        root = Path(tmp)
        code = root / "code"
        code.mkdir()
        source = code / "native_worker.py"
        source.write_text(SOURCE)
        allowed, denied = root / "alice", root / "bob"
        allowed.write_text("ALICE_ALLOWED")
        denied.write_text("BOB_NATIVE_CANARY")
        forbid = (
            'forbid(principal, action == slangGraph::Action::"fs::read", resource) '
            f'when {{ resource.selector == "{denied}" }};'
        )
        install_mac_policy(forbid)
        rows = []
        for control in [True, False]:
            if not control and case == "rpc_identity":
                rows.append(
                    dict(
                        case_id=case,
                        control=False,
                        status="unsupported",
                        reason="Direct filesystem syscalls carry no resource RPC identity payload",
                    )
                )
                continue
            dispatcher = ObjectBrokerDispatcher(
                {
                    "native_read": LinuxToolSpec(
                        "native_worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
                    )
                },
                runtime_roots=(
                    code,
                    *(Path(p).resolve() for p in sys.path if p and Path(p).is_dir()),
                ),
            )
            manifest = "runs linux\nfs read @{path} need"
            arguments = dict(path=str(allowed), other=str(denied), attack="none")
            if not control:
                if case == "omitted_read":
                    arguments["attack"] = case
                elif case == "overdeclared":
                    manifest += f"\nfs read {denied} need"
                elif case in {"dac_vs_operator_forbid", "local_override"}:
                    arguments["path"] = str(denied)
            start = time.perf_counter()
            value = error = result = security = override = None
            try:
                if not control and case == "local_override":
                    try:
                        install_mac_policy("forbid(principal,action,resource) when {false};")
                    except RuntimeError as exc:
                        override = str(exc)
                security = cedar_security(
                    native_read,
                    manifest=manifest,
                    policy="permit(principal,action,resource);",
                    dispatcher=None if not control and case == "missing_enforcer" else dispatcher,
                )
                if not control and case == "resource_change":
                    original = dispatcher.invoke

                    def changed(principal, call, grant, original=original):
                        return original(
                            principal, replace(call, args={**call.args, "path": str(denied)}), grant
                        )

                    dispatcher.invoke = changed
                principal = Principal("alice", frozenset(), frozenset(), "fixed-session")
                call = ToolCall(
                    Tool("native_read", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                    arguments,
                    {},
                    "call",
                    0,
                )
                result = security.host_executor.invoke(principal, call, ())
                value = result.value
            except Exception as exc:
                error = dict(type=type(exc).__name__, message=str(exc))
            rows.append(
                dict(
                    schema_version=2,
                    case_id=case,
                    control=control,
                    status="refused" if error else "completed",
                    mode="native_direct_filesystem",
                    concrete_executor="ObjectBrokerDispatcher/kernel fs grants",
                    resource_access="Path.read_text in isolated worker; no filesystem broker calls",
                    host=platform.node(),
                    principal="alice",
                    manifest=manifest,
                    operator_forbid=forbid,
                    manifest_sha256=hashlib.sha256(manifest.encode()).hexdigest(),
                    source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
                    arguments=arguments,
                    result=serial(value),
                    error=error,
                    override=override,
                    grant=serial(security.host_executor.authorization_grants()) if security else [],
                    lowering=serial(dispatcher.lowering_records()),
                    activation=serial(result.receipt) if result else None,
                    broker_decisions=serial(dispatcher.audit_records()),
                    legitimate_result=isinstance(value, dict)
                    and value.get("allowed") == "ALICE_ALLOWED",
                    observed_effect="BOB_NATIVE_CANARY" in json.dumps(value),
                    resource_after={"alice": allowed.read_text(), "bob": denied.read_text()},
                    elapsed_ms=(time.perf_counter() - start) * 1000,
                    timing_scope="shared host; authorization, activation and direct worker read",
                )
            )
        print(json.dumps(rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", choices=CASES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    if args.output is None or args.repetitions < 1:
        parser.error("Require output and positive repetitions")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "worker.py").write_text(SOURCE)
    (args.output / "driver.py").write_bytes(Path(__file__).read_bytes())
    (args.output / "evidence_utils.py").write_bytes(
        Path(__file__).with_name("evidence_utils.py").read_bytes()
    )
    from application_campaign import capture_framework

    before = capture_framework(args.output)
    (args.output / "framework-before.json").write_text(json.dumps(before, indent=2) + "\n")
    driver = (args.output / "driver.py").resolve()
    plan = dict(
        cases=CASES,
        repetitions=args.repetitions,
        host=platform.node(),
        python=sys.executable,
        framework_sources=before,
        driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(),
        scope="Direct native filesystem reads; RPC identity is unsupported; shared host",
    )
    (args.output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    with (args.output / "trials.jsonl").open("w") as stream:
        for repeat in range(args.repetitions):
            for case in CASES:
                started = datetime.now(UTC).isoformat()
                completed = subprocess.run(
                    [sys.executable, str(driver), "--child", case],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                (args.output / f"{case}-{repeat}.log").write_text(
                    completed.stdout + completed.stderr
                )
                if completed.returncode:
                    raise RuntimeError(f"Native matrix child failed: {case}; retained process log")
                for row in json.loads(completed.stdout):
                    row.update(
                        repeat=repeat, started_at=started, finished_at=datetime.now(UTC).isoformat()
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
            print(repeat, "complete", flush=True)
    after = capture_framework(args.output)
    (args.output / "framework-after.json").write_text(json.dumps(after, indent=2) + "\n")
    if before != after:
        raise RuntimeError("Framework sources changed during the cohort; no stable-source claim")


if __name__ == "__main__":
    main()
