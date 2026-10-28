"""Dishonest manifests and fixed operator policy on the production native broker."""

import argparse
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from composition import MANIFEST, record_task, state
from evidence_utils import serial
from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    install_mac_policy,
    sqlite_record_mediator,
)
from langgraph.prebuilt.security.mediators.records import RECORDS

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
POLICY = "permit(principal,action,resource);"
FORBID = (
    'forbid(principal,action in [slangGraph::Action::"db_rec'
    'ord::read",slangGraph::Action::"db_record::write",slang'
    'Graph::Action::"db_record::delete"],resource) when {res'
    'ource.selector == "notes/bob"};'
)


def child(case):
    install_mac_policy(FORBID)
    rows = []
    with tempfile.TemporaryDirectory(prefix="slg-broker-mac-") as tmp:
        database = Path(tmp) / "records.sqlite"
        with sqlite3.connect(database) as conn:
            conn.execute(SQLITE_RECORD_SCHEMA)
            conn.executemany(
                "INSERT INTO records VALUES (?,?)",
                [("alice", "ALICE_ALLOWED"), ("bob", "BOB_PRIVATE_CANARY")],
            )
        source = Path(__file__).with_name("record_worker.py")
        for control in [True, False]:
            dispatcher = ObjectBrokerDispatcher(
                {
                    "record_task": LinuxToolSpec(
                        "record_worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
                    )
                },
                runtime_roots=tuple(Path(p).resolve() for p in sys.path if p and Path(p).is_dir()),
                mediators=(sqlite_record_mediator(database, database_id="notes"),),
            )
            manifest = MANIFEST
            arguments = dict(
                record="notes/alice", operation="read", attack="none", database=str(database)
            )
            if not control:
                if case == "omitted_read":
                    arguments["attack"] = "substitute"
                if case == "rpc_identity":
                    arguments["attack"] = "spoof"
                if case == "overdeclared":
                    manifest += "\ndb_record read notes/bob need"
                if case in ["dac_vs_operator_forbid", "local_override"]:
                    arguments["record"] = "notes/bob"
            before = state(database)
            start = time.perf_counter()
            result = None
            error = None
            security = None
            override = None
            try:
                if not control and case == "local_override":
                    try:
                        install_mac_policy("forbid(principal,action,resource) when {false};")
                    except RuntimeError as exc:
                        override = str(exc)
                security = cedar_security(
                    record_task,
                    manifest=manifest,
                    classes=RECORDS.class_declaration(),
                    policy=POLICY,
                    dispatcher=None if not control and case == "missing_enforcer" else dispatcher,
                    mac_forbids="",
                )
                if not control and case == "resource_change":
                    original = dispatcher.invoke

                    def changed(principal, call, grant, original=original):
                        return original(
                            principal,
                            replace(call, args={**call.args, "record": "notes/bob"}),
                            grant,
                        )

                    dispatcher.invoke = changed
                principal = Principal("alice", frozenset(), frozenset(), "fixed-session")
                call = ToolCall(
                    Tool("record_task", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                    arguments,
                    {},
                    "call",
                    0,
                )
                result = security.host_executor.invoke(principal, call, ())
            except Exception as exc:
                error = dict(type=type(exc).__name__, message=str(exc))
            after = state(database)
            value = result.value if result else None
            rows.append(
                dict(
                    control=control,
                    case_id=case,
                    mode="production_native_broker",
                    concrete_executor="ObjectPolicyHostExecutor/ObjectBrokerDispatcher",
                    principal="alice",
                    host=platform.node(),
                    manifest=manifest,
                    policy=POLICY,
                    operator_forbid=FORBID,
                    manifest_identity=hashlib.sha256(manifest.encode()).hexdigest(),
                    policy_identity=hashlib.sha256((POLICY + FORBID).encode()).hexdigest(),
                    grant=serial(security.host_executor.authorization_grants()) if security else [],
                    lowering=serial(dispatcher.lowering_records()),
                    activation=serial(result.receipt) if result else "not-applicable",
                    attempted_operation=arguments,
                    effect_trace=serial(dispatcher.audit_records()),
                    resource_before=before,
                    resource_after=after,
                    result=serial(value),
                    error=error,
                    override=override,
                    legitimate_result=value == {"found": True, "value": "ALICE_ALLOWED"},
                    observed_effect="BOB_PRIVATE_CANARY" in json.dumps(value) or before != after,
                    elapsed_ms=(time.perf_counter() - start) * 1000,
                )
            )
    print(json.dumps(rows))


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
                        repeat=repeat,
                        session=repeat,
                        source_revision=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
            print(f"broker MAC repeat {repeat} complete", flush=True)


if __name__ == "__main__":
    main()
