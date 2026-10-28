# ruff: noqa: E501
"""Sealed-operator conflict cases with policy-derived broker isolation."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
import time
import uuid
from pathlib import Path

from langchain_core.tools import tool
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

MANIFEST = """runs linux
map operation=read db_record read @{record} need
map operation=write db_record write @{record} need
map operation=delete db_record delete @{record} need
returns sensitive"""
PRINCIPAL_POLICY = """permit(principal == slangGraph::User::"alice", action in [slangGraph::Action::"db_record::read", slangGraph::Action::"db_record::write", slangGraph::Action::"db_record::delete"], resource)
when { resource.selector == "notes/alice" };"""
OPERATOR_POLICY = """forbid(principal, action in [slangGraph::Action::"db_record::write", slangGraph::Action::"db_record::delete"], resource);"""
CASES = (
    ("allowed_read", "read", "none"),
    ("mediated_update", "write", "none"),
    ("mediated_delete", "delete", "none"),
    ("direct_update_during_read", "read", "hidden_direct_update"),
    ("direct_delete_during_read", "read", "hidden_direct_delete"),
)


@tool("record_task")
def record_task(
    record: str, operation: str, attack: str, database: str, value: str = "updated"
) -> dict:
    """Read a declared record and optionally attempt a hidden modification."""
    raise RuntimeError("unconfined fallback is forbidden")


def _state(database: Path) -> dict[str, str]:
    with sqlite3.connect(database) as connection:
        return dict(connection.execute("SELECT key,value FROM records ORDER BY key"))


def run(output: Path, repetitions: int) -> None:
    output.mkdir(parents=True, exist_ok=False)
    worker = ROOT / "eval/remaining/record_worker.py"
    digest = hashlib.sha256(worker.read_bytes()).hexdigest()
    for name, text in (
        ("manifest.slp", MANIFEST),
        ("principal.cedar", PRINCIPAL_POLICY),
        ("operator.cedar", OPERATOR_POLICY),
    ):
        (output / name).write_text(text + "\n")
    (output / "plan.json").write_text(
        json.dumps(
            {
                "cases": CASES,
                "repetitions": repetitions,
                "worker_sha256": digest,
                "restriction_source": "Cedar principal policy intersected with sealed operator policy",
            },
            indent=2,
        )
        + "\n"
    )
    install_mac_policy(OPERATOR_POLICY)
    with (output / "trials.jsonl").open("w") as stream:
        for repetition in range(repetitions):
            for case_id, operation, attack in CASES:
                with tempfile.TemporaryDirectory(prefix="slg-policy-conflict-") as folder:
                    database = Path(folder) / "records.sqlite"
                    marker = "BOB_CONFLICT_" + uuid.uuid4().hex
                    with sqlite3.connect(database) as connection:
                        connection.execute("PRAGMA journal_mode=WAL")
                        connection.execute(SQLITE_RECORD_SCHEMA)
                        connection.executemany(
                            "INSERT INTO records VALUES (?,?)",
                            (("alice", "ALICE_ALLOWED"), ("bob", marker)),
                        )
                    mediator = sqlite_record_mediator(database, database_id="notes")
                    dispatcher = ObjectBrokerDispatcher(
                        {"record_task": LinuxToolSpec("record_worker:run", worker, digest)},
                        runtime_roots=tuple(
                            Path(item).resolve()
                            for item in sys.path
                            if item and Path(item).is_dir()
                        ),
                        mediators=(mediator,),
                    )
                    security = cedar_security(
                        record_task,
                        manifest=MANIFEST,
                        classes=RECORDS.class_declaration(),
                        policy=PRINCIPAL_POLICY,
                        dispatcher=dispatcher,
                    )
                    principal = Principal(
                        "alice", frozenset(), frozenset(), f"conflict-{repetition}"
                    )
                    arguments = {
                        "record": "notes/alice",
                        "operation": operation,
                        "attack": attack,
                        "database": str(database),
                    }
                    call = ToolCall(
                        Tool(
                            "record_task",
                            ToolDac("owner", {"*": "x"}),
                            frozenset(),
                            (),
                        ),
                        arguments,
                        {},
                        uuid.uuid4().hex,
                        0,
                    )
                    before = _state(database)
                    started = time.perf_counter()
                    result = None
                    error = None
                    receipt = None
                    try:
                        response = security.host_executor.invoke(principal, call, ())
                        result = response.value
                        receipt = serial(response.receipt)
                    except Exception as exc:
                        error = {"type": type(exc).__name__, "message": str(exc)}
                    after = _state(database)
                    grants = security.host_executor.authorization_grants()
                    legitimate = result == {"found": True, "value": "ALICE_ALLOWED"} or (
                        isinstance(result, dict)
                        and result.get("legitimate") == {"found": True, "value": "ALICE_ALLOWED"}
                    )
                    unauthorized = before != after or marker in json.dumps(result)
                    stream.write(
                        json.dumps(
                            {
                                "case_id": case_id,
                                "repeat": repetition,
                                "session": repetition,
                                "principal": serial(principal),
                                "attempted_operation": arguments,
                                "principal_policy_sha256": hashlib.sha256(
                                    PRINCIPAL_POLICY.encode()
                                ).hexdigest(),
                                "operator_policy_sha256": hashlib.sha256(
                                    OPERATOR_POLICY.encode()
                                ).hexdigest(),
                                "grant": serial(grants[-1]) if grants else None,
                                "lowering": serial(dispatcher.lowering_records()),
                                "mediator_decisions": serial(dispatcher.audit_records()),
                                "activation": receipt,
                                "resource_before": before,
                                "resource_after": after,
                                "legitimate_result": bool(legitimate),
                                "unauthorized_effect": unauthorized,
                                "result": result,
                                "error": error,
                                "elapsed_ms": (time.perf_counter() - started) * 1000,
                                "classification": (
                                    "allowed"
                                    if case_id == "allowed_read" and legitimate
                                    else "policy_refusal"
                                    if case_id.startswith("mediated_") and error
                                    else "contained"
                                    if legitimate and not unauthorized
                                    else "failed"
                                ),
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", type=int, default=5)
    arguments = parser.parse_args()
    run(arguments.output, arguments.repetitions)
