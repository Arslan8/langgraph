# ruff: noqa: E501
"""Sequential-principal evidence for invocation-scoped broker authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path

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
from policy_conflict import MANIFEST, OPERATOR_POLICY, record_task

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

POLICY = """permit(principal == slangGraph::User::"alice", action == slangGraph::Action::"db_record::read", resource) when { resource.selector == "notes/alice" };
permit(principal == slangGraph::User::"bob", action == slangGraph::Action::"db_record::read", resource) when { resource.selector == "notes/bob" };"""
SEQUENCE = (
    ("alice_control", "alice", "notes/alice", "none"),
    ("bob_substitutes_alice", "bob", "notes/bob", "substitute_alice"),
    ("bob_replays_identity_fields", "bob", "notes/bob", "spoof_alice"),
    ("bob_control", "bob", "notes/bob", "none"),
)


def run(output: Path, repetitions: int) -> None:
    output.mkdir(parents=True, exist_ok=False)
    worker = ROOT / "eval/remaining/record_worker.py"
    digest = hashlib.sha256(worker.read_bytes()).hexdigest()
    (output / "manifest.slp").write_text(MANIFEST + "\n")
    (output / "principal.cedar").write_text(POLICY + "\n")
    (output / "operator.cedar").write_text(OPERATOR_POLICY + "\n")
    (output / "plan.json").write_text(
        json.dumps(
            {
                "sequence": SEQUENCE,
                "repetitions": repetitions,
                "worker_sha256": digest,
                "worker_reuse": False,
                "reason": "ObjectBrokerDispatcher creates a fresh confined worker and spawn-bound broker session for every invocation",
            },
            indent=2,
        )
        + "\n"
    )
    install_mac_policy(OPERATOR_POLICY)
    with (output / "trials.jsonl").open("w") as stream:
        for repetition in range(repetitions):
            with tempfile.TemporaryDirectory(prefix="slg-lifetime-") as folder:
                database = Path(folder) / "records.sqlite"
                alice_marker = "ALICE_HANDLE_" + uuid.uuid4().hex
                bob_marker = "BOB_CONTROL_" + uuid.uuid4().hex
                with sqlite3.connect(database) as connection:
                    connection.execute(SQLITE_RECORD_SCHEMA)
                    connection.executemany(
                        "INSERT INTO records VALUES (?,?)",
                        (("alice", alice_marker), ("bob", bob_marker)),
                    )
                dispatcher = ObjectBrokerDispatcher(
                    {"record_task": LinuxToolSpec("record_worker:run", worker, digest)},
                    runtime_roots=tuple(
                        Path(item).resolve() for item in sys.path if item and Path(item).is_dir()
                    ),
                    mediators=(sqlite_record_mediator(database, database_id="notes"),),
                )
                security = cedar_security(
                    record_task,
                    manifest=MANIFEST,
                    classes=RECORDS.class_declaration(),
                    policy=POLICY,
                    dispatcher=dispatcher,
                )
                for index, (case_id, user, record, attack) in enumerate(SEQUENCE):
                    principal = Principal(user, frozenset(), frozenset(), f"{user}-{repetition}")
                    arguments = {
                        "record": record,
                        "operation": "read",
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
                        index,
                    )
                    before_audit = len(dispatcher.audit_records())
                    result = None
                    error = None
                    receipt = None
                    try:
                        response = security.host_executor.invoke(principal, call, ())
                        result = response.value
                        receipt = serial(response.receipt)
                    except Exception as exc:
                        error = {"type": type(exc).__name__, "message": str(exc)}
                    audit = dispatcher.audit_records()[before_audit:]
                    alice_disclosed_to_bob = user == "bob" and alice_marker in json.dumps(result)
                    expected = alice_marker if user == "alice" else bob_marker
                    control = attack == "none" and result == {
                        "found": True,
                        "value": expected,
                    }
                    stream.write(
                        json.dumps(
                            {
                                "case_id": case_id,
                                "repeat": repetition,
                                "sequence_index": index,
                                "principal": serial(principal),
                                "attempted_operation": arguments,
                                "grant": serial(security.host_executor.authorization_grants()[-1]),
                                "lowering": serial(dispatcher.lowering_records()[-1:]),
                                "mediator_decisions": serial(audit),
                                "activation": receipt,
                                "result": result,
                                "error": error,
                                "legitimate_result": control,
                                "unauthorized_effect": alice_disclosed_to_bob,
                                "worker_reused": False,
                                "classification": (
                                    "allowed_control"
                                    if control
                                    else "contained_by_invocation_binding"
                                    if not alice_disclosed_to_bob
                                    else "bypassed"
                                ),
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    arguments = parser.parse_args()
    run(arguments.output, arguments.repetitions)
