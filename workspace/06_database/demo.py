"""Example 6: Cedar record permissions over a parent-owned SQLite database.

Run from the repository root with the prebuilt environment and Cedar on PATH:
    libs/prebuilt/.venv/bin/python workspace/06_database/demo.py

The demo creates a temporary database, exercises allowed and denied operations,
and removes the database afterwards. It requires Python 3.11+ with SQLite's
setlimit API and Linux Landlock ABI 5+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    HostExecutionDenied,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ObjectPolicyHostExecutor,
    Principal,
    ResourceArg,
    cedar_security,
    effects,
    parse_security_manifest,
    with_principal,
)
from langgraph.prebuilt.security.manifest_consistency import check_manifest_consistency
from langgraph.prebuilt.security.mediators.records import RECORDS
from langgraph.prebuilt.security.mediators.sqlite import (
    SQLITE_RECORD_SCHEMA,
    sqlite_record_mediator,
)

CLASSES = RECORDS.class_declaration()
MANIFEST = """
runs linux
map operation=read   db_record read   @{record} need
map operation=write  db_record write  @{record} need
map operation=delete db_record delete @{record} need
returns sensitive
"""
POLICY = """
permit (
  principal == slangGraph::User::"alice",
  action in [
    slangGraph::Action::"db_record::read",
    slangGraph::Action::"db_record::write",
    slangGraph::Action::"db_record::delete"
  ],
  resource
) when { resource.selector == "notes/alice" };

permit (
  principal == slangGraph::User::"bob",
  action == slangGraph::Action::"db_record::read",
  resource
) when { resource.selector == "notes/bob" };
"""


def styled(text: str, color: str) -> str:
    """Use color in terminals while keeping captured output readable."""
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        return f"\033[{color}m{text}\033[0m"
    return text


def database_state(database: Path) -> dict[str, str]:
    """Inspect demo fixtures from the trusted controller, never from the worker."""
    with sqlite3.connect(database) as connection:
        return dict(connection.execute("SELECT key, value FROM records ORDER BY key"))


def show_records(state: dict[str, str], before: dict[str, str] | None = None) -> None:
    print("  DATABASE  (controller view of demo fixtures)")
    print("  Resource        | Value")
    print("  ----------------+--------------------------------")
    for key, value in state.items():
        change = (
            "  [changed]" if before is not None and before.get(key) != value else ""
        )
        print(f"  {'notes/' + key:<15} | {json.dumps(value)}{change}")
    if before is not None:
        for key in before.keys() - state.keys():
            print(styled(f"  {'notes/' + key:<15} | <deleted>", "33"))
    if not state:
        print("  <empty>")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--step",
        action="store_true",
        help="pause before each scenario; press Enter to continue",
    )
    args = parser.parse_args()
    if not hasattr(sqlite3.Connection, "setlimit"):
        parser.exit(
            2,
            "Demo 06 requires Python 3.11+ with SQLite's Connection.setlimit API.\n"
            f"Current interpreter: {sys.executable} (Python {sys.version.split()[0]})\n"
            "From the repository root, use the prebuilt environment:\n"
            "  libs/prebuilt/.venv/bin/python workspace/06_database/demo.py"
            + (" --step" if args.step else "")
            + "\n",
        )
    print(styled("\n" + "=" * 72, "1;36"))
    print(
        styled(
            "  DEMO 06  |  Typed database access with per-record permissions", "1;36"
        )
    )
    print(styled("=" * 72, "1;36"))
    print("  Worker: records.read / write / delete")
    print("       -> grant-checked broker -> SQLite mediator -> database")
    print("  The worker receives record names, not SQL or a database connection.\n")
    print("  POLICY")
    print("  alice    read, write, delete  -> notes/alice")
    print("  bob      read only           -> notes/bob")
    print("  mallory  no permissions")
    print("  All identities and data below are demonstration fixtures.\n", flush=True)

    @tool
    @effects(Effect.WRITE, resources=[ResourceArg("record", "db_record")])
    def manage_record(record: str, operation: str, value: str = "") -> dict:
        """Read, write, or delete one database record."""
        raise RuntimeError("schema only: execute the confined worker")

    # Keep database files outside every readable code root. Protecting the
    # directory also covers SQLite's journal, WAL and shared-memory sidecars.
    with tempfile.TemporaryDirectory(prefix="slanggraph-database-") as directory:
        database = Path(directory) / "notes.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute(SQLITE_RECORD_SCHEMA)
            connection.executemany(
                "INSERT INTO records VALUES (?, ?)",
                [("alice", "Alice's note"), ("bob", "Bob's private note")],
            )
        artifact = Path(__file__).with_name("worker.py").resolve()
        # Source-only inference recognizes the registered typed client import;
        # neither the worker nor its imports execute during this check.
        report = check_manifest_consistency(
            artifact.read_text(),
            parse_security_manifest(
                CLASSES + "\ntool manage_record {\n" + MANIFEST + "\n}"
            ),
            tool_name="manage_record",
        )
        assert report["consistent"], report["issues"]
        print(
            "Verified typed database API: inferred effects are covered by the manifest"
        )
        print("  [PASS] Worker calls resolve to registered typed resource methods.")
        print(
            "  [PASS] Every inferred operation is permitted by the active manifest.\n"
        )
        show_records(database_state(database))
        dispatcher = ObjectBrokerDispatcher(
            {
                manage_record.name: LinuxToolSpec(
                    "database_worker:manage_record",
                    artifact,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                ),
            },
            runtime_roots=tuple(
                Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
            ),
            mediators=(sqlite_record_mediator(database, database_id="notes"),),
        )
        security = cedar_security(
            manage_record,
            manifest=MANIFEST,
            classes=CLASSES,
            policy=POLICY,
            dispatcher=dispatcher,
        )
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode([manage_record]))
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        executor = security.host_executor
        assert isinstance(executor, ObjectPolicyHostExecutor)

        # These principal choices demonstrate policy; production callers must
        # obtain identity from authentication instead of accepting a user string.
        cases = [
            (
                "alice",
                "read",
                "notes/alice",
                None,
                {"found": True, "value": "Alice's note"},
            ),
            ("alice", "read", "notes/bob", None, None),
            ("alice", "write", "notes/alice", "updated", {"ok": True}),
            ("bob", "write", "notes/bob", "changed", None),
            (
                "bob",
                "read",
                "notes/bob",
                None,
                {"found": True, "value": "Bob's private note"},
            ),
            ("alice", "delete", "notes/alice", None, {"ok": True}),
            ("alice", "read", "notes/alice", None, {"found": False, "value": None}),
            ("mallory", "read", "notes/bob", None, None),
        ]
        explanations = [
            ("Read an allowed record", "Alice's policy permits reading notes/alice."),
            (
                "Try to read another principal's record",
                "Alice's policy does not grant access to notes/bob.",
            ),
            ("Update an allowed record", "Alice's policy permits writing notes/alice."),
            (
                "Try a write with read-only permission",
                "Bob has read permission, but no write permission.",
            ),
            (
                "Read-only access still works",
                "Bob's read grant remains valid; the denied write changed nothing.",
            ),
            (
                "Delete an allowed record",
                "Alice's policy permits deleting notes/alice.",
            ),
            (
                "Read after deletion",
                "Permission is still valid, but the record no longer exists.",
            ),
            (
                "Try an identity with no permissions",
                "No policy grants Mallory access to this record.",
            ),
        ]
        allowed = denied = 0
        for index, (user, operation, record, value, expected) in enumerate(cases):
            title, explanation = explanations[index]
            print(styled(f"[{index + 1}/{len(cases)}] {title}", "1;36"))
            print("-" * 72)
            arguments = (
                f"{record!r}, {value!r}" if operation == "write" else repr(record)
            )
            print(f"  Principal : {user}")
            print(f"  Request   : records.{operation}({arguments})")
            print(
                f"  Expected  : {'permitted' if expected is not None else 'blocked'} - {explanation}"
            )
            if args.step:
                input("  Press Enter to send this request...")
            else:
                print("  Sending request...", flush=True)
            before = database_state(database)
            grant_count = len(executor.authorization_grants())
            principal = Principal(user, frozenset(), frozenset(), "database-demo")
            actual = None
            denial = ""
            try:
                result = graph.invoke(
                    {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": manage_record.name,
                                        "args": {
                                            "record": record,
                                            "operation": operation,
                                            "value": value if value is not None else "",
                                        },
                                        "id": f"database-{index}",
                                    }
                                ],
                            )
                        ]
                    },
                    config=with_principal({}, principal, modules=security.modules),
                )
                message = result["messages"][-1]
                if getattr(message, "status", None) != "error":
                    actual = json.loads(str(message.content))
                else:
                    denial = str(message.content)
            except HostExecutionDenied as exc:
                denial = str(exc)
            assert actual == expected, (user, operation, record, actual, expected)
            after = database_state(database)
            grants = executor.authorization_grants()[grant_count:]
            if actual is None:
                assert denial and "dac:" in denial, denial
                assert not grants, "a denied request unexpectedly received a grant"
                assert after == before, "a denied request changed the database"
                denied += 1
                print(styled(f"  DENY {user} {operation} {record}", "1;31"))
                print("  Grant     : none; denied before worker dispatch")
                print(f"  Reason    : {denial}")
                print("  Database  : unchanged [PASS]")
            else:
                allowed += 1
                print(styled(f"  ALLOW {user} {operation} {record}", "1;32"))
                assert len(grants) == 1
                for line in grants[0].lines:
                    print(
                        f"  Grant     : {line.class_name}::{line.operation} on {line.selector}"
                    )
                print(f"  Response  : {json.dumps(actual, sort_keys=True)}")
                expected_state = dict(before)
                key = record.split("/", 1)[1]
                if operation == "write":
                    expected_state[key] = value
                elif operation == "delete":
                    expected_state.pop(key, None)
                assert after == expected_state, "operation changed unexpected records"
                if operation == "read" and not actual["found"]:
                    print(
                        "  Meaning   : authorized read; record not found (not a policy denial)"
                    )
                print(
                    "  Effect    : "
                    + (
                        "no rows changed"
                        if before == after
                        else "only the granted record changed"
                    )
                    + " [PASS]"
                )
            print()
            show_records(after, before)
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT key, value FROM records").fetchall() == [
                ("bob", "Bob's private note")
            ]
        print(styled("=" * 72, "1;32"))
        print(
            styled(
                f"  PASS  {len(cases)}/{len(cases)} scenarios | {allowed} permitted | {denied} blocked",
                "1;32",
            )
        )
        print("Verified: Bob's record stayed unchanged; Alice's record was deleted.")
    print("Cleanup: temporary database and fixture directory removed.\n")


if __name__ == "__main__":
    main()
