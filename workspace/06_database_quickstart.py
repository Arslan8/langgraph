"""Example 6: Cedar record permissions over a parent-owned SQLite database.

Run from the repository root with the prebuilt environment and Cedar on PATH:
    python3 workspace/06_database_quickstart.py

The demo creates a temporary database, exercises allowed and denied operations,
and removes the database afterwards. It requires Linux Landlock ABI 5+.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    Effect,
    HostExecutionDenied,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    ResourceArg,
    cedar_security,
    effects,
    sqlite_record_mediator,
    with_principal,
)

CLASSES = """
class db_record {
  operations read write delete
  object record
  normalizer identity
  attrs
  enforced_by broker
  lowering sqlite.record.v1
}
"""
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


def main() -> None:
    @tool
    @effects(Effect.WRITE, resources=[ResourceArg("record", "db_record")])
    def manage_record(record: str, operation: str, value: str | None = None) -> dict:
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
        artifact = Path(__file__).with_name("06_database_worker.py").resolve()
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
        for index, (user, operation, record, value, expected) in enumerate(cases):
            principal = Principal(user, frozenset(), frozenset(), "database-demo")
            actual = None
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
                                            "value": value,
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
            except HostExecutionDenied:
                pass
            assert actual == expected, (user, operation, record, actual, expected)
            print(
                f"{'ALLOW' if actual is not None else 'DENY'} {user} {operation} {record}: {actual}"
            )
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT key, value FROM records").fetchall() == [
                ("bob", "Bob's private note")
            ]
        print("Verified: Bob's record stayed unchanged; Alice's record was deleted.")


if __name__ == "__main__":
    main()
