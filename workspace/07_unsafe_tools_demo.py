"""Example 7: contain an unsafe tool with an exact read-only file grant.

Run this controller, never the worker directly:
    python3 workspace/07_unsafe_tools_demo.py

Requires Linux Landlock ABI 5+, libseccomp, and Cedar on PATH. Every attack
targets demo-owned temporary files; no real secrets or remote endpoints are used.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    ResourceArg,
    cedar_security,
    effects,
    with_principal,
)


def main() -> None:
    @tool
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def inspect_file(path: str, secret_path: str) -> dict:
        """Inspect one file; the implementation is deliberately untrusted."""
        raise AssertionError("the schema tool must not run in the parent")

    with tempfile.TemporaryDirectory(prefix="slanggraph-unsafe-demo-") as directory:
        allowed = Path(directory) / "report.txt"
        secret = Path(directory) / "private.txt"
        allowed.write_text("public report")
        secret.write_text("demo-only private data")
        artifact = Path(__file__).with_name("07_unsafe_worker.py").resolve()
        dispatcher = ObjectBrokerDispatcher(
            {
                inspect_file.name: LinuxToolSpec(
                    "unsafe_worker:inspect_file",
                    artifact,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                ),
            },
            # Only code roots: the temporary fixture directory is excluded.
            runtime_roots=tuple(
                Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
            ),
        )
        security = cedar_security(
            inspect_file,
            manifest="runs linux\nfs read @{path} need\nreturns sensitive",
            policy=f"""
                permit (
                    principal == slangGraph::User::"alice",
                    action == slangGraph::Action::"fs::read",
                    resource
                ) when {{ resource.selector == {json.dumps(str(allowed))} }};
            """,
            dispatcher=dispatcher,
        )
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode([inspect_file]))
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        # Demonstration identity only; authenticate the caller in real deployments.
        principal = Principal("alice", frozenset(), frozenset(), "unsafe-demo")
        response = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": inspect_file.name,
                                "args": {
                                    "path": str(allowed),
                                    "secret_path": str(secret),
                                },
                                "id": "unsafe-demo-call",
                            }
                        ],
                    )
                ]
            },
            config=with_principal({}, principal, modules=security.modules),
        )
        message = response["messages"][-1]
        assert getattr(message, "status", None) != "error", message.content
        result = json.loads(str(message.content))
        assert result == {
            "authorized_read": "public report",
            "undeclared_read": "blocked",
            "native_read": "blocked",
            "unauthorized_write": "blocked",
            "socket_creation": "blocked",
        }
        assert allowed.read_text() == "public report"
        assert secret.read_text() == "demo-only private data"
        print("Granted: fs::read on report.txt")
        for attempt, outcome in result.items():
            print(f"{attempt}: {outcome}")
        print("Verified: both fixture files are unchanged.")
        print("The SLP declaration did not make this code safe; the host enforced it.")
        print(
            "Runtime code roots remain readable; this demo does not hide all metadata."
        )


if __name__ == "__main__":
    main()
