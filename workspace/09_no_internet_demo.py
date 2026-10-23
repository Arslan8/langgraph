"""Example 9: operator MAC denies internet authority that DAC permits.

Requires Linux Landlock ABI 5+, libseccomp, and Cedar on PATH. No external
connection is attempted. Run this controller, never the worker directly.
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
    HostExecutionDenied,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ObjectPolicyHostExecutor,
    Principal,
    cedar_security,
    effects,
    with_principal,
)

# An application-defined resource vocabulary, not a built-in network adapter.
# No internet mediator is installed: MAC removes all such authority before
# lowering. Removing MAC would not enable networking without a real adapter.
CLASSES = """
class internet {
  operations connect
  object endpoint
  normalizer identity
  attrs
  enforced_by broker
}
"""
DAC_POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'


def main() -> None:
    # Trusted application configuration supplies MAC; tool arguments do not.
    mac_policy = Path(__file__).with_name("09_no_internet.cedar").read_text()

    @tool
    @effects(Effect.READ)
    def offline_report(path: str) -> dict:
        """Read a local report, optionally using the internet."""
        raise AssertionError("the schema tool must not execute in the parent")

    artifact = Path(__file__).with_name("09_no_internet_worker.py").resolve()
    with tempfile.TemporaryDirectory(prefix="slanggraph-offline-demo-") as directory:
        report = Path(directory) / "report.txt"
        report.write_text("offline report")
        for requirement in ("need", "want"):
            dispatcher = ObjectBrokerDispatcher(
                {
                    offline_report.name: LinuxToolSpec(
                        "offline_worker:offline_report",
                        artifact,
                        hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    )
                },
                runtime_roots=tuple(
                    Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
                ),
            )
            security = cedar_security(
                offline_report,
                classes=CLASSES,
                manifest=(
                    "runs linux\nfs read @{path} need\n"
                    f"internet connect https://example.com {requirement}\n"
                    "returns normal"
                ),
                policy=DAC_POLICY,
                mac_forbids=mac_policy,
                dispatcher=dispatcher,
            )
            builder = StateGraph(MessagesState)
            builder.add_node("tools", ToolNode([offline_report]))
            builder.add_edge(START, "tools")
            graph = builder.compile(security=security)
            # Demo identity; production callers must be authenticated.
            principal = Principal("alice", frozenset(), frozenset(), "offline-demo")
            denial = ""
            message = None
            try:
                response = graph.invoke(
                    {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": offline_report.name,
                                        "args": {"path": str(report)},
                                        "id": f"offline-{requirement}",
                                    }
                                ],
                            )
                        ]
                    },
                    config=with_principal({}, principal, modules=security.modules),
                )
                message = response["messages"][-1]
                if getattr(message, "status", None) == "error":
                    denial = str(message.content)
            except HostExecutionDenied as exc:
                denial = str(exc)

            executor = security.host_executor
            assert isinstance(executor, ObjectPolicyHostExecutor)
            if requirement == "need":
                assert "mac:forbid:" in denial, denial
                assert not executor.authorization_grants()
                assert not dispatcher.lowering_records()
                print("Required internet: denied by MAC before dispatch")
                continue

            assert not denial, denial
            assert message is not None
            grant = executor.authorization_grants()[-1]
            assert [(line.class_name, line.operation) for line in grant.lines] == [
                ("fs", "read")
            ]
            print("Optional internet: removed by MAC; only fs::read remains")
            result = json.loads(str(message.content))
            assert result == {
                "local_read": "offline report",
                "ipv4_tcp": "blocked",
                "ipv4_udp": "blocked",
                "ipv6_tcp": "blocked",
                "ipv6_udp": "blocked",
            }, result
            for name, outcome in result.items():
                print(f"{name}: {outcome}")


if __name__ == "__main__":
    main()
