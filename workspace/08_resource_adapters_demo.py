"""Example 8: implement a domain-specific ResourceMediatorAdapter.

    python3 workspace/08_resource_adapters_demo.py

Requires Linux Landlock ABI 5+, libseccomp, and Cedar. The counter's semantics
cannot be expressed as a file permission: increments must be integers from 1
through 3, and the total cannot exceed 10. One trusted parent owns the counter.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from threading import RLock

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    EnforcementKind,
    HostExecutionDenied,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    ResourceMediatorAdapter,
    ResourceSupport,
    SupportLevel,
    cedar_security,
    effects,
    with_principal,
)

CLASSES = """
class counter {
  operations inspect increment
  object counter
  normalizer identity
  attrs
  enforced_by broker
  lowering counter.local.v1
}
"""
MANIFEST = """
runs linux
counter inspect jobs need
counter increment jobs need
counter inspect retired want
returns sensitive
"""
# Cedar permits the optional resource too. The adapter, separately, cannot
# implement it, so lowering must remove it from the worker's authority.
POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'


def counter_adapter(path: Path, events: list[str]) -> ResourceMediatorAdapter:
    """Keep resource state and all mutation logic in the trusted parent."""
    lock = RLock()
    active = set()

    def assess(line, host):
        if (
            line.class_name != "counter"
            or line.enforcer is not EnforcementKind.BROKER
            or line.lowering != "counter.local.v1"
            or line.selector != "jobs"
            or line.operation not in {"inspect", "increment"}
            or line.attributes
        ):
            return ResourceSupport(SupportLevel.UNSUPPORTED, "unknown counter contract")
        return ResourceSupport(
            SupportLevel.EXACT,
            "inspect or increment jobs by 1..3, with a maximum total of 10",
            witness="tests/security/test_workspace_sandbox_demos.py",
            protected_paths=(str(path.parent),),
            required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
        )

    def activate(lines, context):
        with lock:
            active.add(context.call_id)
            events.append(f"activate:{context.principal_id}")

    def invoke(line, payload, context):
        with lock:
            if context.call_id not in active:
                raise PermissionError("counter lease is inactive")
            value = int(path.read_text())
            if line.operation == "inspect":
                if payload:
                    raise ValueError("inspect takes no payload")
            else:
                if set(payload) != {"amount"} or type(payload["amount"]) is not int:
                    raise ValueError("increment requires only an integer amount")
                amount = payload["amount"]
                if not 1 <= amount <= 3 or value + amount > 10:
                    raise ValueError("counter increment exceeds its semantic limits")
                value += amount
                path.write_text(str(value))
            events.append(f"invoke:{line.operation}")
            return {"value": value}

    def release(context):
        with lock:
            active.discard(context.call_id)
            events.append("release")

    return ResourceMediatorAdapter(
        "counter.local.v1", assess, invoke, activate=activate, release=release
    )


def main() -> None:
    @tool
    @effects(Effect.WRITE)
    def exercise_counter(private_path: str) -> dict:
        """Exercise broker operations against a custom counter."""
        raise AssertionError("the schema tool must not run in the parent")

    with tempfile.TemporaryDirectory(prefix="slanggraph-adapter-demo-") as directory:
        path = Path(directory) / "counter"
        path.write_text("0")
        events = []
        adapter = counter_adapter(path, events)
        artifact = Path(__file__).with_name("08_resource_adapter_worker.py").resolve()
        tools = {
            exercise_counter.name: LinuxToolSpec(
                "adapter_worker:exercise_counter",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            ),
        }
        roots = tuple(Path(p).resolve() for p in sys.path if p and Path(p).is_dir())
        principal = Principal("alice", frozenset(), frozenset(), "adapter-demo")

        def execute(mediators):
            dispatcher = ObjectBrokerDispatcher(
                tools, runtime_roots=roots, mediators=mediators
            )
            security = cedar_security(
                exercise_counter,
                manifest=MANIFEST,
                classes=CLASSES,
                policy=POLICY,
                dispatcher=dispatcher,
            )
            builder = StateGraph(MessagesState)
            builder.add_node("tools", ToolNode([exercise_counter]))
            builder.add_edge(START, "tools")
            graph = builder.compile(security=security)
            response = graph.invoke(
                {
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "name": exercise_counter.name,
                                    "args": {"private_path": str(path)},
                                    "id": "adapter-demo-call",
                                }
                            ],
                        )
                    ]
                },
                config=with_principal({}, principal, modules=security.modules),
            )
            return response["messages"][-1], dispatcher

        message, dispatcher = execute((adapter,))
        assert getattr(message, "status", None) != "error", message.content
        result = json.loads(str(message.content))
        assert result == {
            "before": {"value": 0},
            "increment": {"value": 2},
            "invalid_amount": "denied",
            "payload_override": "denied",
            "optional_resource": "denied",
            "direct_access": "blocked",
        }
        assert path.read_text() == "2"
        assert events == [
            "activate:alice",
            "invoke:inspect",
            "invoke:increment",
            "release",
        ]
        record = dispatcher.lowering_records()[-1]
        assert len(record.plan.removed_wants) == 1
        for attempt, outcome in result.items():
            print(f"{attempt}: {outcome}")
        print("Lifecycle: " + " -> ".join(events))
        print("Optional unsupported resource: removed before dispatch")

        before = list(events)
        try:
            denied, _ = execute(())
        except HostExecutionDenied as exc:
            assert "required_authority_removed" in str(exc), str(exc)
        else:
            assert getattr(denied, "status", None) == "error", denied.content
            assert "required_authority_removed" in str(denied.content), denied.content
        assert path.read_text() == "2" and events == before
        print("Missing required mediator: DENIED before worker execution")
        print("Host confinement and the trusted adapter jointly enforce the resource.")


if __name__ == "__main__":
    main()
