"""Example 5: authorize device operations independently of socket access.

Start `05_pump_simulator.py` in another terminal before running this file. This
is a trusted in-process demonstration: only `PumpSocketAdapter` holds the socket
path. Giving ordinary tool code direct access to that socket would bypass the
authorization boundary demonstrated here.
"""

from __future__ import annotations

import argparse
import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    HostExecutionDenied,
    ObjectPolicyHostExecutor,
    Principal,
    ResourceArg,
    cedar_security,
    effects,
    with_principal,
)

DEVICE_ID = "pump-1"
ROLES = {
    "alice": frozenset({"Operator"}),
    "bob": frozenset({"Technician"}),
    "charlie": frozenset({"Observer"}),
}
OPERATIONS = frozenset({"inspect", "start", "stop", "set_flow", "calibrate"})

# Adding a class extends both the manifest vocabulary and generated Cedar schema.
CLASSES = """
class pump {
  operations inspect start stop set_flow calibrate
  object device
  normalizer identity
  attrs
  enforced_by trusted_tool
}
"""

# `map` is a closed dispatch table. The argument selects among fixed manifest
# lines; it never becomes a Cedar action, entity type, or policy fragment.
MANIFEST = """
runs inprocess
map operation=inspect   pump inspect   @{device_id} need
map operation=start     pump start     @{device_id} need
map operation=stop      pump stop      @{device_id} need
map operation=set_flow  pump set_flow  @{device_id} need
map operation=calibrate pump calibrate @{device_id} need
returns sensitive
"""

POLICY = """
// Authentication supplies the principal and roles. All three roles may call.
permit (principal, action == slangGraph::Action::"call", resource)
when {
  principal.roles.contains("Operator") ||
  principal.roles.contains("Technician") ||
  principal.roles.contains("Observer")
};

// Alice / Operator: inspect, start, stop, and set flow.
permit (
  principal,
  action in [
    slangGraph::Action::"pump::inspect",
    slangGraph::Action::"pump::start",
    slangGraph::Action::"pump::stop",
    slangGraph::Action::"pump::set_flow"
  ],
  resource
) when {
  principal.roles.contains("Operator") && resource.selector == "pump-1"
};

// Bob / Technician: inspect and calibrate.
permit (
  principal,
  action in [
    slangGraph::Action::"pump::inspect",
    slangGraph::Action::"pump::calibrate"
  ],
  resource
) when {
  principal.roles.contains("Technician") && resource.selector == "pump-1"
};

// Charlie / Observer: inspect only.
permit (
  principal,
  action == slangGraph::Action::"pump::inspect",
  resource
) when {
  principal.roles.contains("Observer") && resource.selector == "pump-1"
};
"""


class PumpSocketAdapter:
    """Trusted adapter that validates and sends an authorized pump command."""

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def execute(
        self, device_id: str, operation: str, value: float | None
    ) -> dict[str, Any]:
        # These checks defend the adapter even though the manifest already uses
        # a fixed action map and Cedar restricts the resource to pump-1.
        if device_id != DEVICE_ID:
            raise ValueError(f"unknown device: {device_id}")
        if operation not in OPERATIONS:
            raise ValueError(f"unknown operation: {operation}")
        if operation in {"inspect", "start", "stop"} and value is not None:
            raise ValueError(f"{operation} does not accept a value")
        if operation == "set_flow":
            value = _bounded_number(value, "flow rate", 0.0, 100.0)
        elif operation == "calibrate":
            value = _bounded_number(value, "calibration offset", -10.0, 10.0)

        request = {
            "device_id": device_id,
            "operation": operation,
            "value": value,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3.0)
                connection.connect(str(self.socket_path))
                connection.sendall((json.dumps(request) + "\n").encode())
                response = _read_json_line(connection)
        except OSError as exc:
            raise RuntimeError(
                f"cannot reach pump simulator at {self.socket_path}"
            ) from exc
        if response.get("ok") is not True:
            raise RuntimeError(f"pump rejected command: {response.get('error')}")
        return response


def _bounded_number(
    value: float | None, label: str, minimum: float, maximum: float
) -> float:
    if type(value) not in {int, float}:
        raise ValueError(f"{label} requires a numeric value")
    numeric = float(value)
    if not minimum <= numeric <= maximum:
        raise ValueError(f"{label} must be between {minimum:g} and {maximum:g}")
    return numeric


def _read_json_line(connection: socket.socket) -> dict[str, Any]:
    chunks = bytearray()
    while not chunks.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("pump simulator closed the connection")
        chunks.extend(chunk)
        if len(chunks) > 64 * 1024:
            raise RuntimeError("pump simulator response is too large")
    response = json.loads(chunks)
    if not isinstance(response, dict):
        raise TypeError("pump simulator returned a non-object response")
    return response


@dataclass(frozen=True)
class InvocationResult:
    allowed: bool
    dispatched: bool
    operation: str
    response: dict[str, Any] | None


def build_demo(socket_path: Path, cedar: str) -> tuple[Any, Any]:
    """Build the graph and security configuration around one trusted adapter."""
    adapter = PumpSocketAdapter(socket_path)

    @tool
    @effects(
        Effect.WRITE,
        resources=[ResourceArg("device_id", "pump")],
        sensitivity="critical",
    )
    def control_pump(
        device_id: str, operation: str, value: float | None = None
    ) -> dict[str, Any]:
        """Perform one operation on a simulated pump."""
        return adapter.execute(device_id, operation, value)

    security = cedar_security(
        control_pump,
        classes=CLASSES,
        manifest=MANIFEST,
        policy=POLICY,
        executable=cedar,
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([control_pump]))
    builder.add_edge(START, "tools")
    return builder.compile(security=security), security


def invoke(
    graph: Any,
    security: Any,
    principal_id: str,
    operation: str,
    value: float | None,
    call_number: int,
) -> InvocationResult:
    """Invoke once and print the complete derivation and decision."""
    roles = ROLES.get(principal_id, frozenset())
    principal = Principal(principal_id, roles, frozenset(), "demo-session")
    config = with_principal({}, principal, modules=security.modules)
    executor = security.host_executor
    assert isinstance(executor, ObjectPolicyHostExecutor)
    grants_before = len(executor.authorization_grants())
    artifacts_before = len(executor.authorizer.authorization_artifacts())

    print(f"\nPrincipal: {principal_id} roles={sorted(roles)}")
    print(f"Request: device={DEVICE_ID} operation={operation} value={value!r}")
    if operation in OPERATIONS:
        print(
            f'Derived: action=slangGraph::Action::"pump::{operation}" '
            f"resource={DEVICE_ID}"
        )
    else:
        print("Derived: rejected; operation is not in the manifest's closed map")

    message = None
    dispatch_error: str | None = None
    try:
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "control_pump",
                                "args": {
                                    "device_id": DEVICE_ID,
                                    "operation": operation,
                                    "value": value,
                                },
                                "id": f"call-{call_number}",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        message = result["messages"][-1]
    except HostExecutionDenied as exc:
        # A manifest or Cedar denial happens before a grant exists.
        dispatch_error = str(exc)
    except ValueError as exc:
        # The operation was authorized, but trusted-adapter validation rejected
        # malformed device data before it could reach the socket.
        dispatch_error = str(exc)
    grants = executor.authorization_grants()
    allowed = len(grants) > grants_before
    dispatched = (
        allowed
        and dispatch_error is None
        and message is not None
        and getattr(message, "status", None) != "error"
    )
    print(f"Authorization: {'ALLOW' if allowed else 'DENY'}")
    if allowed:
        grant = grants[-1]
        for line in grant.lines:
            print(
                f"Surviving grant: {line.class_name}::{line.operation} {line.selector}"
            )
    else:
        print("Surviving grant: none")

    response: dict[str, Any] | None = None
    if dispatched:
        assert message is not None
        response = json.loads(str(message.content))
        print(f"Device response: {json.dumps(response, sort_keys=True)}")
    elif allowed:
        detail = dispatch_error or getattr(message, "content", "unknown error")
        print(f"Dispatch rejected: {detail}")
    else:
        print("Device response: not dispatched")

    artifacts = executor.authorizer.authorization_artifacts()
    if len(artifacts) > artifacts_before:
        print(f"Cedar artifacts: {artifacts[-1]}")
    return InvocationResult(allowed, dispatched, operation, response)


def run_automated_demo(graph: Any, security: Any, log_path: Path) -> None:
    """Exercise the role matrix and prove denied commands never reached the pump."""
    before = _read_log(log_path)
    cases = [
        ("alice", "set_flow", 25.0, True, True),
        ("alice", "calibrate", 1.5, False, False),
        ("bob", "calibrate", 1.5, True, True),
        ("bob", "start", None, False, False),
        ("charlie", "inspect", None, True, True),
        ("charlie", "stop", None, False, False),
        # Input validation is a separate gate after operation authorization.
        ("alice", "set_flow", 1000.0, True, False),
        # This string cannot become a Cedar action because it is not mapped.
        ("alice", "pump::calibrate", 1.0, False, False),
    ]
    for number, (
        principal,
        operation,
        value,
        expected_allowed,
        expected_dispatched,
    ) in enumerate(cases, 1):
        result = invoke(graph, security, principal, operation, value, number)
        assert result.allowed is expected_allowed
        assert result.dispatched is expected_dispatched

    new_entries = _read_log(log_path)[len(before) :]
    assert [entry["operation"] for entry in new_entries] == [
        "set_flow",
        "calibrate",
        "inspect",
    ]
    final_state = new_entries[-1]["after"]
    assert final_state == {
        "running": False,
        "flow_rate": 25.0,
        "calibration_offset": 1.5,
    }
    print("\nAutomated assertions passed:")
    print("  denied commands created no simulator log entries")
    print("  denied commands caused no pump state changes")
    print("  set_flow and calibrate used the same socket but different permissions")


def _read_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run_interactive(graph: Any, security: Any) -> None:
    print("Principal selection is a demo substitute for real authentication.")
    principal = input("Principal [alice, bob, or charlie]: ").strip().lower()
    print("Commands: inspect, start, stop, set_flow NUMBER, calibrate NUMBER")
    print("Also: principal NAME, help, quit")
    call_number = 1
    while True:
        raw = input(f"pump({principal})> ").strip()
        if not raw:
            continue
        if raw in {"quit", "exit"}:
            return
        if raw == "help":
            print("inspect | start | stop | set_flow NUMBER | calibrate NUMBER")
            continue
        if raw.startswith("principal "):
            principal = raw.split(maxsplit=1)[1].strip().lower()
            continue
        words = raw.split()
        operation = words[0]
        if len(words) > 2:
            print("Rejected: expected OPERATION [NUMBER]")
            continue
        try:
            value = float(words[1]) if len(words) == 2 else None
        except ValueError:
            print("Rejected: value must be numeric")
            continue
        invoke(graph, security, principal, operation, value, call_number)
        call_number += 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket", type=Path, default=Path("/tmp/slanggraph-pump.sock")
    )
    parser.add_argument(
        "--log", type=Path, default=Path("/tmp/slanggraph-pump-commands.jsonl")
    )
    parser.add_argument("--cedar", default="cedar")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    graph, security = build_demo(args.socket, args.cedar)
    if args.demo:
        run_automated_demo(graph, security, args.log)
    else:
        run_interactive(graph, security)


if __name__ == "__main__":
    main()
