from __future__ import annotations

from slanggraph_eval.benchmark_adapters import (
    route_asb_call,
    route_injecagent_call,
    route_tool_call,
    tool_message_value,
)


def test_all_benchmark_adapters_route_through_tool_node() -> None:
    calls = []

    def execute(args):
        calls.append(dict(args))
        return {"accepted": True, "args": dict(args)}

    messages = [
        route_tool_call("send_email", {"recipient": "alice@example"}, execute),
        route_injecagent_call(
            {"name": "Execute", "parameters": {"command": "printf parity"}},
            execute,
        ),
        route_asb_call("sys_monitor", {"target": "loopback"}, execute),
    ]

    assert calls == [
        {"recipient": "alice@example"},
        {"command": "printf parity"},
        {"target": "loopback"},
    ]
    assert all(tool_message_value(message)["accepted"] for message in messages)
