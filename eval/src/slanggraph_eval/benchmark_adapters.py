"""Thin benchmark adapters that execute calls through LangGraph `ToolNode`."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from types import SimpleNamespace
from typing import Any

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import ToolNode
from pydantic import create_model


def route_tool_call(
    name: str,
    args: Mapping[str, Any],
    executor: Callable[[Mapping[str, Any]], Any],
    *,
    call_id: str = "benchmark-call",
) -> ToolMessage:
    """Translate one benchmark call into a real LangGraph `ToolNode` call."""
    fields = {key: (_field_type(value), ...) for key, value in args.items()}
    schema = create_model(f"{_identifier(name)}Args", **fields)

    def invoke(**kwargs: Any) -> Any:
        return executor(kwargs)

    tool = StructuredTool.from_function(
        func=invoke,
        name=name,
        description=f"Pinned benchmark adapter for {name}.",
        args_schema=schema,
    )
    node = ToolNode((tool,))
    message = AIMessage(
        content="",
        tool_calls=[{"name": name, "args": dict(args), "id": call_id, "type": "tool_call"}],
    )
    runtime = SimpleNamespace(
        store=None,
        context=None,
        stream_writer=lambda *values: None,
        execution_info=None,
        server_info=None,
    )
    result = node.invoke(
        {"messages": [message]},
        config={"configurable": {"__pregel_runtime": runtime}},
    )
    tool_message = result["messages"][0]
    if not isinstance(tool_message, ToolMessage):
        raise TypeError("ToolNode did not return a ToolMessage")
    return tool_message


class AgentDojoToolNodeElement:
    """AgentDojo-compatible pipeline element backed by LangGraph `ToolNode`."""

    name = "slanggraph-tool-node"

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args or {}
        calls = messages[-1].get("tool_calls") or ()
        if not calls:
            return query, runtime, env, messages, extra_args or {}
        from agentdojo.types import (
            ChatToolResultMessage,
            text_content_block_from_string,
        )

        outputs = []
        for call in calls:

            def execute(args: Mapping[str, Any], call=call):
                value, error = runtime.run_function(env, call.function, dict(args))
                if error:
                    raise RuntimeError(str(error))
                return value

            result = route_tool_call(
                call.function,
                call.args,
                execute,
                call_id=call.id,
            )
            outputs.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(str(result.content))],
                    tool_call_id=call.id,
                    tool_call=call,
                    error=None,
                )
            )
        return query, runtime, env, [*messages, *outputs], extra_args or {}


def route_injecagent_call(
    item: Mapping[str, Any], executor: Callable[[Mapping[str, Any]], Any]
) -> ToolMessage:
    """Route an InjecAgent action record through `ToolNode`."""
    name = str(item["name"])
    parameters = item.get("parameters", {})
    if not isinstance(parameters, Mapping):
        raise TypeError("InjecAgent parameters must be a mapping")
    return route_tool_call(name, parameters, executor, call_id="injecagent-call")


def route_asb_call(
    tool_name: str,
    parameters: Mapping[str, Any],
    executor: Callable[[Mapping[str, Any]], Any],
) -> ToolMessage:
    """Route an ASB/AIOS tool request through `ToolNode`."""
    return route_tool_call(tool_name, parameters, executor, call_id="asb-call")


def tool_message_value(message: ToolMessage) -> Any:
    """Decode the JSON content emitted by `ToolNode` when possible."""
    if isinstance(message.content, str):
        try:
            return json.loads(message.content)
        except json.JSONDecodeError:
            return message.content
    return message.content


def _field_type(value: Any) -> type[Any]:
    if type(value) in {str, int, float, bool, list, dict}:
        return type(value)
    return Any


def _identifier(name: str) -> str:
    value = "".join(character if character.isalnum() else "_" for character in name)
    if not value or value[0].isdigit():
        value = "Tool_" + value
    return value
