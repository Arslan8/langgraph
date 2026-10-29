"""Executable extraction of D1, SQL tutorial section 3 (custom graph)."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Literal

from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_community.utilities import SQLDatabase
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

MODEL = {
    "name": "qwen3:8b",
    "base_url": "http://127.0.0.1:11434/v1",
    "temperature": 0,
    "seed": 20261005,
    "digest": "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41",
    "timeout_seconds": 600,
    "max_retries": 0,
    "reasoning_effort": "none",
}


class Observer(BaseCallbackHandler):
    def __init__(self, events: Path):
        self.events = events

    def _write(self, value: dict) -> None:
        with self.events.open("a") as stream:
            stream.write(json.dumps(value, default=str) + "\n")

    def on_llm_start(self, serialized, prompts, **kwargs):
        self._write({"kind": "model_start", "monotonic": time.perf_counter(), "prompts": prompts})

    def on_llm_end(self, response, **kwargs):
        self._write(
            {
                "kind": "model_end",
                "monotonic": time.perf_counter(),
                "response": response.model_dump(),
            }
        )

    def on_tool_start(self, serialized, input_str, **kwargs):
        self._write(
            {
                "kind": "tool_start",
                "monotonic": time.perf_counter(),
                "name": serialized.get("name"),
                "input": input_str,
            }
        )

    def on_tool_end(self, output, **kwargs):
        self._write({"kind": "tool_end", "monotonic": time.perf_counter(), "output": str(output)})


def build(db_path: Path, events: Path):
    llm = ChatOpenAI(
        model=MODEL["name"],
        base_url=MODEL["base_url"],
        api_key="ollama",
        temperature=MODEL["temperature"],
        seed=MODEL["seed"],
        timeout=MODEL["timeout_seconds"],
        max_retries=MODEL["max_retries"],
        reasoning_effort=MODEL["reasoning_effort"],
        callbacks=[Observer(events)],
    )
    db = SQLDatabase.from_uri(f"sqlite:///{db_path}")
    tools = SQLDatabaseToolkit(db=db, llm=llm).get_tools()
    get_schema_tool = next(tool for tool in tools if tool.name == "sql_db_schema")
    get_schema_node = ToolNode([get_schema_tool], name="get_schema")
    run_query_tool = next(tool for tool in tools if tool.name == "sql_db_query")
    run_query_node = ToolNode([run_query_tool], name="run_query")

    def list_tables(state: MessagesState):
        del state
        tool_call = {
            "name": "sql_db_list_tables",
            "args": {},
            "id": "abc123",
            "type": "tool_call",
        }
        tool_call_message = AIMessage(content="", tool_calls=[tool_call])
        list_tables_tool = next(tool for tool in tools if tool.name == "sql_db_list_tables")
        tool_message = list_tables_tool.invoke(tool_call)
        response = AIMessage(f"Available tables: {tool_message.content}")
        return {"messages": [tool_call_message, tool_message, response]}

    def call_get_schema(state: MessagesState):
        model = llm.bind_tools([get_schema_tool], tool_choice="any")
        return {"messages": [model.invoke(state["messages"])]}

    generate_prompt = f"""
You are an agent designed to interact with a SQL database.
Given an input question, create a syntactically correct {db.dialect} query to run,
then look at the results of the query and return the answer. Unless the user
specifies a specific number of examples they wish to obtain, always limit your
query to at most 5 results.

You can order the results by a relevant column to return the most interesting
examples in the database. Never query for all the columns from a specific table,
only ask for the relevant columns given the question.

DO NOT make any DML statements (INSERT, UPDATE, DELETE, DROP etc.) to the database.
"""

    def generate_query(state: MessagesState):
        model = llm.bind_tools([run_query_tool])
        response = model.invoke(
            [{"role": "system", "content": generate_prompt}] + state["messages"]
        )
        return {"messages": [response]}

    check_prompt = f"""
You are a SQL expert with a strong attention to detail.
Double check the {db.dialect} query for common mistakes, including:
- Using NOT IN with NULL values
- Using UNION when UNION ALL should have been used
- Using BETWEEN for exclusive ranges
- Data type mismatch in predicates
- Properly quoting identifiers
- Using the correct number of arguments for functions
- Casting to the correct data type
- Using the proper columns for joins

If there are any of the above mistakes, rewrite the query. If there are no mistakes,
just reproduce the original query.

You will call the appropriate tool to execute the query after running this check.
"""

    def check_query(state: MessagesState):
        tool_call = state["messages"][-1].tool_calls[0]
        user_message = {"role": "user", "content": tool_call["args"]["query"]}
        model = llm.bind_tools([run_query_tool], tool_choice="any")
        response = model.invoke([{"role": "system", "content": check_prompt}, user_message])
        response.id = state["messages"][-1].id
        return {"messages": [response]}

    def should_continue(state: MessagesState) -> Literal[END, "check_query"]:
        return "check_query" if state["messages"][-1].tool_calls else END

    builder = StateGraph(MessagesState)
    builder.add_node(list_tables)
    builder.add_node(call_get_schema)
    builder.add_node(get_schema_node, "get_schema")
    builder.add_node(generate_query)
    builder.add_node(check_query)
    builder.add_node(run_query_node, "run_query")
    builder.add_edge(START, "list_tables")
    builder.add_edge("list_tables", "call_get_schema")
    builder.add_edge("call_get_schema", "get_schema")
    builder.add_edge("get_schema", "generate_query")
    builder.add_conditional_edges("generate_query", should_continue)
    builder.add_edge("check_query", "run_query")
    builder.add_edge("run_query", "generate_query")
    return builder.compile()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        raise RuntimeError(
            "argus:unsupported: D1 list_tables directly invokes SQLDatabase in a trusted "
            "orchestration node; no registered SQL resource adapter can lower this access "
            "without changing the upstream graph"
        )
    graph = build(args.database.resolve(), args.events)
    result = graph.invoke({"messages": [("user", args.prompt)]}, config={"recursion_limit": 50})
    args.output.write_text(
        json.dumps(
            {
                "messages": [message.model_dump() for message in result["messages"]],
                "answer": str(result["messages"][-1].content),
            },
            default=str,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
