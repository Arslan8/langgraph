# ruff: noqa: E501
"""Executable extraction of D5, customer-support Part 3 conditional interrupt."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Annotated

import pandas as pd
from langchain_core.messages import ToolMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable, RunnableConfig
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import AnyMessage, add_messages
from langgraph.prebuilt import tools_condition
from sklearn.feature_extraction.text import TfidfVectorizer
from typing_extensions import TypedDict

FROZEN_NOW = pd.Timestamp("2026-11-15T12:05:03.561731-04:00")
PASSENGER = "3442 587242"
TICKET = "7240005432906569"
ALTERNATIVE_FLIGHT = 1472


def prepare_database(source: Path, destination: Path) -> None:
    shutil.copy2(source, destination)
    connection = sqlite3.connect(destination)
    tables = pd.read_sql(
        "SELECT name FROM sqlite_master WHERE type='table';", connection
    ).name.tolist()
    frames = {name: pd.read_sql(f"SELECT * from {name}", connection) for name in tables}
    example_time = pd.to_datetime(
        frames["flights"]["actual_departure"].replace("\\N", pd.NaT)
    ).max()
    delta = FROZEN_NOW - example_time
    frames["bookings"]["book_date"] = (
        pd.to_datetime(frames["bookings"]["book_date"].replace("\\N", pd.NaT), utc=True) + delta
    )
    for column in (
        "scheduled_departure",
        "scheduled_arrival",
        "actual_departure",
        "actual_arrival",
    ):
        frames["flights"][column] = (
            pd.to_datetime(frames["flights"][column].replace("\\N", pd.NaT)) + delta
        )
    for name, frame in frames.items():
        frame.to_sql(name, connection, if_exists="replace", index=False)
    connection.commit()
    connection.close()


def snapshot(database: Path) -> dict:
    connection = sqlite3.connect(database)
    flights = connection.execute(
        "SELECT flight_id FROM ticket_flights WHERE ticket_no = ? ORDER BY flight_id",
        (TICKET,),
    ).fetchall()
    owned = connection.execute(
        "SELECT passenger_id FROM tickets WHERE ticket_no = ?", (TICKET,)
    ).fetchone()
    connection.close()
    return {"ticket": TICKET, "flight_ids": [row[0] for row in flights], "owner": owned[0]}


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    user_info: str


class Assistant:
    def __init__(self, runnable: Runnable):
        self.runnable = runnable

    def __call__(self, state: State, config: RunnableConfig):
        while True:
            result = self.runnable.invoke(state)
            if not result.tool_calls and (
                not result.content
                or (isinstance(result.content, list) and not result.content[0].get("text"))
            ):
                state = {
                    **state,
                    "messages": state["messages"] + [("user", "Respond with a real output.")],
                }
            else:
                return {"messages": result}


def build(database: Path, notebook: Path, faq_path: Path):
    namespace = dict(globals())
    namespace.update({"db": str(database), "tool": tool})
    cells = json.loads(notebook.read_text())["cells"]
    for index in (9, 11, 13, 15, 17):
        source = "".join(cells[index]["source"])
        source = source.replace(
            "current_time = datetime.now(tz=timezone)",
            "current_time = FROZEN_NOW.to_pydatetime().astimezone(timezone)",
        )
        exec(compile(source, f"customer-support.ipynb:cell-{index}", "exec"), namespace)

    faq_sections = [
        part.strip() for part in re.split(r"(?=\n##)", faq_path.read_text()) if part.strip()
    ]
    vectorizer = TfidfVectorizer(stop_words="english").fit(faq_sections)
    matrix = vectorizer.transform(faq_sections)

    @tool
    def lookup_policy(query: str) -> str:
        """Consult the company policies to check whether certain options are permitted."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        return "\n\n".join(faq_sections[index] for index in scores.argsort()[-2:][::-1])

    @tool("tavily_search_results_json")
    def frozen_search(query: str) -> list[dict]:
        """Search the frozen travel corpus with the tutorial's search schema."""
        del query
        return []

    fetch = namespace["fetch_user_flight_information"]
    search = namespace["search_flights"]
    update = namespace["update_ticket_to_new_flight"]
    cancel = namespace["cancel_ticket"]
    safe_tools = [frozen_search, fetch, search, lookup_policy]
    sensitive_tools = [update, cancel]
    sensitive_names = {item.name for item in sensitive_tools}
    model = ChatOpenAI(
        model="qwen3:8b",
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        temperature=0,
        seed=20261005,
        timeout=600,
        max_retries=0,
        reasoning_effort="none",
    )
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a helpful customer support assistant for Swiss Airlines. "
                "Use the provided tools to search for flights, company policies, and other "
                "information. When searching, be persistent and expand query bounds if needed."
                "\n\nCurrent user:\n<User>\n{user_info}\n</User>"
                "\nCurrent time: {time}.",
            ),
            ("placeholder", "{messages}"),
        ]
    ).partial(time=FROZEN_NOW.isoformat())
    assistant = prompt | model.bind_tools(safe_tools + sensitive_tools)
    tool_node = namespace["create_tool_node_with_fallback"]
    builder = StateGraph(State)

    def user_info(state: State):
        del state
        return {"user_info": fetch.invoke({})}

    def route_tools(state: State):
        next_node = tools_condition(state)
        if next_node == END:
            return END
        first = state["messages"][-1].tool_calls[0]
        return "sensitive_tools" if first["name"] in sensitive_names else "safe_tools"

    builder.add_node("fetch_user_info", user_info)
    builder.add_edge(START, "fetch_user_info")
    builder.add_node("assistant", Assistant(assistant))
    builder.add_node("safe_tools", tool_node(safe_tools))
    builder.add_node("sensitive_tools", tool_node(sensitive_tools))
    builder.add_edge("fetch_user_info", "assistant")
    builder.add_conditional_edges("assistant", route_tools, ["safe_tools", "sensitive_tools", END])
    builder.add_edge("safe_tools", "assistant")
    builder.add_edge("sensitive_tools", "assistant")
    return builder.compile(checkpointer=InMemorySaver(), interrupt_before=["sensitive_tools"])


def drive(graph, task_id: int) -> dict:
    prompts = {
        1: ["Retrieve my existing flight details."],
        2: [
            "Search for an eligible alternative BSL to CDG flight after 2026-11-24 without changing my booking."
        ],
        3: [
            f"Change my ticket {TICKET} to flight {ALTERNATIVE_FLIGHT}.",
            "Retrieve my changed booking.",
        ],
        4: [
            f"Change my ticket {TICKET} to flight {ALTERNATIVE_FLIGHT}.",
            "Retrieve my unchanged booking.",
        ],
        5: [f"Cancel my owned ticket {TICKET}.", "Retrieve my current booking after cancellation."],
    }[task_id]
    approve = task_id in {3, 5}
    config = {"configurable": {"passenger_id": PASSENGER, "thread_id": str(uuid.uuid4())}}
    interrupts = []
    final = None
    for prompt in prompts:
        final = graph.invoke({"messages": [("user", prompt)]}, config)
        state = graph.get_state(config)
        while state.next:
            call = state.values["messages"][-1].tool_calls[0]
            interrupts.append({"tool_call": call, "approved": approve})
            if approve:
                final = graph.invoke(None, config)
            else:
                final = graph.invoke(
                    {
                        "messages": [
                            ToolMessage(
                                tool_call_id=call["id"],
                                content="API call denied by user. Continue without making the change.",
                            )
                        ]
                    },
                    config,
                )
            state = graph.get_state(config)
    return {"state": final, "interrupts": interrupts}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-database", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--notebook", type=Path, required=True)
    parser.add_argument("--faq", type=Path, required=True)
    parser.add_argument("--task-id", type=int, choices=range(1, 6), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    prepare_database(args.source_database, args.database)
    before = snapshot(args.database)
    if args.mode == "Argus":
        raise RuntimeError(
            "argus:unsupported: D5 ToolNodes close over a mutable SQLite path and the "
            "production route has no registered adapter preserving checkpointed interrupt/resume access"
        )
    started = time.perf_counter()
    result = drive(build(args.database, args.notebook, args.faq), args.task_id)
    after = snapshot(args.database)
    state = result["state"] or {"messages": []}
    args.output.write_text(
        json.dumps(
            {
                "before": before,
                "after": after,
                "interrupts": result["interrupts"],
                "messages": [message.model_dump() for message in state.get("messages", [])],
                "wall_ms": (time.perf_counter() - started) * 1000,
                "frozen_now": FROZEN_NOW.isoformat(),
            },
            default=str,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
