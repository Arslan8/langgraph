# ruff: noqa: E501
"""Executable extraction of D4, the researcher/chart-generator network."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Annotated, Literal

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.tools import tool
from langchain_experimental.utilities import PythonREPL
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import create_react_agent
from langgraph.types import Command
from sklearn.feature_extraction.text import TfidfVectorizer


def llm() -> ChatOpenAI:
    return ChatOpenAI(
        model="qwen3:8b",
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        temperature=0,
        seed=20261005,
        timeout=600,
        max_retries=0,
        reasoning_effort="none",
    )


def make_system_prompt(suffix: str) -> str:
    return (
        "You are a helpful AI assistant, collaborating with other assistants."
        " Use the provided tools to progress towards answering the question."
        " If you are unable to fully answer, that's OK, another assistant with different tools "
        "will help where you left off. Execute what you can to make progress."
        " If you or any of the other assistants have the final answer or deliverable,"
        " prefix your response with FINAL ANSWER so the team knows to stop.\n" + suffix
    )


def build(gdp_path: Path, artifact: Path, observer: Path):
    payload = json.loads(gdp_path.read_text())[1]
    documents = []
    for code in ("GBR", "FRA", "DEU", "JPN", "CAN"):
        rows = sorted(
            (row for row in payload if row["countryiso3code"] == code),
            key=lambda row: row["date"],
        )
        country = rows[0]["country"]["value"]
        values = ", ".join(f"{row['date']}: {row['value']}" for row in rows)
        documents.append(
            {
                "url": "https://api.worldbank.org/v2/indicator/NY.GDP.MKTP.CD",
                "content": f"{country} annual GDP current US dollars: {values}",
            }
        )
    vectorizer = TfidfVectorizer(stop_words="english").fit([item["content"] for item in documents])
    matrix = vectorizer.transform([item["content"] for item in documents])

    @tool("tavily_search")
    def tavily_tool(query: str) -> list[dict]:
        """Search the frozen public-data corpus and return up to five results."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        return [documents[index] for index in scores.argsort()[::-1]]

    repl = PythonREPL()

    @tool
    def python_repl_tool(
        code: Annotated[str, "The python code to execute to generate your chart."],
    ):
        """Execute Python code to generate the chart; print values to expose them."""
        try:
            result = repl.run(code)
            figure = plt.gcf()
            lines = []
            for axis in figure.axes:
                for line in axis.lines:
                    lines.append(
                        {
                            "x": [str(value) for value in line.get_xdata().tolist()],
                            "y": [float(value) for value in line.get_ydata().tolist()],
                        }
                    )
            if lines:
                figure.savefig(artifact)
                observer.write_text(json.dumps({"lines": lines}, indent=2) + "\n")
        except BaseException as exc:
            return f"Failed to execute. Error: {exc!r}"
        return f"Successfully executed:\n```python\n{code}\n```\nStdout: {result}\n\nIf complete, respond with FINAL ANSWER."

    def get_next_node(last_message: BaseMessage, goto: str):
        return END if "FINAL ANSWER" in str(last_message.content) else goto

    research_agent = create_react_agent(
        llm(),
        tools=[tavily_tool],
        prompt=make_system_prompt(
            "You can only do research. You are working with a chart generator colleague."
        ),
    )

    def research_node(state: MessagesState) -> Command[Literal["chart_generator", END]]:
        result = research_agent.invoke(state)
        goto = get_next_node(result["messages"][-1], "chart_generator")
        result["messages"][-1] = HumanMessage(
            content=result["messages"][-1].content, name="researcher"
        )
        return Command(update={"messages": result["messages"]}, goto=goto)

    chart_agent = create_react_agent(
        llm(),
        [python_repl_tool],
        prompt=make_system_prompt(
            "You can only generate charts. You are working with a researcher colleague."
        ),
    )

    def chart_node(state: MessagesState) -> Command[Literal["researcher", END]]:
        result = chart_agent.invoke(state)
        goto = get_next_node(result["messages"][-1], "researcher")
        result["messages"][-1] = HumanMessage(
            content=result["messages"][-1].content, name="chart_generator"
        )
        return Command(update={"messages": result["messages"]}, goto=goto)

    workflow = StateGraph(MessagesState)
    workflow.add_node("researcher", research_node)
    workflow.add_node("chart_generator", chart_node)
    workflow.add_edge(START, "researcher")
    return workflow.compile()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdp", type=Path, required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        raise RuntimeError(
            "argus:unsupported: D4 requires one persistent PythonREPL namespace across "
            "tool calls; the production Linux route creates an isolated fresh worker per call"
        )
    started = time.perf_counter()
    result = build(args.gdp, args.artifact, args.observer).invoke(
        {"messages": [("user", args.prompt)]}, {"recursion_limit": 150}
    )
    args.output.write_text(
        json.dumps(
            {
                "answer": str(result["messages"][-1].content),
                "messages": [message.model_dump() for message in result["messages"]],
                "artifact": str(args.artifact),
                "observer": str(args.observer),
                "wall_ms": (time.perf_counter() - started) * 1000,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
