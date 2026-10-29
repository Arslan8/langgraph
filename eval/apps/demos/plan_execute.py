"""Executable extraction of D3, the complete async planner/executor/replanner graph."""

from __future__ import annotations

import argparse
import asyncio
import json
import operator
import time
from pathlib import Path
from typing import Annotated

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from typing_extensions import TypedDict


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


class PlanExecute(TypedDict):
    input: str
    plan: list[str]
    past_steps: Annotated[list[tuple], operator.add]
    response: str


class Plan(BaseModel):
    steps: list[str] = Field(description="different steps to follow, should be in sorted order")


class Response(BaseModel):
    response: str


class Act(BaseModel):
    action: Response | Plan = Field(
        description="Respond when complete; otherwise provide only remaining plan steps."
    )


def build(corpus_path: Path):
    corpus = json.loads(corpus_path.read_text())
    texts = [f"{item['title']} {item['content']}" for item in corpus]
    vectorizer = TfidfVectorizer(stop_words="english").fit(texts)
    matrix = vectorizer.transform(texts)

    @tool("tavily_search_results_json")
    def frozen_search(query: str) -> list[dict]:
        """Search the frozen web corpus and return up to three relevant results."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        return [
            {"url": corpus[index]["url"], "content": corpus[index]["content"]}
            for index in scores.argsort()[-3:][::-1]
        ]

    agent_executor = create_react_agent(
        llm(), [frozen_search], prompt="You are a helpful assistant."
    )
    planner_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "For the given objective, come up with a simple step by step plan. "
                "This plan should involve individual tasks that yield the answer. Do not "
                "add superfluous steps. The final step should produce the final answer, "
                "and each step must contain all information needed.",
            ),
            ("placeholder", "{messages}"),
        ]
    )
    planner = planner_prompt | llm().with_structured_output(Plan)
    replanner_prompt = ChatPromptTemplate.from_template(
        """For the given objective, update the simple step by step plan.
Objective: {input}
Original plan: {plan}
Completed steps: {past_steps}
If no more steps are needed, respond to the user. Otherwise return only steps still needed."""
    )
    replanner = replanner_prompt | llm().with_structured_output(Act)

    async def execute_step(state: PlanExecute):
        plan = state["plan"]
        plan_str = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(plan))
        task = plan[0]
        task_formatted = f"For the following plan:\n{plan_str}\n\nExecute step 1: {task}"
        response = await agent_executor.ainvoke({"messages": [("user", task_formatted)]})
        return {"past_steps": [(task, response["messages"][-1].content)]}

    async def plan_step(state: PlanExecute):
        plan = await planner.ainvoke({"messages": [("user", state["input"])]})
        return {"plan": plan.steps}

    async def replan_step(state: PlanExecute):
        output = await replanner.ainvoke(state)
        if isinstance(output.action, Response):
            return {"response": output.action.response}
        return {"plan": output.action.steps}

    def should_end(state: PlanExecute):
        return END if state.get("response") else "agent"

    workflow = StateGraph(PlanExecute)
    workflow.add_node("planner", plan_step)
    workflow.add_node("agent", execute_step)
    workflow.add_node("replan", replan_step)
    workflow.add_edge(START, "planner")
    workflow.add_edge("planner", "agent")
    workflow.add_edge("agent", "replan")
    workflow.add_conditional_edges("replan", should_end, ["agent", END])
    return workflow.compile()


async def run(args) -> None:
    if args.mode == "Argus":
        raise RuntimeError(
            "argus:unsupported: D3 requires async ToolNode execution, while the selected "
            "per-call Lean lifecycle route is synchronous-only and refuses async dispatch"
        )
    started = time.perf_counter()
    result = await build(args.corpus).ainvoke(
        {"input": args.prompt, "plan": [], "past_steps": [], "response": ""},
        {"recursion_limit": 50},
    )
    args.output.write_text(
        json.dumps(
            {
                "answer": result.get("response"),
                "state": result,
                "wall_ms": (time.perf_counter() - started) * 1000,
            },
            default=str,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    asyncio.run(run(parser.parse_args()))
