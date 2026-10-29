# ruff: noqa: E501
"""Executable extraction of D2, the complete agentic-RAG graph."""

from __future__ import annotations

import argparse
import html
import json
import time
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer

MODEL = {
    "name": "qwen3:8b",
    "base_url": "http://127.0.0.1:11434/v1",
    "temperature": 0,
    "seed": 20261005,
    "reasoning_effort": "none",
}


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]


def model() -> ChatOpenAI:
    return ChatOpenAI(
        model=MODEL["name"],
        base_url=MODEL["base_url"],
        api_key="ollama",
        temperature=MODEL["temperature"],
        seed=MODEL["seed"],
        timeout=600,
        max_retries=0,
        reasoning_effort=MODEL["reasoning_effort"],
    )


def chunks(paths: list[Path]) -> list[str]:
    result = []
    for path in paths:
        parser = TextExtractor()
        parser.feed(path.read_text(errors="replace"))
        words = html.unescape(" ".join(parser.parts)).split()
        for start in range(0, len(words), 60):
            result.append(" ".join(words[start : start + 100]))
    return result


def build(paths: list[Path]):
    documents = chunks(paths)
    vectorizer = TfidfVectorizer(stop_words="english").fit(documents)
    matrix = vectorizer.transform(documents)

    @tool("retrieve_blog_posts")
    def retrieve_blog_posts(query: str) -> str:
        """Search and return information about Lilian Weng blog posts on LLM agents, prompt engineering, and adversarial attacks on LLMs."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        indices = scores.argsort()[-5:][::-1]
        return "\n\n".join(documents[index] for index in indices)

    tools = [retrieve_blog_posts]

    def grade_documents(state) -> Literal["generate", "rewrite"]:
        class Grade(BaseModel):
            binary_score: str = Field(description="Relevance score 'yes' or 'no'")

        prompt = PromptTemplate(
            template="""You are a grader assessing relevance of a retrieved document to a user question.
Here is the retrieved document:\n\n{context}\n\nHere is the user question: {question}
If the document contains keyword(s) or semantic meaning related to the user question, grade it as relevant.
Give a binary score 'yes' or 'no' score to indicate whether the document is relevant to the question.""",
            input_variables=["context", "question"],
        )
        chain = prompt | model().with_structured_output(Grade)
        messages = state["messages"]
        score = chain.invoke(
            {"question": messages[0].content, "context": messages[-1].content}
        ).binary_score
        return "generate" if score == "yes" else "rewrite"

    def agent(state):
        response = model().bind_tools(tools).invoke(state["messages"])
        return {"messages": [response]}

    def rewrite(state):
        question = state["messages"][0].content
        response = model().invoke(
            [
                HumanMessage(
                    content=f"""Look at the input and reason about the underlying semantic intent.
Here is the initial question:\n-------\n{question}\n-------\nFormulate an improved question:"""
                )
            ]
        )
        return {"messages": [response]}

    def generate(state):
        messages = state["messages"]
        prompt = PromptTemplate.from_template(
            """You are an assistant for question-answering tasks. Use the following pieces of retrieved context to answer the question. If you don't know the answer, say that you don't know. Use three sentences maximum and keep the answer concise.
Question: {question}
Context: {context}
Answer:"""
        )
        response = (prompt | model()).invoke(
            {"context": messages[-1].content, "question": messages[0].content}
        )
        return {"messages": [response]}

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent)
    workflow.add_node("retrieve", ToolNode([retrieve_blog_posts]))
    workflow.add_node("rewrite", rewrite)
    workflow.add_node("generate", generate)
    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges("agent", tools_condition, {"tools": "retrieve", END: END})
    workflow.add_conditional_edges("retrieve", grade_documents)
    workflow.add_edge("generate", END)
    workflow.add_edge("rewrite", "agent")
    return workflow.compile()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--documents", nargs=3, type=Path, required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        raise RuntimeError(
            "argus:unsupported: D2 retrieve_blog_posts closes over an in-process "
            "TF-IDF index; no registered retriever resource adapter or Linux worker "
            "endpoint preserves the upstream retriever-tool contract"
        )
    started = time.perf_counter()
    graph = build(args.documents)
    result = graph.invoke({"messages": [("user", args.prompt)]}, {"recursion_limit": 50})
    args.output.write_text(
        json.dumps(
            {
                "answer": str(result["messages"][-1].content),
                "messages": [message.model_dump() for message in result["messages"]],
                "wall_ms": (time.perf_counter() - started) * 1000,
            },
            default=str,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
