"""Demo 12b: observe all built-in events through real local operations."""

import argparse
import json
import sqlite3
from collections import Counter
from contextlib import closing
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory

from langchain_core.documents import Document
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis import Analysis, BuiltinEvent
from langgraph.prebuilt.analysis.adapters.operations import ObservedOperations
from langgraph.runtime import Runtime
from langgraph.store.memory import InMemoryStore
from local_receiver import local_receiver
from typing_extensions import TypedDict


class Branch(TypedDict):
    text: str
    size: int


def child_graph():
    graph = StateGraph(Branch)
    graph.add_node("count", lambda state: {"size": len(state["text"])})
    graph.add_edge(START, "count")
    graph.add_edge("count", END)
    return graph.compile()


@tool
def add(a: int, b: int) -> int:
    """Add non-negative numbers; negative input demonstrates a real tool error."""
    if a < 0 or b < 0:
        raise ValueError("Use non-negative numbers")
    return a + b


def tour(query, *, operations, analysis, model, directory, sender):
    # Resource operations really write and read a temporary file.
    path = directory / "notes.txt"
    notes = "Callbacks observe events. Developers choose their result format."
    assert operations.write_text(path, notes) == len(notes)
    assert operations.read_text(path) == notes

    # Retrieval runs an actual SQLite query over two documents.
    with closing(sqlite3.connect(":memory:")) as documents:
        documents.execute("CREATE TABLE docs (text TEXT)")
        documents.executemany(
            "INSERT INTO docs VALUES (?)", [(notes,), ("Unrelated note",)]
        )
        retriever = RunnableLambda(
            lambda term: [
                Document(page_content=row[0])
                for row in documents.execute(
                    "SELECT text FROM docs WHERE text LIKE ?", (f"%{term}%",)
                )
            ]
        )
        matches = operations.retrieve(retriever, query)
        assert len(matches) == 1 and matches[0].page_content == notes
    context = operations.transform(
        matches, lambda docs: "\n".join(doc.page_content for doc in docs)
    )

    # This invokes llama.cpp. There is no canned model response or fallback.
    answer = operations.model(
        model,
        [
            ("system", "Give a short one-sentence summary of the supplied notes."),
            ("human", context),
        ],
    )
    assert isinstance(answer.content, str) and answer.content.strip()

    # The same real tool runs once successfully and once with an error.
    tools = ToolNode([add], analysis=analysis, handle_tool_errors=True)
    for a, expected_status in ((2, "success"), (-1, "error")):
        result = tools.invoke(
            [
                {
                    "name": "add",
                    "args": {"a": a, "b": 3},
                    "id": f"add-{a}",
                    "type": "tool_call",
                }
            ],
            runtime=Runtime(),
        )["messages"][0]
        assert result.status == expected_status
        if expected_status == "success":
            assert result.content == "5"

    state = {}
    operations.state_write(state, "answer", answer.content)
    assert operations.state_read(state, "answer") == answer.content
    store = InMemoryStore()
    operations.store_write(store, ("tour",), "answer", {"text": answer.content})
    assert operations.store_read(store, ("tour",), "answer").value == {
        "text": answer.content
    }

    # Use the actual LangGraph checkpointer serializer and restore a detached value.
    saver = InMemorySaver()
    checkpoint = empty_checkpoint()
    checkpoint["channel_values"] = {"answer": answer.content}
    checkpoint["channel_versions"] = {"answer": 1}
    saved = operations.checkpoint_save(
        saver,
        {"configurable": {"thread_id": "event-tour", "checkpoint_ns": ""}},
        checkpoint,
        {"source": "input", "step": 0, "parents": {}},
        {"answer": 1},
    )
    checkpoint["channel_values"]["answer"] = "changed after saving"
    restored = operations.checkpoint_restore(saver, saved)
    assert restored.checkpoint["channel_values"]["answer"] == answer.content

    # Execute two compiled child graphs and actually reduce their outputs.
    child = child_graph()
    branches = [
        operations.child(child, {"text": text, "size": 0})
        for text in (context, answer.content)
    ]
    merged = operations.merge(
        branches, lambda results: sum(branch["size"] for branch in results)
    )
    assert merged == len(context) + len(answer.content)

    # Send bytes to a real receiver bound only to loopback and verify its reply.
    body = json.dumps({"answer": answer.content, "merged_size": merged}).encode()
    assert operations.send(body, sender) == b"received"
    return answer.content


def coverage(counts):
    print("\nCoverage (actual emitted events):")
    for event in BuiltinEvent:
        print(
            f"  {'SEEN' if counts[event] else 'MISSING':7} {event.value:28} {counts[event]}"
        )
    total = sum(bool(counts[event]) for event in BuiltinEvent)
    print(f"{total}/{len(BuiltinEvent)} event types observed")
    return total == len(BuiltinEvent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8081/v1")
    parser.add_argument("--model", default="qwen3:8b")
    args = parser.parse_args()
    model = ChatOpenAI(
        model=args.model,
        base_url=args.base_url,
        api_key="local",
        temperature=0,
        max_tokens=80,
        timeout=120,
        max_retries=0,
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )
    counts = Counter()

    def record(event, payload):
        counts[event] += 1
        print(f"{sum(counts.values()):02} {event.value}", flush=True)

    completed = False
    try:
        with (
            Analysis() as analysis,
            TemporaryDirectory() as directory,
            local_receiver() as (sender, received),
        ):
            for event in BuiltinEvent:
                analysis.on(event, partial(record, event))
            operations = ObservedOperations(analysis)
            answer = operations.run(
                "Callbacks",
                partial(
                    tour,
                    operations=operations,
                    analysis=analysis,
                    model=model,
                    directory=Path(directory),
                    sender=sender,
                ),
                lambda text: print(f"\nPublished answer: {text}", flush=True),
            )
            assert len(received) == 1 and json.loads(received[0])["answer"] == answer
            completed = True
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as error:  # noqa: BLE001 — report coverage, then exit nonzero.
        print(f"\nTour failed ({type(error).__name__}): {error}")
        print("For local model setup, see workspace/12b_all_analysis_events/README.md.")
    all_seen = coverage(counts)
    if not completed or not all_seen:
        raise SystemExit(1)
    print("All operation effects verified.")


if __name__ == "__main__":
    main()
