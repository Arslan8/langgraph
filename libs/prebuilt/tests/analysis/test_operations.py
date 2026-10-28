"""Plain adapters execute operations and do not require standardized results."""

from functools import partial
from socket import socketpair

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.runnables import RunnableLambda
from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.store.memory import InMemoryStore
from typing_extensions import TypedDict

from langgraph.prebuilt.analysis import Analysis, BuiltinEvent, local
from langgraph.prebuilt.analysis.adapters.operations import ObservedOperations


class ChildState(TypedDict):
    value: int


def test_adapters_execute_operations_and_cover_non_tool_events(tmp_path):
    seen, publications = [], []
    graph = StateGraph(ChildState)
    graph.add_node("double", lambda state: {"value": state["value"] * 2})
    graph.add_edge(START, "double")
    graph.add_edge("double", END)
    child = graph.compile()

    with Analysis() as analysis:

        def callback(event, payload):
            seen.append(event)
            return (
                object()
            )  # Arbitrary callback returns never replace operation output.

        for event in BuiltinEvent:
            analysis.on(event, partial(callback, event))
        operations = ObservedOperations(analysis)

        def workflow(value):
            path = tmp_path / "notes.txt"
            assert operations.write_text(path, value) == len(value)
            assert operations.read_text(path) == value
            selected = operations.retrieve(RunnableLambda(lambda query: [query]), value)
            prompt = operations.transform(selected, lambda rows: " ".join(rows))
            # Provider double only in this unit test; demo 12b uses live llama.cpp.
            result = operations.model(FakeListChatModel(responses=["answer"]), prompt)
            assert result.content == "answer"
            state = {}
            operations.state_write(state, "text", result.content)
            assert operations.state_read(state, "text") == "answer"
            store = InMemoryStore()
            operations.store_write(store, ("test",), "text", state)
            assert operations.store_read(store, ("test",), "text").value == state
            saver = InMemorySaver()
            checkpoint = empty_checkpoint()
            checkpoint["channel_values"] = {"text": "answer"}
            checkpoint["channel_versions"] = {"text": 1}
            config = operations.checkpoint_save(
                saver,
                {"configurable": {"thread_id": "test", "checkpoint_ns": ""}},
                checkpoint,
                {"source": "input", "step": 0, "parents": {}},
                {"text": 1},
            )
            checkpoint["channel_values"]["text"] = "mutated"
            restored = operations.checkpoint_restore(saver, config)
            assert restored.checkpoint["channel_values"]["text"] == "answer"
            branches = [operations.child(child, {"value": i}) for i in (2, 3)]
            total = operations.merge(
                branches, lambda rows: sum(row["value"] for row in rows)
            )
            assert total == 10
            left, right = socketpair()
            with left, right:
                operations.send(b"answer", left.sendall)
                assert right.recv(6) == b"answer"
            return result.content

        assert operations.run("notes", workflow, publications.append) == "answer"
        assert publications == ["answer"]
        tools = {
            BuiltinEvent.TOOL_PROPOSE,
            BuiltinEvent.TOOL_PREPARE,
            BuiltinEvent.TOOL_DISPATCH,
            BuiltinEvent.TOOL_RESULT,
            BuiltinEvent.TOOL_ERROR,
        }
        assert set(seen) == set(BuiltinEvent) - tools
        assert seen[0] == BuiltinEvent.INPUT_ADMIT
        assert seen[-1] == BuiltinEvent.OUTPUT_EMIT


def test_observer_failure_cannot_prevent_an_operation(tmp_path, caplog):
    path = tmp_path / "never-written.txt"

    def fail(payload):
        raise ValueError("listener stopped operation")

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.RESOURCE_WRITE, fail)
        operations = ObservedOperations(analysis)
        operations.write_text(path, "operation proceeds")
        assert path.read_text() == "operation proceeds"
        assert "ValueError" in caplog.text


@pytest.mark.parametrize(
    "method, before, after",
    [
        ("model", BuiltinEvent.MODEL_REQUEST, BuiltinEvent.MODEL_RESPONSE),
        ("retrieve", BuiltinEvent.RETRIEVAL_REQUEST, BuiltinEvent.RETRIEVAL_RESULT),
        ("child", BuiltinEvent.CHILD_START, BuiltinEvent.CHILD_RETURN),
    ],
)
def test_failed_invocation_does_not_emit_success(method, before, after):
    seen = []

    def fail(value):
        raise ValueError("operation failed")

    with Analysis() as analysis:
        analysis.on(before, lambda payload: seen.append(before))
        analysis.on(after, lambda payload: seen.append(after))
        operations = ObservedOperations(analysis)
        with pytest.raises(ValueError, match="operation failed"):
            getattr(operations, method)(RunnableLambda(fail), "input")
        assert seen == [before]


def test_transform_merge_and_publication_order():
    order = []
    with Analysis() as analysis:
        for event in (
            BuiltinEvent.INPUT_ADMIT,
            BuiltinEvent.CONTEXT_BEFORE,
            BuiltinEvent.CONTEXT_AFTER,
            BuiltinEvent.BRANCH_MERGE,
            BuiltinEvent.OUTPUT_EMIT,
        ):
            analysis.on(event, lambda payload, event=event: order.append(event.value))
        operations = ObservedOperations(analysis)

        def transform(value):
            order.append("transform executes")
            return value.upper()

        def reducer(values):
            order.append("merge executes")
            return ", ".join(values)

        def workflow(value):
            transformed = operations.transform(value, transform)
            return operations.merge([transformed, value], reducer)

        assert (
            operations.run(
                "text", workflow, lambda value: order.append("publish executes")
            )
            == "TEXT, text"
        )
        assert order == [
            "input.admit",
            "context.transform.before",
            "transform executes",
            "context.transform.after",
            "merge executes",
            "dispatch.branch.merge",
            "output.emit",
            "publish executes",
        ]


def test_copy_or_logging_failures_do_not_stop_operations(monkeypatch):
    class Uncopyable:
        def __deepcopy__(self, memo):
            raise ValueError("cannot copy")

    def broken_log(*args, **kwargs):
        raise RuntimeError("logging handler failed")

    monkeypatch.setattr(local.logger, "warning", broken_log)
    value = Uncopyable()
    with Analysis() as analysis:
        analysis.on(BuiltinEvent.RESOURCE_SEND, lambda payload: None)
        operations = ObservedOperations(analysis)
        assert operations.send(value, lambda payload: payload) is value
