"""Explicit plain-callback instrumentation around application operations.

These adapters execute the supplied operation. They do not supply authorization,
provenance, persistence beyond the selected backend, or automatic global hooks.
"""

from collections.abc import Callable, MutableMapping, Sequence
from pathlib import Path
from typing import Any, TypeVar

from langgraph.prebuilt.analysis.events import BuiltinEvent as Event
from langgraph.prebuilt.analysis.local import Analysis

T = TypeVar("T")


class ObservedOperations:
    """Connect ordinary synchronous operations to an Analysis dispatcher.

    Payloads and callback results have no required analysis schema. Observers
    receive detached payloads, and their failures are logged. Callback results
    are ignored; operation results and exceptions are preserved. Before
    events mark attempted operations, not successful completion. Paired after
    events run only when the operation returns successfully.
    """

    def __init__(self, analysis: Analysis) -> None:
        self.analysis = analysis

    def run(self, value: Any, workflow: Callable, publish: Callable) -> Any:
        """Admit input, run a workflow, then publish its output."""
        self.analysis._notify(Event.INPUT_ADMIT, value)
        result = workflow(value)
        self.analysis._notify(Event.OUTPUT_EMIT, result)
        publish(result)
        return result

    def model(self, model: Any, messages: Any, *, config=None) -> Any:
        """Observe a real model's invoke method."""
        self.analysis._notify(Event.MODEL_REQUEST, messages)
        result = model.invoke(messages, config=config)
        self.analysis._notify(Event.MODEL_RESPONSE, result)
        return result

    def retrieve(self, retriever: Any, query: Any, *, config=None) -> Any:
        """Observe a retriever's invoke method, returning its original results."""
        self.analysis._notify(Event.RETRIEVAL_REQUEST, query)
        result = retriever.invoke(query, config=config)
        self.analysis._notify(Event.RETRIEVAL_RESULT, result)
        return result

    def transform(self, value: Any, operation: Callable[..., T]) -> T:
        self.analysis._notify(Event.CONTEXT_BEFORE, value)
        result = operation(value)
        self.analysis._notify(Event.CONTEXT_AFTER, result)
        return result

    def read_text(self, path: str | Path) -> str:
        """Read a UTF-8 resource; no resource grant is created by this observer."""
        self.analysis._notify(Event.RESOURCE_READ, Path(path))
        return Path(path).read_text(encoding="utf-8")

    def write_text(self, path: str | Path, text: str) -> int:
        self.analysis._notify(Event.RESOURCE_WRITE, {"path": Path(path), "text": text})
        return Path(path).write_text(text, encoding="utf-8")

    def send(self, value: Any, sender: Callable[..., T]) -> T:
        """Observe a caller-supplied transport; the caller owns its destination."""
        self.analysis._notify(Event.RESOURCE_SEND, value)
        return sender(value)

    def state_read(self, state: MutableMapping, key: str) -> Any:
        self.analysis._notify(Event.STATE_READ, key)
        return state[key]

    def state_write(self, state: MutableMapping, key: str, value: Any) -> None:
        self.analysis._notify(Event.STATE_WRITE, {"key": key, "value": value})
        state[key] = value

    def store_read(self, store: Any, namespace: tuple[str, ...], key: str) -> Any:
        self.analysis._notify(Event.STORE_READ, {"namespace": namespace, "key": key})
        return store.get(namespace, key)

    def store_write(
        self, store: Any, namespace: tuple[str, ...], key: str, value: dict
    ) -> None:
        self.analysis._notify(
            Event.STORE_WRITE, {"namespace": namespace, "key": key, "value": value}
        )
        store.put(namespace, key, value)

    def checkpoint_save(
        self, saver: Any, config: Any, checkpoint: Any, metadata: Any, new_versions: Any
    ) -> Any:
        self.analysis._notify(Event.CHECKPOINT_SAVE, checkpoint)
        return saver.put(config, checkpoint, metadata, new_versions)

    def checkpoint_restore(self, saver: Any, config: Any) -> Any:
        self.analysis._notify(Event.CHECKPOINT_RESTORE, config)
        return saver.get_tuple(config)

    def child(self, graph: Any, value: Any, *, config=None) -> Any:
        self.analysis._notify(Event.CHILD_START, value)
        result = graph.invoke(value, config=config)
        self.analysis._notify(Event.CHILD_RETURN, result)
        return result

    def merge(self, branches: Sequence, reducer: Callable[..., T]) -> T:
        """Execute the reducer over completed branches, then report its output."""
        result = reducer(branches)
        self.analysis._notify(Event.BRANCH_MERGE, result)
        return result
