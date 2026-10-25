"""Trusted external interpreter contract; deliberately not a Python interpreter."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Protocol

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.errors import ConfigurationError
from langgraph.prebuilt.analysis.provenance.records import DependencyEdge, ValueRecord
from langgraph.prebuilt.analysis.serialization import canonical


class InterpreterAdapter(Protocol):
    adapter_id: str
    version: str
    operations: frozenset[str]

    def register(self, content: object) -> ValueRef: ...
    def derive(
        self,
        operation: str,
        content: object,
        inputs: tuple[ValueRef, ...],
        selectors: tuple[ValueRef, ...] = (),
    ) -> ValueRef: ...
    def guarded_call(self, principal, call) -> object: ...


@dataclass(frozen=True, slots=True)
class InterpreterBinding:
    adapter_id: str
    version: str
    operations: frozenset[str]

    def __post_init__(self):
        object.__setattr__(self, "operations", frozenset(self.operations))
        if not self.adapter_id or not self.version or not self.operations:
            raise ConfigurationError("analysis:invalid_interpreter_binding")


class InterpreterBoundary(BoundaryAdapter):
    """Task-isolated control scopes, precise declared operations, conservative fallback."""

    def __init__(self, runtime, binding: InterpreterBinding, guarded_dispatch):
        super().__init__(runtime)
        self.binding = binding
        self._dispatch = guarded_dispatch
        self._control = ContextVar(f"analysis-control-{id(self)}", default=())

    def register(self, content):
        return self.value(content)

    @contextmanager
    def control(self, condition: ValueRef) -> Iterator[None]:
        self.runtime.store.get(condition)
        token = self._control.set((*self._control.get(), condition))
        try:
            yield
        finally:
            self._control.reset(token)

    def derive(
        self,
        operation: str,
        content,
        inputs: tuple[ValueRef, ...],
        selectors: tuple[ValueRef, ...] = (),
    ) -> ValueRef:
        # Unknown operations must still supply all actual inputs; no precision claim.
        effective = operation if operation in self.binding.operations else "opaque"
        output = ValueRecord(
            self.runtime.tenant_id,
            self.runtime.session_id,
            self.runtime.run_id,
            canonical(content).encode(),
        )
        controls = tuple(
            DependencyEdge(parent=ref, kind="control") for ref in self._control.get()
        )
        return self.runtime.store.derive(
            (*inputs, *selectors), output, effective, edges=controls
        )

    def guarded_call(self, principal, call):
        # The injected dispatcher must be the existing guarded dispatch/HostRouter.
        return self._dispatch(principal, call, self._control.get())
