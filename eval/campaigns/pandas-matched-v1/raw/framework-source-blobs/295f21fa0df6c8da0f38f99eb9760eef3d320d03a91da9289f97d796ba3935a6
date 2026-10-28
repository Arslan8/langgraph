"""Explicit trusted boundary instrumentation; arbitrary Python is not intercepted."""

from collections.abc import Awaitable, Callable
from typing import TypeVar
from uuid import uuid4

from langgraph.prebuilt.analysis.contracts import (
    AnalysisEvent,
    AnalysisSnapshot,
    ValueRef,
)
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable
from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.analysis.runtime import AnalysisRuntime
from langgraph.prebuilt.analysis.serialization import canonical

T = TypeVar("T")


class BoundaryAdapter:
    def __init__(self, runtime: AnalysisRuntime) -> None:
        self.runtime = runtime

    def value(
        self, content, parents: tuple[ValueRef, ...] = (), operation: str = "admit"
    ) -> ValueRef:
        record = ValueRecord(
            self.runtime.tenant_id,
            self.runtime.session_id,
            self.runtime.run_id,
            canonical(content).encode(),
        )
        return self.runtime.store.derive(parents, record, operation)

    def event(
        self,
        name: str,
        refs: tuple[ValueRef, ...],
        *,
        destination: str = "",
        invocation_id: str | None = None,
        attempt_id: str | None = None,
        metadata=None,
    ) -> AnalysisEvent:
        spec = self.runtime.registry.events.get(name)
        if spec is None:
            raise AnalysisUnavailable("analysis:unregistered_boundary")
        return AnalysisEvent(
            event_id=str(uuid4()),
            event_name=name,
            phase=spec.phase,
            tenant_id=self.runtime.tenant_id,
            session_id=self.runtime.session_id,
            run_id=self.runtime.run_id,
            invocation_id=invocation_id or str(uuid4()),
            attempt_id=attempt_id or str(uuid4()),
            input_refs=refs,
            destination=destination,
            metadata=metadata or {},
        )

    def before(
        self, name: str, refs: tuple[ValueRef, ...], **kwargs
    ) -> AnalysisSnapshot:
        snapshot = self.runtime.process(self.event(name, refs, **kwargs))
        if snapshot.unavailable_analyzers or snapshot.status in (
            "pending",
            "unavailable",
        ):
            raise AnalysisUnavailable("analysis:required_unavailable")
        return snapshot

    async def abefore(
        self, name: str, refs: tuple[ValueRef, ...], **kwargs
    ) -> AnalysisSnapshot:
        snapshot = await self.runtime.aprocess(self.event(name, refs, **kwargs))
        if snapshot.unavailable_analyzers or snapshot.status in (
            "pending",
            "unavailable",
        ):
            raise AnalysisUnavailable("analysis:required_unavailable")
        return snapshot

    def call(
        self,
        before: str,
        after: str,
        inputs: tuple[ValueRef, ...],
        operation: Callable[[], T],
        encode: Callable[[T], object],
        *,
        destination: str = "",
    ) -> tuple[T, ValueRef]:
        self.before(before, inputs, destination=destination)
        result = operation()
        ref = self.value(encode(result), inputs, after)
        self.before(after, (ref,), destination=destination)
        return result, ref

    async def acall(
        self,
        before: str,
        after: str,
        inputs: tuple[ValueRef, ...],
        operation: Callable[[], Awaitable[T]],
        encode: Callable[[T], object],
        *,
        destination: str = "",
    ) -> tuple[T, ValueRef]:
        await self.abefore(before, inputs, destination=destination)
        result = await operation()
        ref = self.value(encode(result), inputs, after)
        await self.abefore(after, (ref,), destination=destination)
        return result, ref
