"""Event callbacks with developer-owned payloads and results."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Set
from copy import deepcopy
from math import isfinite
from typing import TYPE_CHECKING, Any, Self

from langchain_core.messages import ToolMessage

if TYPE_CHECKING:
    from langgraph.types import Command

    from langgraph.prebuilt.tool_node import ToolCallRequest

from langgraph.prebuilt.analysis.errors import ConfigurationError
from langgraph.prebuilt.analysis.events import BuiltinEvent, EventSpec
from langgraph.prebuilt.analysis.execution import CallbackExecutor

logger = logging.getLogger(__name__)


class Analysis:
    """Dispatch explicit events without imposing payload or result schemas.

    Callbacks receive the emitted payload unchanged. Their return values,
    including `None`, are returned unchanged in subscription order. Nothing is
    persisted or converted to findings. Observer failures are logged and do not
    stop delivery or confer enforcement authority.
    Use `StructuredAnalysis` to opt into standardized findings and provenance.
    """

    def __init__(self) -> None:
        self._callbacks: dict[
            BuiltinEvent | EventSpec, list[tuple[Callable[..., Any], float | None]]
        ] = {}
        self._executor = CallbackExecutor()
        self._closed = False

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("analysis:session_closed")

    @staticmethod
    def _check_event(event: BuiltinEvent | EventSpec) -> None:
        if not isinstance(event, (BuiltinEvent, EventSpec)):
            raise ConfigurationError("analysis:use_builtin_event_or_event_spec")

    def on(
        self,
        events: BuiltinEvent | EventSpec | Set[BuiltinEvent | EventSpec],
        callback: Callable[..., Any],
        *,
        timeout: float | None = None,
    ) -> None:
        """Subscribe a callback to one event or a set; optional timeout in seconds."""
        self._check_open()
        selected = frozenset(events) if isinstance(events, Set) else (events,)
        if not selected or not callable(callback):
            raise ConfigurationError("analysis:invalid_subscription")
        if timeout is not None and (not isfinite(timeout) or timeout <= 0):
            raise ConfigurationError("analysis:invalid_timeout")
        for event in selected:
            self._check_event(event)
        for event in selected:
            self._callbacks.setdefault(event, []).append((callback, timeout))

    @staticmethod
    def _log_failure(event, error):
        name = event.value if isinstance(event, BuiltinEvent) else event.name
        try:
            logger.warning(
                "Analysis observer failed: %s (%s)", name, type(error).__name__
            )
        except Exception:
            pass  # A broken logging handler is not an execution gate either.

    def _deliver(self, event, payload, *, detached=False):
        self._check_open()
        self._check_event(event)
        results = []
        for callback, timeout in tuple(self._callbacks.get(event, ())):
            try:
                value = deepcopy(payload) if detached else payload
                result = self._executor.call(callback, value, timeout=timeout)
            except Exception as error:
                self._log_failure(event, error)
                result = None
            results.append(result)
        return tuple(results)

    async def _adeliver(self, event, payload, *, detached=False):
        self._check_open()
        self._check_event(event)
        results = []
        for callback, timeout in tuple(self._callbacks.get(event, ())):
            try:
                value = deepcopy(payload) if detached else payload
                result = await self._executor.acall(callback, value, timeout=timeout)
            except asyncio.CancelledError as error:
                task = asyncio.current_task()
                if task is not None and getattr(task, "cancelling", lambda: True)():
                    raise  # Preserve cancellation requested by the caller.
                self._log_failure(event, error)
                result = None
            except Exception as error:
                self._log_failure(event, error)
                result = None
            results.append(result)
        return tuple(results)

    def emit(
        self, event: BuiltinEvent | EventSpec, payload: Any = None
    ) -> tuple[Any, ...]:
        """Deliver data; log observer failures and continue with later callbacks.

        Successful outputs retain their original format. Failed callbacks occupy
        a None slot; this tuple is not an authorization decision or clean finding.
        """
        return self._deliver(event, payload)

    async def aemit(
        self, event: BuiltinEvent | EventSpec, payload: Any = None
    ) -> tuple[Any, ...]:
        """Deliver to sync/async observers; preserve caller-requested cancellation."""
        return await self._adeliver(event, payload)

    def _notify(self, event, payload=None):
        """Framework observation: detached inputs, no result or denial channel."""
        try:
            self._deliver(event, payload, detached=True)
        except Exception as error:
            self._log_failure(event, error)

    async def _anotify(self, event, payload=None):
        try:
            await self._adeliver(event, payload, detached=True)
        except Exception as error:
            self._log_failure(event, error)

    def wrap_tool_call(
        self,
        request: "ToolCallRequest",
        execute: Callable[["ToolCallRequest"], "ToolMessage | Command"],
    ) -> "ToolMessage | Command":
        """ToolNode hook: emit proposal and completion around actual execution.

        Proposals carry a detached tool-call mapping. Completion payloads are
        detached copies of tool results or errors. Observer failures are logged.
        Callback return values do not replace the tool's result.
        """
        self._notify(BuiltinEvent.TOOL_PROPOSE, request.tool_call)
        try:
            result = execute(request)
        except Exception as error:
            self._notify(BuiltinEvent.TOOL_ERROR, error)
            raise
        event = (
            BuiltinEvent.TOOL_ERROR
            if isinstance(result, ToolMessage) and result.status == "error"
            else BuiltinEvent.TOOL_RESULT
        )
        self._notify(event, result)
        return result

    async def awrap_tool_call(
        self,
        request: "ToolCallRequest",
        execute: Callable[["ToolCallRequest"], Awaitable["ToolMessage | Command"]],
    ) -> "ToolMessage | Command":
        """Async ToolNode hook with the same payload and failure semantics."""
        await self._anotify(BuiltinEvent.TOOL_PROPOSE, request.tool_call)
        try:
            result = await execute(request)
        except Exception as error:
            await self._anotify(BuiltinEvent.TOOL_ERROR, error)
            raise
        event = (
            BuiltinEvent.TOOL_ERROR
            if isinstance(result, ToolMessage) and result.status == "error"
            else BuiltinEvent.TOOL_RESULT
        )
        await self._anotify(event, result)
        return result

    def close(self) -> None:
        """Release the executor; running synchronous callbacks cannot be killed."""
        if not self._closed:
            self._closed = True
            self._executor.close()
            self._callbacks.clear()

    def __enter__(self) -> Self:
        self._check_open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
