"""Mediate observer callbacks without transforming graph computation values."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextvars import ContextVar
from functools import partial
from typing import Any
from uuid import UUID, uuid4

from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage
from langchain_core.outputs import Generation, LLMResult
from langchain_core.runnables import RunnableConfig

from langgraph.callbacks import GraphInterruptEvent, GraphResumeEvent
from langgraph.types import Interrupt

_active_filter: ContextVar[bool] = ContextVar(
    "callback_publication_filter", default=False
)
_logger = logging.getLogger(__name__)


class _CallbackGuard(BaseCallbackHandler):
    raise_error = True
    run_inline = True

    def __init__(
        self,
        target,
        config,
        output_filter,
        aoutput_filter,
        asynchronous,
        callback_filter,
        acallback_filter,
    ):
        self._target = target
        self._observer = {
            "token": str(uuid4()),
            "type": f"{type(target).__module__}.{type(target).__qualname__}",
        }
        self._config = config
        self._filter = output_filter
        self._afilter = aoutput_filter
        self._asynchronous = asynchronous
        self._callback_filter = callback_filter
        self._acallback_filter = acallback_filter

    @property
    def __class__(self):
        # Stream taps and tracers are identified by their original interfaces.
        return type(self._target)

    def __getattribute__(self, name):
        if name in {"tap_output_iter", "tap_output_aiter"} and not hasattr(
            object.__getattribute__(self, "_target"), name
        ):
            raise AttributeError(name)
        if name.startswith("on_"):
            asynchronous = object.__getattribute__(self, "_asynchronous")
            method = object.__getattribute__(
                self, "_adeliver" if asynchronous else "_deliver"
            )
            return partial(method, name)
        if name.startswith("ignore_"):
            return getattr(object.__getattribute__(self, "_target"), name)
        return object.__getattribute__(self, name)

    def __getattr__(self, name):
        return getattr(self._target, name)

    def _authorize(self, value, delivery=None):
        if _active_filter.get():
            raise PermissionError("callback:recursive_publication")
        token = _active_filter.set(True)
        try:
            if delivery is not None and self._callback_filter is not None:
                return self._callback_filter(value, self._config, delivery)
            return self._filter(value, self._config)
        finally:
            _active_filter.reset(token)

    async def _aauthorize(self, value, delivery=None):
        if _active_filter.get():
            raise PermissionError("callback:recursive_publication")
        token = _active_filter.set(True)

        async def run():
            if delivery is not None and self._acallback_filter is not None:
                return await self._acallback_filter(value, self._config, delivery)
            return await self._afilter(value, self._config)

        pending = asyncio.create_task(run())
        try:
            return await asyncio.shield(pending)
        except asyncio.CancelledError:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            raise
        finally:
            _active_filter.reset(token)

    def _record(self, name, args, kwargs):
        # Error observers receive the payload, never a live traceback or an
        # approval exception's executable continuations and private attributes.
        if name.endswith("_error") and args and isinstance(args[0], BaseException):
            args = (RuntimeError(*args[0].args), *args[1:])
        return {
            "callback": name,
            "observer": dict(self._observer),
            "args": args,
            "kwargs": kwargs,
        }

    @staticmethod
    def _delivery(name, effective, original_kwargs, original_args):
        if (
            isinstance(effective, dict)
            and effective.get("callback") == name
            and isinstance(effective.get("args"), (list, tuple))
            and isinstance(effective.get("kwargs"), dict)
        ):
            return name, effective["args"], effective["kwargs"]
        routing = {
            key: value
            for key, value in original_kwargs.items()
            if key in {"run_id", "parent_run_id"}
            and (type(value) is UUID or value is None)
        }
        routing.setdefault("run_id", uuid4())
        text = effective if isinstance(effective, str) else "[redacted]"
        if name in {"on_interrupt", "on_resume"}:
            original = original_args[0] if original_args else None
            run_id = getattr(original, "run_id", None)
            if type(run_id) is not UUID:
                run_id = None
            status = getattr(original, "status", "pending")
            if status not in {
                "input",
                "pending",
                "done",
                "interrupt_before",
                "interrupt_after",
                "out_of_steps",
            }:
                status = "pending"
            if name == "on_interrupt":
                event = GraphInterruptEvent(
                    run_id,
                    status,
                    "",
                    (),
                    (Interrupt(value=effective, id="security_output"),),
                )
            else:
                event = GraphResumeEvent(run_id, status, "", ())
            return name, (event,), {}
        if name == "on_chain_start":
            return (
                name,
                ({}, effective),
                {**routing, "name": "security_output", "tags": [], "metadata": {}},
            )
        if name in {"on_chain_end", "on_tool_end"}:
            return name, (effective,), routing
        if name.endswith("_error"):
            return name, (RuntimeError(effective),), routing
        if name in {
            "on_llm_start",
            "on_chat_model_start",
            "on_tool_start",
            "on_retriever_start",
        }:
            payload = (
                [text]
                if name == "on_llm_start"
                else [[HumanMessage(content=text)]]
                if name == "on_chat_model_start"
                else text
            )
            return (
                name,
                ({}, payload),
                {**routing, "name": "security_output", "tags": [], "metadata": {}},
            )
        if name == "on_llm_end":
            return name, (LLMResult(generations=[[Generation(text=text)]]),), routing
        if name == "on_retriever_end":
            return (
                name,
                ([Document(page_content=text, metadata={"security_redacted": True})],),
                routing,
            )
        if name in {"on_text", "on_llm_new_token"}:
            return name, (text,), routing
        if name == "on_agent_action":
            return (
                name,
                (AgentAction(tool="security_output", tool_input=text, log=text),),
                routing,
            )
        if name == "on_agent_finish":
            return (
                name,
                (AgentFinish(return_values={"output": effective}, log=text),),
                routing,
            )
        return (
            "on_custom_event",
            ("security_output", effective),
            {"run_id": routing["run_id"], "tags": [], "metadata": {}},
        )

    def _callback_error(self):
        if self._target.raise_error:
            raise
        # Handler failures must not print arbitrary exception payloads.
        _logger.warning("An authorized callback handler failed")

    def _deliver(self, name, /, *args, **kwargs):
        record = self._record(name, args, kwargs)
        dispatch = partial(self._dispatch, name, kwargs, args)
        if self._callback_filter is not None:
            return self._authorize(record, dispatch)
        return dispatch(self._authorize(record))

    def _dispatch(self, name, original_kwargs, original_args, effective):
        if (
            isinstance(effective, dict)
            and effective.get("callback") == name
            and effective.get("observer") != self._observer
        ):
            raise PermissionError("callback:observer_transformation_unsupported")
        method, args, kwargs = self._delivery(
            name, effective, original_kwargs, original_args
        )
        token = _active_filter.set(False)
        try:
            return getattr(self._target, method)(*args, **kwargs)
        except NotImplementedError:
            raise
        except Exception:
            self._callback_error()
        finally:
            _active_filter.reset(token)

    async def _adeliver(self, name, /, *args, **kwargs):
        record = self._record(name, args, kwargs)
        dispatch = partial(self._adispatch, name, kwargs, args)
        if self._acallback_filter is not None:
            return await self._aauthorize(record, dispatch)
        return await dispatch(await self._aauthorize(record))

    async def _adispatch(self, name, original_kwargs, original_args, effective):
        if (
            isinstance(effective, dict)
            and effective.get("callback") == name
            and effective.get("observer") != self._observer
        ):
            raise PermissionError("callback:observer_transformation_unsupported")
        method, args, kwargs = self._delivery(
            name, effective, original_kwargs, original_args
        )
        callback = getattr(self._target, method)
        token = _active_filter.set(False)
        try:
            if inspect.iscoroutinefunction(callback) or self._target.run_inline:
                result = callback(*args, **kwargs)
            else:
                result = await asyncio.to_thread(callback, *args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result
        except NotImplementedError:
            raise
        except Exception:
            self._callback_error()
        finally:
            _active_filter.reset(token)


class _TapCallbackGuard(_CallbackGuard):
    def _tap_value(self, effective):
        if (
            isinstance(effective, dict)
            and effective.get("callback") == "on_chain_stream"
            and effective.get("observer") != self._observer
        ):
            raise PermissionError("callback:observer_transformation_unsupported")
        if (
            isinstance(effective, dict)
            and effective.get("callback") == "on_chain_stream"
            and isinstance(effective.get("args"), (list, tuple))
            and len(effective["args"]) == 1
        ):
            return effective["args"][0]
        return effective

    def tap_output_iter(self, run_id, output: Iterator[Any]) -> Iterator[Any]:
        pending = deque()

        def permitted():
            for raw in output:
                value = self._tap_value(
                    self._authorize(
                        self._record("on_chain_stream", (raw,), {"run_id": run_id})
                    )
                )
                pending.append((raw, value))
                yield value

        permitted_iter = permitted()
        tapped = self._target.tap_output_iter(run_id, permitted_iter)
        try:
            for value in tapped:
                if not pending:
                    raise PermissionError("callback:tap_added_output")
                raw, expected = pending.popleft()
                if value is not expected:
                    raise PermissionError("callback:tap_changed_output")
                yield raw
            if pending:
                raise PermissionError("callback:tap_dropped_output")
        finally:
            for iterator in (tapped, permitted_iter, output):
                close = getattr(iterator, "close", None)
                if close is not None:
                    close()

    async def tap_output_aiter(
        self, run_id, output: AsyncIterator[Any]
    ) -> AsyncIterator[Any]:
        pending = deque()

        async def permitted():
            async for raw in output:
                value = self._tap_value(
                    await self._aauthorize(
                        self._record("on_chain_stream", (raw,), {"run_id": run_id})
                    )
                )
                pending.append((raw, value))
                yield value

        permitted_iter = permitted()
        tapped = self._target.tap_output_aiter(run_id, permitted_iter)
        try:
            async for value in tapped:
                if not pending:
                    raise PermissionError("callback:tap_added_output")
                raw, expected = pending.popleft()
                if value is not expected:
                    raise PermissionError("callback:tap_changed_output")
                yield raw
            if pending:
                raise PermissionError("callback:tap_dropped_output")
        finally:
            for iterator in (tapped, permitted_iter, output):
                close = getattr(iterator, "aclose", None)
                if close is not None:
                    await close()


def guard_callback_manager(
    manager: Any,
    config: RunnableConfig,
    output_filter: Callable[[Any, RunnableConfig], Any],
    aoutput_filter: Callable[[Any, RunnableConfig], Awaitable[Any]],
    *,
    asynchronous: bool,
    callback_filter: Callable[..., Any] | None = None,
    acallback_filter: Callable[..., Awaitable[Any]] | None = None,
) -> None:
    """Wrap each handler once per boundary, preserving inherited membership."""
    cache = {}

    def wrap(handler):
        if (
            type(handler) in {_CallbackGuard, _TapCallbackGuard}
            and handler._filter is output_filter
            and handler._afilter is aoutput_filter
            and handler._callback_filter is callback_filter
            and handler._acallback_filter is acallback_filter
        ):
            if handler._config is config and handler._asynchronous == asynchronous:
                return handler
            handler = handler._target
        key = id(handler)
        if key not in cache:
            guard_type = (
                _TapCallbackGuard
                if hasattr(handler, "tap_output_iter")
                and hasattr(handler, "tap_output_aiter")
                else _CallbackGuard
            )
            cache[key] = guard_type(
                handler,
                config,
                output_filter,
                aoutput_filter,
                asynchronous,
                callback_filter,
                acallback_filter,
            )
        return cache[key]

    manager.handlers = [wrap(handler) for handler in manager.handlers]
    manager.inheritable_handlers = [
        wrap(handler) for handler in manager.inheritable_handlers
    ]
