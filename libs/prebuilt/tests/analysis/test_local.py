"""Plain callbacks own their payloads, results and side effects."""

import asyncio
from threading import Event

import pytest

from langgraph.prebuilt.analysis import Analysis, BuiltinEvent, EventSpec
from langgraph.prebuilt.analysis.errors import ConfigurationError


def test_callbacks_receive_original_payload_and_preserve_arbitrary_results():
    payload, result = object(), object()
    seen = []
    with Analysis() as analysis:
        analysis.on(BuiltinEvent.INPUT_ADMIT, seen.append)
        analysis.on(BuiltinEvent.INPUT_ADMIT, lambda value: result)
        assert analysis.emit(BuiltinEvent.INPUT_ADMIT, payload) == (None, result)
        assert seen == [payload]
        assert analysis.emit(BuiltinEvent.MODEL_REQUEST, payload) == ()


def test_event_sets_custom_events_and_isolated_subscriptions():
    custom = EventSpec("example.document", "before", "application", True)
    events = {BuiltinEvent.INPUT_ADMIT, custom}
    seen = []
    with Analysis() as first, Analysis() as second:
        first.on(events, seen.append)
        events.clear()
        first.emit(custom, "custom")
        first.emit(BuiltinEvent.INPUT_ADMIT, "builtin")
        second.emit(custom, "other session")
        assert seen == ["custom", "builtin"]


@pytest.mark.parametrize("events", ["input.admit", {"input.admit"}, set()])
def test_invalid_subscriptions(events):
    with Analysis() as analysis:
        with pytest.raises(ConfigurationError):
            analysis.on(events, lambda payload: None)
        with pytest.raises(ConfigurationError):
            analysis.emit("input.admit")


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_timeouts(timeout):
    with Analysis() as analysis:
        with pytest.raises(ConfigurationError, match="invalid_timeout"):
            analysis.on(BuiltinEvent.INPUT_ADMIT, lambda value: None, timeout=timeout)


@pytest.mark.asyncio
async def test_async_emission_accepts_sync_async_and_awaitable_callbacks():
    payload = object()
    seen = []

    async def callback(value):
        await asyncio.sleep(0)
        seen.append(value)
        return {"private_format": value}

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.INPUT_ADMIT, seen.append)
        analysis.on(BuiltinEvent.INPUT_ADMIT, callback)
        analysis.on(BuiltinEvent.INPUT_ADMIT, lambda value: callback(value))
        result = await analysis.aemit(BuiltinEvent.INPUT_ADMIT, payload)
        assert result == (
            None,
            {"private_format": payload},
            {"private_format": payload},
        )
        assert seen == [payload] * 3
        assert analysis.emit(BuiltinEvent.INPUT_ADMIT, payload) == (None, None, None)


@pytest.mark.asyncio
async def test_failures_are_logged_and_delivery_continues(caplog):
    seen = []

    def fail(value):
        raise ValueError("developer error")

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.INPUT_ADMIT, fail)
        analysis.on(BuiltinEvent.INPUT_ADMIT, seen.append)
        assert analysis.emit(BuiltinEvent.INPUT_ADMIT) == (None, None)
        assert await analysis.aemit(BuiltinEvent.INPUT_ADMIT) == (None, None)
        assert seen == [None, None]
        assert "ValueError" in caplog.text


def test_sync_timeout_and_cleanup():
    release = Event()
    try:
        with Analysis() as analysis:
            analysis.on(
                BuiltinEvent.INPUT_ADMIT, lambda _: release.wait(), timeout=0.01
            )
            assert analysis.emit(BuiltinEvent.INPUT_ADMIT) == (None,)
    finally:
        release.set()
    analysis.close()
    with pytest.raises(RuntimeError, match="session_closed"):
        analysis.emit(BuiltinEvent.INPUT_ADMIT)


@pytest.mark.asyncio
async def test_async_cancellation_and_timeout():
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def callback(value):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.INPUT_ADMIT, callback)
        task = asyncio.create_task(analysis.aemit(BuiltinEvent.INPUT_ADMIT))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled.is_set()
    cancelled.clear()
    with Analysis() as analysis:
        analysis.on(BuiltinEvent.INPUT_ADMIT, callback, timeout=0.01)
        assert await analysis.aemit(BuiltinEvent.INPUT_ADMIT) == (None,)
        assert cancelled.is_set()


def test_context_manager_closes_on_exception():
    with pytest.raises(ValueError), Analysis() as analysis:
        raise ValueError("caller failed")
    with pytest.raises(RuntimeError, match="session_closed"):
        analysis.on(BuiltinEvent.INPUT_ADMIT, lambda _: None)
