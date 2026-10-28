"""Observer delivery must not alter computation streams or reuse authority."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from langchain_core.callbacks import BaseCallbackHandler

from langgraph.pregel._callback_guard import guard_callback_manager

pytestmark = pytest.mark.anyio


class Observer(BaseCallbackHandler):
    def __init__(self):
        self.seen = []

    def on_chain_end(self, value, **kwargs):
        self.seen.append(value)


class Tap(Observer):
    def tap_output_iter(self, run_id, output):
        for value in output:
            self.seen.append(value)
            yield value

    async def tap_output_aiter(self, run_id, output):
        async for value in output:
            self.seen.append(value)
            yield value


def manager_for(handler, config, sync, asynchronous=False, async_filter=None):
    async def wrapped(value, config):
        return sync(value, config)

    manager = SimpleNamespace(handlers=[handler], inheritable_handlers=[handler])
    guard_callback_manager(
        manager, config, sync, async_filter or wrapped, asynchronous=asynchronous
    )
    return manager


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_tap_receives_effective_values_but_computation_receives_originals(
    asynchronous,
):
    target = Tap()
    manager = manager_for(target, {}, lambda value, config: "[redacted]", asynchronous)
    handler = manager.handlers[0]
    first, second = {"secret": "a"}, {"secret": "b"}

    async def inputs():
        yield first
        yield second

    output = (
        [x async for x in handler.tap_output_aiter(uuid4(), inputs())]
        if asynchronous
        else list(handler.tap_output_iter(uuid4(), iter([first, second])))
    )
    assert output[0] is first and output[1] is second
    assert target.seen == ["[redacted]", "[redacted]"]
    assert manager.inheritable_handlers[0] is handler


def test_ordinary_observer_does_not_become_a_stream_tap():
    handler = manager_for(Observer(), {}, lambda value, config: value).handlers[0]
    assert not hasattr(handler, "tap_output_aiter")
    assert not hasattr(handler, "tap_output_iter")


def test_reused_handler_is_rebound_to_new_config_authority():
    observed = []

    def authorize(value, config):
        observed.append(config["principal"])
        return value

    manager = manager_for(Observer(), {"principal": "first"}, authorize)
    old = manager.handlers[0]

    guard_callback_manager(
        manager, {"principal": "second"}, authorize, old._afilter, asynchronous=False
    )
    manager.handlers[0].on_chain_end("public", run_id=uuid4())
    assert observed == ["second"]
    assert manager.handlers[0] is not old


async def test_cancellation_does_not_deliver_even_if_policy_swallows_it():
    started = asyncio.Event()
    target = Observer()

    async def authorize(value, config):
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return value

    handler = manager_for(
        target, {}, lambda value, config: value, True, authorize
    ).handlers[0]
    pending = asyncio.create_task(handler.on_chain_end("private", run_id=uuid4()))
    await asyncio.wait_for(started.wait(), 1)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert target.seen == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_taps_that_change_values_are_rejected(asynchronous):
    class Changing(Tap):
        def tap_output_iter(self, run_id, output):
            for _ in output:
                yield {"substitution": True}

        async def tap_output_aiter(self, run_id, output):
            async for _ in output:
                yield {"substitution": True}

    handler = manager_for(
        Changing(), {}, lambda value, config: value, asynchronous
    ).handlers[0]

    async def inputs():
        yield {"value": "public"}

    with pytest.raises(PermissionError, match="tap_changed_output"):
        if asynchronous:
            _ = [x async for x in handler.tap_output_aiter(uuid4(), inputs())]
        else:
            list(handler.tap_output_iter(uuid4(), iter([{"value": "public"}])))


@pytest.mark.parametrize("in_place", [False, True])
def test_effective_record_cannot_retarget_the_observer(in_place):
    target = Observer()

    def retarget(value, config):
        if in_place:
            value["observer"]["token"] = "different"
            return value
        return {**value, "observer": {"token": "different", "type": "other"}}

    handler = manager_for(target, {}, retarget).handlers[0]
    with pytest.raises(PermissionError, match="observer_transformation_unsupported"):
        handler.on_chain_end("public", run_id=uuid4())
    assert target.seen == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_tap_observer_cannot_be_retargeted(asynchronous):
    target = Tap()
    handler = manager_for(
        target, {}, lambda value, config: {**value, "observer": {}}, asynchronous
    ).handlers[0]

    async def inputs():
        yield "private"

    with pytest.raises(PermissionError, match="observer_transformation_unsupported"):
        if asynchronous:
            _ = [value async for value in handler.tap_output_aiter(uuid4(), inputs())]
        else:
            list(handler.tap_output_iter(uuid4(), iter(["private"])))
    assert target.seen == []
