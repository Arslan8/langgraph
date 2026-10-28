"""Publication filters close event producers when consumption stops."""

import asyncio

import pytest
from langchain_core.tracers.log_stream import RunLog

from langgraph.pregel._io import _OutputEnvelope
from langgraph.pregel.main import _filter_stream_events, _filter_stream_logs

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("framed", [False, True])
@pytest.mark.parametrize("stop", ["deny", "close", "cancel"])
@pytest.mark.parametrize("kind", ["event", "log"])
async def test_event_filter_closes_producer(framed, stop, kind):
    closed = asyncio.Event()
    filtering = asyncio.Event()

    async def producer():
        try:
            if kind == "event":
                yield {
                    "event": "on_chain_stream",
                    "name": "source",
                    "run_id": "source-id",
                    "parent_ids": [],
                    "data": {"chunk": "public"},
                }
            else:
                yield RunLog(
                    state={
                        "id": "source-id",
                        "name": "source",
                        "type": "chain",
                        "logs": {},
                        "streamed_output": [],
                        "final_output": "public",
                    }
                )
            await asyncio.Event().wait()
        finally:
            closed.set()

    async def filter_value(value, config):
        filtering.set()
        if stop == "deny":
            raise PermissionError("denied")
        if stop == "cancel":
            await asyncio.Event().wait()
        return value.rebuild(value.content) if framed else value

    stream = (
        _filter_stream_events(producer(), filter_value, {}, framed=framed)
        if kind == "event"
        else _filter_stream_logs(producer(), filter_value, {}, framed=framed, diff=True)
    )
    if stop == "deny":
        with pytest.raises(PermissionError):
            await anext(stream)
    elif stop == "cancel":
        pending = asyncio.create_task(anext(stream))
        await asyncio.wait_for(filtering.wait(), 1)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
    else:
        result = await anext(stream)
        if kind == "event":
            assert result["data"] == {"chunk": "public"}
        else:
            assert result.ops[0]["value"]["final_output"] == "public"
        await stream.aclose()
    assert closed.is_set()


@pytest.mark.parametrize("format", ["legacy-log", "legacy-log-patch"])
def test_published_log_state_does_not_alias_internal_state(format):
    source = {
        "id": "id",
        "name": "name",
        "type": "chain",
        "logs": {},
        "streamed_output": [],
        "final_output": {"value": "public"},
    }
    result = _OutputEnvelope(source, format, (), "").rebuild(source)
    result.ops[0]["value"]["final_output"]["value"] = "changed by consumer"
    assert source["final_output"] == {"value": "public"}
