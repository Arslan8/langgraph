"""Plain callbacks observe real ToolNode executions without manual emission."""

import asyncio

import pytest
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool
from langgraph.runtime import Runtime

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis import Analysis, BuiltinEvent
from langgraph.prebuilt.security import SecurityConfig


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_actual_tool_executes_once_and_result_callback_cannot_replace_it(
    asynchronous,
):
    effects, seen = [], []

    @tool
    def record(message: str) -> str:
        """Record one message."""
        effects.append(message)
        return message

    def on_result(message):
        assert effects == ["hello"]
        seen.append(message)
        return "ignored callback result"

    async def aon_result(message):
        return on_result(message)

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_RESULT, aon_result if asynchronous else on_result)
        node = ToolNode(
            [record],
            wrap_tool_call=analysis.wrap_tool_call,
            awrap_tool_call=analysis.awrap_tool_call,
        )
        calls = [
            {
                "name": "record",
                "args": {"message": "hello"},
                "id": "one",
                "type": "tool_call",
            }
        ]
        result = (
            await node.ainvoke(calls, runtime=Runtime())
            if asynchronous
            else node.invoke(calls, runtime=Runtime())
        )
        assert effects == ["hello"]
        assert len(seen) == 1
        assert seen[0].content == "hello"
        assert result["messages"][0] == seen[0]
        assert result["messages"][0] is not seen[0]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("handled", [False, True])
@pytest.mark.asyncio
async def test_real_tool_errors_are_not_success_events(asynchronous, handled):
    errors, successes = [], []

    @tool
    def fail() -> str:
        """Raise a tool error."""
        raise ValueError("tool failed")

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_RESULT, successes.append)
        analysis.on(BuiltinEvent.TOOL_ERROR, errors.append)
        node = ToolNode(
            [fail],
            handle_tool_errors=handled,
            wrap_tool_call=analysis.wrap_tool_call,
            awrap_tool_call=analysis.awrap_tool_call,
        )
        calls = [{"name": "fail", "args": {}, "id": "one", "type": "tool_call"}]

        async def invoke():
            if asynchronous:
                return await node.ainvoke(calls, runtime=Runtime())
            return node.invoke(calls, runtime=Runtime())

        if handled:
            await invoke()
            assert isinstance(errors[0], ToolMessage)
            assert errors[0].status == "error"
        else:
            with pytest.raises(ValueError, match="tool failed"):
                await invoke()
            assert isinstance(errors[0], ValueError)
        assert not successes
        assert len(errors) == 1


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "case", ["success", "failure", "unknown", "denied", "callback_failure"]
)
@pytest.mark.asyncio
async def test_native_tool_lifecycle(asynchronous, case):
    order = []

    @tool
    def record() -> str:
        """Execute a real tool body."""
        order.append("body")
        if case == "failure":
            raise ValueError("tool failed")
        return "done"

    with Analysis() as analysis:
        for event in (
            BuiltinEvent.TOOL_PROPOSE,
            BuiltinEvent.TOOL_PREPARE,
            BuiltinEvent.TOOL_DISPATCH,
            BuiltinEvent.TOOL_RESULT,
            BuiltinEvent.TOOL_ERROR,
        ):

            def callback(payload, event=event):
                order.append(event.value)
                if case == "callback_failure" and event == BuiltinEvent.TOOL_DISPATCH:
                    raise ValueError("callback failed")

            async def acallback(payload, callback=callback):
                callback(payload)

            analysis.on(event, acallback if asynchronous else callback)
        node = ToolNode(
            [record],
            analysis=analysis,
            handle_tool_errors=True,
            security=SecurityConfig() if case == "denied" else None,
        )
        calls = [
            {
                "name": "missing" if case == "unknown" else "record",
                "args": {},
                "id": "one",
                "type": "tool_call",
            }
        ]
        if asynchronous:
            await node.ainvoke(calls, runtime=Runtime())
        else:
            node.invoke(calls, runtime=Runtime())
        expected = ["tool.propose", "tool.prepare"]
        if case not in ("unknown", "denied"):
            expected.append("tool.dispatch")
            expected.append("body")
        expected.append(
            "tool.result" if case in ("success", "callback_failure") else "tool.error"
        )
        assert order == expected


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_native_tool_lifecycle_tracks_wrapper_retries(asynchronous):
    order = []

    @tool
    def record() -> str:
        """Record actual execution."""
        order.append("body")
        return "done"

    def twice(request, execute):
        execute(request)
        return execute(request)

    async def atwice(request, execute):
        await execute(request)
        return await execute(request)

    with Analysis() as analysis:
        for event in (
            BuiltinEvent.TOOL_PROPOSE,
            BuiltinEvent.TOOL_PREPARE,
            BuiltinEvent.TOOL_DISPATCH,
            BuiltinEvent.TOOL_RESULT,
        ):
            analysis.on(event, lambda payload, event=event: order.append(event.value))
        node = ToolNode(
            [record], analysis=analysis, wrap_tool_call=twice, awrap_tool_call=atwice
        )
        calls = [{"name": "record", "args": {}, "id": "one", "type": "tool_call"}]
        if asynchronous:
            await node.ainvoke(calls, runtime=Runtime())
        else:
            node.invoke(calls, runtime=Runtime())
        assert order == [
            "tool.propose",
            "tool.prepare",
            "tool.dispatch",
            "body",
            "tool.prepare",
            "tool.dispatch",
            "body",
            "tool.result",
        ]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("hook", ["native", "wrapper"])
@pytest.mark.asyncio
async def test_observers_cannot_mutate_execution_or_replace_results(asynchronous, hook):
    effects = []

    @tool
    def record(message: str) -> str:
        """Record a real effect."""
        effects.append(message)
        return message

    def mutate(payload):
        if isinstance(payload, dict):
            payload["name"] = "missing"
            payload["args"] = {"message": "changed"}
        else:
            payload.content = "changed"
            payload.status = "error"
        return False  # Neither a returned decision nor mutation controls execution.

    with Analysis() as analysis:
        analysis.on(
            {
                BuiltinEvent.TOOL_PROPOSE,
                BuiltinEvent.TOOL_DISPATCH,
                BuiltinEvent.TOOL_RESULT,
            },
            mutate,
        )
        kwargs = (
            {"analysis": analysis}
            if hook == "native"
            else {
                "wrap_tool_call": analysis.wrap_tool_call,
                "awrap_tool_call": analysis.awrap_tool_call,
            }
        )
        node = ToolNode([record], handle_tool_errors=False, **kwargs)
        calls = [
            {
                "name": "record",
                "args": {"message": "original"},
                "id": "one",
                "type": "tool_call",
            }
        ]
        result = (
            await node.ainvoke(calls, runtime=Runtime())
            if asynchronous
            else node.invoke(calls, runtime=Runtime())
        )
        assert effects == ["original"]
        assert result["messages"][0].content == "original"
        assert result["messages"][0].status == "success"


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("denied", [False, True])
@pytest.mark.asyncio
async def test_failed_observers_do_not_change_runtime_security_decisions(
    asynchronous, denied, caplog
):
    effects = []

    @tool
    def record() -> str:
        """Record actual execution."""
        effects.append("executed")
        return "done"

    def failed(payload):
        raise ValueError("logger unavailable")

    with Analysis() as analysis:
        analysis.on(set(BuiltinEvent), failed)
        node = ToolNode(
            [record],
            analysis=analysis,
            handle_tool_errors=False,
            security=SecurityConfig() if denied else None,
        )
        calls = [{"name": "record", "args": {}, "id": "one", "type": "tool_call"}]
        result = (
            await node.ainvoke(calls, runtime=Runtime())
            if asynchronous
            else node.invoke(calls, runtime=Runtime())
        )
        assert effects == ([] if denied else ["executed"])
        assert result["messages"][0].status == ("error" if denied else "success")
        assert "Analysis observer failed" in caplog.text


@pytest.mark.asyncio
async def test_self_cancelled_observer_does_not_cancel_tool():
    @tool
    def record() -> str:
        """Execute despite observer self-cancellation."""
        return "done"

    async def cancelled(payload):
        raise asyncio.CancelledError()

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_DISPATCH, cancelled)
        node = ToolNode([record], analysis=analysis)
        result = await node.ainvoke(
            [{"name": "record", "args": {}, "id": "one", "type": "tool_call"}],
            runtime=Runtime(),
        )
        assert result["messages"][0].content == "done"


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_error_observer_does_not_mask_original_tool_exception(asynchronous):
    original = ValueError("original tool failure")

    @tool
    def fail() -> str:
        """Raise the tool's own error."""
        raise original

    def observer(payload):
        raise RuntimeError("observer failure")

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_ERROR, observer)
        node = ToolNode([fail], analysis=analysis, handle_tool_errors=False)
        calls = [{"name": "fail", "args": {}, "id": "one", "type": "tool_call"}]
        with pytest.raises(ValueError) as raised:
            if asynchronous:
                await node.ainvoke(calls, runtime=Runtime())
            else:
                node.invoke(calls, runtime=Runtime())
        assert raised.value is original
