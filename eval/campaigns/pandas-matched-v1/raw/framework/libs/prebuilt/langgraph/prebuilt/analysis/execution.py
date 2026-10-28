"""Callback execution shared by plain listeners and structured consumers."""

import asyncio
import inspect
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any


class CallbackExecutor:
    """Execute trusted callbacks without interpreting their return values."""

    def __init__(self) -> None:
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="analysis")

    def call(
        self, callback: Callable[..., Any], *args: Any, timeout: float | None = None
    ) -> Any:
        if inspect.iscoroutinefunction(callback):
            raise TypeError("analysis:async_callback_requires_aemit")
        future = self._pool.submit(callback, *args)
        try:
            result = future.result(timeout=timeout)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("analysis:async_callback_requires_aemit")
            return result
        finally:
            future.cancel()

    async def acall(
        self, callback: Callable[..., Any], *args: Any, timeout: float | None = None
    ) -> Any:
        async def invoke():
            if inspect.iscoroutinefunction(callback):
                return await callback(*args)
            future = self._pool.submit(callback, *args)
            try:
                result = await asyncio.wrap_future(future)
                return await result if inspect.isawaitable(result) else result
            finally:
                future.cancel()

        return await asyncio.wait_for(invoke(), timeout)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
