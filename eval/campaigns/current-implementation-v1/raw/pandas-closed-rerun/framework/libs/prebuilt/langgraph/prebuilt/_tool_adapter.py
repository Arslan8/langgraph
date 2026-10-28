"""Tool conversion that preserves explicit Runnable security/runtime context."""

from __future__ import annotations

from typing import Any

from langchain_core.runnables import Runnable, RunnableConfig
from langchain_core.tools import BaseTool, StructuredTool


def preserve_tool_config(runnable: Runnable, converted: BaseTool) -> BaseTool:
    """Forward explicit config, including on low-level tool callback entry points."""
    if isinstance(converted, StructuredTool):

        def invoke(config: RunnableConfig, callbacks: Any = None, **kwargs: Any) -> Any:
            return runnable.invoke(kwargs, config={**config, "callbacks": callbacks})

        async def ainvoke(
            config: RunnableConfig, callbacks: Any = None, **kwargs: Any
        ) -> Any:
            return await runnable.ainvoke(
                kwargs, config={**config, "callbacks": callbacks}
            )

        converted.func = invoke
        converted.coroutine = ainvoke
    return converted
