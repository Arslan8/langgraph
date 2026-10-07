"""Platform-neutral execution bridge for activated host confinement."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.types import PolicyConstraint, Principal, ToolCall


class HostExecutionDenied(PermissionError):
    """Raised before tool code runs when host enforcement cannot be established."""


@runtime_checkable
class HostToolExecutor(Protocol):
    """Execute mediated calls only after platform enforcement is activated."""

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Reject missing or dynamically unresolved tool execution manifests."""
        ...

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> Any:
        """Activate confinement and execute one synchronous tool call."""
        ...

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> Any:
        """Activate confinement and execute one asynchronous tool call."""
        ...
