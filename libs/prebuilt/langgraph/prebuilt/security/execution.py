"""Platform-neutral execution bridge for activated host confinement."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.enforcement import ActivationReceipt
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
)


class HostExecutionDenied(PermissionError):
    """Raised before tool code runs when host enforcement cannot be established."""


@dataclass(frozen=True, slots=True)
class HostExecutionResult:
    """A tool value paired with verified worker-activation evidence."""

    value: Any
    receipt: ActivationReceipt


class HostExecutionError(RuntimeError):
    """Tool failure after host activation, with evidence and outcome state."""

    def __init__(
        self,
        reason: str,
        receipt: ActivationReceipt,
        outcome: ExecutionOutcome,
    ) -> None:
        super().__init__(reason)
        self.receipt = receipt
        self.outcome = outcome


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
    ) -> HostExecutionResult:
        """Activate confinement and execute one synchronous tool call."""
        ...

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Activate confinement and execute one asynchronous tool call."""
        ...
