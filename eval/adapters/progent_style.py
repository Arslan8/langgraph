"""Thin slangGraph module around Progent's released policy decision point."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from langgraph.prebuilt.security import Decision, SecurityModule, Verdict


class ProgentStyle(SecurityModule):
    """Expose Progent's released checker through the slangGraph hook interface.

    This wrapper deliberately contains no policy semantics. The injected checker is
    `secagent.check_tool_call` from the pinned Progent checkout.
    """

    name = "progent_style"

    def __init__(self, checker: Callable[[str, Mapping[str, Any]], None]) -> None:
        self._checker = checker

    def tool_call_permission(self, principal: Any, call: Any) -> Decision:
        del principal
        try:
            self._checker(call.tool.name, dict(call.normalized))
        except Exception as exc:
            return Decision(Verdict.DENY, f"progent:{type(exc).__name__}")
        return Decision(Verdict.ALLOW, "progent:allowed")
