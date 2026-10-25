"""Parent-only implementation, optional custom validation, and host assessment."""

from collections.abc import Mapping
from threading import Lock
from typing import Any

from langgraph.prebuilt.security import (
    ResourceInvocation,
    ResourceSupport,
    SupportLevel,
)

from .api import CounterAPI


class CounterBackend(CounterAPI):
    """Perform the operation; the worker never receives this object."""

    def __init__(self) -> None:
        self.value = 0
        self._lock = Lock()

    def increment(self, amount: int) -> int:
        with self._lock:
            self.value += amount
            return self.value


class CounterMediator:
    """Own lowering support and validate requests before backend effects."""

    def validate(
        self, operation: str, arguments: Mapping[str, Any], context: ResourceInvocation
    ) -> None:
        if not 1 <= arguments["amount"] <= 3:
            raise ValueError("amount must be 1, 2, or 3")

    def assess(self, line, host):
        # The framework already matched this exact resource object and operation.
        # Report the host protection this parent-owned implementation requires.
        return ResourceSupport(
            SupportLevel.EXACT,
            "typed operations on the parent-owned counter",
            witness="tests/security/test_workspace_sandbox_demos.py",
            required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
        )
