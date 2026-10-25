"""Shared contract and broker client. Importing this creates no backend state."""

from abc import ABC, abstractmethod

from langgraph.prebuilt.security.mediators.contracts import (
    ResourceContract,
    ResourceMediator,
)


class CounterAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def increment(self, amount: int) -> int:
        """Add to a counter and return its new value."""
        raise NotImplementedError


def counter_resource(
    *,
    implementation: CounterAPI | None = None,
    mediator: ResourceMediator | None = None,
) -> ResourceContract[CounterAPI]:
    # One declaration supports both a shared definition and parent-side binding.
    return ResourceContract(
        CounterAPI,
        class_name="counter",
        object_kind="counter",
        lowering="counter.local.v1",
        implementation=implementation,
        mediator=mediator,
    )


COUNTER = counter_resource()
counter = COUNTER.client(export=__name__ + ".counter")
