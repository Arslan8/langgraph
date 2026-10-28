"""Non-file typed resource fixture: a parent-owned invocation counter."""

from abc import ABC, abstractmethod

from langgraph.prebuilt.security import ResourceSupport, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract


class CounterAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def increment(self, amount: int) -> int:
        raise NotImplementedError


class Counter(CounterAPI):
    def __init__(self):
        self.value = 0

    def increment(self, amount: int) -> int:
        self.value += amount
        return self.value


def assessment(line, host):
    return ResourceSupport(SupportLevel.EXACT, "parent-owned typed counter", witness=__file__)


CONTRACT = ResourceContract(
    CounterAPI, class_name="counter", object_kind="counter", lowering="counter.local.v1"
)
counter = CONTRACT.client(export=__name__ + ".counter")
