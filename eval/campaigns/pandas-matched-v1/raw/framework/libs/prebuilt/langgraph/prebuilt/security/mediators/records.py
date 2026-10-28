"""Typed record API shared by database workers, inference, and backends."""

from abc import ABC, abstractmethod
from typing import TypedDict

from langgraph.prebuilt.security.mediators.contracts import ResourceContract


class RecordRead(TypedDict):
    found: bool
    value: str | None


class RecordMutation(TypedDict):
    ok: bool


class RecordsAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def read(self, record: str) -> RecordRead:
        """Read one record."""
        raise NotImplementedError

    @abstractmethod
    def write(self, record: str, value: str) -> RecordMutation:
        """Replace one record's text."""
        raise NotImplementedError

    @abstractmethod
    def delete(self, record: str) -> RecordMutation:
        """Delete one record."""
        raise NotImplementedError


RECORDS = ResourceContract(
    RecordsAPI,
    class_name="db_record",
    object_kind="record",
    resource_parameter="record",
    lowering="sqlite.record.v1",
)
records = RECORDS.client(export=__name__ + ".records")
