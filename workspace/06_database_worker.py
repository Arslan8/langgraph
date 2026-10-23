"""Untrusted database tool: it receives record names, never a connection."""

from langgraph.prebuilt.security import object_request


def manage_record(record: str, operation: str, value: str | None = None):
    """Request one operation on the exact record selected in the manifest."""
    payload = {"value": value} if operation == "write" else {}
    return object_request("db_record", operation, record, payload)
