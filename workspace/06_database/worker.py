"""Untrusted database tool: it receives record names, never a connection."""

from langgraph.prebuilt.security.mediators.records import records


def manage_record(record: str, operation: str, value: str = ""):
    """Request one operation on the exact record selected in the manifest."""
    if operation == "read":
        return records.read(record)
    if operation == "write":
        return records.write(record, value)
    # The manifest's closed operation map rejects other selectors before dispatch.
    return records.delete(record)
