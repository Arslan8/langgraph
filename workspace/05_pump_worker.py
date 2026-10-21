"""Untrusted pump tool: no socket path or device credentials are available here."""

from langgraph.prebuilt.security.object_broker import object_request


def control_pump(device_id: str, operation: str, value: float | None = None):
    """Request one operation through the parent-owned capability broker."""
    return object_request("pump", operation, device_id, {"value": value})
