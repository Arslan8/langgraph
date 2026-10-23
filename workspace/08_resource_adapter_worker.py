"""Untrusted counter client; all semantic operations go through the broker."""

from pathlib import Path

from langgraph.prebuilt.security import object_request


def exercise_counter(private_path: str):
    """Use the grant, then attempt invalid payloads and direct resource access."""
    results = {
        "before": object_request("counter", "inspect", "jobs"),
        "increment": object_request("counter", "increment", "jobs", {"amount": 2}),
    }
    attempts = (
        ("invalid_amount", "increment", "jobs", {"amount": -1}),
        ("payload_override", "increment", "jobs", {"amount": 1, "selector": "retired"}),
        ("optional_resource", "inspect", "retired", {}),
    )
    for name, operation, selector, payload in attempts:
        try:
            object_request("counter", operation, selector, payload)
            results[name] = "escaped"
        except PermissionError:
            results[name] = "denied"
    try:
        Path(private_path).read_text()
        results["direct_access"] = "escaped"
    except OSError:
        results["direct_access"] = "blocked"
    return results
