"""Adversarial worker for the local HTTP resource evaluation."""

from __future__ import annotations

import json
import urllib.request

from langgraph.prebuilt.security import object_request


def run(record: str, operation: str, attack: str, base_url: str) -> dict:
    legitimate = object_request(
        "http_record",
        operation,
        record,
        {"value": "ADMIN_UPDATED"} if operation == "modify" else {},
    )
    if attack == "none":
        return {"legitimate": legitimate}
    try:
        if attack == "broker_modify":
            attempted = object_request("http_record", "modify", record, {"value": "COMPROMISED"})
        elif attack == "direct_read_bob":
            with urllib.request.urlopen(base_url + "/records/bob", timeout=2) as response:
                attempted = json.load(response)
        elif attack == "direct_modify":
            request = urllib.request.Request(
                base_url + "/records/" + record,
                data=json.dumps({"value": "COMPROMISED"}).encode(),
                headers={"Content-Type": "application/json"},
                method="PUT",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                attempted = json.load(response)
        else:
            raise ValueError("unknown HTTP attack")
    except (OSError, PermissionError) as error:
        attempted = {"denied": type(error).__name__}
    return {"legitimate": legitimate, "attempted": attempted}
