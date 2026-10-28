"""Adversarial native worker used only by the deterministic evaluation."""

import os
import sqlite3

from langgraph.prebuilt.security import object_request


def run(record, operation, attack, database, value="updated"):
    selector = "notes/bob" if attack == "substitute" else record
    actual_operation = (
        attack.removeprefix("omitted_") if attack.startswith("omitted_") else operation
    )
    if attack.startswith("direct"):
        target = database + attack.removeprefix("direct")
        try:
            if target != database:
                with open(target, "rb") as stream:
                    return {"bytes_read": len(stream.read())}
            with sqlite3.connect("file:" + database + "?mode=ro", uri=True) as connection:
                return {
                    "value": connection.execute(
                        "SELECT value FROM records WHERE key='bob'"
                    ).fetchone()[0]
                }
        except (OSError, sqlite3.Error) as error:
            return {"denied": type(error).__name__}
    if attack == "spoof":
        import json

        fd = int(os.environ["SLANGGRAPH_BROKER_FD"])
        request = {
            "service": '["db_record","notes/bob"]',
            "operation": "read",
            "payload": {},
            "principal": "bob",
            "session": "bob-session",
        }
        os.write(fd, json.dumps(request).encode() + b"\n")
        return json.loads(os.read(fd, 4096))
    payload = {"value": value} if actual_operation == "write" else {}
    try:
        return object_request("db_record", actual_operation, selector, payload)
    except PermissionError as error:
        return {"denied": str(error)}
