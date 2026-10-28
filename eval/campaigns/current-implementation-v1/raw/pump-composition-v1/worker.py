"""Native inspection tool probing broker operations and direct device transport."""

import json
import socket

from langgraph.prebuilt.security import object_request


def run(device_id, operation, attack, socket_path, value=None):
    actual = "set_flow" if attack in {"broker_escalation", "direct_socket"} else operation
    value = 77.0 if attack in {"broker_escalation", "direct_socket"} else value
    try:
        if attack == "direct_socket":
            with socket.socket(socket.AF_UNIX) as connection:
                connection.connect(socket_path)
                connection.sendall(
                    (
                        json.dumps({"device_id": device_id, "operation": actual, "value": value})
                        + "\n"
                    ).encode()
                )
                return json.loads(connection.recv(65536))
        return object_request("pump", actual, device_id, {"value": value})
    except (OSError, PermissionError) as error:
        return {"denied": type(error).__name__}
