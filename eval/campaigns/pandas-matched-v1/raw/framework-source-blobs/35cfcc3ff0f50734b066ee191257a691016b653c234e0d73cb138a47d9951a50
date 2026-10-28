"""Trusted stdio proxy for broker-scoped MCP servers."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.broker import SpawnRecord

_MAX_FRAME = 1_048_576


@dataclass(frozen=True, slots=True)
class McpServerSpec:
    """Pinned process and minimal environment for one MCP stdio server."""

    command: tuple[str, ...]
    credential_env: str
    environment: Mapping[str, str] = field(default_factory=dict)
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        command = tuple(self.command)
        if not command or any(not item for item in command):
            raise ValueError("MCP command must be non-empty")
        if not self.credential_env or "=" in self.credential_env:
            raise ValueError("MCP credential environment name is invalid")
        if self.credential_env in self.environment:
            raise ValueError("MCP environment cannot supply the credential")
        if self.timeout_s <= 0:
            raise ValueError("MCP timeout must be positive")
        object.__setattr__(self, "command", command)
        object.__setattr__(
            self, "environment", MappingProxyType(dict(self.environment))
        )


class McpStdioProxy:
    """Execute one JSON-RPC exchange without exposing its credential to a tool."""

    def __init__(self, spec: McpServerSpec) -> None:
        self.spec = spec

    def __call__(
        self,
        token: str,
        operation: str,
        payload: Mapping[str, Any],
        spawn: SpawnRecord,
    ) -> Any:
        """Relay one broker-authorized request to a clean MCP subprocess."""
        del spawn
        if operation != "invoke":
            raise PermissionError("mcp:operation_not_supported")
        request = dict(payload)
        if request.get("jsonrpc") != "2.0" or "method" not in request:
            raise ValueError("mcp:invalid_jsonrpc_request")
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) + 1 > _MAX_FRAME:
            raise ValueError("mcp:request_too_large")
        environment = {**dict(self.spec.environment), self.spec.credential_env: token}
        process = subprocess.Popen(
            self.spec.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=environment,
        )
        try:
            stdout, _ = process.communicate(
                encoded + b"\n", timeout=self.spec.timeout_s
            )
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise TimeoutError("mcp:server_timeout") from exc
        if process.returncode != 0:
            raise RuntimeError("mcp:server_failed")
        if not stdout.endswith(b"\n") or len(stdout) > _MAX_FRAME:
            raise ValueError("mcp:invalid_response_frame")
        try:
            response = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("mcp:invalid_response_json") from exc
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
            raise ValueError("mcp:invalid_jsonrpc_response")
        if response.get("id") != request.get("id"):
            raise ValueError("mcp:response_id_mismatch")
        if token.encode() in stdout:
            raise PermissionError("mcp:credential_exfiltration")
        return response


def mcp_service_map(
    specs: Mapping[str, McpServerSpec],
) -> Mapping[str, McpStdioProxy]:
    """Create broker service handlers named `mcp:<server>` from pinned specs."""
    if any(not name for name in specs):
        raise ValueError("MCP server names must be non-empty")
    return MappingProxyType(
        {f"mcp:{name}": McpStdioProxy(spec) for name, spec in specs.items()}
    )
