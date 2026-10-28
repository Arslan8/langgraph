"""Standalone trusted launcher for one profile-bound slangGraph tool call."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.check import load_profile_paths
from langgraph.prebuilt.security.landlock import LandlockSandboxExecutor
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.types import Principal, Tool, ToolCall

_MAX_REQUEST = 1_048_576


def main(argv: Sequence[str] | None = None) -> int:
    """Run one call through the same profile, policy, and Landlock pipeline."""
    parser = argparse.ArgumentParser(prog="slanggraph-exec")
    parser.add_argument("--profiles", action="append", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--runtime-root", action="append", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--session", required=True)
    args = parser.parse_args(argv)
    try:
        profiles = load_profile_paths(args.profiles)
        tool_profile = profiles.tools[args.tool]
        principal_profile = profiles.principals[args.principal]
        artifact = Path(args.artifact).resolve(strict=True)
        payload = _read_request()
        call_args = payload.get("args")
        normalized = payload.get("normalized", call_args)
        call_id = payload.get("call_id")
        if (
            not isinstance(call_args, dict)
            or not isinstance(normalized, dict)
            or not isinstance(call_id, str)
            or not call_id
        ):
            raise ValueError("request requires args, normalized, and call_id")
        spec = LinuxToolSpec(
            args.entrypoint,
            artifact,
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
        )
        executor = LandlockSandboxExecutor(
            profiles,
            {args.tool: spec},
            runtime_roots=tuple(Path(item) for item in args.runtime_root),
        )
        principal = Principal(
            args.principal,
            principal_profile.roles,
            principal_profile.scopes,
            args.session,
        )
        tool = Tool(args.tool, tool_profile.as_tool_dac(), frozenset(), ())
        result = executor.invoke(
            principal,
            ToolCall(tool, call_args, normalized, call_id, 0),
            (),
        )
        response = {
            "grant_hash": result.receipt.grant_digest,
            "mechanisms": sorted(
                {item.mechanism for item in result.receipt.rule_enforcement}
            ),
            "result": result.value,
            "status": "ok",
        }
    except (
        KeyError,
        OSError,
        PermissionError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        response = {"error": str(exc), "status": "denied"}
        print(json.dumps(response, sort_keys=True, default=repr))
        return 1
    print(json.dumps(response, sort_keys=True, default=repr))
    return 0


def _read_request() -> dict[str, Any]:
    frame = sys.stdin.buffer.readline(_MAX_REQUEST + 1)
    if not frame or len(frame) > _MAX_REQUEST or not frame.endswith(b"\n"):
        raise ValueError("invalid request frame")
    value = json.loads(frame)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
