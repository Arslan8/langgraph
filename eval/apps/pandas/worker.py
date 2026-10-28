"""Run the unmodified upstream sandbox program in the existing Linux worker."""

import io
import json
import sys
from pathlib import Path


def compute(sandbox_source: str, payload: dict) -> dict:
    module = {"__name__": "upstream_sandbox"}
    exec(compile(Path(sandbox_source).read_text(), sandbox_source, "exec"), module)
    if payload.get("sandbox_serialization") is not None:
        from sandbox_codec import VERSIONS, repair_runner

        if payload["sandbox_serialization"] not in VERSIONS:
            raise ValueError("Unsupported sandbox serialization version")
        module["SANDBOX_RUNNER_SCRIPT"] = repair_runner(
            module["SANDBOX_RUNNER_SCRIPT"],
            payload["sandbox_serialization"],
            payload.get("computation_api"),
        )
    original_input, original_output = sys.stdin, sys.stdout
    stream = io.StringIO()
    try:
        sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))
        sys.stdout = stream
        exec(module["SANDBOX_RUNNER_SCRIPT"], {"__name__": "__main__"})
        return json.loads(stream.getvalue())
    finally:
        sys.stdin, sys.stdout = original_input, original_output
