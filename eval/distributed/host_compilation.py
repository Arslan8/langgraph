"""Two-stage policy preparation across Linux and container host compilers."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import uuid
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    LinuxObjectDispatcher,
    LinuxToolSpec,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
MANIFEST = "runs linux\nfs read @{path} need"
POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
SOURCE = """from pathlib import Path

def run(path, other=None):
    result = {"allowed": Path(path).read_text()}
    if other is not None:
        try:
            result["forbidden"] = Path(other).read_text()
        except OSError as error:
            result["forbidden_blocked"] = type(error).__name__
    return result
"""


@tool("common_read")
def common_read(path: str, other: str | None = None) -> dict:
    """Read one policy-selected file and probe an undeclared path."""
    raise RuntimeError("unconfined fallback is forbidden")


def run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="slg-host-compile-") as folder:
        root = Path(folder)
        tool_root = root / "trusted-tool"
        data_root = root / "data"
        tool_root.mkdir()
        data_root.mkdir()
        source = tool_root / "common_worker.py"
        allowed = data_root / "allowed.txt"
        forbidden = data_root / "forbidden.txt"
        source.write_text(SOURCE)
        allowed.write_text("PORTABLE_ALLOWED")
        forbidden.write_text("PORTABLE_FORBIDDEN")
        artifact = hashlib.sha256(source.read_bytes()).hexdigest()
        prepared = {
            "tool": "common_read",
            "artifact_sha256": artifact,
            "manifest": MANIFEST,
            "principal_policy": POLICY,
        }
        prepared_bytes = json.dumps(prepared, sort_keys=True, separators=(",", ":")).encode()
        prepared_hash = hashlib.sha256(prepared_bytes).hexdigest()
        (output / "prepared.json").write_text(
            json.dumps({**prepared, "sha256": prepared_hash}, indent=2) + "\n"
        )
        profiles = {
            "linux": {
                "dispatcher": "LinuxObjectDispatcher",
                "enforcement": "bubblewrap+Landlock+seccomp",
            },
            "container": {
                "dispatcher": "DockerObjectDispatcher",
                "image": IMAGE,
            },
        }
        (output / "host-profiles.json").write_text(json.dumps(profiles, indent=2) + "\n")
        dispatchers = {
            "linux": LinuxObjectDispatcher(
                {"common_read": LinuxToolSpec("common_worker:run", source, artifact)},
                runtime_roots=(tool_root,),
            ),
            "container": DockerObjectDispatcher(
                {"common_read": LinuxToolSpec("common_worker:run", source, artifact)},
                image=IMAGE,
                private_roots=(root,),
            ),
        }
        rows = []
        try:
            for host, dispatcher in dispatchers.items():
                security = cedar_security(
                    common_read,
                    manifest=MANIFEST,
                    policy=POLICY,
                    dispatcher=dispatcher,
                )
                principal = Principal("alice", frozenset(), frozenset(), "portable-session")
                for case, other in (("allowed", None), ("forbidden_probe", forbidden)):
                    arguments = {"path": str(allowed), "other": str(other) if other else None}
                    call = ToolCall(
                        Tool(
                            "common_read",
                            ToolDac("owner", {"*": "x"}),
                            frozenset(),
                            (),
                        ),
                        arguments,
                        {},
                        uuid.uuid4().hex,
                        0,
                    )
                    result = security.host_executor.invoke(principal, call, ())
                    rows.append(
                        {
                            "host": host,
                            "case_id": case,
                            "prepared_sha256": prepared_hash,
                            "grant": serial(security.host_executor.authorization_grants()[-1]),
                            "generated_restrictions": serial(
                                dispatcher.lowering_records()
                                if hasattr(dispatcher, "lowering_records")
                                else dispatcher.execution_records()
                            ),
                            "activation": serial(result.receipt),
                            "result": result.value,
                            "allowed_succeeded": result.value.get("allowed") == "PORTABLE_ALLOWED",
                            "forbidden_blocked": "PORTABLE_FORBIDDEN"
                            not in json.dumps(result.value),
                        }
                    )
            missing_error = None
            try:
                missing_security = cedar_security(
                    common_read,
                    classes="""class remote_record {
  operations read
  object record
  normalizer identity
  attrs
  enforced_by broker
  lowering remote.record.v1
}""",
                    manifest="runs linux\nremote_record read alice need",
                    policy=POLICY,
                    dispatcher=dispatchers["linux"],
                )
                missing_call = ToolCall(
                    Tool(
                        "common_read",
                        ToolDac("owner", {"*": "x"}),
                        frozenset(),
                        (),
                    ),
                    {"path": str(allowed), "other": None},
                    {},
                    uuid.uuid4().hex,
                    0,
                )
                missing_security.host_executor.invoke(principal, missing_call, ())
            except Exception as exc:
                missing_error = {"type": type(exc).__name__, "message": str(exc)}
            rows.append(
                {
                    "host": "linux-missing-broker-capability",
                    "case_id": "missing_capability",
                    "prepared_sha256": prepared_hash,
                    "explicit_refusal": missing_error,
                    "silently_weakened": False,
                }
            )
        finally:
            dispatchers["container"].close()
        (output / "trials.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.output)
