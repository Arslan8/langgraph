"""Exercise useful authorized work through the production Docker dispatcher."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
SOURCE = """from pathlib import Path
import json

def compute(path, private, seed=False):
    values = json.loads(Path(path).read_text())
    result = {"sum": sum(values), "residual": Path('/tmp/prior').exists()}
    if seed:
        Path('/tmp/prior').write_text('PRIVATE_A')
    try:
        result['private'] = Path(private).read_text()
    except OSError as error:
        result['private_error'] = type(error).__name__
    return result
"""


@tool
def compute(path: str, private: str, seed: bool = False) -> dict:
    """Compute a sum in the selected isolated runtime."""
    raise AssertionError("Coordinator callback must not execute")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "worker.py").write_text(SOURCE)
    (args.output / "driver.py").write_bytes(Path(__file__).read_bytes())
    with tempfile.TemporaryDirectory(prefix="slg-container-grants-") as tmp:
        root = Path(tmp)
        source = root / "compute.py"
        source.write_text(SOURCE)
        allowed, private = root / "allowed.json", root / "private.txt"
        allowed.write_text("[7, 11, 23]")
        private.write_text("BOB_PRIVATE_CANARY")
        dispatcher = DockerObjectDispatcher(
            {
                "compute": LinuxToolSpec(
                    "compute:compute", source, hashlib.sha256(source.read_bytes()).hexdigest()
                )
            },
            image=IMAGE,
            private_roots=[root],
        )
        rows = []
        try:
            security = cedar_security(
                compute,
                manifest="runs linux\nfs read @{path} need",
                policy="permit(principal,action,resource);",
                dispatcher=dispatcher,
            )
            for case, user, seed in [
                ("first", "alice", True),
                ("same", "alice", False),
                ("changed", "bob", False),
            ]:
                principal = Principal(user, frozenset(), frozenset(), "session")
                call = ToolCall(
                    Tool("compute", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                    {"path": str(allowed), "private": str(private), "seed": seed},
                    {},
                    case,
                    0,
                )
                result = security.host_executor.invoke(principal, call, ())
                rows.append(
                    {
                        "case": case,
                        "value": result.value,
                        "receipt": result.receipt.canonical(),
                        "execution": dict(dispatcher.execution_records()[-1]),
                    }
                )
                assert result.value["sum"] == 41
                assert "private" not in result.value
                assert result.value["residual"] == (case == "same")
                print(case, result.value, flush=True)
            assert rows[0]["execution"]["container_id"] == rows[1]["execution"]["container_id"]
            assert rows[0]["execution"]["container_id"] != rows[2]["execution"]["container_id"]
        finally:
            dispatcher.close()
            (args.output / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
