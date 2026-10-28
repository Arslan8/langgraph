"""Real Docker check of the production lifecycle primitive, not executor acceptance."""

import argparse
import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

from langgraph.prebuilt.security._container_lifecycle import (
    ContainerIdentity,
    ContainerLifecycle,
    DockerContainerRuntime,
)

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    component = (
        Path(__file__).resolve().parents[2]
        / "libs/prebuilt/langgraph/prebuilt/security/_container_lifecycle.py"
    )
    (args.output / "component.py").write_bytes(component.read_bytes())
    (args.output / "driver.py").write_bytes(Path(__file__).read_bytes())
    identity = ContainerIdentity(*("a" * 64 for _ in range(5)))
    runtime = DockerContainerRuntime(
        lambda identity: [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=128m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=1m",
            "--user=0:0",
            "--entrypoint",
            "/bin/sleep",
            IMAGE,
            "infinity",
        ]
    )
    lifecycle = ContainerLifecycle(runtime)
    rows = []

    def execute(lease, code):
        result = subprocess.run(
            ["docker", "exec", lease.container_id, "/usr/bin/python3", "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {"status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

    try:
        with lifecycle.lease(identity) as first:
            result = execute(
                first, "from pathlib import Path; Path('/tmp/prior').write_text('PRIVATE_A')"
            )
            rows.append(
                {"case": "seed_private_state", "container_id": first.container_id, **result}
            )
            assert result["status"] == 0
        with lifecycle.lease(identity) as same:
            result = execute(
                same, "from pathlib import Path; print(Path('/tmp/prior').read_text())"
            )
            rows.append(
                {"case": "same_authority_reuse", "container_id": same.container_id, **result}
            )
            assert same.reused and same.container_id == first.container_id
            assert result["stdout"].strip() == "PRIVATE_A"
        with lifecycle.lease(replace(identity, principal_digest="b" * 64)) as changed:
            result = execute(
                changed, "from pathlib import Path; print(Path('/tmp/prior').exists())"
            )
            old = subprocess.run(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    f"id={first.container_id}",
                    "--format",
                    "{{.ID}}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            rows.append(
                {
                    "case": "principal_change",
                    "container_id": changed.container_id,
                    "old_absent": old.returncode == 0 and not old.stdout.strip(),
                    **result,
                }
            )
            assert changed.container_id != first.container_id and not changed.reused
            assert result["status"] == 0 and result["stdout"].strip() == "False"
            assert rows[-1]["old_absent"]
    finally:
        lifecycle.close()
        (args.output / "observations.json").write_text(
            json.dumps(
                {
                    "scope": (
                        "Production lifecycle component only; "
                        "HostToolExecutor integration remains incomplete"
                    ),
                    "component_sha256": hashlib.sha256(component.read_bytes()).hexdigest(),
                    "image": IMAGE,
                    "rows": rows,
                },
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
