"""Run native file canaries with an official APF-projected OpenShell policy."""

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

SOURCE = """import json, pathlib, subprocess
result = {"allowed": pathlib.Path("/fixtures/alice").read_text()}
try:
    result["denied"] = pathlib.Path("/fixtures/bob").read_text()
except OSError as error:
    result["denied"] = {"error": type(error).__name__, "errno": error.errno}
for name, path in [("allowed_child", "/fixtures/alice"), ("denied_child", "/fixtures/bob")]:
    child = subprocess.run(["/usr/bin/cat", path], capture_output=True, text=True)
    result[name] = {"status": child.returncode, "stdout": child.stdout, "stderr": child.stderr}
try:
    result["denied_metadata_size"] = pathlib.Path("/fixtures/bob").stat().st_size
except OSError as error:
    result["denied_metadata_size"] = {"error": type(error).__name__}
print("SLG_RESULT=" + json.dumps(result))
"""


def policy_matches(actual, expected):
    """Compare effective authority, allowing only omitted protobuf defaults."""
    value = actual.get("policy", {})
    if actual.get("status") != "effective" or set(value) - {
        "version",
        "filesystem_policy",
        "landlock",
        "process",
        "network_policies",
        "network_middlewares",
    }:
        return False
    fs = value.get("filesystem_policy", {})
    if set(fs) - {"include_workdir", "read_only", "read_write"}:
        return False
    normalized = {
        "include_workdir": fs.get("include_workdir", False),
        "read_only": fs.get("read_only", []),
        "read_write": fs.get("read_write", []),
    }
    return (
        normalized == expected["filesystem_policy"]
        and value.get("version") == expected["version"]
        and value.get("landlock") == expected["landlock"]
        and value.get("process") == expected["process"]
        and not value.get("network_policies")
        and not value.get("network_middlewares")
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:18080")
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.policy, out / "projected-policy.json")
    shutil.copyfile(__file__, out / "driver.py")
    (out / "canary.py").write_text(SOURCE)
    image = subprocess.check_output(["docker", "image", "inspect", args.image], text=True)
    (out / "image.json").write_text(image)
    identity = dict(
        model=None,
        host=platform.node(),
        image=json.loads(image)[0]["Id"],
        cli_sha256=hashlib.sha256(args.cli.read_bytes()).hexdigest(),
        policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
        scope=(
            "APF official static projection in native OpenShell; no dynamic APF service integration"
        ),
        timing_scope=(
            "shared host; sandbox create, activation and canaries; no comparative latency claim"
        ),
    )
    (out / "plan.json").write_text(
        json.dumps({**identity, "repetitions": args.repetitions}, indent=2) + "\n"
    )
    prefix = [str(args.cli.resolve()), "--gateway-endpoint", args.endpoint]
    for repeat in range(args.repetitions):
        name = f"slg-native-{repeat}"
        started = datetime.now(UTC).isoformat()
        start = time.perf_counter()
        result = None
        try:
            completed = subprocess.run(
                [
                    *prefix,
                    "sandbox",
                    "create",
                    "--name",
                    name,
                    "--from",
                    args.image,
                    "--policy",
                    str(out / "projected-policy.json"),
                    "--no-auto-providers",
                    "--no-tty",
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    SOURCE,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            (out / f"{repeat}-stdout.log").write_text(completed.stdout)
            (out / f"{repeat}-stderr.log").write_text(completed.stderr)
            for line in completed.stdout.splitlines():
                if line.startswith("SLG_RESULT="):
                    result = json.loads(line.removeprefix("SLG_RESULT="))
            policy = subprocess.run(
                [*prefix, "policy", "get", name, "--full", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            (out / f"{repeat}-effective-policy.json").write_text(policy.stdout)
            (out / f"{repeat}-policy-error.log").write_text(policy.stderr)
            passed = bool(
                completed.returncode == 0
                and result
                and result.get("allowed") == "ALICE_ALLOWED"
                and result.get("denied") == {"error": "PermissionError", "errno": 13}
                and result.get("allowed_child", {}).get("stdout") == "ALICE_ALLOWED"
                and result.get("allowed_child", {}).get("status") == 0
                and result.get("denied_child", {}).get("status") == 1
                and "Permission denied" in result.get("denied_child", {}).get("stderr", "")
                and "BOB_NATIVE_CANARY" not in json.dumps(result)
                and policy.returncode == 0
                and policy_matches(json.loads(policy.stdout), json.loads(args.policy.read_text()))
            )
            row = {
                **identity,
                "repeat": repeat,
                "started_at": started,
                "status": "completed",
                "exit_status": completed.returncode,
                "result": result,
                "passed": passed,
            }
        except subprocess.TimeoutExpired as error:
            row = {
                **identity,
                "repeat": repeat,
                "started_at": started,
                "status": "timeout",
                "passed": False,
                "error": str(error),
            }
        finally:
            cleanup = subprocess.run(
                [*prefix, "sandbox", "delete", name], capture_output=True, text=True, timeout=30
            )
            (out / f"{repeat}-cleanup.log").write_text(cleanup.stdout + cleanup.stderr)
        row.update(
            finished_at=datetime.now(UTC).isoformat(),
            elapsed_ms=(time.perf_counter() - start) * 1000,
            cleanup_exit_status=cleanup.returncode,
        )
        if cleanup.returncode:
            row["passed"] = False
        with (out / "trials.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(repeat, row["status"], row["passed"], flush=True)


if __name__ == "__main__":
    main()
