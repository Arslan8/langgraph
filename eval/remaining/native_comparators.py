"""Focused official native sandboxes, exact file grants and native chain."""

import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "eval/campaigns/remaining-v1/raw/native-comparators"
OUT.mkdir(exist_ok=False)
with (OUT / "trials.jsonl").open("w") as stream:
    for name in ["nono", "sandlock"]:
        binary = ROOT / f"eval/vendor/{name}/target/release/{name}"
        revision = subprocess.check_output(
            ["git", "-C", str(binary.parents[2]), "rev-parse", "HEAD"], text=True
        ).strip()
        for repeat in range(20):
            with tempfile.TemporaryDirectory(prefix="slg-compare-") as tmp:
                root = Path(tmp)
                allowed = root / "allowed"
                denied = root / "bob"
                cwd = root / "cwd"
                cwd.mkdir()
                allowed.write_text("ALICE_ALLOWED")
                denied.write_text("BOB_NATIVE_CANARY")
                if name == "nono":
                    prefix = [
                        str(binary),
                        "run",
                        "--block-net",
                        "--no-rollback",
                        "--read-file",
                        str(allowed),
                    ]
                else:
                    prefix = [
                        str(binary),
                        "run",
                        "--no-supervisor",
                        "-r",
                        "/usr",
                        "-r",
                        "/lib",
                        "-r",
                        "/lib64",
                        "-r",
                        str(allowed),
                    ]
                for case, command in [
                    ("allowed_read", ["/bin/cat", str(allowed)]),
                    ("denied_read", ["/bin/cat", str(denied)]),
                    ("allowed_chain", ["/usr/bin/env", "/bin/cat", str(allowed)]),
                    ("denied_chain", ["/usr/bin/env", "/bin/cat", str(denied)]),
                    ("metadata", ["/usr/bin/stat", "-c", "%s", str(denied)]),
                    ("allowed_metadata", ["/usr/bin/stat", "-c", "%s", str(allowed)]),
                ]:
                    cmd = [*prefix, "--", *command]
                    t = time.perf_counter()
                    try:
                        p = subprocess.run(
                            cmd,
                            cwd=cwd,
                            text=True,
                            capture_output=True,
                            timeout=30,
                            stdin=subprocess.DEVNULL,
                        )
                        status = p.returncode
                        stdout = p.stdout
                        stderr = p.stderr
                    except subprocess.TimeoutExpired as e:
                        status = "timeout"
                        stdout = str(e.stdout)
                        stderr = str(e.stderr)
                    effect = (
                        ("BOB_NATIVE_CANARY" in stdout)
                        if case != "metadata"
                        else stdout.strip() == str(denied.stat().st_size)
                    )
                    row = dict(
                        case_id=case,
                        repeat=repeat,
                        session=repeat,
                        mode=name,
                        concrete_executor=str(binary),
                        source_revision=revision,
                        host=socket.gethostname(),
                        principal="same OS user; Alice policy fixture",
                        policy={"read": [str(allowed)], "write": []},
                        command=cmd,
                        exit_status=status,
                        stdout=stdout,
                        stderr=stderr,
                        observed_effect=effect,
                        legitimate_result=status == 0
                        and (
                            "ALICE_ALLOWED" in stdout
                            if "read" in case or "chain" in case
                            else stdout.strip() == str(allowed.stat().st_size)
                        )
                        if case.startswith("allowed")
                        else None,
                        elapsed_ms=(time.perf_counter() - t) * 1000,
                        scope=(
                            "filesystem content and native exec; metadata separately"
                            " observed; no semantic row claims"
                        ),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
        print(name, "complete", flush=True)
