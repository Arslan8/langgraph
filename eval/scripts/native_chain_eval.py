"""Separate exec-enabled profile: useful native binary A invoking native binary B."""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import cedar_security
from langgraph.prebuilt.security.errors import SecurityConfigurationError

from slanggraph_eval.isolation import alternatives as alt
from slanggraph_eval.isolation.runtime import host_snapshot

SOURCE = (
    "import subprocess\n"
    "child = subprocess.run(['/usr/bin/env', '/bin/cat', p['path']], "
    "capture_output=True, text=True, timeout=3)\n"
    "result = {'returncode': child.returncode, 'stdout': child.stdout, 'stderr': child.stderr}\n"
)


@tool("run")
def native_tool(path: str) -> str:
    """Read through a native executable chain, without an approved language terminal."""
    return subprocess.run(["/usr/bin/env", "/bin/cat", path], capture_output=True, text=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session", type=int)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=10)
    args = parser.parse_args()
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    alt.WORKER = Path(alt.__file__).with_name("binary_worker.py")
    image = subprocess.check_output(
        ["docker", "image", "inspect", "slg-linux-test:latest", "--format", "{{.Id}}"], text=True
    ).strip()
    (output / "host.json").write_text(json.dumps(host_snapshot(), indent=2))
    if args.session is None:
        plan = dict(
            source=SOURCE,
            profile="exec-enabled native chain",
            image=image,
            sessions=5,
            samples=args.samples,
            warmup=args.warmup,
            binaries={str(p): alt.digest(p) for p in [Path("/usr/bin/env"), Path("/bin/cat")]},
            worker_sha256=alt.digest(alt.WORKER),
        )
        try:
            cedar_security(native_tool, policy=alt.POLICY, manifest=alt.MANIFEST)
        except SecurityConfigurationError as error:
            plan["verified_admission"] = {"status": "rejected", "diagnostic": str(error)}
        else:
            raise RuntimeError("native API unexpectedly admitted; review comparator")
        (output / "plan.json").write_text(json.dumps(plan, indent=2))
        (output / "binary_worker.py.txt").write_bytes(alt.WORKER.read_bytes())
        for session in range(5):
            command = [
                sys.executable,
                __file__,
                "--output",
                str(output / f"session-{session}"),
                "--session",
                str(session),
                "--samples",
                str(args.samples),
                "--warmup",
                str(args.warmup),
            ]
            subprocess.run(command, check=True)
        rows = [
            json.loads(line)
            for session in range(5)
            for line in (output / f"session-{session}/samples.jsonl").read_text().splitlines()
        ]
        (output / "samples.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        (output / "summary.json").write_text(
            json.dumps(
                alt.summarize(rows, ("plain", "landlock", "container"), args.samples), indent=2
            )
        )
        return
    rng = random.Random(20261401 + args.session)
    lifecycle = []
    denials = []
    with tempfile.TemporaryDirectory(prefix="eval-native-chain-") as temporary:
        root = Path(temporary)
        allowed = root / "allowed"
        hidden = root / "hidden"
        allowed.write_text("")
        hidden.write_text(uuid.uuid4().hex)
        reads = [*alt.runtime_reads(), str(allowed)]
        with (
            alt.container_session(reads, [], image, lifecycle) as container,
            (output / "samples.jsonl").open("x") as stream,
        ):
            for index in range(1 + args.warmup + args.samples):
                order = ["plain", "landlock", "container"]
                rng.shuffle(order)
                for mode in order:
                    token = uuid.uuid4().hex
                    allowed.write_text(token)
                    start = time.perf_counter_ns()
                    response = alt.execute(
                        mode,
                        SOURCE,
                        {"path": str(allowed)},
                        reads,
                        [],
                        image,
                        container=container if mode == "container" else None,
                    )
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    value = response.get("value", {})
                    valid = value.get("returncode") == 0 and value.get("stdout") == token
                    row = dict(
                        case="env_to_cat",
                        condition=mode,
                        session=args.session,
                        round=index,
                        phase="first_use"
                        if index == 0
                        else "warmup"
                        if index <= args.warmup
                        else "measured",
                        elapsed_ms=elapsed,
                        valid=valid,
                        response=response,
                        expected_sha256=hashlib.sha256(token.encode()).hexdigest(),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
                    if not valid:
                        raise RuntimeError(f"chain failed: {mode}: {response}")
            # Three distinct repeats per mode/session are security checks, not timing samples.
            for repetition in range(3):
                token = uuid.uuid4().hex
                hidden.write_text(token)
                for mode in ("plain", "landlock", "container"):
                    response = alt.execute(
                        mode,
                        SOURCE,
                        {"path": str(hidden)},
                        reads,
                        [],
                        image,
                        container=container if mode == "container" else None,
                    )
                    value = response.get("value", {})
                    exposed = value.get("returncode") == 0 and value.get("stdout") == token
                    assert exposed == (mode == "plain")
                    denials.append(
                        dict(mode=mode, repetition=repetition, exposed=exposed, response=response)
                    )
    (output / "security.json").write_text(json.dumps(denials, indent=2))
    (output / "lifecycle.json").write_text(json.dumps(lifecycle, indent=2))
    print(f"native chain session {args.session} complete", flush=True)


if __name__ == "__main__":
    main()
