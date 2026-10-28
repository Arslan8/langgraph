"""Separate measured one-shot container cohort; never relabel an amortization model."""

import argparse
import hashlib
import json
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from slanggraph_eval.isolation.alternatives import execute, runtime_reads

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"


def session(output, number):
    rng = random.Random(20261029 + number)
    with (
        tempfile.TemporaryDirectory(prefix="slg-cold-") as tmp,
        (output / f"session-{number}.jsonl").open("w") as stream,
    ):
        path = Path(tmp) / "allowed"
        path.write_text("cold-container-authorized")
        for index in range(31):
            modes = ["plain", "container"]
            rng.shuffle(modes)
            for mode in modes:
                start = time.perf_counter()
                response = execute(
                    mode,
                    "result=open(p['path']).read()",
                    dict(path=str(path)),
                    [*runtime_reads(), sys.base_prefix, str(path)],
                    [],
                    IMAGE,
                )
                elapsed = (time.perf_counter() - start) * 1000
                row = dict(
                    case_id="one_shot_read",
                    session=number,
                    round=index,
                    mode=mode,
                    phase="first_use" if index == 0 else "warmup" if index <= 10 else "measured",
                    concrete_executor="evaluation adapter/docker run --rm"
                    if mode == "container"
                    else "plain subprocess",
                    response=response,
                    legitimate_result=response.get("value") == "cold-container-authorized",
                    elapsed_ms=elapsed,
                    source_revision=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    timer=(
                        "execute call includes fresh container launch, worker, t"
                        "ransport and --rm exit; fixture setup excluded"
                    ),
                )
                stream.write(json.dumps(row) + "\n")
                stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session", type=int)
    args = parser.parse_args()
    if args.session is not None:
        session(args.output, args.session)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    for number in range(5):
        with (args.output / f"session-{number}.log").open("w") as log:
            p = subprocess.run(
                [sys.executable, __file__, "--output", str(args.output), "--session", str(number)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        if p.returncode:
            raise RuntimeError("session failed; inspect retained log")
        print(f"cold session {number} complete", flush=True)


if __name__ == "__main__":
    main()
