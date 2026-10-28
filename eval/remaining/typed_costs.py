"""Paired-session timing of a useful typed resource with real admission and authorization."""

import argparse
import hashlib
import json
import platform
import random
import subprocess
import sys
import time
from pathlib import Path

from counter_resource import CONTRACT, Counter, assessment, counter
from evidence_utils import serial
from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
)


@tool
def increment() -> int:
    """Increment the registered parent-owned counter."""
    return counter.increment(2)


def session(output, number):
    backends = {m: Counter() for m in ["plain", "verified", "broker"]}
    executors = {}
    setup = []
    worker = Path(__file__).with_name("counter_worker.py")
    for mode in ["verified", "broker"]:
        resource = CONTRACT.bind(implementation=backends[mode], assess=assessment)
        start = time.perf_counter()
        dispatcher = None
        if mode == "broker":
            dispatcher = ObjectBrokerDispatcher(
                {
                    "increment": LinuxToolSpec(
                        "counter_worker:increment",
                        worker,
                        hashlib.sha256(worker.read_bytes()).hexdigest(),
                    )
                },
                resources=(resource,),
                runtime_roots=tuple(Path(p).resolve() for p in sys.path if p and Path(p).is_dir()),
            )
        security = cedar_security(
            increment,
            resources=(resource,) if mode == "verified" else (),
            manifest=("runs linux\n" if mode == "broker" else "runs inprocess\n")
            + resource.permission("increment"),
            policy="permit(principal,action,resource);",
            dispatcher=dispatcher,
        )
        setup.append(
            dict(mode=mode, elapsed_ms=(time.perf_counter() - start) * 1000, admission="accepted")
        )
        executors[mode] = security.host_executor
    (output / f"setup-{number}.json").write_text(json.dumps(setup, indent=2))
    rng = random.Random(20261028 + number)
    with (output / f"session-{number}.jsonl").open("w") as stream:
        for index in range(31):
            modes = ["plain", "verified", "broker"]
            rng.shuffle(modes)
            for mode in modes:
                before = backends[mode].value
                receipt = None
                grant = None
                error = None
                start = time.perf_counter()
                try:
                    if mode == "plain":
                        value = backends[mode].increment(2)
                    else:
                        call = ToolCall(
                            Tool("increment", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                            {},
                            {},
                            f"{number}-{index}-{mode}",
                            0,
                        )
                        result = executors[mode].invoke(
                            Principal("alice", frozenset(), frozenset(), str(number)), call, ()
                        )
                        value = result.value
                        receipt = serial(result.receipt)
                        grant = serial(executors[mode].authorization_grants()[-1])
                except Exception as exc:
                    error = dict(type=type(exc).__name__, message=str(exc))
                    value = None
                elapsed = (time.perf_counter() - start) * 1000
                row = dict(
                    case_id="counter_increment",
                    session=number,
                    round=index,
                    mode=mode,
                    phase="first_use" if index == 0 else "warmup" if index <= 10 else "measured",
                    concrete_executor="ObjectPolicyHostExecutor/"
                    + ("ObjectBrokerDispatcher" if mode == "broker" else "InProcess")
                    if mode != "plain"
                    else "direct typed backend",
                    host=platform.node(),
                    principal="alice",
                    grant=grant,
                    activation=receipt or "not-applicable",
                    resource_before=before,
                    resource_after=backends[mode].value,
                    result=value,
                    error=error,
                    legitimate_result=value == before + 2 and backends[mode].value == before + 2,
                    elapsed_ms=elapsed,
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
            result = subprocess.run(
                [sys.executable, __file__, "--output", str(args.output), "--session", str(number)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        if result.returncode:
            raise RuntimeError(f"session {number} failed; raw log retained")


if __name__ == "__main__":
    main()
