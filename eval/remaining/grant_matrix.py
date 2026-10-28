"""Required work plus optional authority pruning on the real production coordinator."""

import argparse
import hashlib
import json
import platform
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "libs/prebuilt"))
from evidence_utils import serial  # noqa: E402
from langgraph.prebuilt.security import (  # noqa: E402
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Requirement,
)
from tests.security.test_object_broker import setup  # noqa: E402

SOURCE = """from langgraph.prebuilt.security import object_request
def run(operation, selector):
    required = object_request("pump", "inspect", "pump-1")
    try:
        optional = object_request("pump", "calibrate", "pump-1")
    except PermissionError:
        optional = "removed"
    return {"required":required,"optional":optional}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "worker.py").write_text(SOURCE)
    with (args.output / "trials.jsonl").open("w") as stream:
        for repeat in range(20):
            for case in [
                "required_success",
                "want_missing",
                "need_missing",
                "wrong_grant",
                "wrong_principal",
                "activation_failure",
            ]:
                with tempfile.TemporaryDirectory(prefix="slg-grant-") as tmp:
                    base, principal, call, grant, seen = setup.__wrapped__(Path(tmp))
                    source = Path(tmp) / "composite.py"
                    source.write_text(SOURCE)
                    mediators = base.mediators
                    if case == "activation_failure":

                        def fail(lines, context):
                            raise RuntimeError("fixture activation failure")

                        mediators = (replace(mediators[0], activate=fail),)
                    dispatcher = ObjectBrokerDispatcher(
                        {
                            "pump_tool": LinuxToolSpec(
                                "composite:run",
                                source,
                                hashlib.sha256(source.read_bytes()).hexdigest(),
                            )
                        },
                        mediators=mediators,
                        runtime_roots=base.runtime_roots,
                    )
                    if case in ["want_missing", "need_missing"]:
                        optional = replace(
                            grant.lines[0],
                            line_id="optional",
                            operation="calibrate",
                            requirement=Requirement.WANT
                            if case == "want_missing"
                            else Requirement.NEED,
                        )
                        grant = replace(grant, lines=(*grant.lines, optional))
                    if case == "wrong_grant":
                        grant = replace(grant, call_id="other")
                    if case == "wrong_principal":
                        principal = replace(principal, user_id="bob")
                    start = time.perf_counter()
                    result = None
                    error = None
                    try:
                        result = dispatcher.invoke(principal, call, grant)
                    except Exception as exc:
                        error = dict(type=type(exc).__name__, message=str(exc))
                    row = dict(
                        case_id=case,
                        repeat=repeat,
                        session=repeat,
                        mode="production_broker_fixture",
                        concrete_executor="ObjectBrokerDispatcher/production coordinator",
                        host=platform.node(),
                        source_revision=hashlib.sha256(SOURCE.encode()).hexdigest(),
                        principal=serial(principal),
                        grant=serial(grant),
                        grant_identity=grant.digest,
                        authorization=(
                            "preconstructed grant fixture; Cedar composition tested separately"
                        ),
                        lowering=serial(dispatcher.lowering_records()),
                        activation=serial(result.receipt) if result else "not-applicable",
                        result=serial(result.value) if result else None,
                        error=error,
                        effect_trace=seen,
                        legitimate_result=result is not None
                        and result.value["required"] == "inspected",
                        observed_effect=case not in ["required_success", "want_missing"]
                        and bool(seen),
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()


if __name__ == "__main__":
    main()
