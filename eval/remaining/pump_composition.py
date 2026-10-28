"""Shared-socket pump composition ablation with the existing simulator and adapter."""

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path

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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402 - repository path setup


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sim = load("eval_pump_simulator", ROOT / "workspace/05_custom_resource/simulator.py")
demo = load("eval_pump_demo", ROOT / "workspace/05_custom_resource/demo.py")
MODES = ["call_authorization_native", "transport_only", "production_composition"]
CASES = [
    ("allowed_inspect", "charlie", "inspect", "none", None),
    ("allowed_set_flow", "alice", "set_flow", "none", 25.0),
    ("allowed_calibrate", "bob", "calibrate", "none", 1.5),
    ("denied_declared", "charlie", "set_flow", "none", 77.0),
    ("broker_escalation", "charlie", "inspect", "broker_escalation", None),
    ("direct_socket", "charlie", "inspect", "direct_socket", None),
]


@tool("control_pump")
def control_pump(
    device_id: str, operation: str, attack: str, socket_path: str, value: float | None = None
) -> dict:
    """Run one declared device operation in a confined worker."""
    raise RuntimeError("no fallback")


def run(output, repetitions):
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name("pump_worker.py")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    (output / "plan.json").write_text(
        json.dumps(
            dict(cases=CASES, modes=MODES, repetitions=repetitions, worker_sha256=digest), indent=2
        )
    )
    for name, text in [
        ("manifest.slp", demo.MANIFEST),
        ("policy.cedar", demo.POLICY),
        ("worker.py", source.read_text()),
    ]:
        (output / name).write_text(text)
    with (output / "trials.jsonl").open("w") as stream:
        for repetition in range(repetitions):
            for mode in MODES:
                for case, principal_id, operation, attack, value in CASES:
                    with tempfile.TemporaryDirectory(prefix="slg-pump-eval-") as folder:
                        socket_path = Path(folder) / "pump.sock"
                        log = Path(folder) / "commands.jsonl"
                        pump = sim.Pump(log)
                        server = sim.PumpServer(socket_path, pump)
                        thread = threading.Thread(
                            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
                        )
                        thread.start()
                        try:
                            _, old = demo.build_demo(socket_path, "cedar")
                            dispatcher = ObjectBrokerDispatcher(
                                {"control_pump": LinuxToolSpec("pump_worker:run", source, digest)},
                                mediators=old.host_executor.dispatcher.mediators,
                                runtime_roots=tuple(
                                    Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
                                ),
                            )
                            security = cedar_security(
                                control_pump,
                                classes=demo.CLASSES,
                                manifest=demo.MANIFEST,
                                policy=demo.POLICY,
                                dispatcher=dispatcher,
                            )
                            executor = security.host_executor
                            principal = Principal(
                                principal_id, frozenset(), frozenset(), f"pump-{repetition}"
                            )
                            args = dict(
                                device_id="pump-1",
                                operation=operation,
                                attack=attack,
                                socket_path=str(socket_path),
                                value=value,
                            )
                            call = ToolCall(
                                Tool("control_pump", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                                args,
                                {},
                                uuid.uuid4().hex,
                                0,
                            )
                            before = asdict(pump.state)
                            start = time.perf_counter()
                            grant = None
                            receipt = None
                            result = None
                            error = None
                            try:
                                if mode == "production_composition":
                                    response = executor.invoke(principal, call, ())
                                    result = response.value
                                    receipt = serial(response.receipt)
                                    grant = executor.authorization_grants()[-1]
                                else:
                                    if mode == "call_authorization_native":
                                        grant = executor._authorize(principal, call, ())
                                    actual = (
                                        "set_flow"
                                        if attack in {"broker_escalation", "direct_socket"}
                                        else operation
                                    )
                                    payload = (
                                        77.0
                                        if attack in {"broker_escalation", "direct_socket"}
                                        else value
                                    )
                                    result = demo.PumpSocketAdapter(socket_path).execute(
                                        "pump-1", actual, payload
                                    )
                            except Exception as exc:
                                error = dict(type=type(exc).__name__, message=str(exc))
                            elapsed = (time.perf_counter() - start) * 1000
                            after = asdict(pump.state)
                            commands = (
                                [json.loads(line) for line in log.read_text().splitlines()]
                                if log.exists()
                                else []
                            )
                            forbidden = principal_id == "charlie" and any(
                                x["operation"] != "inspect" for x in commands
                            )
                            row = dict(
                                case_id=case,
                                session=repetition,
                                repeat=repetition,
                                mode=mode,
                                concrete_executor="ObjectPolicyHostExecutor/ObjectBrokerDispatcher"
                                if mode == "production_composition"
                                else "trusted reference harness/PumpSocketAdapter",
                                source_revision=digest,
                                host=platform.node(),
                                principal=serial(principal),
                                policy_identity=hashlib.sha256(demo.POLICY.encode()).hexdigest(),
                                manifest_identity=hashlib.sha256(
                                    demo.MANIFEST.encode()
                                ).hexdigest(),
                                grant_identity=grant.digest if grant else "not-applicable",
                                grant=serial(grant),
                                attempted_operation=args,
                                authorization="granted"
                                if grant
                                else "not-applicable"
                                if mode == "transport_only"
                                else "denied",
                                lowering=serial(dispatcher.lowering_records()),
                                activation=receipt or "not-applicable",
                                effect_trace=commands,
                                resource_before=before,
                                resource_after=after,
                                observed_effect=forbidden,
                                legitimate_result=case.startswith("allowed")
                                and bool(commands)
                                and commands[-1]["operation"] == operation,
                                result=result,
                                error=error,
                                elapsed_ms=elapsed,
                            )
                            stream.write(json.dumps(row, sort_keys=True) + "\n")
                            stream.flush()
                        finally:
                            server.shutdown()
                            server.server_close()
                            thread.join()
            print(f"Pump repetition {repetition} complete", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    run(args.output, args.repetitions)
