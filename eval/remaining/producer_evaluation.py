"""Compare offline fixture requirements with manual input through unchanged Cedar."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from evidence_utils import serial
from langgraph.prebuilt.security import (
    CedarObjectAuthorizer,
    CedarPolicySet,
    EnforcementKind,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    parse_security_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = Path(__file__).with_name("requirement_producer.py")


def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=False)
    fixtures = [f'read_text("/fixtures/alice-{i}.txt")' for i in range(6)] + [
        'records.read("notes/alice")',
        'records.read("notes/bob")',
        'pump.inspect("pump-1")',
        'pump.set_flow("pump-1", 25)',
    ]
    manual = [
        dict(
            class_name="fs",
            operation="read",
            selector=f"/fixtures/alice-{i}.txt",
            requirement="need",
        )
        for i in range(6)
    ] + [
        dict(class_name="db_record", operation="read", selector="notes/alice", requirement="need"),
        dict(class_name="db_record", operation="read", selector="notes/bob", requirement="need"),
        dict(class_name="pump", operation="inspect", selector="pump-1", requirement="need"),
        dict(class_name="pump", operation="set_flow", selector="pump-1", requirement="need"),
    ]
    rows = []
    for i, source in enumerate(fixtures):
        p = subprocess.run(
            [sys.executable, str(PRODUCER)],
            input=source,
            text=True,
            capture_output=True,
            check=True,
        )
        requirements = json.loads(p.stdout)["requirements"]
        assert requirements == [manual[i]]
        rows.append(
            dict(
                case_id=f"fixture-{i}",
                source=source,
                manual=[manual[i]],
                produced=requirements,
                equal=True,
                producer_sha256=hashlib.sha256(PRODUCER.read_bytes()).hexdigest(),
            )
        )
    for source in [
        "read_text(path)",
        'unknown("x")',
        'records.read(resolve("alice"))',
        '__import__("os").system("id")',
    ]:
        p = subprocess.run(
            [sys.executable, str(PRODUCER)], input=source, text=True, capture_output=True
        )
        assert p.returncode == 2
        rows.append(
            dict(
                case_id="unsupported-" + str(len(rows)),
                source=source,
                exit_status=p.returncode,
                result=json.loads(p.stdout),
            )
        )
    # Real restricted-runtime execution for literal-file fixtures; separate exact vs
    # under/overdeclaration.
    with tempfile.TemporaryDirectory(prefix="slg-producer-") as tmp:
        tmp = Path(tmp)
        bob = tmp / "bob"
        bob.write_text("BOB_CANARY")
        for i in range(6):
            target = tmp / f"alice-{i}"
            target.write_text(f"allowed-{i}")
            module_path = tmp / f"fixture_{i}.py"
            module_path.write_text(
                (
                    "from langchain_core.tools import tool\nfrom langgraph.pr"
                    "ebuilt.security.inprocess import read_text\n@tool\ndef ru"
                    'n() -> str:\n    """Literal file fixture."""\n    return '
                    "read_text("
                )
                + repr(str(target))
                + ")\n"
            )
            spec = importlib.util.spec_from_file_location(f"fixture_{i}", module_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            produced = json.loads(
                subprocess.check_output(
                    [sys.executable, str(PRODUCER)], input=f"read_text({str(target)!r})", text=True
                )
            )["requirements"]
            policy = (
                'permit(principal,action == slangGraph::Action::"fs::read",resource) '
                f'when {{resource.selector == "{target}"}};'
            )
            for condition in ["manual", "produced", "underdeclared", "overdeclared"]:
                requirement = (
                    produced[0]
                    if condition == "produced"
                    else dict(class_name="fs", operation="read", selector=str(target))
                )
                manifest = "runs inprocess\n" + (
                    "returns normal"
                    if condition == "underdeclared"
                    else f"fs read {requirement['selector']} need"
                )
                if condition == "overdeclared":
                    manifest += f"\nfs read {bob} need"
                error = None
                result = None
                security = None
                try:
                    security = cedar_security(module.run, manifest=manifest, policy=policy)
                    principal = Principal("alice", frozenset(), frozenset(), "producer")
                    call = ToolCall(
                        Tool("run", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                        {},
                        {},
                        f"{i}-{condition}",
                        0,
                    )
                    result = security.host_executor.invoke(principal, call, ())
                except Exception as exc:
                    error = dict(type=type(exc).__name__, message=str(exc))
                rows.append(
                    dict(
                        case_id=f"execution-{i}",
                        mode=condition,
                        manifest=manifest,
                        policy=policy,
                        grant=serial(security.host_executor.authorization_grants())
                        if security
                        else [],
                        result=serial(result),
                        error=error,
                        legitimate_result=result is not None and result.value == f"allowed-{i}",
                        observed_effect=result is not None and "BOB_CANARY" in str(result.value),
                    )
                )
    import sqlite3
    import threading

    from composition import record_task
    from langgraph.prebuilt.security import (
        SQLITE_RECORD_SCHEMA,
        ObjectPolicyHostExecutor,
        sqlite_record_mediator,
    )
    from langgraph.prebuilt.security.mediators.records import RECORDS
    from pump_composition import demo, sim

    for index in range(6, 10):
        requirement = manual[index]
        for condition in ["manual", "produced"]:
            req = (
                requirement
                if condition == "manual"
                else json.loads(
                    subprocess.check_output(
                        [sys.executable, str(PRODUCER)], input=fixtures[index], text=True
                    )
                )["requirements"][0]
            )
            with tempfile.TemporaryDirectory(prefix="slg-producer-typed-") as folder:
                folder = Path(folder)
                server = None
                if req["class_name"] == "db_record":
                    database = folder / "records.sqlite"
                    with sqlite3.connect(database) as conn:
                        conn.execute(SQLITE_RECORD_SCHEMA)
                        conn.executemany(
                            "INSERT INTO records VALUES (?,?)",
                            [("alice", "allowed"), ("bob", "BOB_CANARY")],
                        )
                    worker = Path(__file__).with_name("record_worker.py")
                    dispatcher = ObjectBrokerDispatcher(
                        {
                            "record_task": LinuxToolSpec(
                                "record_worker:run",
                                worker,
                                hashlib.sha256(worker.read_bytes()).hexdigest(),
                            )
                        },
                        runtime_roots=tuple(
                            Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
                        ),
                        mediators=(sqlite_record_mediator(database, database_id="notes"),),
                    )
                    manifest = "runs linux\ndb_record read " + req["selector"] + " need"
                    policy = (
                        'permit(principal, action == slangGraph::Action::"db_rec'
                        'ord::read", resource) when {resource.selector == "notes'
                        '/alice"};'
                    )
                    security = cedar_security(
                        record_task,
                        manifest=manifest,
                        classes=RECORDS.class_declaration(),
                        policy=policy,
                        dispatcher=dispatcher,
                    )
                    executor = security.host_executor
                    name = "record_task"
                    arguments = dict(
                        record=req["selector"],
                        operation=req["operation"],
                        attack="none",
                        database=str(database),
                    )
                    principal_id = "alice"
                else:
                    socket_path = folder / "pump.sock"
                    pump = sim.Pump(folder / "commands.jsonl")
                    server = sim.PumpServer(socket_path, pump)
                    thread = threading.Thread(
                        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
                    )
                    thread.start()
                    _, security = demo.build_demo(socket_path, "cedar")
                    dispatcher = security.host_executor.dispatcher
                    manifest = (
                        "runs linux\npump " + req["operation"] + " " + req["selector"] + " need"
                    )
                    parsed = parse_security_manifest(
                        demo.CLASSES + "\ntool control_pump {\n" + manifest + "\n}",
                        enforcers={EnforcementKind.BROKER: dispatcher},
                    )
                    authorizer = CedarObjectAuthorizer(
                        parsed,
                        CedarPolicySet(
                            {"control_pump": "permit(principal, action, resource);"}, demo.POLICY
                        ),
                    )
                    executor = ObjectPolicyHostExecutor(
                        authorizer, dispatcher, tool_owners={"control_pump": "application"}
                    )
                    name = "control_pump"
                    arguments = dict(
                        device_id=req["selector"],
                        operation=req["operation"],
                        value=25.0 if req["operation"] == "set_flow" else None,
                    )
                    principal_id = "alice"
                result = None
                error = None
                try:
                    principal = Principal(principal_id, frozenset(), frozenset(), "producer-typed")
                    call = ToolCall(
                        Tool(name, ToolDac("owner", {"*": "x"}), frozenset(), ()),
                        arguments,
                        {},
                        condition,
                        0,
                    )
                    result = executor.invoke(principal, call, ())
                except Exception as exc:
                    error = dict(type=type(exc).__name__, message=str(exc))
                finally:
                    if server:
                        server.shutdown()
                        server.server_close()
                        thread.join()
                rows.append(
                    dict(
                        case_id=f"execution-{index}",
                        mode=condition,
                        requirements=[req],
                        manifest=manifest,
                        grant=serial(executor.authorization_grants()),
                        result=serial(result),
                        error=error,
                        lowering=serial(dispatcher.lowering_records()),
                        audit=serial(dispatcher.audit_records()),
                        legitimate_result=result is not None,
                        observed_effect=result is not None and "BOB_CANARY" in str(result.value),
                    )
                )
    (output / "trials.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    (output / "scope.json").write_text(
        json.dumps(
            dict(
                fixture_count=10,
                unknown_forms=4,
                file_execution_conditions=4,
                typed_resource_execution=(
                    "comparison of requirement output only; composition evid"
                    "ence separately tests record/pump production routes"
                ),
                trusted_boundary=(
                    "offline subprocess emits requirements; no generated pol"
                    "icy or privileged plugin"
                ),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
