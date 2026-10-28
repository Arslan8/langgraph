# ruff: noqa: E501
"""Third-resource integration: brokered local HTTP records and direct bypasses."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    EnforcementKind,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    ResourceSupport,
    SupportLevel,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    install_mac_policy,
)
from langgraph.prebuilt.security.resource_mediator import ResourceMediatorAdapter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

CLASSES = """class http_record {
  operations read modify
  object record
  normalizer identity
  attrs
  enforced_by broker
  lowering local.http.v1
}"""
MANIFEST = """runs linux
map operation=read http_record read @{record} need
map operation=modify http_record modify @{record} need
returns sensitive"""
POLICY = """permit(principal == slangGraph::User::"alice", action == slangGraph::Action::"http_record::read", resource) when { resource.selector == "alice" };
permit(principal == slangGraph::User::"admin", action in [slangGraph::Action::"http_record::read", slangGraph::Action::"http_record::modify"], resource) when { resource.selector == "alice" };"""
OPERATOR_POLICY = """forbid(principal, action == slangGraph::Action::"http_record::modify", resource) unless { principal == slangGraph::User::"admin" };"""
CASES = (
    ("allowed_read", "alice", "read", "none"),
    ("broker_modify_during_read", "alice", "read", "broker_modify"),
    ("direct_read_bob", "alice", "read", "direct_read_bob"),
    ("direct_modify_during_read", "alice", "read", "direct_modify"),
    ("allowed_admin_modify", "admin", "modify", "none"),
)


@tool("http_task")
def http_task(record: str, operation: str, attack: str, base_url: str) -> dict:
    """Use one declared HTTP-record operation from a confined worker."""
    raise RuntimeError("unconfined fallback is forbidden")


class Store:
    def __init__(self, bob_marker: str) -> None:
        self.values = {"alice": "ALICE_HTTP", "bob": bob_marker}
        self.lock = threading.Lock()


def handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            key = self.path.removeprefix("/records/")
            with store.lock:
                value = store.values.get(key)
            self._reply(200 if value is not None else 404, {"value": value})

        def do_PUT(self):
            key = self.path.removeprefix("/records/")
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            with store.lock:
                store.values[key] = body["value"]
            self._reply(200, {"ok": True})

        def _reply(self, status: int, value: dict) -> None:
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    return Handler


def adapter(base_url: str) -> ResourceMediatorAdapter:
    def assess(line, host):
        if (
            line.enforcer is EnforcementKind.BROKER
            and line.class_name == "http_record"
            and line.operation in {"read", "modify"}
            and line.lowering == "local.http.v1"
        ):
            return ResourceSupport(
                SupportLevel.EXACT,
                "adapter fixes the URL record to the authorized selector and validates payload shape",
                "http-record-adapter-tests-v1",
            )
        return ResourceSupport(SupportLevel.UNSUPPORTED, "unsupported HTTP line")

    def invoke(line, payload, context):
        url = base_url + "/records/" + line.selector
        if line.operation == "read":
            if payload:
                raise ValueError("read payload must be empty")
            with urllib.request.urlopen(url, timeout=2) as response:
                return json.load(response)
        if set(payload) != {"value"} or type(payload["value"]) is not str:
            raise ValueError("modify payload requires one string value")
        request = urllib.request.Request(
            url,
            data=json.dumps({"value": payload["value"]}).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.load(response)

    return ResourceMediatorAdapter("local-http-record-v1", assess, invoke)


def run(output: Path, repetitions: int) -> None:
    output.mkdir(parents=True, exist_ok=False)
    worker = Path(__file__).with_name("http_worker.py")
    digest = hashlib.sha256(worker.read_bytes()).hexdigest()
    for name, text in (
        ("classes.slp", CLASSES),
        ("manifest.slp", MANIFEST),
        ("principal.cedar", POLICY),
        ("operator.cedar", OPERATOR_POLICY),
    ):
        (output / name).write_text(text + "\n")
    (output / "plan.json").write_text(
        json.dumps(
            {
                "cases": CASES,
                "repetitions": repetitions,
                "worker_sha256": digest,
                "adapter_file": str(Path(__file__).relative_to(ROOT)),
                "core_changes": [],
            },
            indent=2,
        )
        + "\n"
    )
    install_mac_policy(OPERATOR_POLICY)
    with (output / "trials.jsonl").open("w") as stream:
        for repetition in range(repetitions):
            for case_id, user, operation, attack in CASES:
                marker = "BOB_HTTP_" + uuid.uuid4().hex
                store = Store(marker)
                server = ThreadingHTTPServer(("127.0.0.1", 0), handler(store))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                base_url = f"http://127.0.0.1:{server.server_port}"
                try:
                    dispatcher = ObjectBrokerDispatcher(
                        {"http_task": LinuxToolSpec("http_worker:run", worker, digest)},
                        runtime_roots=tuple(
                            Path(item).resolve()
                            for item in sys.path
                            if item and Path(item).is_dir()
                        ),
                        mediators=(adapter(base_url),),
                    )
                    security = cedar_security(
                        http_task,
                        classes=CLASSES,
                        manifest=MANIFEST,
                        policy=POLICY,
                        dispatcher=dispatcher,
                    )
                    principal = Principal(user, frozenset(), frozenset(), f"http-{repetition}")
                    arguments = {
                        "record": "alice",
                        "operation": operation,
                        "attack": attack,
                        "base_url": base_url,
                    }
                    call = ToolCall(
                        Tool(
                            "http_task",
                            ToolDac("owner", {"*": "x"}),
                            frozenset(),
                            (),
                        ),
                        arguments,
                        {},
                        uuid.uuid4().hex,
                        0,
                    )
                    before = dict(store.values)
                    started = time.perf_counter()
                    result = None
                    error = None
                    receipt = None
                    try:
                        response = security.host_executor.invoke(principal, call, ())
                        result = response.value
                        receipt = serial(response.receipt)
                    except Exception as exc:
                        error = {"type": type(exc).__name__, "message": str(exc)}
                    after = dict(store.values)
                    legitimate = (
                        operation == "read"
                        and result
                        and result.get("legitimate") == {"value": "ALICE_HTTP"}
                    ) or (operation == "modify" and after["alice"] == "ADMIN_UPDATED")
                    unauthorized = marker in json.dumps(result) or (
                        user == "alice" and after != before
                    )
                    grants = security.host_executor.authorization_grants()
                    stream.write(
                        json.dumps(
                            {
                                "case_id": case_id,
                                "repeat": repetition,
                                "principal": serial(principal),
                                "attempted_operation": arguments,
                                "grant": serial(grants[-1]) if grants else None,
                                "lowering": serial(dispatcher.lowering_records()),
                                "mediator_decisions": serial(dispatcher.audit_records()),
                                "activation": receipt,
                                "resource_before": before,
                                "resource_after": after,
                                "legitimate_result": bool(legitimate),
                                "unauthorized_effect": unauthorized,
                                "result": result,
                                "error": error,
                                "elapsed_ms": (time.perf_counter() - started) * 1000,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    arguments = parser.parse_args()
    run(arguments.output, arguments.repetitions)
