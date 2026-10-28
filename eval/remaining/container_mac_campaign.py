"""Real controller restarts apply changed operator MAC to native Docker work."""

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from container_dispatcher_campaign import absent, identities
from container_executor_probe import IMAGE, SOURCE, compute
from langchain_core.messages import AIMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    Principal,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher


def child(request_path):
    request = json.loads(request_path.read_text())
    root = Path(request["root"])
    source = root / "compute.py"
    dispatcher = DockerObjectDispatcher(
        {
            "compute": LinuxToolSpec(
                "compute:compute", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        image=IMAGE,
        private_roots=[root],
    )
    result = {"phase": request["phase"], "calls": [], "pid": os.getpid()}
    try:
        security = cedar_security(
            compute,
            manifest="runs linux\nfs read @{path} need\nfs read @{private} want",
            policy="permit(principal,action,resource);",
            dispatcher=dispatcher,
        )
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode([compute]))
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        config = with_principal(
            {}, Principal("alice", frozenset(), frozenset(), "session"), modules=security.modules
        )
        for index in range(2 if request["phase"] == "broad" else 1):
            state = {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "compute",
                                "id": f"{request['phase']}-{index}",
                                "args": {
                                    "path": str(root / "allowed.json"),
                                    "private": str(root / "private.txt"),
                                    "seed": request["phase"] == "broad" and index == 0,
                                },
                            }
                        ],
                    )
                ]
            }
            output = (
                asyncio.run(graph.ainvoke(state, config))
                if request["async"]
                else graph.invoke(state, config)
            )
            message = output["messages"][-1]
            result["calls"].append(
                {
                    "status": message.status,
                    "content": message.content,
                    "execution": dict(dispatcher.execution_records()[-1]),
                    "receipt": dispatcher.activation_receipts()[-1].canonical(),
                }
            )
        try:
            install_mac_policy("forbid(principal, action, resource) when {false};")
        except RuntimeError as exc:
            result["replacement_refusal"] = str(exc)
    finally:
        dispatcher.close()
        result["cleanup"] = [
            absent(dispatcher, c["execution"]["container_id"]) for c in result["calls"]
        ]
        Path(request["result"]).write_text(json.dumps(result, indent=2) + "\n")


def verify_pair(row):
    try:
        broad, narrow = row["controllers"]
        assert broad["returncode"] == narrow["returncode"] == 0
        a, b = broad["result"], narrow["result"]
        assert a["pid"] != b["pid"]
        assert a["phase"] == "broad" and b["phase"] == "narrow"
        first, reuse = a["calls"]
        (last,) = b["calls"]
        for call, prior, private in (
            (first, False, True),
            (reuse, True, True),
            (last, False, False),
        ):
            assert call["status"] == "success"
            value = json.loads(call["content"])
            assert value["sum"] == 41 and value["residual"] is prior
            if private:
                assert value["private"] == "PRIVATE_CANARY"
            else:
                assert "private" not in value and value["private_error"] == "FileNotFoundError"
            assert call["receipt"]["mode"] == "enforced"
            assert len(call["receipt"]["activated_obligations"]) == (2 if private else 1)
        assert first["execution"]["container_id"] == reuse["execution"]["container_id"]
        assert first["execution"]["container_id"] != last["execution"]["container_id"]
        assert first["execution"]["identity_digest"] != last["execution"]["identity_digest"]
        for controller in (a, b):
            assert "already installed" in controller["replacement_refusal"]
            assert all(
                c["returncode"] == 0 and not c["stdout"].strip() for c in controller["cleanup"]
            )
        return True
    except (KeyError, AssertionError, ValueError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    if args.output is None or args.repetitions < 1:
        parser.error("output and positive repetitions required")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    before = identities()
    driver = Path(__file__).resolve()
    before[str(driver.relative_to(driver.parents[2]))] = hashlib.sha256(
        driver.read_bytes()
    ).hexdigest()
    for path, digest in before.items():
        target = args.output / "sources" / digest
        target.parent.mkdir(exist_ok=True)
        target.write_bytes((driver.parents[2] / path).read_bytes())
    rows = []
    for repetition in range(args.repetitions):
        row = {"repetition": repetition, "async": bool(repetition % 2), "controllers": []}
        with tempfile.TemporaryDirectory(prefix="slg-operator-restart-") as tmp:
            root = Path(tmp)
            (root / "compute.py").write_text(SOURCE)
            (root / "allowed.json").write_text("[7, 11, 23]")
            (root / "private.txt").write_text("PRIVATE_CANARY")
            for phase in ("broad", "narrow"):
                output = args.output / f"{repetition:02d}-{phase}"
                output.mkdir()
                policy_dir = root / phase
                policy_dir.mkdir(mode=0o700)
                policy = (
                    "forbid(principal, action, resource) when {false};"
                    if phase == "broad"
                    else 'forbid(principal, action == slangGraph::Action::"fs::read", resource) '
                    "when {resource.selector == " + json.dumps(str(root / "private.txt")) + "};"
                )
                (policy_dir / "mac.cedar").write_text(policy)
                (output / "operator.cedar").write_text(policy)
                request = {
                    "root": str(root),
                    "phase": phase,
                    "async": row["async"],
                    "result": str(output / "result.json"),
                }
                (output / "request.json").write_text(json.dumps(request))
                with (
                    (output / "stdout.log").open("w") as stdout,
                    (output / "stderr.log").open("w") as stderr,
                ):
                    process = subprocess.run(
                        [sys.executable, str(driver), "--child", str(output / "request.json")],
                        env={**os.environ, "LANGGRAPH_MAC_DIR": str(policy_dir)},
                        stdout=stdout,
                        stderr=stderr,
                        timeout=90,
                    )
                row["controllers"].append(
                    {
                        "phase": phase,
                        "returncode": process.returncode,
                        "result": json.loads((output / "result.json").read_text())
                        if (output / "result.json").exists()
                        else None,
                    }
                )
        rows.append(row)
        (args.output / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(repetition, verify_pair(row), flush=True)
    after = identities()
    after[str(driver.relative_to(driver.parents[2]))] = hashlib.sha256(
        driver.read_bytes()
    ).hexdigest()
    passed = all(verify_pair(row) for row in rows) and before == after
    report = {
        "passed": passed,
        "pairs": len(rows),
        "source_before": before,
        "source_after": after,
        "scope": "operator changes across graceful controller restart; no crash-reclamation claim",
    }
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    raise SystemExit(not passed)


if __name__ == "__main__":
    main()
