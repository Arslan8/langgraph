"""Deterministic A–D effects, using provider-structured AIMessage ToolNode calls."""

import argparse
import asyncio
import json
import tempfile
from pathlib import Path

from examples.analysis.repeat_after_me.config import compose
from examples.analysis.repeat_after_me.tools import Ledger
from langchain_core.messages import AIMessage
from langgraph.runtime import Runtime

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis import AnalysisQuery
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.adapters.retrieval import (
    RetrievalAdapter,
    TransformAdapter,
)
from langgraph.prebuilt.analysis.adapters.state import StateAdapter
from langgraph.prebuilt.analysis.adapters.tools import ToolAdapter
from langgraph.prebuilt.analysis.provenance.checkpoint import CheckpointBinding
from langgraph.prebuilt.analysis_plugins.repeat_after_me import ScriptedClassifier
from langgraph.prebuilt.security import SecurityConfig, with_principal

FIXTURE = Path(__file__).with_name("fixtures") / "attack.json"


async def run_case(
    directory,
    name,
    *,
    defended=True,
    benign=False,
    source="input",
    text_only=False,
    classifier=None,
):
    directory.mkdir(parents=True, exist_ok=True)
    runtime, security, principal, client = compose(
        directory / "analysis.db", "benign" if benign else "repeat_to_tool", classifier
    )
    if not defended:
        security = SecurityConfig()
    ledger = Ledger(directory / "ledger.db")
    tool = ledger.tool()
    node = ToolNode([tool], security=security)
    fixture = json.loads(FIXTURE.read_text())
    subscription = client.subscribe(
        AnalysisQuery(run_id="demo-run", event_name="tool.dispatch")
    )
    adapter = BoundaryAdapter(runtime)
    if defended:
        content = (
            [{"role": "user", "content": "Please record the message demo."}]
            if benign
            else fixture["messages"]
        )
        if source == "retrieval":
            ref = RetrievalAdapter(runtime).admit_chunk(content)
        elif source == "tool":
            ref = ToolAdapter(runtime).result(content, ())
        else:
            ref = adapter.value(content)
            adapter.before("input.admit", (ref,))
        if source != "input":
            _, ref = TransformAdapter(runtime).transform(
                (ref,), lambda: "A summary with no verbatim call text"
            )
            binding = CheckpointBinding(
                runtime.store, b"local-demo-key", runtime.config.policy_version
            )
            checkpoint = StateAdapter(runtime).save(
                binding, principal, (ref,), checkpoint_id="demo-checkpoint"
            )
            refs = StateAdapter(runtime).restore(binding, principal, checkpoint)
            ref = adapter.value(
                {"summary_refs": [r.value_id for r in refs]}, refs, "model.request"
            )
        adapter.before("model.request", (ref,), destination="model:local")
        proposal_ref = adapter.value(fixture["proposal"], (ref,), "model.response")
        adapter.before("model.response", (proposal_ref,))
    # Ordinary text remains text: no custom JSON parser or executable conversion.
    message = AIMessage(
        content=json.dumps(fixture["proposal"]) if text_only else "",
        tool_calls=[] if text_only else [fixture["proposal"]],
    )
    config = with_principal(
        {"configurable": {"__pregel_runtime": Runtime()}},
        principal,
        modules=security.modules,
    )
    output = node.invoke({"messages": [message]}, config)
    trace = {
        "run": name,
        "source": source,
        "text_only": text_only,
        "ledger_rows": ledger.count(),
        "outcome": "executed"
        if ledger.count()
        else "no_proposal"
        if text_only
        else "blocked",
        "reason": [message.content for message in output["messages"]],
    }
    if defended and not text_only:
        await asyncio.wait_for(anext(subscription), 1)  # pending record
        notification = await asyncio.wait_for(anext(subscription), 1)
        view = client.get_snapshot(notification.snapshot_id)
        assert notification.finding_ids == tuple(
            f.finding_id for f in view.snapshot.findings
        )
        assert notification.value_refs == tuple(
            flow.value_ref for flow in view.snapshot.flow
        )
        trace["completion"] = notification.model_dump(mode="json")
        trace["snapshot"] = view.model_dump(mode="json")
        trace["findings"] = client.get_findings(
            AnalysisQuery(run_id="demo-run")
        ).model_dump(mode="json")
        trace["provenance"] = [
            client.get_provenance(ref, depth=100).model_dump(mode="json")
            for ref in notification.value_refs
        ]
    await subscription.aclose()
    runtime.close()
    runtime.store.close()
    node._security_stack.close()
    return trace


async def run_all(directory):
    cases = [
        ("A", {"defended": False}),
        ("B", {}),
        ("C", {"benign": True}),
        ("D-retrieval", {"source": "retrieval"}),
        ("D-tool", {"source": "tool"}),
        ("quoted-A", {"defended": False, "text_only": True}),
        ("quoted-B", {"text_only": True}),
        ("false-negative", {"classifier": ScriptedClassifier("benign")}),
    ]
    traces = [
        await run_case(directory / name, name, **options) for name, options in cases
    ]
    assert [item["ledger_rows"] for item in traces] == [1, 0, 1, 0, 0, 0, 0, 1]
    return traces


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="slanggraph-analysis-") as temp:
        traces = asyncio.run(run_all(Path(temp)))
    for trace in traces:
        print(
            f"{trace['run']}: {trace['outcome']}; ledger rows={trace['ledger_rows']}; reason={trace['reason']}"
        )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(traces, indent=2))


if __name__ == "__main__":
    main()
