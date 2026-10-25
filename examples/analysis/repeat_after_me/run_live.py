"""Optional local Ollama replay or end-to-end attempt; no automatic downloads."""

import argparse
import asyncio
import json
import tempfile
import urllib.request
from pathlib import Path

from examples.analysis.repeat_after_me.config import compose
from examples.analysis.repeat_after_me.run_offline import FIXTURE, run_case
from examples.analysis.repeat_after_me.tools import Ledger
from langchain_core.messages import AIMessage, convert_to_messages
from langgraph.runtime import Runtime

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis.adapters.agent import AgentAdapter
from langgraph.prebuilt.analysis_plugins.repeat_after_me import LLMRepeatClassifier
from langgraph.prebuilt.security import with_principal


def local_classifier(model_name="llama3.1:8b"):
    from langchain_ollama import ChatOllama  # noqa: PLC0415 - optional live provider

    with urllib.request.urlopen(
        "http://localhost:11434/api/version", timeout=5
    ) as response:
        version = json.load(response)["version"]
    with urllib.request.urlopen(
        "http://localhost:11434/api/tags", timeout=5
    ) as response:
        models = json.load(response)["models"]
    model_digest = next(item["digest"] for item in models if item["name"] == model_name)
    model = ChatOllama(
        model=model_name, temperature=0, num_predict=512, client_kwargs={"timeout": 30}
    )
    return model, LLMRepeatClassifier(
        model, model_digest=model_digest, service_version=version
    )


async def live_agent(directory, model, classifier):
    runtime, security, principal, client = compose(
        directory / "analysis.db", classifier=classifier
    )
    ledger = Ledger(directory / "ledger.db")
    tool = ledger.tool()
    node = ToolNode([tool], security=security)
    adapter = AgentAdapter(runtime)
    fixture = json.loads(FIXTURE.read_text())
    messages = convert_to_messages(fixture["messages"])
    await adapter.aadmit(messages)
    config = with_principal(
        {"configurable": {"__pregel_runtime": Runtime()}},
        principal,
        modules=security.modules,
    )
    defended = adapter.wrap(
        model.bind_tools([tool]),
        tool_schemas=[tool.get_input_schema().model_json_schema()],
        destination="model:local",
        object_router=node._security_object_router,
    )
    response = await defended.ainvoke(messages, config)
    result = (
        await node.ainvoke({"messages": [response]}, config)
        if isinstance(response, AIMessage) and response.tool_calls
        else None
    )
    trace = {
        "classifier_configuration": classifier.configuration,
        "proposal": response.tool_calls if isinstance(response, AIMessage) else [],
        "enforcement": str(result),
        "ledger_rows": ledger.count(),
        "outcome": "attack not reproduced"
        if not getattr(response, "tool_calls", None)
        else "executed"
        if ledger.count()
        else "blocked",
    }
    runtime.close()
    runtime.store.close()
    node._security_stack.close()
    return trace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("replay", "agent"), default="replay")
    parser.add_argument("--model", default="llama3.1:8b")
    args = parser.parse_args()
    model, classifier = local_classifier(args.model)
    with tempfile.TemporaryDirectory(prefix="slanggraph-live-") as temp:
        directory = Path(temp)
        trace = asyncio.run(
            run_case(directory, "live-replay", classifier=classifier)
            if args.mode == "replay"
            else live_agent(directory, model, classifier)
        )
    print(
        json.dumps(
            {"configuration": classifier.configuration, "result": trace}, indent=2
        )
    )


if __name__ == "__main__":
    main()
