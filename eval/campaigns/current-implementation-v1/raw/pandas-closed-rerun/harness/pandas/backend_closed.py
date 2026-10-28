"""Headless C-closed backend for the unchanged pandas vendor graph.

Mirrors the pandas path of `apps/backend.py` (same model client, observer
events with the campaign's monotonic timestamps, agent constructor arguments,
workflow contract and output projection). The differences are confined to
`integration_closed.py`: closed-admission recompilation of every vendor graph,
the `dataset_read` input path and the closed compute dispatch graph.
"""

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("request", type=Path)
    args = parser.parse_args()
    request = json.loads(args.request.read_text())
    if request["configuration"] != "C-closed" or request["app"] != "pandas":
        raise ValueError("backend_closed runs only the pandas C-closed configuration")
    root = Path(request["slanggraph_root"])
    sys.path[:0] = [
        str(root / "libs/prebuilt"),
        str(root / "libs/langgraph"),
        str(root / "libs/checkpoint"),
    ]
    import pandas as pd
    from ai_data_science_team import (
        DataVisualizationAgent,
        DataWranglingAgent,
        PandasDataAnalyst,
    )
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt.security import SqliteAuditSink

    here = Path(__file__).resolve().parent

    def load(name, filename):
        spec = importlib.util.spec_from_file_location(name, here / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    closed = load("pandas_integration_closed", "integration_closed.py")
    events = Path(request["events"])

    class Observer(BaseCallbackHandler):
        def on_llm_start(self, serialized, prompts, **kwargs):
            with events.open("a") as stream:
                stream.write(
                    json.dumps(
                        {
                            "kind": "model_start",
                            "monotonic": time.perf_counter(),
                            "prompts": prompts,
                        }
                    )
                    + "\n"
                )

        def on_llm_end(self, response, **kwargs):
            with events.open("a") as stream:
                stream.write(
                    json.dumps(
                        {
                            "kind": "model_end",
                            "monotonic": time.perf_counter(),
                            "response": response.model_dump(),
                        },
                        default=str,
                    )
                    + "\n"
                )

        def on_tool_start(self, serialized, input_str, **kwargs):
            with events.open("a") as stream:
                stream.write(json.dumps({"kind": "tool_start", "input": input_str}) + "\n")

        def on_llm_error(self, error, **kwargs):
            with events.open("a") as stream:
                stream.write(
                    json.dumps({"kind": "model_error", "error_type": type(error).__name__}) + "\n"
                )

    settings = request["model"]
    extra = {}
    if "reasoning_effort" in settings:
        extra["reasoning_effort"] = settings["reasoning_effort"]
    llm = ChatOpenAI(
        model=settings["name"],
        base_url=settings["base_url"],
        api_key="ollama",
        temperature=settings["temperature"],
        seed=settings["seed"],
        timeout=settings["timeout_seconds"],
        max_retries=settings["max_retries"],
        callbacks=[Observer()],
        **extra,
    )
    audit = SqliteAuditSink(events.parent / "security.sqlite")
    dispatch = closed.install_compute(request, audit)
    declarations = request["trusted_declarations"]

    wrangling = DataWranglingAgent(
        model=llm, log=False, bypass_recommended_steps=True, n_samples=100
    )
    visualization = DataVisualizationAgent(model=llm, n_samples=100, log=False)
    closed_wrangling = closed.close_graph(
        "data_wrangling_agent",
        wrangling._compiled_graph,
        declarations["data_wrangling_agent"],
        audit,
    )
    closed_visualization = closed.close_graph(
        "data_visualization_agent",
        visualization._compiled_graph,
        declarations["data_visualization_agent"],
        audit,
    )
    contract = load("pandas_workflow_contract", "workflow_contract.py")
    if request["workflow_contract"] not in contract.VERSIONS:
        raise ValueError("Unsupported workflow contract")
    # The outer vendor graph captures `agent._compiled_graph` at construction,
    # so the closed nested graphs are installed before PandasDataAnalyst is built.
    wrangling._compiled_graph = contract.RequestPreservingStage(
        closed_wrangling, request["task"], "wrangling", request["workflow_contract"]
    )
    visualization._compiled_graph = contract.RequestPreservingStage(
        closed_visualization,
        request["task"],
        "visualization",
        request["workflow_contract"],
    )
    agent = PandasDataAnalyst(
        model=llm,
        data_wrangling_agent=wrangling,
        data_visualization_agent=visualization,
    )
    agent._compiled_graph = closed.close_graph(
        "pandas_data_analyst",
        agent._compiled_graph,
        declarations["pandas_data_analyst"],
        audit,
    )
    (events.parent / "closed-inventory.json").write_text(
        json.dumps(
            [
                closed.inventory("pandas_data_analyst", agent._compiled_graph),
                closed.inventory("data_wrangling_agent", closed_wrangling),
                closed.inventory("data_visualization_agent", closed_visualization),
                closed.inventory("compute_dispatch", dispatch),
            ],
            indent=2,
            default=str,
        )
        + "\n"
    )
    principal = closed.run_principal(request["run_id"])
    data_raw = closed.load_dataset(request, principal)
    if closed.normalization(request) is not None:
        data_raw = closed.json_state(data_raw.to_dict())
    agent.invoke_agent(
        max_retries=request["graph_retries"],
        user_instructions=request["task"],
        data_raw=data_raw,
        config=closed.principal_config(principal),
    )
    result = agent.get_response()
    table = result.get("data_wrangled")
    output = {
        "table": pd.DataFrame(table).to_dict(orient="records") if table is not None else None,
        "plot": result.get("plotly_graph"),
        "routing": result.get("routing_preprocessor_decision"),
        "state": result,
    }
    output["plot_native"] = output["plot"]
    try:
        output["plot"] = contract.portable_plot(output["plot"])
    except (TypeError, ValueError, KeyError) as exc:
        output["plot_normalization_error"] = str(exc)
    Path(request["output"]).write_text(json.dumps(output, default=str, indent=2) + "\n")


if __name__ == "__main__":
    main()
