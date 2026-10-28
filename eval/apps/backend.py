"""Headless adapter to the bundled apps' backend; no copied graph implementation.

This runs in the upstream environment. UI upload, history and rendering are excluded.
"""

import argparse
import asyncio
import importlib.util
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("request", type=Path)
    args = parser.parse_args()
    request = json.loads(args.request.read_text())
    if request.get("integration"):
        root = Path(request["slanggraph_root"])
        sys.path[:0] = [
            str(root / "libs/prebuilt"),
            str(root / "libs/langgraph"),
            str(root / "libs/checkpoint"),
        ]
    import pandas as pd
    import sqlalchemy as sql
    from ai_data_science_team import (
        DataVisualizationAgent,
        DataWranglingAgent,
        PandasDataAnalyst,
    )
    from ai_data_science_team.agents import SQLDatabaseAgent
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_openai import ChatOpenAI

    events = Path(request["events"])

    class Observer(BaseCallbackHandler):
        def on_llm_start(self, serialized, prompts, **kwargs):
            with events.open("a") as stream:
                stream.write(json.dumps({"kind": "model_start", "prompts": prompts}) + "\n")

        def on_llm_end(self, response, **kwargs):
            with events.open("a") as stream:
                stream.write(
                    json.dumps(
                        {"kind": "model_end", "response": response.model_dump()}, default=str
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
    # Only a local endpoint and a public dummy key are supported by this pilot adapter.
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
    fixture = Path(request["fixture_root"])
    if request.get("integration"):
        integration_path = Path(__file__).parent / "pandas/integration.py"
        spec = importlib.util.spec_from_file_location("pandas_integration", integration_path)
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        integration.install(request)
    if request["app"] == "pandas":
        wrangling = DataWranglingAgent(
            model=llm, log=False, bypass_recommended_steps=True, n_samples=100
        )
        visualization = DataVisualizationAgent(model=llm, n_samples=100, log=False)
        contract = None
        if request.get("workflow_contract"):
            contract_spec = importlib.util.spec_from_file_location(
                "pandas_workflow_contract", Path(__file__).parent / "pandas/workflow_contract.py"
            )
            contract = importlib.util.module_from_spec(contract_spec)
            contract_spec.loader.exec_module(contract)
            if request["workflow_contract"] not in contract.VERSIONS:
                raise ValueError("Unsupported workflow contract")
            wrangling._compiled_graph = contract.RequestPreservingStage(
                wrangling._compiled_graph,
                request["task"],
                "wrangling",
                request["workflow_contract"],
            )
            visualization._compiled_graph = contract.RequestPreservingStage(
                visualization._compiled_graph,
                request["task"],
                "visualization",
                request["workflow_contract"],
            )
        agent = PandasDataAnalyst(
            model=llm,
            data_wrangling_agent=wrangling,
            data_visualization_agent=visualization,
        )
        agent.invoke_agent(
            max_retries=request.get("graph_retries", 3),
            user_instructions=request["task"],
            data_raw=pd.read_csv(fixture / "sales.csv"),
        )
        result = agent.get_response()
        table = result.get("data_wrangled")
        output = {
            "table": pd.DataFrame(table).to_dict(orient="records") if table is not None else None,
            "plot": result.get("plotly_graph"),
            "routing": result.get("routing_preprocessor_decision"),
            "state": result,
        }
        if contract is not None:
            output["plot_native"] = output["plot"]
            try:
                output["plot"] = contract.portable_plot(output["plot"])
            except (TypeError, ValueError, KeyError) as exc:
                output["plot_normalization_error"] = str(exc)
    else:
        engine = sql.create_engine("sqlite:///" + str(fixture / "sales.sqlite"))

        @sql.event.listens_for(engine, "connect")
        def observe_sql(connection, _):
            def record(statement):
                with events.open("a") as stream:
                    stream.write(json.dumps({"kind": "sql", "statement": statement}) + "\n")

            connection.set_trace_callback(record)

        with engine.connect() as connection:
            agent = SQLDatabaseAgent(
                model=llm,
                connection=connection,
                n_samples=1,
                log=False,
                bypass_recommended_steps=True,
            )
            asyncio.run(agent.ainvoke_agent(user_instructions=request["task"]))
            table = agent.get_data_sql()
            output = {
                "table": pd.DataFrame(table).to_dict(orient="records")
                if table is not None
                else None,
                "sql": agent.get_sql_query_code(),
                "state": agent.response,
            }
        engine.dispose()
    Path(request["output"]).write_text(json.dumps(output, default=str, indent=2) + "\n")


if __name__ == "__main__":
    main()
