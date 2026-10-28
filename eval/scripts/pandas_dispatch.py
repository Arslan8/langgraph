"""Deterministic checks at the real added Pandas ToolNode boundary."""

import ast
import hashlib
import importlib.util
import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "libs/prebuilt"), str(ROOT / "libs/langgraph")]
os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGSMITH_TRACING"] = "false"


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "benchmark.py").write_bytes(Path(__file__).read_bytes())
    seed = ROOT / "eval/results/pandas-C-february-r1-cd25840ffd594f5a896b160041a2b6a4"
    events = [json.loads(line) for line in (seed / "events.jsonl").read_text().splitlines()]
    payload = next(e["payload"] for e in events if e["kind"] == "computation")
    plan = {
        "kind": "deterministic added-boundary checks",
        "configurations": ["B", "C"],
        "A": "N/A: this dispatch boundary does not exist in A",
        "repetitions": 1,
        "cases": {
            "allowed": "authorized role and complete arguments; effect required",
            "wrong-role": "guest role; deny before effect",
            "missing-field": "omit sandbox_source; reject before effect",
            "unknown-tool": "unregistered tool name; reject before effect",
        },
        "source_run": seed.name,
        "policy_version": 3,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "oracle": (
            "Unique allowed output marker checked independently; tool status "
            "and audit records retained."
        ),
    }
    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    import ai_data_science_team.agents.data_wrangling_agent as wrangling
    import ai_data_science_team.utils.sandbox as sandbox
    from langchain_core.messages import AIMessage
    from langgraph.prebuilt.security import Principal, SqliteAuditSink, with_principal

    spec = importlib.util.spec_from_file_location(
        "pandas_dispatch_integration", ROOT / "eval/apps/pandas/integration.py"
    )
    integration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(integration)
    results = []
    for config in ["B", "C"]:
        for case in plan["cases"]:
            case_id = config + "-" + case
            folder = out / case_id
            folder.mkdir()
            fixture = Path(tempfile.mkdtemp(prefix="slanggraph-dispatch-"))
            (fixture / "outputs").mkdir()
            import pandas as pd

            pd.DataFrame(payload["data"]).to_csv(fixture / "sales.csv", index=False)
            request = json.loads((seed / "request.json").read_text())
            policy = (
                (seed / "policy.slp").read_text().replace(request["fixture_root"], str(fixture))
            )
            (folder / "policy.slp").write_text(policy)
            request.update(
                configuration=config,
                fixture_root=str(fixture),
                events=str(folder / "events.jsonl"),
                effective_policy=str(folder / "policy.slp"),
                run_id=case_id,
            )
            integration.install(request)
            # Inspect only the evaluation adapter's closure to reach its exact
            # production boundary; do not reconstruct a different graph.
            bound = inspect.getclosurevars(wrangling.run_code_sandboxed_subprocess).nonlocals
            graph = bound["node_graph"]
            marker = fixture / "outputs" / "boundary-witness.csv"
            tree = ast.parse(payload["code"])
            function = next(x for x in tree.body if isinstance(x, ast.FunctionDef))
            function.body[-1:-1] = ast.parse(
                f"pd.DataFrame({{'witness': [{case_id!r}]}}).to_csv({str(marker)!r}, index=False)"
            ).body
            candidate = {**payload, "code": ast.unparse(ast.fix_missing_locations(tree))}
            arguments = {
                "sandbox_source": str(Path(sandbox.__file__).resolve()),
                "payload": candidate,
            }
            if case == "missing-field":
                arguments.pop("sandbox_source")
            principal = Principal(
                "alice",
                frozenset({"guest" if case == "wrong-role" else "analyst"}),
                frozenset(),
                case_id,
            )
            call = {
                "name": "unregistered" if case == "unknown-tool" else "compute",
                "args": arguments,
                "id": case_id,
            }
            (folder / "candidate.json").write_text(
                json.dumps({"call": call, "roles": sorted(principal.roles)}, indent=2) + "\n"
            )
            response = None
            exception = None
            try:
                response = graph.invoke(
                    {"messages": [AIMessage(content="", tool_calls=[call])]},
                    config=with_principal({}, principal),
                )
            except Exception as exc:
                exception = {"type": type(exc).__name__, "message": str(exc)}
            actual = marker.exists() and case_id in marker.read_text()
            messages = [m.model_dump(mode="json") for m in response["messages"]] if response else []
            returned_error = bool(messages) and messages[-1].get("status") == "error"
            verdict = {
                "configuration": config,
                "case": case,
                "effect_occurred": actual,
                "passed": actual
                if case == "allowed"
                else not actual and bool(exception or returned_error),
                "exception": exception,
                "messages": messages,
                "policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
                "audit_integrity": SqliteAuditSink(folder / "security.sqlite").verify(),
                "marker": str(marker),
            }
            if bound["executor"]:
                (folder / "activation-receipts.json").write_text(
                    json.dumps(
                        [r.canonical() for r in bound["executor"].activation_receipts()], indent=2
                    )
                    + "\n"
                )
            (folder / "result.json").write_text(json.dumps(verdict, indent=2) + "\n")
            results.append({k: v for k, v in verdict.items() if k not in {"messages", "exception"}})
    (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results))


if __name__ == "__main__":
    main()
