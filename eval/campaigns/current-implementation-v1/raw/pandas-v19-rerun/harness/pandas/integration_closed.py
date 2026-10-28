"""C-closed: the unchanged pandas vendor graph under closed admission (D11).

Configuration C-closed differs from C only in where the security boundary is
drawn. In C, the vendor graphs run without any admission and only the
generated computation passes a separate secured `ToolNode` graph. In C-closed:

- every vendor graph that runs (the outer `PandasDataAnalyst` graph and both
  nested agents, which the outer node bodies invoke directly) is recompiled
  from its own builder with `SecurityConfig(closed_admission=True, ...)`,
  declaring exactly that graph's node names in `trusted_application_nodes`
  and its conditional branches in `trusted_application_branches` (D11). The
  declarations are pinned in the manifest and must equal the builder's names;
  nothing is inferred;
- generated computation goes through the same compute route as C: an exact
  `ToolNode` dispatching to `LinuxSandboxExecutor` with the selected Lean
  grant-v3 lifecycle checker. That dispatch graph is also compiled under
  closed admission (it declares nothing trusted; its single node is admitted
  as an exact `ToolNode`);
- the input dataset is read through the `dataset_read` runtime operation
  (`read_dataset`) against an operator registry pinned to the frozen sales
  fixture digest, with an authorizer that allows exactly that dataset for the
  run principal;
- every graph's final output is returned through the `OutputMediator` that
  closed compilation installs on the compiled graph.

No vendor file is edited. The vendor compiled graphs are only used for their
`.builder`; the node functions, branches, prompts and state schema are the
vendor's own objects.
"""

import hashlib
import importlib.util
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIGURATION = "C-closed"
DATASET_ID = "sales"
PRINCIPAL_ID = "alice"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lifecycle_checker(request):
    """Select the pinned grant-v3 checker exactly as `integration.py` does for C."""
    selection = request.get("lean_worker")
    if (
        request.get("configuration") != CONFIGURATION
        or type(selection) is not dict
        or set(selection) != {"binary", "sha256", "protocol"}
        or selection["protocol"] != "worker-route-grant-v3"
    ):
        raise ValueError("C-closed requires a selected grant-v3 Lean worker route")
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

    return LeanLifecycleChecker(binary_path=selection["binary"], binary_sha256=selection["sha256"])


def run_principal(run_id):
    from langgraph.prebuilt.security import Principal

    return Principal(PRINCIPAL_ID, frozenset({"analyst"}), frozenset(), run_id)


def principal_config(principal):
    from langgraph.prebuilt.security import with_principal

    return with_principal({}, principal)


# --- dataset_read -----------------------------------------------------------


def dataset_registry(path, sha256, max_bytes):
    from langgraph.prebuilt.security.dataset_operation import (
        DatasetEntry,
        DatasetRegistry,
    )

    return DatasetRegistry((DatasetEntry(DATASET_ID, str(path), sha256, max_bytes),))


def make_authorize(events):
    """Allow exactly `sales` for `alice`; deny everything else. Logs each decision."""
    from langgraph.prebuilt.security import Decision, Verdict

    def authorize(principal, request):
        allowed = (
            request.dataset_id == DATASET_ID
            and request.principal_id == PRINCIPAL_ID
            and principal.user_id == PRINCIPAL_ID
        )
        _event(
            events,
            {
                "kind": "dataset_authorize",
                "dataset_id": request.dataset_id,
                "principal_id": request.principal_id,
                "verdict": "allow" if allowed else "deny",
            },
        )
        if allowed:
            return Decision(Verdict.ALLOW, "pandas-closed: pinned sales fixture")
        return Decision(Verdict.DENY, "pandas-closed: dataset not granted")

    return authorize


STATE_NORMALIZATIONS = frozenset({"json-null-v1"})


def json_state(value):
    """JSON transport of controller state: string keys, non-finite floats -> null.

    `json-null-v1` (manifest-v21-closed). The vendor stores `df.to_dict()`
    (integer index keys, NaN for missing values) in graph state, which the
    closed graph's `OutputMediator` refuses (`output_data:string_key_required`,
    `output_data:nonfinite_float`). This applies the same JSON transport C
    already applies to the compute payload, plus NaN/Infinity -> `None`.
    """
    return json.loads(json.dumps(value), parse_constant=lambda _: None)


def normalization(request):
    selected = request.get("state_normalization")
    if selected is not None and selected not in STATE_NORMALIZATIONS:
        raise ValueError("Unsupported state normalization")
    return selected


def load_dataset(request, principal):
    """Read the pinned fixture via `read_dataset` and parse it as the vendor did."""
    import pandas as pd
    from langgraph.prebuilt.security.dataset_operation import read_dataset

    events = Path(request["events"])
    pin = request["dataset"]
    registry = dataset_registry(pin["path"], pin["sha256"], pin["max_bytes"])
    data = read_dataset(principal, DATASET_ID, registry=registry, authorize=make_authorize(events))
    _event(
        events,
        {
            "kind": "dataset_read",
            "dataset_id": DATASET_ID,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    )
    return pd.read_csv(io.BytesIO(data))


# --- closed compilation -----------------------------------------------------


def _security(declaration, audit, **extra):
    from langgraph.prebuilt.security import SecurityConfig

    return SecurityConfig(
        closed_admission=True,
        trusted_application_nodes=frozenset(declaration["nodes"]),
        trusted_application_branches=frozenset(declaration["branches"]),
        audit_sink=audit,
        **extra,
    )


def builder_names(builder):
    return (
        sorted(builder.nodes),
        sorted(
            f"{source}:branch:{name}"
            for source, named in builder.branches.items()
            for name in named
        ),
    )


def close_graph(label, compiled, declaration, audit):
    """Recompile a vendor graph's own builder under closed admission."""
    builder = compiled.builder
    nodes, branches = builder_names(builder)
    if nodes != sorted(declaration["nodes"]) or branches != sorted(declaration["branches"]):
        raise ValueError(f"Pinned trusted declaration differs from vendor graph: {label}")
    return builder.compile(
        checkpointer=compiled.checkpointer,
        name=compiled.name,
        security=_security(declaration, audit),
    )


def inventory(label, closed):
    from langgraph.prebuilt.security.admission import describe

    admitted = closed.builder._security_admission
    return {
        "graph": label,
        "descriptors": [describe(descriptor) for descriptor in admitted],
    }


# --- compute route (same executor, tool and policy as C) --------------------


def install_compute(request, audit):
    """Install the C compute bridge; its dispatch graph is closed-admitted.

    Returns the closed dispatch graph so its inventory can be recorded.
    """
    import ai_data_science_team.utils.sandbox as upstream
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.security import (
        DacOverrides,
        Effect,
        LinuxSandboxExecutor,
        LinuxToolSpec,
        ResourceArg,
        SecurityConfig,
        dac,
        effects,
        parse_profiles,
    )

    normalization(request)
    serialization = request["sandbox_serialization"]
    codec = _load("pandas_sandbox_codec_closed", "sandbox_codec.py")
    if serialization not in codec.VERSIONS:
        raise ValueError("Unsupported sandbox serialization version")
    source = Path(upstream.__file__).resolve()
    events = Path(request["events"])
    checker = lifecycle_checker(request)
    profiles = parse_profiles(
        Path(request["effective_policy"]).read_text(), source="frozen-application.slp"
    )
    artifact = (HERE / "worker.py").resolve()
    executor = LinuxSandboxExecutor(
        profiles,
        {
            "compute": LinuxToolSpec(
                "worker:compute",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(artifact.parent, source.parents[2]),
        default_wall_timeout_s=15,
        lifecycle_checker=checker,
    )
    (events.parent / "lifecycle-selection.json").write_text(
        json.dumps(request["lean_worker"], indent=2) + "\n"
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
        audit_sink=audit,
        closed_admission=True,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(
        Effect.EXEC, Effect.READ, resources=[ResourceArg("sandbox_source", "path", "realpath")]
    )
    def compute(sandbox_source: str, payload: dict) -> dict:
        """Run the generated computation, preserving the upstream sandbox checks."""
        raise RuntimeError("Unconfined fallback is forbidden")

    builder = StateGraph(MessagesState)
    builder.add_node("dispatch", ToolNode([compute], security=security))
    builder.add_edge(START, "dispatch")
    node_graph = builder.compile(security=security)
    config = principal_config(run_principal(request["run_id"]))

    def bridge(
        *,
        code_snippet,
        function_name,
        data,
        timeout=10,
        memory_limit_mb=512,
        data_format="dataframe",
    ):
        payload = {
            "code": code_snippet,
            "function_name": function_name,
            "data": data,
            "memory_limit_mb": memory_limit_mb,
            "data_format": data_format,
            "sandbox_serialization": serialization,
            "computation_api": request.get("computation_api"),
        }
        payload = json.loads(json.dumps(payload))
        _event(
            events,
            {
                "kind": "computation",
                "configuration": CONFIGURATION,
                "payload": payload,
                "fault": None,
                "added_boundary": True,
            },
        )
        if timeout != 15 or memory_limit_mb != 512:
            raise ValueError("Version a new manifest for changed upstream sandbox limits")
        response = node_graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "compute",
                                "args": {"sandbox_source": str(source), "payload": payload},
                                "id": "compute-call",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        message = response["messages"][-1]
        (events.parent / "activation-receipts.json").write_text(
            json.dumps(
                [receipt.canonical() for receipt in executor.activation_receipts()], indent=2
            )
            + "\n"
        )
        if message.status == "error":
            return None, message.content
        result = json.loads(message.content)
        if normalization(request) is not None:
            result = json_state(result)
        return result["result"], result["error"]

    for module_name in ["data_wrangling_agent", "data_visualization_agent"]:
        module = importlib.import_module("ai_data_science_team.agents." + module_name)
        module.run_code_sandboxed_subprocess = bridge
    return node_graph


def _event(events, record):
    with Path(events).open("a") as stream:
        stream.write(json.dumps(record, default=str) + "\n")
