# Getting started

This example secures one tool inside a graph. The trusted application creates
the principal from authenticated identity data; the model and graph state never
choose it.

```python
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityConfig,
    dac,
    effects,
    with_principal,
)

@tool
@dac(
    owner="analyst",
    grants={"analyst": "x", "*": "-"},
    required_scopes={"reports:read"},
)
@effects(
    Effect.READ,
    resources=[ResourceArg("path", "path", "realpath")],
)
def read_report(path: str) -> str:
    """Read one report."""
    return open(path).read()

audit = MemoryAuditSink()
security = SecurityConfig(audit_sink=audit)

builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([read_report]))
builder.add_edge(START, "tools")
graph = builder.compile(security=security)

principal = Principal(
    user_id="alice",
    roles=frozenset({"analyst"}),
    scopes=frozenset({"reports:read"}),
    session_id="session-42",
)
config = with_principal({}, principal, modules=security.modules)
result = graph.invoke(input_value, config=config)
```

Replace `input_value` with normal LangGraph input containing the model's tool
call. A denied call returns an error `ToolMessage`; the function body does not
run.

## Configuration rules

1. Construct `SecurityConfig` in trusted application code.
2. Pass it to `ToolNode`, `StateGraph.compile`, or both. Reusing the same object
   is safe; replacing security on an already secured node is rejected.
3. Build `Principal` from authentication and session data outside graph state.
4. Call `with_principal` for every entry into a secured graph.
5. Pass `security.modules` to `with_principal` so credential preparation hooks
   receive their private principal slots.
6. Use a stable, authenticated `session_id` when audit history, approval, or
   flow state must survive multiple graph invocations.

## Direct invocation

If a tool can run without `ToolNode`, wrap the callable itself:

```python
from langgraph.prebuilt.security import guarded_tool

secured_read_report = guarded_tool(read_report, security=security)
result = secured_read_report.invoke(
    {"path": "/srv/reports/q3.txt"},
    config=config,
)
```

Calling the original `read_report` alias is outside this wrapper. Do not retain
or expose unguarded aliases in a security-sensitive application.

## Next steps

- Add normalized argument policy in [tool authorization](tool-authorization.md).
- Add mandatory modules and delegation in
  [modules and delegation](modules-and-delegation.md).
- Enable cross-call confidentiality in [session flow](session-flow.md).
- Configure durable evidence using [operations](operations.md).

