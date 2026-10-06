# Worked security patterns

These patterns supplement the runnable examples. They show the integration
shape; application tools, identity lookup, storage, and approval UI remain the
operator's responsibility.

## Secure a `ToolNode` in a graph

Declare the tool, configure the graph, and bind the principal at the trusted
request boundary:

```python
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import Effect, Principal, SecurityConfig, dac, effects, with_principal

@tool
@dac(owner="support", grants={"support": "x", "*": "-"}, required_scopes={"records:read"})
@effects(Effect.READ)
def lookup_record(record_id: str) -> str:
    """Look up one support record."""
    return f"record:{record_id}"

security = SecurityConfig()
builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([lookup_record]))
builder.add_edge(START, "tools")
graph = builder.compile(security=security)

principal = Principal("alice", frozenset({"support"}), frozenset({"records:read"}), "session-1")
config = with_principal({}, principal, modules=security.modules)
request = {"messages": [AIMessage(content="", tool_calls=[{"name": "lookup_record", "args": {"record_id": "case-123"}, "id": "call-1"}])]}
result = graph.invoke(request, config=config)
```

The companion LangChain fork accepts the same configuration through
`create_agent(..., security=security)`. Passing `None` preserves upstream agent
construction behavior.

The principal comes from authentication, never from `request` or graph state.
A denial becomes an error `ToolMessage`; the tool body does not execute.

## Request durable human approval

An escalating module sets `can_escalate`, returns an argument-free request, and
requires a real checkpointer:

```python
from langgraph.prebuilt.security import Decision, EscalationRequest, SecurityModule, Verdict

class ReviewWrites(SecurityModule):
    name = "review_writes"
    can_escalate = True

    def tool_call_permission(self, principal, call):
        return Decision(
            Verdict.ESCALATE,
            "write_requires_review",
            escalation=EscalationRequest(
                f"review:{call.call_id}",
                "sensitive write",
                call.tool.name,
                call.call_id,
            ),
        )
```

Pass the module through `SecurityConfig`, compile with a checkpointer, and use a
stable `thread_id`. The first invocation returns an interrupt. Resume with
`Command(resume={"approved": True, "approver": "reviewer-id"})`. Resume reruns
normalization, DAC, preparation, and permission checks before
`resume_permission`; approval is additional restrictive input, not a bypass.

Production approval storage must enforce separation of duty in operator policy.
That Cedar-backed policy is planned and is not provided by the current module
stack.

## Delegate to a child with less authority

Use `delegate` around any child runnable and name the exact scope subset:

```python
from langchain_core.runnables import RunnableLambda
from langgraph.prebuilt.security import SecurityConfig, delegate, principal_from

def child_task(value, config):
    principal = principal_from(config)
    assert principal is not None
    return value, principal.scopes, principal.delegated_by

child = delegate(
    RunnableLambda(child_task),
    scopes=["records:read"],
    security=SecurityConfig(),
)
result = child.invoke("case-123", config=config)
```

The wrapper denies a requested scope absent from the parent, copies private
module slots, and records the parent user in `delegated_by`. It does not stop the
child's Python process from using ambient OS authority; kernel attenuation is
planned.

## Make escape analysis a CI gate

The analyzer is not yet wired into `compile()`. Run it explicitly:

```bash
langgraph-security-taint src --exclude src/generated
langgraph-security-taint src --json > taint-report.json
```

The command exits nonzero for findings and parse errors. Review fingerprints
individually; do not accept an entire baseline. The planned compile gate will
require a reason for each narrow exception and audit the resulting allow-list.

The Python API is useful for custom reporting:

```python
from langgraph.prebuilt.security import analyze_source

report = analyze_source("src", exclude=["src/generated"])
for finding in report.findings:
    print(finding.fingerprint, finding.path, finding.line, finding.kind.value)
if report.findings or report.parse_errors:
    raise SystemExit(1)
```

## Operate audit and observation

Use `SqliteAuditSink` for durable local evidence, call `verify()` during health
checks, and close it during shutdown. Pair it with a redacted observer for
metrics and traces. Audit records intentionally contain an argument hash rather
than argument values. Keep tool results, credentials, approval secrets, and raw
arguments out of logs and telemetry.

Current audit proves the recorded decision sequence and detects chain
tampering. Enforcement denials, adapter attestation, final grants, and unenforced
classes will be added with the adapter contract; they do not exist today.
