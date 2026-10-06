# Write restrictive modules and delegate safely

Mandatory modules can object to an author-authorized call, narrow its arguments,
request approval, and restrict delegation. They cannot grant authority.

## A minimal module

```python
from langgraph.prebuilt.security import Decision, SecurityModule, Verdict

class DenyExternalRecipients(SecurityModule):
    name = "corporate_recipient"

    def tool_call_permission(self, principal, call):
        domain = call.normalized.get("to_domain")
        if domain != "corp.example":
            return Decision(Verdict.DENY, "external_recipient")
        return Decision(Verdict.ALLOW, "corporate_recipient")
```

Install modules in deterministic operator order:

```python
from langgraph.prebuilt.security import SecurityConfig

security = SecurityConfig(modules=[DenyExternalRecipients()])
```

The framework-managed `cap` module is always first. The first `DENY` or
`ESCALATE` stops permission evaluation. Reordering modules can change which
denial is reported, but cannot turn a denial into an allow.

## Use private slots

State required by a module belongs in its `Slot`, never on the module object or
in module-global variables. `tool_alloc_security` initializes per-tool state;
`cred_prepare` initializes per-principal state. During delegation, the framework
copies the parent's blobs and hands `cred_transfer` only the child's slot.

This separation matters under parallel tool calls. A singleton module instance
may be invoked concurrently by threads and async tasks.

## Narrow arguments

Only `tool_call_prepare` may return `TRANSFORM`. Supply the complete replacement
arguments in `Decision.new_args`. The framework rejects normalized values that
become structurally broader and reruns DAC after all transforms.

Use built-in, framework-owned normalizers for security comparisons. Do not
execute tool-authored transformation code in a trusted coordinator and treat
the result as proof of narrowing.

## Request approval

Set `can_escalate = True` and return `ESCALATE` with an
`EscalationRequest`. Compile the graph with a checkpointer. On resume, the
framework validates the response, records one-time approval state, runs
`resume_permission`, and reruns the permission chain. Approval is policy input;
it never overrides an unconditional denial.

Bind approval to the concrete request. If normalized intent or arguments
change, require a new approval. Keep raw arguments and secrets out of approval
payloads.

## Delegate a smaller principal

```python
from langgraph.prebuilt.security import delegate

restricted_child = delegate(
    child_graph,
    scopes=["reports:read"],
    security=security,
)
result = restricted_child.invoke(child_input, config=config)
```

The requested scopes must be a subset of the parent's scopes. Roles remain,
private slots are copied, `cred_transfer` can restrict them, and the child
records `delegated_by`. A secured child must inherit the exact
`SecurityConfig`; delegation rejects replacement with another policy or flow
store.

Scope attenuation does not itself prevent cooperating children from combining
authority through shared state. Enable [session flow](session-flow.md) for
cross-call confidentiality and ensure all children inherit the same durable
flow store.

