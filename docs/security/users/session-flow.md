# Schedule classified sources and sinks across calls

Per-call authorization is not enough when a graph remembers data. A tool can
read a secret into messages or state and a later tool can transmit it.
`SessionFlowPolicy` prevents configured source/sink schedules at mediated call
boundaries. It is a confidentiality control only when classifications
conservatively bound actual reads and outward effects.

## Classify every tool

Classifications are operator-owned enforcement inputs. The framework does not
infer them from declared effects, tool output, prompts, or model behavior.

```python
from langgraph.prebuilt.security import (
    Confidentiality,
    SecurityConfig,
    SessionFlowPolicy,
    SqliteFlowStateStore,
    ToolFlowRule,
    Verdict,
)

flow = SessionFlowPolicy(
    {
        "read_public": ToolFlowRule(Confidentiality.PUBLIC),
        "read_customer_record": ToolFlowRule(Confidentiality.CONFIDENTIAL),
        "send_internal": ToolFlowRule(
            Confidentiality.PUBLIC,
            sink_ceiling=Confidentiality.CONFIDENTIAL,
        ),
        "send_external": ToolFlowRule(
            Confidentiality.PUBLIC,
            sink_ceiling=Confidentiality.PUBLIC,
        ),
    },
    store=SqliteFlowStateStore("security-flow.db"),
)
security = SecurityConfig(flow_policy=flow)
```

`output_label` is the highest confidentiality the operation may read, including
ambient inputs and data it does not return. A `sink_ceiling` is the highest
accumulated session label from which the operation may cause any outward effect
during execution. A tool that both reads and sends must declare both; the source
label is joined before its sink is checked. Configuration fails when a statically
configured tool lacks a rule.

## Runtime behavior

Flow state is keyed by authenticated `user_id` and `session_id`, outside graph
state. Labels only rise:

1. before a parallel ToolNode batch starts, all proposed source labels are
   joined into the session label;
2. before each physical execution, the framework atomically reserves the
   source/sink combination;
3. a sink is denied when the session label exceeds its ceiling; and
4. the reservation is released after post hooks and outcome audit complete only
   when physical termination is confirmed.

Batch premarking intentionally overtaints. A denied or unused source proposed
in a parallel batch may still raise the label. This trades availability for a
race-free guarantee: an egress call cannot beat a sensitive read in the same
batch.

Reservations also cover independent invocations. If a public egress operation
is already active, a newly sensitive source is denied with
`flow:concurrent_egress`. If the source reserves first, the egress operation is
denied with `flow:egress`.

Use `SqliteFlowStateStore` when labels and reservations must coordinate across
principal reconstruction, checkpoints, process restarts, or multiple workers.
The in-memory store is thread-safe but process-local and is rejected when host
execution and session flow are configured together. An uncertain Linux worker
stores a recovery identity beside its active SQLite sink reservation. List IDs
with `unresolved_terminations()` and call `recover_termination()`; recovery
releases the reservation only after the host executor confirms the recorded
boot, PID, and process start-time identity can no longer execute. The record and
reservation survive coordinator restart.

The call boundary defines the implemented lifetime. Do not let a protected
in-process tool leave threads, processes, callbacks, or asynchronous work alive
after it returns. Native execution must keep the reservation and confinement
lease until the worker and all descendants terminate.

## Guard model and framework sinks

Remote model inference, tracing, telemetry, rendering, and artifact publication
can disclose data before another tool call occurs. Add named rules for them and
guard the entire effect:

```python
with flow.guard_operation(principal, "model:remote"):
    response = model.invoke(messages)
```

For a remote model, configure `model:remote` with a `sink_ceiling` appropriate
to the provider and endpoint. This guard is explicit; `ToolNode` does not
automatically wrap model clients or arbitrary callbacks.

## Preserve taint across sessions and artifacts

A new session identifier does not reset classification. Before importing a
checkpoint, exposing a shared artifact, or copying protected state, propagate
the source label:

```python
decision = flow.transfer_session(source_principal, target_principal)
if decision.verdict is not Verdict.ALLOW:
    raise PermissionError(decision.reason)
```

The transfer is atomic and denies if a newly sensitive target would conflict
with an active sink. Only trusted application code may create security sessions.
Copies that bypass this API are outside the protected execution model.

## Guarantee and boundary

The mechanism enforces a coarse scheduling policy over operator classifications;
it does not inspect or infer data dependencies and is not proof of
noninterference against hostile code. A public-classified in-process tool can
still read confidential ambient data, and a source can transmit internally,
unless the implementation is trusted or external host/service adapters constrain
its effective input authority and channels.

Flow rules must be derived from the conservatively bounded effective authority,
including runtime baseline and degradation. If that upper bound is unknown, do
not authorize an outward effect using an ordinary label. Escape analysis is a
diagnostic, not proof that arbitrary Python and native dependencies have no
unmediated effects. See [security boundary](security-boundary.md).
