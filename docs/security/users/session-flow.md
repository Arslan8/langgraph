# Enforce information flow across calls

Per-call authorization is not enough when a graph remembers data. A tool can
read a secret into messages or state and a later tool can transmit it. Enable
`SessionFlowPolicy` when the application requires confidentiality across
mediated calls.

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

`output_label` is the highest confidentiality the tool may return. A
`sink_ceiling` is the highest accumulated session label the tool may accept.
Configuration fails when a statically configured tool lacks a rule.

## Runtime behavior

Flow state is keyed by authenticated `user_id` and `session_id`, outside graph
state. Labels only rise:

1. before a parallel ToolNode batch starts, all proposed source labels are
   joined into the session label;
2. before each physical execution, the framework atomically reserves the
   source/sink combination;
3. a sink is denied when the session label exceeds its ceiling; and
4. the reservation is released after post hooks and outcome audit complete.

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
The in-memory store is thread-safe but process-local. A crashed persistent sink
reservation fails closed and requires operator repair; never silently discard
it while the external effect may still be running.

## Guarantee and boundary

Within calls mediated by `ToolNode` and `guarded_tool`, data remembered through
messages, model context, graph state, checkpoints, results, and same-session
delegation cannot later leave through a lower-classified configured sink. The
policy is coarse session taint, not value-level provenance, and provides no
automatic declassification.

It does not mediate model final text, arbitrary Python graph nodes, callbacks,
renderers, or external actions that bypass the tool boundary. Route those
effects through `guarded_tool`, keep them inside the same no-egress compartment,
or treat them as trusted TCB behavior. See [security boundary](security-boundary.md).

