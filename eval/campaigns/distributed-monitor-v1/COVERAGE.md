# Attack coverage and applicability

| Distinct attack | Attacker control | Protected property | Enforcing component | Full result |
|---|---|---|---|---|
| Record selector substitution | Tool implementation | Alice cannot read Bob | SQLite mediator plus bound grant | Blocked; Alice control succeeds |
| Hidden UPDATE | Tool implementation | Read authority does not imply write | Mediator and worker isolation | Blocked; read succeeds |
| Hidden DELETE | Tool implementation | Read authority does not imply delete | Mediator and worker isolation | Blocked; read succeeds |
| Direct DB/WAL recovery | Tool implementation | Broker cannot be bypassed | Lowered filesystem deny | Blocked; mediated read succeeds |
| Raw pump socket | Tool implementation | Inspect does not imply `set_flow` | Broker plus socket isolation | Blocked; inspect succeeds |
| Sealed-policy conflict | Manifest and principal | Operator deny dominates | Policy intersection and lowering | Writes blocked; reads succeed |
| Credential/handle replay | Later invocation | Authority is invocation-bound | Fresh worker and grant binding | Replay/substitution blocked; Bob control succeeds |
| Denial retry over direct path | Tool implementation | Retry cannot widen authority | Same grant plus direct-path isolation | Blocked in full mode, succeeds in ablations |
| Symlink path substitution | Tool/host race | Checked path cannot redirect | Exact admitted object plus Landlock | Blocked in lifecycle test |
| Import-time write/connect | Module initialization | Effects cannot precede isolation | Worker activation order | Blocked in lifecycle test |
| HTTP direct bypass | Tool implementation | Adapter policy covers raw network | HTTP adapter plus network deny | Blocked; selected read succeeds |
| Forbidden document read/write | Tool implementation | Exact input/output locations | Language interpreter and object grant | Blocked; report succeeds |

The fare scenarios characterize a different boundary. They now execute through
slangGraph `StateGraph` and `ToolNode`, with an exact numeric oracle that does
not confuse `$20` with `$200`; they do not execute ACE or IsolateGPT.
Description manipulation did not omit MetroHail in the corrected pilot.
Execution-disruption and result-manipulation payloads reached the model and
produced incorrect answers. The runtime does not claim ACE's planning-integrity
or information-flow defenses; adding those defenses through the common policy
hooks remains future work.

## Baseline interpretation

- Full slangGraph preserved the paired allowed functionality and blocked every
  tested unauthorized resource effect.
- Call-check-only and transport-only variants enforce only their stated layer;
  malicious native effects bypassed them.
- The filesystem-only SQLite variant denied the complete database, including
  Alice's allowed read, so it does not preserve functionality.
- The ACE result is one repeated configuration/host-file availability probe of
  `ToolExecutionSandbox`, not nine attacks and not a full ACE execution. It has
  no supported host-volume/record/operation configuration for these fixtures;
  the control confirms container execution, while result collection requires
  ACE's separate listener and is not treated as an application success.
- The IsolateGPT result is a direct probe of
  `helpers/sandbox/sandbox.py`, not the complete hub/spoke system. The module
  executes the fixtures but cannot express the
  per-principal record, operation, or sealed-operator restrictions. Those rows
  are `restriction_cannot_express`, not bypasses of a supported policy.

## Two representative traces

1. SQLite: Alice's grant contains only `read notes/alice`; lowering assigns
   custody to `sqlite.record.v1:notes` and direct-access prevention to the Linux
   host adapter. The legitimate broker read returns Alice's value. A hidden
   direct UPDATE receives `broker:not_granted`; the before/after snapshots are
   identical, including Bob's synthetic marker.
2. Pump: the grant admits `inspect`, the mediator returns the device state, and
   the worker's raw-socket `set_flow` attempt is denied by the lowered socket
   restriction. The post-trial device state equals the pre-trial state. The
   separate allowed `set_flow` control succeeds when that operation is granted.
