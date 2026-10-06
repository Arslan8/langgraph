# Operate, audit, and troubleshoot security

## Bind trusted identity

Construct `Principal` only after authenticating the request. Use a stable
`session_id` scoped to the authenticated user and conversation. Never accept
roles, scopes, delegation ancestry, approvals, or module slots from messages or
graph state.

`require_principal=True` is the secure default. A configured call without a
bound principal is denied with `no_principal`.

## Persist and verify audit

```python
from langgraph.prebuilt.security import SecurityConfig, SqliteAuditSink

audit = SqliteAuditSink("security-audit.db")
security = SecurityConfig(audit_sink=audit)

valid, first_bad_record = audit.verify()
if not valid:
    raise RuntimeError(f"audit chain failed at {first_bad_record}")
```

SQLite uses WAL and full synchronization. Records include hashed arguments,
stage, module, verdict, reason, principal, session, call index, and execution
outcome. They do not include raw arguments. A pre-dispatch audit failure stops
execution; a completion-audit failure after a possible side effect reports an
indeterminate outcome instead of claiming denial.

Hash chaining detects edits inside retained data. Use `seal()` with a separately
held `AuditWitness` and retain seals outside the audit database to detect valid
prefix or suffix truncation.

## Observe without leaking data

Choose one of the redacted observers:

- `MemorySecurityObserver` for tests and local inspection;
- `LoggingSecurityObserver` for structured logs; or
- `OpenTelemetrySecurityObserver` for compatible tracing and counters.

Observers receive stage, module, verdict, reason, latency, tool, principal, and
call index. Keep raw inputs, outputs, credentials, and approvals in their
designated stores, not telemetry.

## Inspect and analyze before deployment

`introspect(graph)` lists statically reachable ToolNodes, nested subgraphs, and
registered guarded tools. Treat `ToolInventory.complete is False` as a review
requirement: middleware or dynamic registration may introduce tools that were
not classified at compile time.

Run escape analysis in CI:

```bash
langgraph-security-taint src --exclude src/generated
langgraph-security-taint src --json > security-taint.json
```

The command exits nonzero for findings and parse errors. Review each finding;
do not approve a broad baseline. It detects common unmediated aliases and
dangerous APIs, but cannot prove process-wide confinement for dynamic Python.

## Common denials

| Reason | Meaning | Operator action |
| --- | --- | --- |
| `no_principal` | No authenticated principal was bound. | Bind with `with_principal` at the request boundary. |
| `dac:grant` | Neither user, role, nor fallback has execute permission. | Correct author DAC or apply an explicit operator override. |
| `dac:scope` | A required scope is absent. | Fix identity provisioning; do not add scope from model input. |
| `normalization_error` | A resource could not be normalized safely. | Reject malformed input or select the correct built-in normalizer. |
| `module_error:<name>` | A module raised or returned a malformed result. | Fix the module; the denial is intentionally fail closed. |
| `module_timeout:<name>` | Policy exceeded `policy_timeout_s`. | Repair policy latency or adjust the trusted timeout deliberately. |
| `flow:egress` | Accumulated session confidentiality exceeds the sink ceiling. | Keep the session confined or start a separately authorized session; do not clear labels silently. |
| `flow:concurrent_egress` | A sensitive source conflicts with active egress. | Let egress finish, then reconsider the source under policy. |
| `audit_failure` | Required evidence could not be written before execution. | Restore durable audit availability before retrying. |

## Shutdown

Close SQLite audit and flow stores during orderly shutdown. Do not delete audit,
flow, approval, or checkpoint state merely to make a denied operation pass.

