# Frozen evaluation configurations

| Configuration | Closed admission | Principal authorization | Sealed operator policy | Host isolation | Resource mediation | Audit | Per-call Lean |
|---|---|---|---|---|---|---|---|
| Upstream A (historical comparison) | No | No | No | No | No | Harness events only | No |
| Authorization-only B / `call_authorization_native` | No | Cedar call/object decision | No | No | No; native effects remain | Decision trace | No |
| Isolation-only / `filesystem_accessible` | No | No resource decision | No | Linux worker | No | Worker trace | No |
| `C-full` | Yes | Cedar principal policy | Yes | bubblewrap, Landlock, seccomp | Exact-file object grants plus mediated dataset input | SQLite security audit and activation receipts | No |
| `C-full-lean` | Yes | Cedar principal policy | Yes | bubblewrap, Landlock, seccomp | Exact-file object grants plus mediated dataset input | SQLite security audit and activation receipts | Yes, `worker-route-grant-v3` |
| `production_composition` | N/A fixed invocation | Cedar record/operation decision | Where the case specifies it | Fresh Landlock worker | Parent-owned SQLite or pump adapter | Grant, lowering, receipt, broker decision, resource snapshot | No |
| Common language | Yes | Cedar exact-file decision | Yes | Immutable-instruction interpreter | Language primitive for exact file | SQLite security audit | No |
| Common container | Yes | Cedar exact-file decision | Yes | Pinned Docker image and read-only mount | Exact-file object grant | SQLite security audit and container lifecycle | No |

The isolation-only SQLite baseline denies the entire database and therefore
does not preserve Alice's authorized functionality. It is reported as an
unsupported comparison, not as successful enforcement. `C-full` and
`C-full-lean` use the same model, ten tasks, three graph retries, serializers,
state normalization, dataset bytes, output validation, and oracle.

ACE is run through its pinned published `ToolExecutionSandbox`. Its published
configuration has no host-volume or record/operation-policy setting, so the
SQLite and Unix-socket cases are recorded as `configuration_could_not_execute`.
IsolateGPT is run through its pinned published `helpers/sandbox/sandbox.py`;
the per-record, operation, principal, and sealed-operator restrictions are
recorded as `restriction_cannot_express` rather than as bypasses of a supported
policy.
