# Fixed policy and trusted interpreter extension contracts

Run the finite fixtures from the repository root:

```sh
uv run --directory libs/prebuilt pytest tests/analysis/extensions -q
```

`test_fixed_policy.py` defines an immutable typed rule configuration with tool IDs,
argument membership and numeric bounds. Unknown predicate kinds fail validation.
The separate `SecurityModule` evaluates effective arguments before a guarded effect,
with default deny and explicit-deny precedence. ALLOW means no objection in the
existing authorization chain. Findings may change; installed rules and their digest
remain fixed. There is no Progent policy generator, runtime policy update, SMT solver,
or claimed automatic DSL translation.

`test_interpreter_adapter.py` uses protected references, allowed-reader intersection,
explicit field selection, concatenation, conditional control scopes, bounded loops
and guarded calls. Structural siblings are distinct from influence. Selector inputs
and enclosing controls reach derived values. Scope exit is exception-safe and uses
per-runtime ContextVars. Opaque operations conservatively retain all supplied inputs.
The injected effect dispatcher uses `guarded_tool`; it cannot mint a host grant.

`test_model_roles.py` defines the bounded planner/extractor protocol. The planner
receives a trusted task, opaque references and typed status/category/operation fields.
Raw tool data, extractor values and exception strings remain out of its request.
Tool-shaped extraction responses fail schema validation and have no execution path.
The fixture's authorization callback uses the existing SecurityStack with AnalysisFlowPolicy for both model destinations. Opaque handles have structural containment edges and do not expose the protected bytes. This is not a complete isolated model service implementation.

The immutable-policy invariant applies to retries and checkpoint resumes. The
checkpoint binding rejects changed policy/domain/role configuration. Effects already
completed are not rolled back by retries. External interpreter implementations remain
responsible for complete language semantics, control dependence, model/service
isolation, destination checks and persistent completed-effect receipts. These small
fixtures do not implement CaMeL or establish its security guarantees.

Primary pointers: [Progent policy representation and enforcement](https://arxiv.org/html/2504.11703v3),
[CaMeL model separation and control dependence](https://arxiv.org/html/2503.18813v2).
