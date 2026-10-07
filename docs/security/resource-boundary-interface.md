# `ResourceBoundary` interface assessment

This note records what an independently written mandatory module needed from the
public security interface to restrict resource authority. It also lists the
general framework changes made while doing so. None of these changes name or
special-case `ResourceBoundary`.

## Supported by the existing interface

| Requirement | Mechanism |
| --- | --- |
| Return restrictions without building a grant | `tool_call_permission` returns `ALLOW` with typed `ForbidConstraint` values. |
| Attribution | `SecurityStack` stamps the module name and rejects spoofed attribution. The policy identifier and version are carried in constraint IDs and the decision reason. |
| Applying restrictions and computing differences | `TypedPolicyBackend` removes fully matched rules and subtracts representable filesystem subtrees. |
| `need`/`want` revalidation | The requirement ledger is remapped through every narrowing and rechecked. |
| Grant construction, negotiation, lowering, and activation | `LinuxSandboxExecutor` and `EnforcementCoordinator`. The module never sees an executor plan. |
| Decision audit | Module verdicts and constraint attribution flow through the existing observer and audit sinks. Narrowed rules carry `module:constraint_id` provenance. |
| Composition | Forbids from several modules are concatenated. Denial from any module stops the stack. Approval converts only the escalating module's verdict. |

The module needed no tool-specific knowledge. It does not inspect
`ToolCall` arguments: its predicates are evaluated by the framework against the
call's candidate grant, which includes runtime baseline lines.

## Limitations found and general changes

| Limitation | Change |
| --- | --- |
| A forbid could not express "everything in this scope except the listed resources". Modules cannot see the candidate grant, so they cannot enumerate unlisted paths. | `RulePredicate` gained `exempt_subtrees` and `exempt_paths` (subtree predicates only, canonical, inside the selector, bounded at 32). The backend matches only the difference. A partial overlap with an exempt resource is treated as unrepresentable, and the rule is removed. |
| Subtree predicates were limited to the `filesystem` domain, so runtime baseline paths could not receive the same restrictions. | Subtree matching is accepted for `filesystem` and `runtime` rules. Runtime rules are never subtracted: a partial match removes them, and the baseline `need` then denies. |
| An exact-path forbid did not match a containing runtime subtree. A runtime root that held a forbidden file survived. Found by the property test. | `_rule_contains_path` covers both path domains. |
| Constraints were applied in module order, so derived rule IDs, provenance, and the policy digest depended on registration order. | The backend applies constraints in canonical `(module, constraint_id)` order. Effective authority was already order-independent; now the grant digest is too. |
| Without a host executor, constraints on an allowed decision were silently dropped and the tool ran with in-process authority. | `ToolNode` and `guarded_tool` deny with `policy:constraints_require_host_executor`. |
| Every comma-separated line of a profile directive shared one requirement-ledger source. A removed `need` line was hidden by a surviving sibling. Mixing `need` and `want` in one directive raised an error at compile time. | Source identities include the line index, matching the documented per-line `need` semantics. |

## Remaining limitations

- **Per-line `need` granularity.** A `need` line is satisfied while any of its
  operations survives, so a combined line such as `read+write ... need` can lose
  write and still run. Required write must be a separate line. This is the
  existing requirement semantics and was not redefined.
- **Operation complements.** An allowance's ceiling is enforced by forbidding
  the other operations in the `.slp` filesystem vocabulary. Forbidden and
  unlisted resources use an any-operation predicate. A future filesystem
  operation would have to be added to the vocabulary before a ceiling could
  exclude it.
- **No splitting.** A broad rule that overlaps differently restricted resources,
  such as read of the whole scope, is removed rather than split into
  per-resource rules. Splitting would be sound but needs a backend rule-splitting
  primitive.
- **Linux lowering.** Subtree exclusions and incomplete writable-directory
  operation sets are rejected by the reference adapter. The policy result is
  representable but not enforceable, and the call denies before tool code runs.
- **Private `/tmp`.** The grant names the worker's ephemeral `/tmp` with the
  same selector as host `/tmp`, so a scope under `/tmp` conflicts with the
  baseline and denies. Distinguishing ephemeral namespaces in the grant IR would
  remove this.
