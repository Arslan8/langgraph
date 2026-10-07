# Bound resources with `ResourceBoundary`

`ResourceBoundary` is a shipped mandatory module that caps filesystem authority
by operator policy. It is an ordinary `SecurityModule`: it returns typed forbids
through `tool_call_permission`, and the framework applies them to each call's
candidate grant. Tools, profiles, and the Linux executor are unchanged.

The module supplies restrictions, never permissions. A resource it allows is
still inaccessible unless author DAC, the principal's envelope, and every other
module also allow it.

## Configure a policy

```python
from langgraph.prebuilt.security import (
    ResourceAllowance, ResourceBoundary, ResourceBoundaryPolicy, resource_path,
)

policy = ResourceBoundaryPolicy(
    policy_id="project-boundary",
    version="2026-10-07",
    scope=resource_path("/srv/project/**"),
    allow=(
        ResourceAllowance(resource_path("/srv/project/src/**"), {"read"}),
        ResourceAllowance(
            resource_path("/srv/project/artifacts/**"),
            {"read", "write", "create", "delete", "truncate"},
        ),
        ResourceAllowance(resource_path("/srv/project/project.toml"), {"read"}),
    ),
    forbid=(resource_path("/srv/project/credentials/**"),),
)
security = SecurityConfig(
    modules=[ResourceBoundary(policy)],
    dac_overrides=DacOverrides(profiles=profiles.tools),
    host_executor=LinuxSandboxExecutor(profiles, manifests, runtime_roots=roots),
)
```

`resource_path` uses the `.slp` path grammar (an exact absolute path, or a
terminal `/**` subtree) and then the same `realpath` normalizer applied to tool
path arguments. Symlinked or `..` spellings name the same resource as the
normalized argument. Globs, variables, and relative paths are rejected.

The `policy_id@version` pair is embedded in every constraint ID and in the
decision reason. The framework attributes each constraint to the module name,
records it in the provenance of any narrowed rule, and binds the constraint
payload into the grant's policy digest.

[`resource_boundary.py`](../examples/resource_boundary.py) is a runnable
version with two independently written tools.

## Semantics

| Rule | Effect |
| --- | --- |
| Outside `scope` | The module abstains. |
| Inside `scope`, no covering entry | Every operation is forbidden. |
| Covered by allowances | At most the intersection of their operation sets. |
| Covered by a `forbid` entry | Every operation is forbidden. Forbids override allowances. |
| Entry order, duplicates, module order | Do not change the answer. |

All entries must lie inside the scope. The filesystem operation vocabulary is
`read`, `write`, `create`, `delete`, `exec`, and `truncate`. Forbidden and
unlisted resources match every operation, including any outside that list.

The module compiles the policy once into predicates applied to both
`filesystem` and `runtime` grant rules:

- each entry forbids the operations outside its ceiling on its exact path or
  subtree; and
- the scope forbids everything except the allowed entries, using the
  `exempt_subtrees` and `exempt_paths` fields of `RulePredicate`.

## `need` and `want`

Requirement semantics are unchanged. After filtering, the framework rechecks the
requirement ledger:

- A `want` line whose authority is removed disappears, and the call proceeds
  with less authority.
- A `need` line with no surviving rule denies the call before any worker starts.
- A `need` is evaluated per source line, exactly as in DAC: a line keeps its
  status if any of its operations survives. To make mutation mandatory, put it
  on its own line, for example `fs read ${path} need, write+truncate ${path} need`.

| Candidate | Policy | Outcome |
| --- | --- | --- |
| `fs read+write+truncate ${path} want` on source | Read only | Read survives; the worker's mount is read-only and writes fail with `EROFS`. |
| `fs write+truncate ${path} need` on source | Read only | Denied: `required_authority_removed`. |
| `want` read of credentials | No access | Line removed; the path is not mounted. |
| `need` read of credentials | No access | Denied before release. |
| Write requested, DAC grants read only | Write allowed | Write is not added. |

Approval cannot lift these restrictions. A matching approval converts only the
escalating module's verdict; `ResourceBoundary` constraints remain and are
applied after approval.

## Runtime baseline

The executor's baseline grant lines (interpreter, `/usr`, runtime roots, pinned
tool artifact, and private `/tmp`) are `runtime` rules and receive the same
predicates as requested authority. A baseline line conflicting with the policy
is removed. Every baseline line is a non-waivable `need`, so the call is denied
with `required_authority_removed:baseline:...`. The module never exempts a path
because Python needs it.

Two consequences for deployment:

- Do not place a runtime root, interpreter, or tool artifact inside a forbidden
  or unlisted part of the scope.
- Do not choose a scope under `/tmp`. The worker's private `/tmp` is a baseline
  subtree, and the grant does not distinguish it from host `/tmp`. Any scope
  below `/tmp` therefore denies every call.

## Enforcement limitations

A semantically valid filtered grant can still be unenforceable by the Linux
adapter. Execution is then rejected before tool code runs; the original broad
authority is never retained.

| Situation | Result |
| --- | --- |
| A broad subtree containing a forbidden subtree | Filtered to an `exclude_subtrees` rule. Linux reports `adapter_rule_unsupported` (`path_exclusion_requires_broker`) and denies. |
| A broad subtree containing allowed resources of different ceilings (for example, read of the whole scope) | Not representable as one rule plus exclusions, so the rule is removed. A `need` denies. |
| Writable directory missing any of `read`, `write`, `create`, `delete`, `truncate` | Linux reports `adapter_lowering_failed` and denies. |
| Configured without `host_executor` | Denied with `policy:constraints_require_host_executor`. |

Profiles should request the narrowest resources they use. Separate lines for
source, artifacts, and configuration lower to exact read-only and read-write
mounts.

See the [interface assessment](../resource-boundary-interface.md) for what the
public hooks support and which framework changes this module required.
