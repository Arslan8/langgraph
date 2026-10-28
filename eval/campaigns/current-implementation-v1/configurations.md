# Configuration definitions

| Property | Upstream | Authorization-only | Fully protected (headline) |
| --- | --- | --- | --- |
| Application/task/data/model | Frozen, identical | Frozen, identical | Frozen, identical |
| Closed graph admission | No | Yes for the measured closed ablation | Required |
| Principal and exact resource normalization | Upstream behavior only | Cedar decision is added | Cedar decision is added |
| Sealed operator mandatory policy | No | No claim | Required and installed before graph execution |
| Durable hash-chained audit | No slangGraph audit | Required | Required |
| Effect containment | Only whatever upstream already implements | Explicitly not claimed | Exact matching activation evidence, no waivers, confirmed cleanup |
| Eligible current dispatchers | Upstream executor | Any explicitly labeled ablation | Immutable language, Docker read-only, and object broker |

“Authorization-only” is not shorthand for protection. It asks whether call-level
policy and audit preserve application behavior while deliberately retaining the
original executor. If that executor can open a database file, an authorized
call can still bypass the selected record. Those bypasses are kept as failures.

The headline configuration requires `SecurityConfig(closed_admission=True)`, a
sealed operator policy installed by `install_mac_policy`, real Cedar, durable
audit, an exact supported current dispatcher, matching grant/activation
identities, zero enforcement waivers and confirmed cleanup. Missing or
unsupported components refuse.

The current runtime-MAC implementation accepts only
`_LanguageSandboxDispatcher`, `DockerObjectDispatcher`, and
`ObjectBrokerDispatcher` behind the exact `ObjectPolicyHostExecutor`/Cedar
combination. It rejects direct `LinuxSandboxExecutor` ToolNodes with
`mac:tool_requires_object_authorization`. Consequently, the Lean-backed
Landlock cohort is reported as a closed-admission/Cedar/profile/audit route
measurement, but not as the mandatory-MAC headline configuration. The same
limitation applies when interpreting the current C-closed Pandas route. This is
a current implementation gap, not an evaluation exception.
