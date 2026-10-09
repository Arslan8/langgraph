# AppArmor-style confinement profiles

`ConfinementPolicy` provides tool-attached mandatory profiles using slangGraph's
typed MAC pipeline. It does not install Linux AppArmor policy. Instead, it
removes authority from the candidate grant, rechecks every `need`, and relies on
the configured host executor to enforce the remaining grant.

```python
from langgraph.prebuilt.security import (
    AuthorityDomain,
    ConfinementDeny,
    ConfinementPolicy,
    ConfinementProfile,
    ResourceAllowance,
    RulePredicate,
    SecurityConfig,
    resource_path,
)

profile = ConfinementProfile(
    "reporter",
    "2026-10-08",
    tools=frozenset({"build_report"}),
    path_scope=resource_path("/srv/report/**"),
    path_allow=(
        ResourceAllowance(
            resource_path("/srv/report/input/**"), frozenset({"read"})
        ),
        ResourceAllowance(
            resource_path("/srv/report/output/**"),
            frozenset({"read", "write", "create", "delete", "truncate"}),
        ),
    ),
    path_forbid=(resource_path("/srv/report/input/secrets/**"),),
    deny=(
        ConfinementDeny(
            "offline",
            RulePredicate(domain=AuthorityDomain.NETWORK.value),
            "network_disabled",
        ),
    ),
)

security = SecurityConfig(
    modules=[ConfinementPolicy([profile])],
    host_executor=executor,
)
```

Within `path_scope`, unlisted paths receive no authority. Each allowance is a
ceiling, not a grant: DAC and every other mandatory module must still allow the
operation. Explicit deny predicates can remove any typed authority domain. The
special tool name `*` creates a baseline profile; baseline and tool-specific
profiles intersect when both match.

By default a tool without a matching profile is denied. Set
`require_profile=False` only when unprofiled tools are intentionally allowed.
Constraints require a host executor, and unsupported native lowering denies the
call before tool code starts.
