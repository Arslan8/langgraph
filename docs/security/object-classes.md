# Open object classes

For the exhaustive syntax, directive, normalization, Cedar-mapping, and
validation reference, see [security manifest language](manifests.md). This page
focuses on the architecture and Python wiring.

For a tool that only needs call authorization and does not access a protected
resource, use the high-level helper:

```python
security = cedar_security(
    greet,
    manifest="""
        runs inprocess
        returns normal
    """,
    policy=caller_policy,
)
```

The helper derives the internal tool identity from `greet.name`; neither the
manifest body nor the Cedar policy needs to repeat it. It also generates the
tool-owner ceiling internally. A resource-free tool needs no host dispatcher,
receipt, class, or normalizer.

The same helper accepts resource operations for explicitly trusted in-process
tools:

```python
security = cedar_security(
    read_file,
    manifest="""
        runs inprocess
        fs read @{path} need
        returns sensitive
    """,
    policy=caller_and_resource_policy,
)
```

`fs read` is built into `cedar_security`; ordinary users do not declare it.
The helper supplies its `FsPath` Cedar entity, `fs.realpath` normalizer, and
trusted-tool enforcement binding.

The helper expands and normalizes the invocation, evaluates every operation in
Cedar, constructs an exact `ObjectGrant`, canonicalizes descriptor-declared
resource arguments before dispatch, and records enforcement evidence. Call
`security.host_executor.authorization_grants()` to review the issued grants.
Call `security.host_executor.authorizer.authorization_artifacts()` to locate
the retained Cedar schema, entity set, policies, and requests for each decision.
Only classes declared with `enforced_by trusted_tool` use this convenience path;
other enforcement loci require an explicit dispatcher.

The effective permission of that trusted in-process execution is the
intersection of slangGraph authorization and the coordinator's existing host
permission. A host allow does not grant an operation denied by slangGraph, and
a slangGraph allow does not overcome a host denial. The tool runs under the
coordinator's host identity, so honoring the slangGraph side of the intersection
is a TCB obligation enforced by operator trust or an enabled language sandbox,
not by a per-call kernel sandbox. The operating system independently enforces
the host side of the intersection.

The object-policy API lets a tool plugin add resources such as database tables,
secrets, queues, browser origins, or store keys without changing the `.slp`
grammar. A class declares its operations, canonicalizer, Cedar attributes, and
enforcement locus. A tool manifest then enumerates the objects it needs or
wants.

For a trusted in-process tool, a power user can add a class directly through
the same helper:

```python
security = cedar_security(
    read_record,
    classes="""
        class record {
          operations read
          object item
          normalizer identity
          attrs owner
          enforced_by trusted_tool
        }
    """,
    manifest="record read @{record_id} need",
    policy=caller_and_record_policy,
    labels=trusted_record_labels,
)
```

Plugins may instead construct `ObjectClass` values and pass them through the
`classes=` keyword of `parse_security_manifest`. Textual and programmatic class
declarations receive the same duplicate-name, normalizer, operation, schema,
and enforcement validation.

```slp
class db {
  operations  select insert update delete ddl
  object      table
  normalizer  sql.table_ref
  attrs       owner schema
  enforced_by broker
  lowering    postgres.role_grant
}

class secret {
  operations  read
  object      item
  normalizer  identity
  attrs       owner
  enforced_by broker
}

tool run_report {
  runs    broker
  db      select reports.@{quarter} need
  secret  read reporting_api_key    want
  returns sensitive
}
```

Parse this with `parse_security_manifest`. The registry generates a Cedar schema
containing `Action::"db::select"`, `Action::"secret::read"`, and entity types
whose attributes come from the class declarations.

```python
from langgraph.prebuilt.security import (
    CedarObjectAuthorizer,
    CedarPolicySet,
    EnforcementKind,
    ObjectPolicyHostExecutor,
    SecurityConfig,
    parse_security_manifest,
)

manifest = parse_security_manifest(
    text,
    normalizers={"my.normalizer": normalize_object},
    enforcers={EnforcementKind.BROKER: broker_enforcer},
)
policies = CedarPolicySet(
    owner_permits={"run_report": owner_cedar},
    principal_permits=principal_cedar,
    share_permits=shares_cedar,
    mac_forbids=operator_forbids_cedar,
)
authorizer = CedarObjectAuthorizer(
    manifest,
    policies,
    executable="cedar",
    enforcement_waivers={},
)
executor = ObjectPolicyHostExecutor(
    authorizer,
    dispatcher,
    tool_owners={"run_report": "reporting"},
    labels=trusted_labels,
)
security = SecurityConfig(host_executor=executor)
```

Pass `security` to `ToolNode` or `StateGraph.compile`. The executor replaces the
legacy descriptor DAC for that ToolNode. The generated owner ceiling must
permit the bound tool call, while caller eligibility is derived from the
principal/share policy's access to the manifest-derived resource lines. A
resource-free manifest still requires an explicit caller-side `call` permit.
MAC can only remove lines. Removing a `need` line denies the call; removing a
`want` line omits it from the grant, and a resource-bearing call with no
surviving lines is denied.

Normalizers and label providers are trusted code. Policy sees only their
canonical selector and declared attributes, never the raw argument. The built-in
normalizers are `identity`, `fs.realpath`, `sql.table_ref`, and `mail.domain`. A
normalizer may only return attributes listed by its class.

The dispatcher is also trusted. It receives the finite `ObjectGrant`, activates
the declared kernel, broker, resource-side, or framework controls, and returns
an `ActivationReceipt`. Each surviving line must have exactly one
`RuleEnforcement` entry marked `exact` or `tightened`; missing, duplicate,
additional, or digest-mismatched evidence makes the result indeterminate.
ToolNode configuration fails when a manifest class lacks an enforcer for its
declared locus. An operator may explicitly waive a class with a non-empty reason
through `enforcement_waivers`; every affected line is then bound into the grant
digest, must be reported as `unsupported`, and requires a `degraded` receipt.

The policy partitions are intentionally monotone:

- owner, principal, and share policy sets may contain only Cedar `permit`
  policies;
- the MAC policy set may contain only Cedar `forbid` policies;
- the owner and principal/share sides must both allow each line;
- class operations absent from the declaration fail manifest parsing;
- Cedar validation or evaluation errors deny.
