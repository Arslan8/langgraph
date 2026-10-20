# slangGraph security project workspace

This workspace contains progressively more complete examples of slangGraph tool
security. The examples teach the runtime contract that the student policy
inference project must target; they are not the complete project by themselves.

## Run the examples

Run each example from the repository root:

```bash
python3 workspace/01_quickstart.py
python3 workspace/02_dac_quickstart.py
python3 workspace/03_dac_principal_quickstart.py
python3 workspace/04_resource_grant_quickstart.py
```

The examples introduce these ideas in order:

1. A minimal graph and tool invocation.
2. Cedar discretionary access control attached to a tool.
3. An authenticated principal supplied when invoking the graph.
4. A tool argument mapped to a normalized resource operation, authorized by
   Cedar, converted into an exact grant, and enforced during execution.

Example 4 also prints the retained temporary directory containing the generated
Cedar schema, entities, policies, and requests. These artifacts can be copied or
edited for Cedar CLI experiments without changing a grant that has already been
issued.

## What the student project must build

The project is not merely about adding object classes or writing Cedar
policies. Students must build a policy inference engine that analyzes tools and
produces precise, explainable, least-privilege capability requirements.

The intended pipeline is:

```text
tool implementation + descriptor + examples or traces
                         |
                         v
              inferred resource operations
                         |
                         v
          candidate manifest with supporting evidence
                         |
                         v
              review, validation, and refinement
                         |
                         v
             Cedar authorization per invocation
                         |
                         v
                 exact enforceable grant
```

The inference engine should determine:

- which resources a tool can access;
- which operation it performs on each resource;
- which arguments determine resource identity;
- which trusted normalizer should canonicalize those arguments;
- which capabilities are always required and which are conditional;
- whether the inferred manifest grants more authority than the implementation
  needs;
- which code paths and behaviors have or have not been supported by evidence;
- whether hostile inputs can escape the inferred resource boundary; and
- whether observed runtime behavior remains within the authorized grant.

## Manifest policy versus Cedar policy

The inference engine should primarily infer the authority requested by a tool.
That authority is expressed by the manifest. For example:

```slp
runs inprocess
record read @{record_id} need
returns sensitive
```

Cedar decides whether a principal may receive that authority. Organizational
decisions such as "Alice may update finance records" cannot be safely inferred
from Python tool code alone. They belong in reviewed Cedar policy. An inference
engine may propose such policies, but proposals must be labeled as suggestions
rather than trusted facts.

## Extending the resource vocabulary

The built-in `fs read` class is enough for the filesystem example. A plugin or
power user can introduce another resource class without changing the manifest
grammar:

```slp
class record {
  operations read update
  object item
  normalizer identity
  attrs owner department
  enforced_by trusted_tool
}
```

A useful follow-up exercise is to provide separate tools with deliberately
narrow requirements:

```text
read_record(record_id)          -> record read   @{record_id} need
update_record(record_id, value) -> record update @{record_id} need
```

The inferred manifest for `read_record` must not grant `update`. The manifest
for `update_record` must not grant access to unrelated record identifiers.
Ownership and department restrictions belong in Cedar; required resource
operations belong in the manifest.

## Defining a class is not enforcement

A production-quality class requires all of the following:

- operations with precise semantics;
- a trusted normalizer that produces canonical resource identities;
- trusted labels when Cedar policies depend on resource attributes;
- an enforcement mechanism for every surviving grant line; and
- positive, negative, malformed-input, and adversarial tests.

The examples use `enforced_by trusted_tool`. This means a reviewed in-process
implementation, or its language sandbox, must honor the slangGraph grant. Its
effective permission is the intersection of the slangGraph grant and the
coordinator process's existing host permission.

For untrusted or production integrations, a project may instead require:

- a broker that performs operations for a worker without direct authority;
- a scoped credential enforced by the remote resource;
- a framework hook for framework-owned objects; or
- a kernel-backed enforcement adapter.

Cedar authorization alone is not enforcement. A call must not execute unless
every required operation survives authorization and the declared enforcement
mechanism can enforce the resulting grant.

## Least-privilege success criteria

A successful project should demonstrate that:

1. Allowed calls receive only the operations and resource identities they need.
2. Missing required authority prevents tool code from running.
3. Extra operations are detected as overprivilege.
4. Normalization prevents alternate spellings from bypassing policy.
5. Unknown, malformed, and adversarial inputs fail closed with useful errors.
6. Inference results include evidence, uncertainty, and uncovered paths.
7. Generated Cedar artifacts and final grants are inspectable.
8. Runtime behavior is checked against the inferred and authorized grant.

The open-class mechanism makes the model extensible to database tables,
secrets, queues, API endpoints, browser origins, devices, and other enumerable
resources. Designing the domain-specific inference and enforcement boundary is
part of the student project.
