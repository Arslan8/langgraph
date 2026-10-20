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

Example 5 uses two terminals and a Unix-domain socket:

```bash
# Terminal 1: device behavior and accepted-command log
python3 workspace/05_pump_simulator.py

# Terminal 2: interactive authorized controller
python3 workspace/05_custom_class_quickstart.py
```

The controller accepts `inspect`, `start`, `stop`, `set_flow NUMBER`, and
`calibrate NUMBER`. Enter `principal alice`, `principal bob`, or
`principal charlie` to switch the demonstration identity; `principal mallory`
shows the no-coverage denial. Principal selection is a teaching substitute for
authentication, not an authentication mechanism.

Example 5 deliberately has no caller-side Cedar `Action::"call"` permit. For a
resource-bearing tool, caller eligibility is derived from manifest coverage:

- full coverage permits the complete manifest authority;
- partial coverage requires the invocation's mapped operation to be allowed;
- no coverage denies before dispatch.

Alice, Bob, and Charlie all have partial coverage, with their exact operations
written directly against their Cedar principal identities rather than through
demo roles. Mallory has no coverage. The framework still generates an internal
owner/tool call ceiling; users do not repeat that binding in caller policy.

Run the complete permission matrix and its assertions with:

```bash
python3 workspace/05_custom_class_quickstart.py --demo
```

The examples introduce these ideas in order:

1. A minimal graph and tool invocation.
2. Cedar discretionary access control attached to a tool.
3. An authenticated principal supplied when invoking the graph.
4. A tool argument mapped to a normalized resource operation, authorized by
   Cedar, converted into an exact grant, and enforced during execution.
5. A custom `pump` class whose device operations are authorized independently
   even though every accepted command uses the same Unix-domain socket.

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
class pump {
  operations inspect start stop set_flow calibrate
  object device
  normalizer identity
  attrs
  enforced_by trusted_tool
}
```

A closed manifest map lets one interactive tool select only fixed, declared
operations:

```text
operation=inspect   -> pump::inspect   on @{device_id}
operation=set_flow  -> pump::set_flow  on @{device_id}
operation=calibrate -> pump::calibrate on @{device_id}
```

An argument chooses among those mappings; it cannot supply a Cedar action name,
entity type, or policy. The pump example demonstrates that socket access is not
device-operation authority: `set_flow` and `calibrate` traverse the same socket
but produce different Cedar actions and grants.

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
