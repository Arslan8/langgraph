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

Example 5 requires Linux with Landlock, `libseccomp.so.2`, and the Cedar CLI.
It uses two terminals and a Unix-domain socket:

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

Example 6 adds a parent-owned SQLite database with record-level Cedar
permissions. It requires Python 3.11+, Linux Landlock ABI 5+, libseccomp, and
the Cedar CLI. No database server or manual setup is needed:

```bash
python3 workspace/06_database_quickstart.py
```

The demo creates a temporary database, checks allowed and denied read/write/delete
requests, verifies that another user's record stayed unchanged, and cleans up.
The database directory is kept outside worker-readable code roots. See the
[SQLite mediator contract](../docs/security/object-classes.md#sqlite-record-mediator)
for the fixed schema, payload limits, and integration API.

Examples 7 and 8 demonstrate unsafe worker code and custom resource mediation.
Both require Linux Landlock ABI 5+, libseccomp, and the Cedar CLI:

```bash
python3 workspace/07_unsafe_tools_demo.py
python3 workspace/08_resource_adapters_demo.py
```

[Example 7](07_unsafe_tools_demo.py) grants read access to one temporary file.
The deliberately unsafe [worker](07_unsafe_worker.py) then attempts an undeclared
read, a native `open()` bypass, a write to its read-only file, and socket creation.
Each forbidden operation prints `blocked`; the controller verifies that both
fixture files stayed unchanged. Run the controller above, not the worker alone.
This uses only demo-owned temporary data and creates no external connections.
The manifest describes authority; it does not certify tool behavior. Runtime
code roots remain readable, and filesystem metadata is not fully hidden.

[Example 8](08_resource_adapters_demo.py) implements a counter adapter directly
in the example, with four visible hooks:

- `assess` recognizes the exact class, selector, operations, attributes, and
  `counter.local.v1` lowering contract, and declares the protected directory.
- `activate` establishes per-invocation state using the authenticated context.
- `invoke` validates the payload and applies the counter's semantic limits.
- `release` clears the invocation state after worker/broker activity stops.

Its [worker](08_resource_adapter_worker.py) makes valid requests, then tries an
invalid increment, a payload that changes the selector, and direct resource
access. It also requests `retired`, an optional resource Cedar permits but the
adapter cannot implement. Lowering removes that permission before dispatch.
Finally, the controller repeats the call without the adapter and verifies that
missing required support denies execution before worker activity.

The counter adapter is trusted application code; its semantic checks are part
of the security boundary. It illustrates a resource owned by one parent
process, not a distributed counter or a general transactional store. Temporary
fixtures are cleaned up automatically; the demos exit nonzero if an assertion
fails.

Example 9 configures operator MAC independently of the tool's DAC. It requires
Linux Landlock ABI 5+, libseccomp, and the Cedar CLI:

```bash
python3 workspace/09_no_internet_demo.py
```

[The controller](09_no_internet_demo.py) loads the operator-owned
[no-internet policy](09_no_internet.cedar) and supplies it through
`cedar_security(..., policy=DAC_POLICY, mac_forbids=mac_policy)`.
`policy` supplies discretionary permits; `mac_forbids` supplies mandatory Cedar
forbids. DAC runs first, then MAC removes forbidden authority. Applications using
the lower-level API set `CedarPolicySet(mac_forbids=...)` instead.

Alice's DAC permits the declared file and internet operations. MAC denies
`internet::connect` for every principal and destination. With internet marked
`need`, authorization denies before dispatch. With it marked `want`, the tool
runs with only the local file grant. The isolated worker verifies that IPv4 and
IPv6 TCP/UDP socket creation fails; it never attempts an external connection.
Assertions check the MAC denial, surviving grant, and worker results.

The `internet` class is application-defined. No internet mediator is installed
because MAC removes its authority before lowering. The current Linux sandbox
also blocks direct sockets independently through seccomp; this demo does not
implement a policy-controlled network sandbox toggle. Removing the MAC rule
alone cannot enable internet access. In an application with network-capable
parent brokers, every outbound operation must be covered by the mandatory
policy too: this class name does not automatically classify other custom
resources or disable the coordinator's network access.

The examples introduce these ideas in order:

1. A minimal graph and tool invocation.
2. Cedar discretionary access control attached to a tool.
3. An authenticated principal supplied when invoking the graph.
4. A tool argument mapped to a normalized resource operation, authorized by
   Cedar, converted into an exact grant, and enforced during execution.
5. A custom `pump` class whose device operations are authorized independently
   even though every accepted command uses the same Unix-domain socket.
6. A SQLite `db_record` class with separate read/write/delete permissions per
   record, enforced by a parent-owned database mediator and host file isolation.
7. An unsafe tool constrained by a read-only file grant and host isolation.
8. A custom resource adapter with semantic validation, lifecycle hooks, optional
   authority removal, and denial when required support is missing.
9. Operator-owned mandatory policy removing internet authority despite a DAC
   permit, with local work continuing inside a sandbox that blocks sockets.

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
  enforced_by broker
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

The earlier examples use `enforced_by trusted_tool`. This means a reviewed in-process
implementation, or its language sandbox, must honor the slangGraph grant. Its
effective permission is the intersection of the slangGraph grant and the
coordinator process's existing host permission.

Example 5 uses `enforced_by broker` and an isolated Linux worker instead. Its
trusted adapter checks exact object grants outside the tool process.

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


## Example 5: enforced runtime boundary

`05_pump_worker.py` is the untrusted tool implementation. A fresh Linux worker
activates Landlock, seccomp, resource limits, and a cleared environment before
importing that file. It receives only its arguments and an inherited broker
channel. It cannot open a device socket, create a subprocess, or access files
outside its configured runtime roots and private temporary directory.

`05_custom_class_quickstart.py` owns the trusted pump adapter and socket path.
Its manifest uses `runs linux` and `enforced_by broker`. Cedar authorizes the
requested operation and device before a worker starts. Every worker request is
then checked against that exact invocation grant. Changing `inspect` to
`calibrate`, changing the device, or supplying an identity in the wire request
cannot acquire additional authority. Denied optional grants are absent from the
broker's authority too.

The adapter receives the operation and resource from the grant, not from an
untrusted payload. It only accepts `value` in the payload and validates that
value before contacting the simulator. The small adapter and device protocol
remain reviewed semantic dependencies: the runtime cannot discover what a
physical device command means.

There is no in-process fallback if confinement is unavailable. Runtime roots
are trusted readable code; do not put secrets in those directories. The demo
uses the application's Python import directories as runtime roots. Adapters must
bound their external I/O; terminating a worker cannot undo an already-started
external operation. The pump adapter uses a socket timeout. Permissions cover
operations and objects, not invocation counts or rate limits.

The reusable API is `ObjectBrokerDispatcher`, connected to
`ObjectPolicyHostExecutor`, plus the worker-side `object_request` helper in
`langgraph.prebuilt.security.object_broker`. Register the dispatcher as the
manifest's `EnforcementKind.BROKER` enforcer. Register `ResourceMediatorAdapter` instances through `mediators=`.
The pump adapter recognizes `lowering pump.socket.v1`, the exact device,
operations, and attributes. Its `ResourceSupport` declares the socket path
and required host capabilities. Host isolation and semantic support are
negotiated separately; missing required support and enforcement waivers fail
closed. Unsupported optional authority is removed and recorded by
`dispatcher.lowering_records()`. Bare callback maps are no longer accepted. This runtime complements the static checker; static analysis is not
required to enforce the worker's object capabilities.

The same wiring is now available through
`cedar_security(tool, manifest=manifest_body, classes=classes, policy=policy,
dispatcher=dispatcher)`. Set `runs linux` or `runs broker` in the manifest.
The helper registers the dispatcher's kernel and broker enforcers and derives
the owner ceiling. See [isolated tools](../docs/security/object-classes.md#isolated-tools)
for mixed filesystem and custom-resource grants and the runtime baseline.
