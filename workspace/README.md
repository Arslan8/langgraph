# slangGraph security project workspace

This workspace contains progressively more complete examples of slangGraph tool
security. The examples teach the runtime contract that the student policy
inference project must target; they are not the complete project by themselves.

## Demo folders

Each demo has its own directory and a `demo.py` entry point. Supporting workers,
policies, simulators, and app-owned mediators live beside the demo that uses them.

| Folder | Teaching focus |
| --- | --- |
| [01_quickstart](01_quickstart/README.md) | Basic ToolNode |
| [02_dac](02_dac/README.md) | Discretionary access control |
| [03_principals](03_principals/README.md) | Principal-based policies |
| [04_resource_grants](04_resource_grants/README.md) | Resource grants |
| [05_custom_resource](05_custom_resource/README.md) | Custom resource class: pump |
| [06_database](06_database/README.md) | Using a database mediator |
| [07_manifest_verification](07_manifest_verification/README.md) | Static manifest verification |
| [08_custom_mediator](08_custom_mediator/README.md) | Extending the framework: custom mediator |
| [09_no_internet](09_no_internet/README.md) | Mandatory access control: no internet |
| [10_repeat_after_me](10_repeat_after_me/README.md) | Analysis and provenance block detected Repeat-After-Me tool calls |
| [11_analysis_plugin](11_analysis_plugin/README.md) | Register one analyzer and return a finding |
| [12_analysis_boundaries](12_analysis_boundaries/README.md) | Observe request / execution / response order |
| [13_provenance](13_provenance/README.md) | Preserve source ancestry through transformations |
| [14_information_flow](14_information_flow/README.md) | Propagate confidentiality and check destination clearance |
| [15_analysis_enforcement](15_analysis_enforcement/README.md) | Block a tool when required analysis is unavailable |
| [16_analysis_inspection](16_analysis_inspection/README.md) | Query findings and match completion notifications |
| [17_analysis_checkpoints](17_analysis_checkpoints/README.md) | Restore metadata and reject a changed policy |
| [18_analysis_evaluation](18_analysis_evaluation/README.md) | Count classifier errors and measure processing time |

Demo 10 also supports a [real local LLM mode](10_repeat_after_me/README.md#run-with-a-real-local-llm) with llama.cpp or Ollama.

## Focused analysis lessons

Demos 11–18 each teach one analysis capability independently of the combined
Repeat-After-Me scenario. Start with 11 for the plugin contract; each subsequent
folder has a self-contained `demo.py`, expected behavior, and a small edit to try.
The setup is intentionally visible in each script instead of hidden in a shared
helper. No demo imports another demo or requires a previous run.

Use the prebuilt environment (`uv sync --directory libs/prebuilt` if needed):

```bash
libs/prebuilt/.venv/bin/python workspace/11_analysis_plugin/demo.py
libs/prebuilt/.venv/bin/python workspace/12_analysis_boundaries/demo.py
libs/prebuilt/.venv/bin/python workspace/13_provenance/demo.py
libs/prebuilt/.venv/bin/python workspace/14_information_flow/demo.py
libs/prebuilt/.venv/bin/python workspace/15_analysis_enforcement/demo.py
libs/prebuilt/.venv/bin/python workspace/16_analysis_inspection/demo.py
libs/prebuilt/.venv/bin/python workspace/17_analysis_checkpoints/demo.py
libs/prebuilt/.venv/bin/python workspace/18_analysis_evaluation/demo.py
```

These lessons run offline without credentials, models, Cedar, or a Linux sandbox.
Effects stay in local lists or temporary databases. Each script asserts its expected
outcome. Timing in demo 18 varies by machine; its tiny keyword fixture teaches
metrics, not real-world detection quality. These focused lessons demonstrate the
named behavior, not coverage of every adapter or a complete security proof.

## Run the examples

Run each example from the repository root:

```bash
python3 workspace/01_quickstart/demo.py
python3 workspace/02_dac/demo.py
python3 workspace/03_principals/demo.py
python3 workspace/04_resource_grants/demo.py
```

Example 5 requires Linux with Landlock, `libseccomp.so.2`, and the Cedar CLI.
It uses two terminals and a Unix-domain socket:

```bash
# Terminal 1: device behavior and accepted-command log
python3 workspace/05_custom_resource/simulator.py

# Terminal 2: interactive authorized controller
python3 workspace/05_custom_resource/demo.py
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
python3 workspace/05_custom_resource/demo.py --demo
```

Example 6 adds a parent-owned SQLite database with record-level Cedar
permissions. It requires Python 3.11+, Linux Landlock ABI 5+, libseccomp, and
the Cedar CLI. No database server or manual setup is needed:

```bash
libs/prebuilt/.venv/bin/python workspace/06_database/demo.py
```

The demo shows the policy matrix, each typed request, its actual grant or denial
reason, and a live table of the fixture records with changed/deleted rows marked.
For a presentation, pause before each operation with:

```bash
libs/prebuilt/.venv/bin/python workspace/06_database/demo.py --step
```

Use the prebuilt environment's Python 3.11+ interpreter; a bare `python3` may
select a different environment without SQLite's required `Connection.setlimit`
API. The demo checks this requirement before creating fixtures or dispatching work.

Colors are enabled on terminals and disabled in captured output or when
`NO_COLOR` is set. Record tables are the trusted controller's view of demo data,
not extra data exposed to the worker. The final summary checks every expected
decision and database change, including that denied requests changed nothing.

The demo creates a temporary database, checks allowed and denied read/write/delete
requests, verifies that another user's record stayed unchanged, and cleans up.
The worker calls typed `records.read`, `records.write`, and `records.delete`
methods. A shared `RecordsAPI` contract supplies their signatures, checker effect
mappings, generated SLP class, and backend dispatch validation. The controller
checks the worker source against its manifest before dispatch; it does not import
the worker to perform this analysis. Strings remain inside the broker protocol,
not in the tool-facing operation API.
The database directory is kept outside worker-readable code roots. See the
[SQLite mediator contract](../docs/security/object-classes.md#sqlite-record-mediator)
for the fixed schema, payload limits, and integration API.

Resource backend implementations live in
[`security/mediators/`](../libs/prebuilt/langgraph/prebuilt/security/mediators/README.md).
The database demo imports its backend from `security.mediators.sqlite`. To build
another backend, start with the empty
[`template.py`](../libs/prebuilt/langgraph/prebuilt/security/mediators/template.py)
and follow that directory's implementation and registration guide. The template
intentionally denies support until its resource semantics are implemented.

Example 7 demonstrates static manifest verification. Example 8 demonstrates
runtime resource mediation and requires Linux Landlock ABI 5+, libseccomp, and
the Cedar CLI.

```bash
python3 workspace/07_manifest_verification/demo.py
python3 workspace/08_custom_mediator/demo.py
```

[Example 7](07_manifest_verification/demo.py) uses a real `@tool` and automatic verification
in `cedar_security`. Reading `path` fails against the fixed-file manifest. Replace
`/tmp/other-report.txt` with `@{path}` to cover the read and pass. Alternatively,
return a constant: unused manifest permission is valid. Setup never invokes the tool.

The static contract is **inferred ⊆ manifest** and **inferred ⊆ allowed operations**.
The demo has no manual verifier calls or prints. Framework diagnostics use red
labels and yellow messages; `NO_COLOR` disables highlighting.

[Example 8: custom mediator](08_custom_mediator/demo.py) shows how an application
extends the framework with its own resource mediator. Its rule: increments
must be **1, 2, or 3**. Alice has permission to increment the bound counter.
Adding `2` succeeds; adding `-1` is rejected and leaves the counter at `2`.
This is resource-specific validation, not a DAC permission denial.

Start with the three-line `increment_counter` tool. The shared
[api.py](08_custom_mediator/mediators/api.py) defines the contract and broker client;
[counter.py](08_custom_mediator/mediators/counter.py) separates `CounterBackend`
(the operation) from `CounterMediator` (`assess` for lowering, `validate` for the amount check).
The parent supplies both through `COUNTER.bind(...)`, then registers
`resources=(resource,)`. The framework owns the object identity: the tool calls
`counter.increment(amount)`, and `resource.permission("increment")` declares access
without an application-managed selector. The combined constructor form and
optional-validation behavior are shown in the [demo guide](08_custom_mediator/README.md).

The parent owns the in-memory counter. The tool runs in a confined worker and
uses the typed `counter.increment` API; it has no access to the parent's state.
The same demo file provides the worker function, so there is no separate worker
script. There are no fixture files, lifecycle logs, optional-resource cases, or
payload attack loops. The backend is trusted application code, not a distributed
counter or general transactional store.

Example 9 configures operator MAC independently of the tool's DAC. It requires
Linux Landlock ABI 5+, libseccomp, and the Cedar CLI:

```bash
python3 workspace/09_no_internet/demo.py
```

[The controller](09_no_internet/demo.py) installs the operator-owned
[no-internet policy](09_no_internet/no_internet.cedar) once during trusted
runtime startup using `install_mac_policy(...)`, before any execution.
Every graph, session, and ToolNode in that interpreter is governed by it;
`cedar_security(..., policy=DAC_POLICY)` only supplies the local DAC setup.
The policy cannot be replaced or uninstalled through the public API. Graphs
without supported mediation fail closed, including graphs compiled before
installation and raw Pregel/functional programs. Sync, async, and threaded
execution share the same policy. The legacy `mac_forbids` argument adds local
restrictions only; omitting it does not omit runtime MAC.

The Python controller and runtime bootstrap remain trusted. Every independent
controller process must install the operator policy at startup; this is not a
machine-wide kernel LSM. Arbitrary Python nodes, branches, and tool wrappers
are refused while MAC is active because they lack a supported confinement
boundary. Supported tools use the Linux object broker or the admitted,
restricted in-process resource monitor. Callbacks and runtime services remain
trusted infrastructure; hostile controller code requires OS isolation.

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

Example 10 shows a detected Repeat-After-Me attack blocked before tool execution.
It runs offline with a scripted classifier, the existing ToolNode authorization
path and a temporary SQLite ledger. The baseline inserts one row, the detected
attack inserts zero, and the benign control inserts one. Quoted JSON never executes.

```bash
libs/prebuilt/.venv/bin/python workspace/10_repeat_after_me/demo.py
# Presentation: synthetic transcript and pauses between cases
libs/prebuilt/.venv/bin/python workspace/10_repeat_after_me/demo.py --step --show-prompts
```

[Demo 10's guide](10_repeat_after_me/README.md) explains the public analysis trace,
retrieval/tool-result variants and deliberately missed attack that demonstrates
the limits of classifier detection. It requires no local model or sandbox setup.

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
7. A real tool rejected for an incorrect manifest; fix the manifest to pass.
   [Companion examples](07_manifest_verification/bypasses.py) reject direct library
   and reflection bypasses before execution.
8. A typed counter mediator that accepts a valid increment and rejects an invalid one.
9. Operator-owned mandatory policy removing internet authority despite a DAC
   permit, with local work continuing inside a sandbox that blocks sockets.
10. Required analysis and persistent provenance feeding a fixed restrictive policy,
    with actual tool effects compared before and after enabling the defense.

Example 4 also prints the retained temporary directory containing the generated
Cedar schema, entities, policies, and requests. These artifacts can be copied or
edited for Cedar CLI experiments without changing a grant that has already been
issued.

In-process examples now require mandatory source/manifest consistency admission.
Example 4 uses `security.inprocess.read_text`, which checks the invocation's
surviving grant, instead of reading the file directly. Unknown calls, direct
resource access, missing source, and unsupported bodies fail configuration.
See [admission scope and limitations](../docs/security/manifest-consistency.md).

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

`05_custom_resource/worker.py` is the untrusted tool implementation. A fresh Linux worker
activates Landlock, seccomp, resource limits, and a cleared environment before
importing that file. It receives only its arguments and an inherited broker
channel. It cannot open a device socket, create a subprocess, or access files
outside its configured runtime roots and private temporary directory.

`05_custom_resource/demo.py` owns the trusted pump adapter and socket path.
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

For deployment-wide installation, put `mac.cedar` in a persistent directory.
The default is `/etc/langgraph`. Set `LANGGRAPH_MAC_DIR` in the deployment's
launcher or service environment to choose another directory:

```bash
mkdir -p "$HOME/my-deployment/policy"
cp workspace/09_no_internet/no_internet.cedar "$HOME/my-deployment/policy/mac.cedar"
export LANGGRAPH_MAC_DIR="$HOME/my-deployment/policy"
python3 workspace/09_no_internet/demo.py
```

Every controller launched with that setting loads the same policy automatically.
Keep the setting in the deployment launcher to retain it across shell sessions.
Relative directories resolve against the controller's startup working directory;
absolute paths are recommended. An explicitly configured empty or missing directory,
missing `mac.cedar`, or unreadable/invalid policy fails closed.
The default `/etc/langgraph` directory and policy must be root-owned. Custom
directories and policies may be owned by root or the deployment user. Neither
may be group/world writable, and symlinks are refused. Without a custom setting,
an absent default policy preserves normal operation.

The directory is selected at first policy load, not per graph or session.
Changing the environment afterward cannot replace the loaded policy, and
`install_mac_policy` cannot override it. Restart controllers after policy changes.
This trusts the deployment launcher and controller account; untrusted code must
run behind an OS boundary. Each container needs access to the configured directory.
