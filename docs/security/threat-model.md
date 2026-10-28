# Threat model

This page states who slangGraph defends against, what it trusts, and what its
route-scoped guarantees cover. The per-route evidence is in
[supported-surface.md](supported-surface.md) and
[evidence-standard.md](evidence-standard.md).

## Adversary

The adversary controls:

- **The AI model's output.** Tool-call choices, arguments and generated text
  are treated as hostile. No guarantee depends on the model behaving well.
- **Untrusted inputs.** These include data the model reads, tool results and
  documents. Prompt injection is assumed to succeed at influencing the model.
- **Admitted tool code.** The body of a language-sandbox tool or of
  generated code run in an isolated worker is untrusted, even though it was
  admitted. Source being available, or code running in-process, does not make
  it trusted.

The adversary does not control the controller process, the deployment
configuration, the operator's policy, the host operating system, LangGraph and
LangChain framework code, or the **application's own graph code** (node
functions written by the developer who deploys the app). Application code is
trusted (advisor decision D11); code it generates at runtime, and tool
implementations, are not.

## Trusted computing base

These components are assumed correct. Their bugs are outside the guarantees
below.

- **The language-sandbox interpreter.** Admitted tool source is lowered to a
  restricted instruction set and executed by our interpreter
  (`security/_language_sandbox.py`, `language_sandbox.py`, `inprocess.py`).
  Admission checks each program's instructions, types and terminal calls,
  and the checker itself is proved in Lean (`proofs/language-route`): any
  program it accepts calls only registered terminals. The interpreter's own
  correctness is **assumed, not proved**. An
  interpreter bug could let admitted code escape the language sandbox. Use
  the isolated-worker route when that risk is unacceptable.
- **Registered terminals.** These are the operations a language-sandbox
  program may call. Their implementations are trusted.
- **Application graph code and the framework.** LangGraph, LangChain (including
  tool binding such as `bind_tools`) and the developer's node functions run in
  the controller and are trusted. Effects they perform directly are outside the
  per-route guarantees except where they pass through a hook (LLM calls) or a
  mediated operation (tools, output, generated computation).
- **The controller runtime.** This covers the policy engine, `HostRouter`,
  mediators, `ObjectManagerHost`, configuration and admission code, the
  LangGraph scheduler, and module initialization and runtime binding as
  listed in each component's premises.
- **Python, the OS kernel and LSMs, bubblewrap, libseccomp and Docker.**
  These are assumed to behave as documented.
- **The Lean kernel and toolchain.** Lean proofs cover a finite model of the
  worker lifecycle, not the Python code, compiler or OS that implement it.

## What "safe" means on a supported route

1. **SGV901, placement.** Every protected action on the admitted surface
   passes the permission check first. Bodies outside the admitted inventory
   are refused before they run.
2. **SGV902, composition.** What executes or is published is exactly what
   was authorized, with the same principal, request, labels and approval
   binding.
3. **SGV903, host enforcement.** On the isolated-worker route the worker
   receives only the granted authority, activation precedes execution, and
   the worker is confirmed cleaned up.

For output publication, the caller receives exactly the authorized content,
and its confidentiality never exceeds the caller's clearance.

## Strength by execution route

| Route | What stops an escape | Strength |
| --- | --- | --- |
| Isolated worker (Linux) | Kernel enforcement: seccomp, namespaces, filesystem grants | Strongest. The lifecycle is Lean-checked and native runs confirm enforcement; kernel correctness is assumed. |
| Language sandbox (in-process) | Our interpreter (TCB) | The checker is proved in Lean: any program it accepts calls only registered terminals during any evaluation (`proofs/language-route`, `checked_program_calls_only_registered`), and it agrees with the Python checker on controls from the real lowering. The interpreter executing the admitted program faithfully is assumed. |
| Output publication | Not code execution | Content and label correspondence is proved under stated premises. |

The supported-route permission guarantees depend on the listed premises and
the deployment rule below. Containment of untrusted code is strongest in host
isolation.

## Trust boundary: trusted application, contained tools (D11)

This section records advisor decision D11 (2026-10-27) and what follows from it.
It is the boundary every route claim is stated against.

### The decision

Three kinds of code run in a slangGraph application. They are treated
differently:

| Code | Written by | Trust | Where it runs |
| --- | --- | --- | --- |
| **Framework**: LangGraph, LangChain, the slangGraph runtime | Us and upstream | Trusted (TCB) | Controller process |
| **Application graph code**: the developer's node functions, prompts, parsers, glue | The developer who deploys the app | **Trusted** | Controller process |
| **Tool implementations and generated code**: tool bodies, code the model writes at runtime | Third parties, or the model under attacker influence | **Untrusted, contained** | Language sandbox or isolated worker |

The line is drawn at **who chose the code**. The deployer chose the framework and
their own graph; they did not choose what a tool does internally or what code
the model generates while reading attacker-controlled input. Only the latter
must be contained.

### Rationale

- **It matches how these systems are built and deployed.** A deploying
  organization reviews and owns its graph. Tools are frequently third-party,
  and generated code is written on the fly by a model that prompt injection can
  steer.
- **It keeps the proof finite.** Containment and proof effort go where the
  attacker actually has code: tool bodies and generated code. Proving arbitrary
  developer Python would be unbounded (see D8: a finite runtime surface).
- **The framework already sits in the TCB.** LangGraph and LangChain run in the
  controller next to the policy engine. Treating them as adversarial would mean
  distrusting the process that enforces policy. Framework features such as
  `bind_tools` are therefore not a security concern.

### What the attacker can reach

The attacker controls model output and untrusted inputs. When the deployment
rule below is followed, the supported paths for that influence are:

1. **Tool calls the model requests.** They pass through a tool node, the proved
   `HostRouter` and policy, and run the untrusted tool implementation inside the
   language sandbox or an isolated worker.
2. **Code the model generates.** It runs only in the isolated worker, with the
   granted authority only (SGV903; the lifecycle is Lean-checked).
3. **Text the model returns.** It is data handed to trusted application code.
4. **Published output.** It passes the proved publication route: the caller gets
   exactly the authorized content, within clearance.

### Worked example: pandas

1. A user asks for monthly sales totals. The pandas app's own node functions,
   which are **trusted**, build a prompt and call the LLM.
2. The LLM, possibly steered by a malicious CSV cell, replies with Python code.
3. Trusted node code passes that code to the compute operation. It runs in the
   **isolated Linux worker**: no network, read access to the granted dataset
   only, no process creation, confirmed cleanup.
4. Results return as inert data. The final answer leaves through the **proved
   publication route**.

The attacker controls step 2's content. The containment that matters is step
3's, and the output check at step 4. Steps 1 and 3's hand-off are trusted
application behavior.

### What D11 does not protect against

D11 is a scope decision, not a claim that these risks are absent:

- **Confused deputy in trusted code.** Application code acts on attacker-
  influenced model text. If a developer writes code that, for example, calls
  `os.remove(model_reply)` or `eval(model_reply)` *in the controller*, that is
  trusted code misbehaving on attacker data, and it is outside our guarantees.
  The defense is the deployment rule below, not a proof.
- **Effects trusted code performs directly.** File, network or service access
  that application code performs itself, rather than through a mediated
  operation, is not checked. Only effects through mediated operations (tools,
  generated computation, output) and hooks (LLM calls) are covered.
- **Malicious or compromised application code.** A deployer who installs a
  malicious graph, or whose dependencies are compromised, is outside the model.

**Deployment rule that follows:** application code must not execute, open,
send or otherwise act on model output directly. It must hand model-produced
code to the compute operation, call tools through tool nodes, and publish
through the output route. Code review of the application is the deployer's
responsibility.

### How D11 appears in the implementation

- **Contained:** tool bodies (language sandbox or worker) and generated code
  (Linux worker). Their routes are proved and gated: `language-sandbox-tool`,
  `tool-node-dispatch`, `linux-worker-compute`.
- **Hooked:** LLM calls made through the runtime's model operation (see LLM
  calls below).
- **Proved on the way out:** output publication.
- **Closed admission** includes explicitly declared trusted application nodes
  and branches, alongside supported tool and model descriptors. Declarations
  bind captured identities and are rechecked before dispatch. A ToolNode cannot
  be declared trusted to bypass tool containment. Trusted application bodies
  execute in the controller; admission does not prove their behavior on hostile
  inputs. The C-closed pandas cohort declares 14 trusted nodes and three trusted
  branches and separately admits its compute ToolNode.

### What the paper may claim under D11

"For an application whose trusted graph code follows the deployment rule,
supported tool calls and model-generated code use the accepted containment
routes, LLM calls made through the runtime's model operation pass a policy hook,
and output published through the mediated route is exactly the authorized
content within clearance. These guarantees depend on the stated route premises
and the correctness of the trusted computing base. Direct effects of trusted
application code are outside the guarantees."

## LLM calls

An LLM call is a modeled runtime operation with a hook point (D9). When a call
goes through the runtime's model operation, the hook asks the policy before the
call, and a deny means the LLM is never invoked. Under closed admission that
operation is an admitted model node: an exact allowlisted model client. The
runtime does not perform the call or guarantee what content the model receives.
Future guards attach at the hook.

Under D11, trusted application code may also call the LLM directly, as the
pandas app does inside its node functions. Such calls are trusted application
behavior and are not policed by the hook. A deployer who wants every LLM call
under policy routes its calls through the runtime's model operation.

## Out of scope

- Whether the model is correct, honest or resistant to manipulation.
- Side channels such as timing, sizes and metadata, and covert channels.
- Availability and denial of service.
- Correctness of any TCB component listed above.
- Capabilities and applications the manifest marks unsupported. They are
  refused or excluded, not proved.
- Whole-system completeness across all of LangGraph. That remains not
  established; acceptance is route-scoped.
