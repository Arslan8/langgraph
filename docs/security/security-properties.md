# Security properties and composition boundaries

slangGraph separates four properties that must not be collapsed into a single
claim:

1. **Invocation authorization** decides whether a principal may request a
   concrete operation.
2. **Worker confinement** limits the authority one worker can exercise while
   that operation runs.
3. **Session information flow** limits where data learned by any earlier
   operation may subsequently travel.
4. **Intent integrity** establishes that an allowed operation is authorized for
   the user's current purpose, rather than merely inside the principal's maximum
   envelope.

An exact per-call grant proves only the first two properties. It does not, by
itself, prove session confidentiality, noninterference, safe model behavior, or
alignment with user intent.

## Cross-call information flow and pooled authority

A read-confined worker can return sensitive data to graph state and a later
network-confined worker can transmit it. Parent-child subset checks likewise do
not prevent siblings from pooling authority through checkpoints, messages,
files, IPC, or the orchestrator.

Therefore the current and phase-one claims are resource-access-control claims,
not end-to-end information-flow claims. A future IFC mode must attach provenance
to tool outputs and soundly propagate it through model inputs and outputs,
messages, graph state, checkpoints, artifacts, delegation, and framework
callbacks. Aggregate checks over a current grant, declared effects, history, or
a lossy flow summary are not evidence of noninterference.

Until that mode exists, policies that require confidentiality across calls must
place the entire session in one compartment with a combined no-egress grant, or
deny the composition. Delegation attenuation limits individual authority only;
it does not prevent collusion between communicating compartments.

## Untrusted results and confused deputies

Every tool result is untrusted, including structured objects, paths, URLs,
commands, markup, artifact references, callback payloads, and checkpoint data.
Trusted observers, renderers, stores, model clients, artifact handlers, and
callbacks must not interpret a result as authority.

Any framework-generated external action derived from a result is a new security
operation. It must receive a fresh normalized intent, grant, policy decision,
enforcement plan, and audit transaction under the originating security context.
Code that performs such an action without mediation belongs to the TCB and is a
confused-deputy vulnerability. Merely escaping or validating a value is not a
substitute for authorization.

## Resource identity and time of use

Each selector declares one resolution mode:

- **stable object**: lowering resolves and verifies an object identity, retains
  a race-resistant handle, and enforces use through that handle;
- **dynamic name**: the enforcing broker resolves the name and reauthorizes the
  resolved identity at every operation boundary.

An adapter may not authorize a pathname, alias, group name, DNS name, or service
label at decision time and later use an independently resolved object. If the
platform cannot retain or revalidate the binding, exact lowering is unsupported.

## Preparation is a separate execution

Built-in pure normalizers are TCB code. A custom transformation receives its own
minimal preflight grant, with no ambient resource or service authority unless an
operator explicitly authorizes it. Its output is untrusted.

The main request must remain no broader than the request presented to preflight,
not merely within the principal's envelope. The implemented in-process
`TRANSFORM` path conservatively requires every normalized security value to stay
equal or become a structural subset. A transformation requiring a richer
partial order must use a registered framework-owned normalizer and prove that
relation. The transformed request then passes normalization, DAC, mandatory
policy, and lowering again.

## Runtime baseline ownership

Runtime authority is an operator-owned request, not an adapter entitlement.
Adapters may report missing requirements, but may not add them to a grant.
Baseline lines are non-waivable `need` rules, pass through mandatory and
combination policy, participate in delegation comparisons, and receive the same
closed-world obligations and activation evidence as tool-requested authority.
An insufficient baseline denies execution.

Declared effects and descriptors are also requests and optimization hints. They
are not proof of what hostile code can do. Mandatory combination checks use the
complete effective grant, including baseline authority and authenticated
channels. Native confinement, not an author declaration, establishes that
unlisted effects are unavailable.

## Revocation and irreversible effects

An activation receipt proves a bounded startup condition. Revalidation detects
stale evidence but does not itself withdraw authority already issued.

- Brokers check live grant and lease state at each request and revoke credentials
  or channels when a lease ends.
- Local supervisors terminate or quarantine workers and descendants when a
  required lease is lost. Race-free revocation requires platform support.
- Open files, accepted remote requests, emitted messages, and other committed
  side effects may be irrevocable. Each adapter documents its commit point.
- After a commit point, cancellation means “stop further effects,” not rollback.

The audit outcome is `INDETERMINATE` whenever the framework cannot establish
whether an irrevocable operation crossed its commit point.

## Authority is not purpose

A principal envelope states maximum authority. It does not prove that an
operation is appropriate for the current task. Consequential operations require
task-scoped authority issued by a trusted application boundary and bound to the
principal, artifact, normalized concrete parameters, policy version, expiry,
and replay rules. Human approval is one possible issuer; model text and tool
output are not.

Even with exact confinement, a compromised model can maliciously select an
allowed file, recipient, or query. slangGraph must claim that such an operation
was exactly authorized and confined—not that it was beneficial, intended, or
safe—unless task-specific authority independently establishes that property.
