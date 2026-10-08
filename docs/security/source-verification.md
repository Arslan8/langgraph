# Tool verification framework

## Developer acceptance workflow

From `libs/prebuilt`, run:

```sh
make security-verify
```

This source-only command recomputes the router proof and adapter checks,
prints an actionable repair queue, and writes `security-verification-report.json`.
Each finding has a stable rule ID, source location, structural fingerprint,
owner, and fix guidance. It does not execute source candidates or tool bodies.
Exit 0 now requires complete verification. Findings, missing proof evidence,
unsupported analysis and exhausted analysis budgets all prevent acceptance.
The Python CLI uses exit 1 for an incomplete result and exit 2 for an invalid input/report. Make may map a failed
subcommand to its own exit code.

Schema 2 separates `regression_checks_passed` from `acceptance_passed`.
`acceptance_passed` equals `complete`; clearing the known patterns no longer
produces a successful exit. Schema 1 reports remain usable for fingerprint
comparison, never for importing their earlier acceptance decision.

To compare iterations without treating an old report as authority:

```sh
make security-verify SECURITY_REPORT=/tmp/slanggraph-before.json
# After making changes:
uv run python -m langgraph.prebuilt.security.developer_verification \
  --compare /tmp/slanggraph-before.json --output /tmp/slanggraph-after.json
```

The comparison reports new, resolved, and remaining task fingerprints. Line-only
edits do not change adapter fingerprints; structural changes do. No finding is
waived automatically. `--list-checks` prints the rule descriptions without
running analysis.

| Rule | Developer obligation |
| --- | --- |
| `SGV101` | Preserve effective authorized results through the actual effect. |
| `SGV102` | Include current object DAC in the resume chain. |
| `SGV103` | Normalize or reject every supported state/model input shape. |
| `SGV104` | Mediate callback publication as well as normal stream yields. |
| `SGV105` | Bind stored state to invocation identity, not just channel names. |
| `SGV106` | Place checkpoint history, writes, and administrative effects. |
| `SGV107` | Bind backing-store read results to authoritative ownership and effective values. |
| `SGV108` | Authenticate and principal-bind checkpoint history tuples before publication. |
| `SGV190` | Restore missing/unresolved analyzer inputs or update its model. |
| `SGV201` | Restore the router's required protocol and exact identity bindings. |
| `SGV301` / `SGV302` | Resolve escape findings and stale/malformed waivers. |

These adapter rules detect specific review patterns. They are not a replacement
for full dataflow, path dominance, alias, or isolation analysis. For example,
assigning an authorized result without using it is not a correct fix merely
because it clears a discarded-expression diagnostic. Missing required source
or methods fails analysis; newly declared checkpoint methods are inspected
without extending a fixed API list. Other novel structures may still require
an analyzer extension and must not be described as proved.

The report separates implementation findings from verifier-owned proof work:
`SGV901` (placement), `SGV902` (adapter composition), and `SGV903` (host adapter
and isolation evidence). Developers are not asked to waive these gaps. The
older command, used in CI, remains an equivalent alias:

```sh
make security-verify-complete
```

Both commands require system proof closure. Clearing the implementation findings
alone does not satisfy either. CI uploads the same JSON repair queue developers get
locally. Add checker regressions in `test_adapter_verification.py` and CLI/report
regressions in `test_developer_verification.py` when extending a rule. Candidate
fixtures must remain source-only; include both rejected and corrected examples.

## Current layered verification

ADR 0007 changes the main proof obligation to the composed object-manager
boundary. The current command is:

```sh
uv run python -m langgraph.prebuilt.security.layered_verification \
  --require-complete --output layered-verification-report.json
```

This lower-level evidence command reruns the router proof, inventories the independent ten-class/30-operation
contract, checks request/operation declaration drift, records adapter call-site
candidates and source hashes, runs adapter regressions, and checks escape-waiver disposition. The
[recorded report](layered-verification-report.json) separates these results.
Candidate discovery is syntactic, not an alias, inheritance, or dominance
analysis. It cannot establish placement completeness. The system gate therefore
remains nonzero until a placement and composition proof is implemented and
discharges the remaining obligations. Omitting `--require-complete` now has the
same fail-closed behavior.

## API ledger and publication transfer analysis

The [agreed non-bypassability scope and permutation matrix](../../verifier/docs/README.md)
defines the assignment. `make security-verify-permutations` runs the finite
denial/binding regression matrices and writes a separate test-evidence report.
It does not turn incomplete system verification into acceptance.

`evidence.obligations` records every function/method declaration in the supplied
repository snapshot, including private/nested definitions and new source files.
Each row binds its location and symbol to the source digest and records partial
router/publication evidence separately from outstanding composition obligations.
This deliberately includes helpers and verifier code: the declaration count is
a conservative inventory, not a number of public APIs or a coverage percentage.
Inherited APIs appear additionally in the publication engine's surface inventory;
unresolved bases and dynamic behavior prevent closure. Static discovery does not
establish that arbitrary runtime-generated methods have been enumerated.

`evidence.publications.proof` uses the existing interprocedural transfer engine
for `MediatedStore`, `MediatedCheckpointer` and `OutputMediator`. It follows
supported helper bodies, aliases, inherited methods and branches, with per-entry
steps, call graphs, publication bindings and unsupported-source diagnostics.
Source dependencies and package initializers are discovered without importing
candidate code. A verified entry under an incomplete source model does not
establish an adapter proof. Ordinary helper names never establish authority.

The transfer engine now supports explicit publication contracts:

- `ReadSource(target)` supplies a fresh opaque data identity and no permission.
  It models acquisition for this property only. It does not prove authorization
  of the read itself or side effects; those need `Operation` contracts.
- `return_requirements` requires a fresh matching grant for the exact API result
  on every modeled normal exit. Selectors include the receiver as positional
  argument zero for ordinary methods. Principal/resource bindings can be required
  alongside `result:`. The contract applies to newly discovered and inherited
  APIs as well as the original surface.
- `refusing_authorizers` is an explicit trusted primitive contract for functions
  whose normal return already establishes authorization. It is never inferred
  from a function's spelling or a successful example. Primitive failure payloads
  must not publish protected data. Dynamic exception publication stays unresolved.
- `allow_none_return`, false by default, can explicitly treat a statically known
  `None` as an unprotected absence marker. The repository data-propagation model
  enables this for constructor completion and empty results; it does not exempt
  any call/effect from analysis or authorize publication of other values.

`VerificationSpec.entry_bindings` separately specifies the original entry
arguments required at each authorizer. It applies through aliases and helper
calls and is checked even when authorization and effect agree with each other.
Selectors use the original entry's argument order, including `self` at zero for
instance methods and keyword-only arguments after positional arguments. Enabling
this contract requires every discovered entry to have a contract; stale or
unclassified entries remain unresolved. `authorizations` records both actual and
expected arguments with an `entry_bound` result.

The engine models field-only native `typing.NamedTuple` and
`typing_extensions.NamedTuple` declarations with postponed annotations and
immutable literal defaults. Constructor positional/keyword binding, field and
tuple projections, `_replace`, and `_asdict` preserve the actual value identities.
Replacement creates a new record; dictionary conversion detaches its top-level
mapping. Both retain dependencies on nested mutable values, so changing an
authorized record's nested data invalidates its pending or established grant.
Native invalid constructor arguments and immutable-field writes stop the normal
continuation; enclosing exception handlers are still analyzed.
Configured effect contracts take precedence over native generated-method
handling. Publishing a supported data-only record still requires the declared
grant for that exact record; executable capabilities inside its fields cannot
escape by being wrapped in a tuple. Records with explicitly effectful methods
remain capability-bearing objects.

This model covers the source declarations of `CheckpointTuple`, `GetOp`,
`PutOp`, `SearchOp`, `MatchCondition`, and `ListNamespacesOp`. It does not infer
that arbitrary API inputs have those shapes from their annotations. Custom
record methods, subclasses, effectful defaults and unmodeled generated members
remain unresolved. Selecting a record itself as an API surface also requires
generated-method verification. These contracts and source-only binding
permutations are exercised in `test_verification_named_tuples.py` and
`test_verification_named_tuple_publication.py`.

Immediate synchronous generator expressions supplied as the sole argument to
resolved native `tuple` or `list` consumers use the finite comprehension model.
This preserves callee/first-iterable evaluation order, local target bindings,
filters, exceptions and fresh authority for each iteration. Deferred generators,
unknown consumers, async generators, assignment expressions, later call arguments
and unknown or mutating iterables remain unresolved. The source-only matrix in
`test_verification_generators.py` covers 576 combinations plus ordering, alias,
exception and unsupported-shape regressions. An effect-free entry can be locally
verified while the existing whole-spec gate remains incomplete because no
dispatch obligation was reached; these are different report fields.

The repository analysis intentionally does **not** declare router calls as
refusing-return authorizers: they can return escalation objects. Correct receiver
binding and that result protocol still need a model. Ownership, integrity,
pending-write authentication and host composition also remain separate obligations.
The generic engine can prove supported publication contracts; the current
repository adapter composition is not yet proved. See the source-only positive
and negative fixtures in `test_verification_publication.py` and
`test_publication_verification.py` for extension tests.

CI uses the developer command's strict gate and separately runs Tool API conformance. The router
proof requires the correct authorization protocol for each entry and the
original input identities, including the original approval on resume. Matching
an altered principal at both authorization and dispatch is insufficient.

The prior installed-source report and its 175-entry denominator are historical
whole-Python diagnostics, not current object-manager coverage. That optional
analysis remains available below; the shared source transfer engine is still
used to prove the router. Unsupported tool internals are not automatically
discharged as host-MAC obligations: framework access must first be shown to
cross the authenticated object boundary.

## Optional whole-Python diagnostic

`langgraph.prebuilt.security.verification` is an interprocedural source analyzer
with an installed-framework driver. It computes authorization state through
helper bodies; it does not accept hashes or successful examples as proof that a
helper preserves authority.

From `libs/prebuilt`, run the legacy integrated diagnostic:

```sh
uv run python -m langgraph.prebuilt.security.verification \
  --installed --output tool-verification-report.json
```

This discovers installed Tool/base-class source, scans the prebuilt package for
new classes, follows transitive imports to already loaded source modules in the
discovered framework distributions, analyzes every discovered surface method,
and runs the execution
API conformance matrix. Both layers must pass for exit zero. It is no longer the
system gate in CI; the layered gate above replaces it without upgrading any of
its unresolved obligations to passing results.

Dependency discovery reads source and existing module dictionaries; it does not
execute candidate imports or invoke lazy export hooks. A loaded export can
identify an additional source provider, but it cannot establish an alias or
replace analysis of the export mechanism. Dependencies outside the inventoried
distributions and modules that have not been loaded still require source or an
explicit primitive model when reached. This collector is not a claim that all
possible dynamic imports have been discovered. Missing source for a loaded
dependency fails the installed audit; namespace packages need no fabricated
initializer.

## A verification result that can succeed

The source-only legacy gateway fixture demonstrates the supported language:

```sh
uv run python -m langgraph.prebuilt.security.verification \
  ../../docs/security/verification-fixtures/legacy_gateway.json \
  --output legacy-gateway-proof.json
```

This returns `complete: true` for seven discovered entry points. The fixture
contains sync/async gateway APIs, a derived tool, method aliases, and policy
helpers. Its `policy` and `legacy` imports name **terminal contracts**, not
installed modules: the analyzer parses the fixture and never executes it. This
result applies to the fixture, not the installed LangGraph implementation.

The test suite changes the fixture to omit checks, substitute arguments, repeat
dispatch, reuse superseded decisions, add an unguarded API, expose an executable,
or introduce unsupported behavior. Those variants cannot receive a successful
result. Adding a new source file under a configured source root also changes the
inventory automatically.

## Transfer rules

The abstract state contains local identities, pending policy decisions, possible
verdicts, and fresh authorization facts. A fact is indexed by the permission
domain and the exact selected argument identities, normally principal and
request. The request must include security-relevant tool identity and
arguments; the terminal contract must preserve that binding.

1. Calling an authorizer creates a pending decision and supersedes earlier
   authority for those bindings. Calling an authorizer is not itself approval.
2. A branch that establishes `decision.verdict is Verdict.ALLOW` grants a fresh
   authorization fact. Other verdict paths do not.
3. Calling a terminal operation requires that exact fact and consumes it. A
   physical retry requires another successful decision.
4. Helper calls bind positional/keyword arguments, analyze the callee's body,
   and propagate path-specific returns and authorization facts back to the
   caller. Aliases retain their identity. Immutable tuple construction, unpacking
   and constant-index projection preserve element identities. Known tuple and
   dictionary and native list arguments can be forwarded through variadic helpers without
   losing principal/request/constraint identities. Arbitrary positional variadic
   API inputs retain their unknown length; they are never treated as empty
   arguments. Native keyword dictionaries retain an unknown remainder rather
   than assuming no keys. Assignment
   expressions evaluate their value before binding it, retaining the same
   identity on true and false branches. Function-local name annotations do not
   execute or initialize a value; annotated assignment values still execute.
5. Boolean conditions short-circuit and retain path-specific verdict facts.
   Exception handlers use a conservative exceptional-prefix state with assigned
   locals made unknown and authorization cleared. Finalizers run on normal,
   return and exceptional exits. Handlers must establish fresh authorization;
   this can reject safe programs until a more precise exception model exists.
   Uncaught exceptional paths leave the live-path budget only after checking
   their payloads for escaping capabilities. An enclosing handler or finalizer,
   including one in a caller, keeps those paths live. Each entry records its
   `settled_exceptions` count separately from explored dispatch obligations.
6. Dictionaries with known string keys preserve aliases, projections, merges,
   shallow copies, `get` and `setdefault` results. `setdefault` evaluates its
   default expression even for an existing key; an insertion revokes dependent
   grants. `update` accepts a known finite native mapping and explicit keyword
   entries, reads its source after evaluating all arguments, and applies keyword
   overrides last. An empty update changes no authority. Unknown mapping tails
   and iterable-of-pairs updates remain unresolved. Bound mapping methods retain
   dependencies on their receivers. Readonly proxies reject mutating methods
   before argument evaluation.
   Subscript assignment and deletion update
   every alias and revoke pending and granted authority whose bound object
   graphs reach the changed object. Readonly mapping proxies retain a dependency
   on their live backing mapping; shallow copies preserve nested aliases.
   Handler-entry dictionary contents are unknown because any prefix may have
   mutated them. Returning a dictionary or exception containing an executable
   capability prevents verification, including cyclic containers.
7. Source-defined ordinary objects get distinct allocation identities. The
   engine analyzes their constructors, follows field aliases and bound methods,
   and revokes dependent authorization on field writes or deletion. Custom object
   protocols and escaping object interfaces remain unresolved. Every class
   definition is checked for initialization effects, including unused classes.
8. Standard dataclasses with literal defaults and the supported `frozen`/`slots`
   options bind constructor arguments to fresh fields and analyze the actual
   `__post_init__` body. Frozen writes raise; explicit `object.__setattr__` writes
   remain modeled and invalidate dependent grants. Standard `field` declarations
   support literal defaults and statically bound source or data factories.
   Factories run through the call analyzer in the defining module, in field
   order. Their mutations, returned aliases, authority and exceptions propagate
   to the caller. Failure skips later factories and post-initialization.
   Unknown supplied arguments retain a path through the stdlib factory sentinel;
   merely supplying an argument does not prove that the factory is skipped.
   Lambdas, dynamic metadata, unsupported field options, inheritance and generated
   API surfaces remain unresolved. Known scalar comparisons can discharge
   literal validation branches.
9. Standard `isinstance` queries follow known builtin and source inheritance,
   including the supported collection ABCs. Unknown ordinary values retain both
   outcomes and their original identities. A positive query does not grant
   authorization or turn an unknown receiver into a trusted builtin method.
   Tuple class information short-circuits only after evaluating its argument
   expressions. Invalid arguments raise; custom instance-check protocols and
   unresolved metaclasses remain unresolved. Supplied source replacing a
   standard type-model module invalidates the model assumptions.
10. Literal module constants resolve directly and through source re-exports.
    Their use as configuration keys preserves dictionary projections and
    authorization bindings. Postponed annotations do not execute; dynamic
    initializers, eager annotations and ambiguous rebinding remain unresolved.
    Relative imports use the containing package, including the distinct rule
    for package initializers. Imports beyond that package or without a containing
    package prevent certification. The package-module manifest is included in
    the certificate because identical source text can resolve differently when
    executed as a package instead of an ordinary module. Wildcard imports and
    arbitrary lazy exports still require their own models.
11. Finite `for` loops over known tuples and mappings follow each iteration,
    preserving aliases, fresh-decision consumption, `break`, `continue`, loop
    `else` and finalizers. Mapping keys, values and items views stay live until
    iteration starts and retain dependencies on their backing mapping. A write
    during active mapping iteration remains unresolved, including writes through
    aliases and readonly proxy backing stores. Nested object writes invalidate
    authorization for the changed object without changing the iterator layout.
12. Standard native reentrant-lock context managers expose their body to the
    analyzer. Acquisition grants no authority, mutations still revoke dependent
    grants, and exit neither suppresses exceptions nor changes control flow.
    Source overrides of the standard lock modules invalidate this contract.
    Unknown context-manager protocols remain unresolved. This rule assumes the
    native `_thread.RLock` behavior and proves no concurrency property.
13. Immutable-set normalization preserves an existing `frozenset` identity and
    deduplicates known inert members using their actual builtin equality and
    hashing rules. Membership, subset/equality comparisons and known collection
    lengths select the corresponding branches. Arbitrary member hashing and
    equality remain unresolved. Known unhashable members and non-iterable
    constructor inputs raise before subsequent statements. Tuple conversion
    from known mapping views preserves the live element aliases. Empty and
    singleton immutable sets have known iteration order; larger unordered
    sets require an additional order model and cannot certify an arbitrary
    chosen order. Standard `frozenset` data factories follow these same rules.
14. Ordinary methods bind their receiver by Python's method protocol, regardless
    of the first parameter's spelling. Standard static methods receive no
    implicit receiver; class methods retain the actual derived class when
    inherited or accessed through an instance. Constructor and dataclass
    post-initializer calls use the same binding rules. Bound-method aliases
    retain dependencies on their receiver, so a dependent write revokes their
    authorization. Standard `typing.override` metadata preserves the method
    object and does not exempt its body from analysis. Class/module shadowing,
    late decorator imports, unsupported descriptor chains and custom decorators
    remain unresolved; a declared effect terminal cannot be skipped as metadata.
15. Native `**kwargs` dictionaries support symbolic presence and stable value
    identities for known string keys. Named parameters are excluded from their
    remainder; positional-only names may still appear. Copies and live proxies
    retain the appropriate aliases and independent deletion state. Projection,
    `get`, `pop`, `setdefault`, membership and writes account for both presence
    and absence. Forwarding to a known source signature preserves remaining
    keywords across helpers and snapshots each expansion before later arguments
    run. Duplicate and missing required arguments raise before the callee body.
    Unknown dictionary lengths are not zero, and unknown keys cannot be used as
    a finite iteration inventory. Multiple open expansions, open literal merges
    and callable targets without a source/signature model remain unresolved.
    This transfer rule requires inert keyword-key hashing and equality: native
    packing preserves string-subclass keys and does not establish that condition
    by itself. Source-defined custom hashing/equality protocols prevent a
    certificate; protocols outside the supplied source universe remain an
    explicit input-contract assumption, not a verified runtime restriction.
16. Standard `typing` and `typing_extensions` metadata has its runtime meaning.
    Module branches guarded by a known, already imported `TYPE_CHECKING` select
    the runtime body; type-only classes and imports cannot supply an API or
    helper binding. Unknown conditions, late imports, rebinding and source
    replacements remain unresolved. Function-local shadows retain their actual
    values. `cast` evaluates both arguments, enforces ordinary Python argument
    binding and returns the exact `val` identity. It does not establish a runtime
    type, grant authorization or hide an executable escape. Side effects in the
    type expression still run through analysis and revoke dependent authority.
    Keyword forwarding and binding failures use the same exception semantics as
    ordinary calls; the standard operation cannot be awaited. This typing model
    does not resolve lazy package export hooks.
17. Constant lazy-export lookups follow the actual module `__getattr__` and
    ordinary source helper bodies. The restricted import model supports literal
    tables, local bindings, known conditions, string interpolation, native
    `importlib.import_module`, module attribute lookup, and an optional cache of
    the exact returned reference under its own export name. Every cache write,
    including writes on failing paths, must preserve that binding. Missing
    source, unknown calls, effect terminals, other mutations, recursive lookups,
    conflicting submodule bindings and budget exhaustion prevent resolution.
    Import-error handlers are checked even when the normal import succeeds;
    they must raise an inert native error. Diagnostic text containing the error
    remains unknown text, never a chosen string for a branch. Finalizers are
    checked on both normal and exceptional-prefix states, and alternate returns
    must select the same value. Unused imports also undergo export analysis.
    Resolved bindings record the helper functions and analysis steps in
    `export_resolutions`; their target functions still undergo ordinary API
    authorization analysis. A terminal contract cannot disappear through alias
    rewriting. This rule assumes ordinary import machinery and stable module
    bindings, and does not exempt module initialization, decorators or defaults
    from the whole-source checks.
18. Native list construction, literals, known integer indexing, slices, copies,
    unpacking and argument expansion preserve the actual element identities.
    Shallow copies have separate outer storage and shared nested dependencies.
    `append`, `extend`, `insert`, `pop`, `clear`, `reverse`, indexed writes and
    deletion revoke authority dependent on the changed list. Bound list methods
    retain their receiver dependency and remain executable capabilities.
    Slice bounds are evaluated before index validation; argument and literal
    expansions snapshot elements before later expressions can mutate the source.
    Native binding, bounds and slice failures stop the normal continuation, and
    handlers still require fresh authorization. Exceptional-prefix contents
    become unknown. Finite list loops use the existing fresh-per-dispatch rule;
    mutation before another iteration remains unresolved instead of certifying
    a stale snapshot. List factories allocate fresh storage. Custom index and
    iteration protocols, comparison-driven methods and arbitrary list operations
    remain outside this transfer rule.
19. Inert `typing.TypedDict` and `typing_extensions.TypedDict` declarations
    construct ordinary dictionaries. The model accepts a single native base or
    supported declaration, an optional literal `total` flag, and postponed field
    annotations without values. Construction preserves the dictionary model's
    shallow copies, aliases, mutations and executable-escape checks. Required
    keys and field annotations do not validate runtime data or grant authority.
    `isinstance(value, Declaration)` raises `TypeError`; constructed values have
    native dictionary behavior. Custom declaration bodies, eager annotations,
    decorators, generic/multiple bases, unknown inputs and open constructor
    keyword tails remain unresolved. A declaration selected as an API surface
    requires native dictionary method verification; it cannot certify an empty
    method inventory.
20. Native `ContextVar` construction and positional `get`/`set`/`reset` calls
    preserve value identity in the current execution context. Module declarations
    require an inert native constructor, literal name/default and, if annotated,
    postponed annotations. Existing module variables may be unset or contain an
    inherited value; a default never implies the entering context is empty.
    Local construction starts unset. Reset tokens record the previous binding
    (including absence), are tied to the exact variable, and can be consumed
    only once; native resets need not occur in stack order. Writes revoke
    dependent grants, saved values retain their own identity, and nested aliases
    remain live. Inherited decisions cannot establish fresh authorization.
    Executable/receiver assignments and context capabilities escaping an API
    remain unresolved. Exception-prefix state is unknown rather than stale.
    Direct source calls and awaits share the current context; copying/switching
    contexts, scheduling tasks, unknown reset tokens and token introspection or
    context-manager behavior require additional models.
21. Eager dictionary and list comprehensions over known finite iterables reuse
    the loop transfer rules. The first iterable is evaluated in the surrounding
    scope; iteration targets are local, shadow globals even before assignment,
    and do not leak afterward. Filters short-circuit in order, nested generators
    run in order, and dictionary keys execute before values. Every iteration
    requires fresh authority for its dispatches, even if a later dictionary
    value overwrites the same key. Empty or exceptional iterations cannot hide
    later execution. Mutable aliases, executable escapes and writes during
    active iteration retain their existing checks. Unknown/unbounded iteration,
    async generators and comprehension assignment expressions remain unresolved.
22. Statically named ordinary source classes use Python's C3 method resolution
    order, recorded per admitted surface in the report. Leftmost overrides and
    diamond siblings cannot be replaced by a direct-parent approximation.
    Bound `super` lookup starts after its lexical or explicit class in the actual
    receiver's order. Instance, class and static descriptors preserve their
    corresponding bindings; classmethods retain the most-derived class.
    Source initializers can reach the native no-argument `object.__init__`.
    Proxy/method capabilities retain receiver dependencies and cannot escape.
    Inconsistent orders, late or unknown bases, custom metaclasses, unbound
    descriptors, changed lexical class cells and slots-dataclass class cells
    remain unresolved. This rule supplies no trust in argument annotations or
    in unknown receiver values.
23. An unresolved call, unsupported syntax, unknown base class, executable escape,
   recursion, or exhausted budget prevents a successful verification result.

The engine explores both outcomes of unknown input-boolean branches. It preserves
   separate states rather than combining authority from different paths. A syntax
inventory also flags calls the transfer analysis did not cover or prove
unreachable through modeled control flow. Counterexamples
include the entry point, helper call path, terminal line, and binding identities.

Every method on the configured surface and its discovered descendants is an
entry point, including inherited and private methods. A helper exposed as a
method therefore cannot quietly rely on a caller that checked permission first.
Ordinary module helpers can be analyzed through their callers. Returning an
executable or receiver capability from a surface is rejected.

## Project specifications

A JSON specification supplies `sources` (module name to file path), or
`source_roots` (package name to directory), `surfaces` (root class names),
`authorizers`, `operations`, and optional `async_terminals` and
`terminal_parameters` (qualified terminal target to ordered parameter names). Paths are relative to
the specification. See [the fixture specification](verification-fixtures/legacy_gateway.json).

The loader records `__init__.py` files as package modules automatically. For
source supplied under another filename, `package_modules` explicitly lists the
source modules that are packages. The Python `VerificationSpec` interface accepts
the same manifest for source strings; it does not infer package status merely
from another module sharing a dotted prefix.

A terminal specifies a qualified target, argument bindings such as `arg:0` and
`arg:1`, and optionally a permission domain. Async terminals must be declared
and awaited. Synchronous primitives cannot silently stand in for coroutines.
Keyword calls require a declared terminal parameter order; missing bound
arguments, duplicate bindings and unknown keyword names fail verification.
The installed adapter lists synchronous and asynchronous host terminals for
both ToolNode and guarded tools and binds host constraints to the exact
authorizing decision.
There is no trusted-helper wildcard, unchecked-method list, or ignore-failures
option. Source hashes, terminal contracts, budgets, and the analyzer hash are
included in the result.

## Scope and current status

This is verification of an explicit, restricted execution model. It is not a
proof of arbitrary Python. The primitive authorizer's correctness, the supplied
terminal-effect boundary, absence of external concurrent writes to security
inputs, ordinary object semantics,
and the declared meaning of imports/Verdict remain assumptions. Primitive results
and their exception payloads are modeled as inert data (or a Decision), not
hidden executable capabilities;
that terminal contract must also hold. In particular,
user-defined descriptors, coercion/equality effects, monkeypatching, and hostile
concurrent mutation are outside this model. Choosing incomplete source roots or
misdeclaring a primitive changes the theorem; a successful result does not
validate those assumptions.

Unbounded or unknown-iterator loops, arbitrary collection operations,
unknown-receiver heap writes, unknown
argument expansions, unsupported lazy package exports, custom decorators, and unresolved
dispatch currently
produce `unresolved`. They are not counted as verified. Supporting them requires
new transfer rules plus positive and counterexample tests. Effectful definition
defaults/decorators/eager annotations cannot hide in unused helpers.

The installed implementation does **not** yet satisfy the integrated gate. The
latest source audit discovers 175 entries: one verifies and 174 remain
unresolved. The report records reached symbolic dispatch obligations separately;
their count can change with the transfer rules and analysis budget. Explored
paths do not prove unexplored paths or discharge unresolved entries. The
runtime matrix passes all 15,744 cases, including host
execution and activation denial. The [current summary](source-verification-summary.json)
records both layers. A passing fixture proves that the engine has a working
positive path; it does not discharge these production obligations. Complete
MAC publication/lifetime/confidentiality guarantees remain separate properties.
