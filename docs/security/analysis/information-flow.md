# Runtime information flow

The provenance DAG has runtime-assigned identities and immutable content versions.
Equal strings from two sources remain different values. Data and control dependence
are influence edges; containment is structural. Copy, formatting, normalization,
parsing, serialization, summary, reducer/cache adaptation and child return preserve
participating parents. Model responses conservatively depend on all submitted
context, including tool schemas. This is conservative taint propagation, not an
inference about the model's true reasoning.

`SecurityLabels` remains the confidentiality/integrity representation. Unknown
external data starts at unknown integrity. Combining untrusted influence never
endorses it. Low integrity by itself is not the Repeat-After-Me policy trigger.
Risk tags and confidentiality compartments accumulate by union. The registered
allowed-readers domain combines sets by intersection: `{A,B}` and `{B,C}` become
`{B}`. Public imposes no restriction; an empty set permits no reader; unknown blocks
protected release. Domain versions/configuration digests bind restores and snapshots.

Plugins can add dependencies and restrictive domain labels, never prune ancestry.
Trusted interpreter instrumentation can select a field precisely, including selector
and active control dependence, without adding unrelated structural siblings. Opaque
operations inherit all declared inputs and controls. Missing conservative bounds
must block required paths. A trusted adapter is responsible for the completeness of
its declared semantics; ordinary analyzers cannot claim interpreter precision.

SQLite serializes metadata commits. Signed checkpoints use the existing
`seal_checkpoint`/`authenticate_checkpoint` mechanism and bind policy, domain and
role configuration. Restore imports value metadata and canonical finding/snapshot
records and rejects mismatched configuration or tampered envelopes. The caller must
persist the envelope and keep the signing key out of graph state and workers.
Analysis-enabled `MediatedCheckpointer` embeds the analysis envelope in its authenticated checkpoint payload and restores an influence anchor for the resumed run. Custom checkpointers outside that composition path must explicitly use `CheckpointBinding`.

No declassification or endorsement API is enabled. No metadata records are silently
dropped to recover capacity. The in-memory store is for isolated tests; use SQLite
for durability. Protected storage and its keys are trusted. A malicious administrator
with database and signing-key access is outside the threat model.

`AnalysisFlowPolicy` also requires an operator-declared `read_bounds` entry for
protected tool effects. Bounds must include host baseline authority and degradation;
missing/unknown bounds deny the effect before dispatch. These declarations are
trusted transfer summaries, not conclusions inferred from an absence of observed
reads. `SessionFlowPolicy` still supplies atomic source/sink reservations.
