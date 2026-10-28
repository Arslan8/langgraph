# Demo 17: checkpointing analysis metadata

For plugin writers who choose the optional provenance/checkpoint utilities. Save
analysis metadata, close the original session, and restore into a fresh store:

```python
with StructuredAnalysis(configuration={"format": "v1"}) as analysis:
    source = analysis.value("Private report", confidentiality={"secret"})
    summary = analysis.value("Summary", parents=(source,))
    checkpoint = analysis.checkpoint(summary)

with checkpoint.restore() as restored:
    labels = restored.client.get_labels(summary)
    provenance = restored.client.get_provenance(summary)
```

Run:

```bash
libs/prebuilt/.venv/bin/python workspace/17_analysis_checkpoints/demo.py
```

Expected output:

```text
Fresh store: summary identity, ancestry and secret label restored
Restore with incompatible configuration: rejected
```

The local session manages IDs, its in-memory store and a signing key. The returned
checkpoint handle retains the trusted scope/key separately from its authenticated
envelope. Restoring checks that envelope before importing its records into a new
store. Value identity, ancestry and the inherited `secret` label survive; analyzers
are not rerun or reinstalled, and live notification queues are not replayed.

`configuration={"format": "v1"}` is meaningful application metadata, not an identity
string. Restoring under `{"format": "v2"}` is rejected because the saved analysis
configuration no longer matches. This is checkpoint integrity/compatibility checking,
not runtime argument-based detection or an operation authorization decision.

## Try it

Restore with `{"format": "v1"}` instead: it succeeds. Add another derived value and
checkpoint it to see its ancestry survive restoration too.

## Scope

The handle is a trusted **in-process** convenience. Keep it private: it holds restore
authority and signing material. The envelope is authenticated, not encrypted. This
example does not persist keys across processes or resume a running graph. Production
persistence should use `CheckpointBinding` with application-managed keys, identity,
configuration and storage. Plugins using private data formats can use their own
checkpoint mechanism instead.

No key, principal, tenant, session, run or checkpoint ID needs to be invented in this
local lesson. Context managers close both the source and restored stores. If needed,
run `uv sync --directory libs/prebuilt` first. No model or service is used.

[All demos](../README.md) · [Provenance lesson](../13_provenance/README.md)
