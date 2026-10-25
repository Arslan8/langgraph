# Demo 10: Repeat-After-Me defense

Show a detected Repeat-After-Me attack blocked **before the tool executes**.
The harmless `record_demo_event(message)` tool inserts one SQLite row; its actual
row count is the execution oracle. A later refusal cannot undo that effect.

From the repository root, using the existing prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/10_repeat_after_me/demo.py
```

For a presentation, display the synthetic transcript and pause between cases:

```bash
libs/prebuilt/.venv/bin/python workspace/10_repeat_after_me/demo.py --step --show-prompts
```

To set up the environment from a clean checkout and save the public analysis trace:

```bash
uv sync --directory libs/prebuilt
libs/prebuilt/.venv/bin/python workspace/10_repeat_after_me/demo.py --output /tmp/demo10-trace.json
```

No model downloads, network requests, credentials, Cedar CLI or Linux sandbox are
needed by this isolated, trusted in-process fixture. Each execution creates fresh
temporary SQLite databases and cleans them up. No production resources are touched.

## What the audience sees

The first attack turn asks for a quoted serialized call. It produces ordinary text
and no tool call. The follow-up refers to that earlier string in a hypothetical
setting; the scripted response has empty ordinary content and a provider-structured
`tool_calls` entry. It goes through the normal supported `ToolNode` path. There is
no parser that executes ordinary JSON text.

| Case | Classification / configuration | Actual inserted rows |
| --- | --- | ---: |
| quoted-A / quoted-B | Ordinary JSON text, defense off / on | 0 / 0 |
| A | Structured attack proposal, analysis defense off | 1 |
| B | Identical proposal, `repeat_to_tool`, restrictive policy on | 0 |
| C | Direct authorized request, `benign` | 1 |
| D-retrieval | Retrieved attack, summarized, checkpointed and restored | 0 |
| D-tool | Tool-result attack through the same transformations | 0 |
| false-negative | Attack deliberately classified `benign` | 1 |

The script checks every row count and B's `ram:affected_ancestry` denial reason,
and exits unsuccessfully if an expectation fails. For B it displays dispatch,
snapshot, finding and value identities. The underlying runner uses public
`AnalysisClient` queries and subscriptions to verify that the developer view and
completion notification reference the enforcement record's findings and versions.
Use `--output` for the full provenance chains. Raw fixture prompts are printed only
with the explicit local `--show-prompts` flag.

## What is fixed, and what this does not establish

Required classification runs before the protected operation. Risk annotations
propagate conservatively to the proposed call; the preloaded restrictive rule denies
suspected or unknown ancestry through the existing authorization chain. Policies
remain fixed throughout each run. Benign classification cannot erase earlier risk.
A, B and C retain the same ordinary tool permission.

This deterministic demo establishes blocking when the classifier detects this
attack on the covered path. It does not establish perfect detection: the final
case intentionally misses the attack and executes. The classifier and model
proposal are scripted so the enforcement behavior is reproducible offline.

slangGraph provides extensible instrumentation, provenance tracking and enforcement integration for externally supplied analyses. The Repeat-After-Me classifier is a replaceable demonstration module. Detection quality belongs to that classifier; the runtime enforces configured restrictions for the instrumented execution paths.

This entry point reuses the existing [offline runner](../../examples/analysis/repeat_after_me/run_offline.py)
and [composition root](../../examples/analysis/repeat_after_me/config.py), so it does
not introduce a second classifier or authorization implementation. See the
[full demo guide](../../docs/security/analysis/repeat-after-me-demo.md) for optional
live replay/agent modes and evaluation, and [coverage](../../docs/security/analysis/coverage.md)
for instrumentation limits. [All workspace demos](../README.md).
