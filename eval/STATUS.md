# Evaluation implementation status

Captured on 2026-10-05. This file separates executable evidence from planned
capability so partial results cannot be mistaken for completed experiments.

## Completed locally

- Hardware, Ollama, model tags, immutable model/layer digests, temperature, seed,
  and 40,960-token server context are recorded.
- Both selected open-weight models produced a real tool call through Ollama's
  OpenAI-compatible endpoint.
- All baseline repositories and Python packages are pinned; vendoring is
  reproducible with `scripts/fetch_pins.sh`.
- The analyzer emits machine-readable sink reports and scores explicit mediation
  models from the same report.
- Eight deliberate vulntools and the E1 exposure census exist. AgentDojo's sampled
  in-memory tools are reported separately; the InjecAgent pin exposes schemas but
  no executable tool bodies and is therefore `N/A`, not zero.
- All eight local canaries land with no defense and after Progent approves the same
  policy-conformant calls.
- The pinned `qwen3:8b` generated all eight seed calls once at temperature zero;
  raw responses are stored in `transcripts/e2/qwen3-8b.json`, each record is
  hash-audited, and all implemented E2 conditions replay those exact calls.
- Released Eydii, Forge, and Nuggets call-boundary wrappers are exercised locally
  for the same below-boundary E2 question.
- Progent checker/module parity is 3/3. CaMeL's released tests pass 126/126, and a
  single local-Ollama runner smoke test completed.
- Audit databases are hash-chained; `make tables` verifies them before rendering.

## Pending

- Finish the full released CaMeL E2 replay for the ordinary untrusted-tag cases;
  the trusted-tag/post-validation auxiliary variant is implemented separately.
- Run full E0 AgentDojo reproduction and E3 parity for both models.
- Add InjecAgent and ASB thin adapters and execute their specified suites.
- Build and execute E4 synthetic graph-shape completeness cases.
- Run E5 only after executable adapters exist; latency cannot be inferred from a
  capability model.

## Blocked by core implementation, not evaluation code

The LangGraph security layer currently lacks the planned final `Grant` IR, Cedar
policy adapter, enforcement-adapter contract, Linux reference worker, and service
adapters. Consequently:

- E1 `slanggraph-host-adapter` and `slanggraph-composed-adapters` values are
  static capability projections, independent of any particular platform lowering.
- E2 cannot yet truthfully claim platform denial, service re-check, credential
  subset enforcement, or adapter audit evidence.
- E3 and E5 slangGraph adapter rows cannot run.

These rows remain pending rather than being replaced by mocks. The local canaries
and third-party wrappers may use doubles only to isolate their stated boundary;
slangGraph enforcement requires real, attested adapters for the selected platform
and resource services.
