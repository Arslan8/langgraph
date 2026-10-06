# slangGraph evaluation

This directory is the self-contained evaluation artifact for the kernel-enforced
slangGraph design. Evaluation code, pinned baseline metadata, synthetic vulnerable
tools, adapters, transcripts, audit databases, and generated tables live here.
Nothing in this directory is required by the LangGraph libraries at runtime.

## Claim and primary measure

The primary claim is structural: interface-level defenses leave security-sensitive
sinks below their mediation point, while a sufficiently capable set of enforcement
adapters can mediate the resulting resource operation. The headline measure is
**sink exposure**, not attack-success rate.

slangGraph itself is not a Landlock system. Its policy pipeline constructs a
platform-neutral grant, and a selected adapter set lowers that grant to enforcement
available on the deployment. Landlock plus seccomp is the planned Linux reference
adapter; Windows isolation, WASI, microVM, service-broker, and resource-side adapters
can implement the same capability contract. E1 therefore names slangGraph adapter
models by capability rather than treating a Linux mechanism as the architecture.
It also records a separate host model. A projected adapter capability counts only
when the host model provides the corresponding host-bound capability; otherwise
the sink remains exposed with a `host lacks ... capability` decision.

The shared static instrument emits one record for every filesystem, network,
process, database/service, native, or dynamic sink reachable from a tool argument.
It then projects that one report through explicit mediation models for each defense.
This is intentionally generous to interface defenses: a sink is credited as
mediated whenever a sound argument constraint could dominate every tainted path,
even when the released policy does not contain that constraint.

Static exposure is an upper bound. A reported path may not be feasible at runtime.
The local canary PoCs provide a lower bound. The artifact reports the gap rather
than treating either number as ground truth.

## Safety boundary

PoCs target only deliberately vulnerable tools under `vulntools/` and benchmark
harnesses intended for evaluation. They use temporary directories, loopback
listeners, and local canaries. They do not exploit, probe, or modify Progent,
CaMeL, bolt-ons, or any third-party deployment.

## Reproducibility rules

- All model calls use the local Ollama OpenAI-compatible endpoint.
- Hosted and closed-source models are prohibited, including transcript generation
  and judging.
- Temperature is zero; model tag, immutable model ID/layer digest, context size,
  and seed are recorded with each run.
- Git repositories and Python distributions are pinned in `PINS.md`.
- Hardware and local model inventory are recorded in `HARDWARE.md`.
- Absolute ASR and utility are not compared with papers using GPT-4-class hosted
  models. Only within-artifact comparisons are valid.

## Experiment map

| ID | Purpose | Live model |
| --- | --- | --- |
| E0 | Reproduce released Progent/CaMeL baselines | as required by baseline |
| E1 | Static exposure census | no |
| E2 | Deterministic canary PoCs | seed generation once; replay thereafter |
| E3 | AgentDojo, InjecAgent, and ASB parity | yes, both local models |
| E4 | Mediation completeness on synthetic graph shapes | no |
| E5 | Per-stage and end-to-end overhead | no |

## Current implementation status

Hardware, exact model identities, dependency pins, the static instrument, eight
deliberately vulnerable tools, the E1 census, frozen local-model E2 transcripts,
local E2 canaries, and released Progent/bolt-on call-boundary runs are implemented.
CaMeL's released tests and a local-Ollama plumbing smoke test also run at the pin.
See `STATUS.md` for the exact completed/pending boundary and `reproduction/E0.md`
for baseline qualifications.

The repository's current security layer does **not** yet contain the planned final
Grant, Cedar policy adapter, host model, enforcement-adapter contract, Linux
reference adapter, or service adapters. Therefore a zero-exposure static projection for the composed
adapter model is a capability-model result, not runtime blocking evidence. No report
may label a slangGraph adapter condition as dynamically verified until the selected
adapters exist and emit enforcement audit records.

## Local commands

```bash
cd eval
make format
make lint
make test
make tables
make bolt-on-pocs
make seed-transcripts
```

`make tables` only reads audit databases and reports; it never runs an experiment.
