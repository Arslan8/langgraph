# Change log

- Added a reader-facing `Baseline` that uses the same adapted Pandas workflow,
  model callbacks, task code, retry budget, data conversions, serializer, and
  correctness oracle without slangGraph authorization, activation, mediation,
  audit, or runtime validation.
- Reran both `Baseline` and protected `slangGraph` (`C-full-lean`) in one new
  interleaved 100-trial campaign. No timings from the earlier protected-only
  campaign are reused.
- Replaced the invalid `C-full` versus `C-full-lean` interpretation with a
  complete-system Baseline/slangGraph ratio. `C-full` remains an optional
  checks-disabled ablation.
- Preserved the five protected `monthly_mean` non-finite output refusals and
  reports them beside the primary timing result.
- Added paired repetition-block bootstrap analysis and the application-overhead
  graph. The old campaigns remain unchanged.
