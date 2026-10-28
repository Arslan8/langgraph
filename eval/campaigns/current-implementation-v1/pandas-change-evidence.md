# Why the earlier Pandas upstream score changed

The move from 29/50 to 50/50 is not an unchanged-configuration rerun. The model
identity, temperature, seed, task corpus, and oracle stayed fixed, but the
application/evaluation adapter changed materially.

The earlier upstream cohort used zero graph retries and had no recorded
workflow contract, recursive serializer, or period-aggregation API. Its 21
failures were all completed executions whose output missed the oracle: every
repetition of `monthly_chart`, `product_totals`, `grouped_mean`, and
`missing_count`, plus one `regional_totals` trial. That repeat-stable pattern is
evidence against attributing the difference merely to random model variation.

Manifest v19 instead uses:

- original-request preservation (`preserve-request-v5`), addressing observed
  routing loss such as dropping “mean sales”;
- three bounded graph repair retries, with every attempt retained, instead of
  zero retries;
- `recursive-json-v2`, which preserves Timestamp/Period/PeriodIndex results
  across the same subprocess boundary;
- a general `period-aggregation-v1` helper and period-boundary guidance that
  computes from supplied data/column names without receiving task IDs or oracle
  values; and
- the same changes in A, B, and C, so they are compatibility changes rather than
  a protected-only advantage.

The retained one-factor probes provide direct evidence for the serialization
part: original executions fail with `Timestamp is not JSON serializable`, while
the repaired executions return the same data with an ISO timestamp; the period
probe likewise returns the derived `2026-01` period only after the general
repair. The v19 five-by-ten acceptance cohort then passes 50/50 in each mode.
The current frozen-revision rerun is reported separately and is not pooled with
that historical acceptance cohort.

This supports a causal explanation at the level of the changed adapter
features. It does not allocate each of the 21 old oracle mismatches to exactly
one repair, because a complete factorial ablation of request preservation,
retry count, serializer, and period helper was not run.

Evidence:

- old plan/results: `eval/campaigns/remaining-v1/raw/pandas-full/`;
- v19 plan/results: `eval/campaigns/remediation-v2/raw/pandas-v19-full/`;
- serializer pairs: `eval/campaigns/remediation-v1/raw/serialization-final/`;
- period pairs: `eval/campaigns/remediation-v2/raw/period-serialization/`;
- frozen current rerun: `eval/campaigns/current-implementation-v1/raw/pandas-v19-rerun/`.
