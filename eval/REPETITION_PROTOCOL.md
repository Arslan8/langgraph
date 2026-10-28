# Fixed repetition protocol

## Completed evidence

The [alternative-backend evaluation](reports/alternatives-v2/report.md) is complete:
verified-language versus Landlock and rootless-container execution, 16 raw-operation
microbenchmarks, and the recorded Pandas application computation. The
[native-chain profile](reports/native-chain-v2/report.md) separately measures a
useful native binary calling another native binary. Every primary timing cell has
100 measured calls. All samples, oracles, paired statistics and source hashes have
been validated.

The original Bubblewrap executor still fails its namespace preflight on this host.
That failure is preserved in reports/repeated-v2. The new host modes are explicitly
identified **evaluation adapters**, not relabeled Bubblewrap measurements. Old
single-session timings remain in the historical appendix and are not pooled with
these new cohorts.

## Fixed counts

| Quantity | Count per workload and mode |
| --- | ---: |
| Fresh benchmark process sessions | 5 |
| Measured calls per session | 20 |
| Total measured calls | **100** |
| Excluded warmups per session | 10 |
| Total excluded warmups | 50 |
| Separately retained first-use calls per session | 1 |
| Total first-use calls | 5 |

Mode order is randomized within matched rounds with recorded session-specific
seeds. Sessions and benchmark families run sequentially. Each invocation starts a
fresh Python worker for the subprocess and host modes. The container's namespace
and mounts persist within a grant-specific session. Creation and teardown are
outside the invocation timer and reported separately: five containers for each
operation/application family, ten for the comparison's two grant shapes. Those
lifecycle observations are not described as 100 cold-start measurements.

Verified-mode static admission/setup uses 20 constructions per workload per
session, giving 100 setup observations. These are not invocation samples or
invocation warmups. The common read comparison uses the production Cedar object
authorizer across all three modes. Raw-operation and application experiments
measure execution with explicit fixed grants and exclude Cedar authorization.

The fixed 100-call budget is an engineering choice for consistent comparisons,
not a power calculation or guarantee of confidence-interval width. Five fresh
process sessions expose variation hidden by one process run. They are adjacent
sessions on one machine, not independent machine replications. Counts were fixed
before the run; failures are retained rather than replaced or dropped.

## Statistics

Report mean, median, nearest-rank P95, sample SD and sample variance over measured
calls. Compute overhead from matched round differences. Approximate 95% intervals
use Student t on the five session mean differences (df=4; critical value 2.776445),
not 100 independent-call degrees of freedom. This assumes approximately normal,
independent session means; adjacent sessions may remain correlated. No across-host
or across-task confidence claim follows. P95 is descriptive with limited tail
resolution. A confidence interval crossing zero does not establish a speedup or
a nonzero overhead.

## Security repetition is not coverage

The deterministic census has 59 distinct cases: 49 forbidden operation/surface
combinations and ten allowed controls. Each is repeated three times in each of
three modes (531 trials). The repetitions check stability; they do not create
additional independent attacks.

The production verified-mode controls contain four checks repeated three times
(12 trials): allowed read, ungranted path denial, binding-mutation rejection, and
manifest-mismatch rejection. The native-chain profile additionally checks its
hidden-file restriction three times in every session (15 per mode). This verifies
that each freshly established session applies its restriction, without increasing
the count of distinct forbidden cases.

The old model-driven workflow and CSV injection experiments remain five-run pilots.
They are not part of the new primary timing results. The new Pandas experiment
replays the actual recorded computation and upstream sandbox program; it makes no
claim to be a new full model-driven run or a verified-language application port.

## Reproduction and publication gate

From the repository root, using new output directories:

```sh
uv run --project eval python -m slanggraph_eval.isolation.alternatives \
  --output eval/reports/alternatives-new
uv run --project eval python eval/scripts/native_chain_eval.py \
  --output eval/reports/native-chain-new
```

The report scripts intentionally select named frozen cohorts. To publish a new
cohort, explicitly select its directory in `alternative_report.py` and
`paper_evaluation.py`, run `verified_controls.py` for that cohort, and validate
before publication. The validator checks complete per-session sample matrices,
parent oracles, archived source hashes, paired summaries, and the security census.
The current published cohort is alternatives-v2 with native-chain-v2.
