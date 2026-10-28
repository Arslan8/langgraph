# Prospective remediation evidence

This campaign is incomplete acceptance, not a replacement for `remaining-v1` or `completed-v2`. See `acceptance.json` for all fourteen dispositions. No old raw observation, failure count, or waiver was replaced.

## Changes

- The Linux worker response reader enforces one monotonic deadline across an entire frame. A worker cannot bypass the timeout by writing a partial frame and stalling. Six regressions exercise deadlines, fragmentation and malformed frames. This is an independently identified defect; it is not claimed as the cause of historical profiler failures.
- Pandas manifest v10 uses the same recursive JSON serializer in A, B and confined C. Nested DataFrame timestamps, NumPy scalars and missing values are converted explicitly; unsupported values and key collisions fail. The upstream import, execution and resource checks remain in place. Installing the repair does not mutate the original runner's globals.
- New application cohorts default to v10. `--sandbox-serialization original` selects the original serializer and v9 model configuration. The task list and valid-output frozen oracle semantics remain unchanged. Malformed outputs count as failures instead of aborting the cohort, and an unsuccessful process cannot count as a utility success.
- The profiler executes the application in separate globals and restores its hooks. The profile driver accepts explicit input/output locations, preserves Python virtual-environment symlinks, pins execution to an available CPU as the original workflow campaign did, and retains timeout/error rows. Spans are inclusive and nested; they are not additive phase totals.
- New application rows include source/model/policy identity, timestamps, timing scope and explicit missing phase fields. This is a prospective improvement, not a universal-schema or retrospective engineering-hours claim.

## Evidence selection

`raw/serialization-final` is the final six-case paired serialization cohort: original and repaired behavior for each of A/B/C. It preserves executed adapter sources and source digests. Earlier serialization development cohorts remain separate. These are deterministic computation tests, not full-workflow utility scores.

`raw/profile-pinned-v3` contains one complete, instrumented C workflow. `profile-validation.json` independently checks its result against the original date-filtered-total oracle and reports per-call inclusive measurements. The earlier profile attempts retain a virtual-environment-path setup failure and a model-service connection failure. The local frozen model was verified and its service started before the successful run. No cause is assigned to historical worker-protocol failures based on this success.

`raw/pandas-utility` is a new uninstrumented cohort of ten tasks in each of A/B/C, one repetition each, using v10. It is separate from the original fifty trials per condition. Its failures remain failures. Source snapshots, model identity, policies and raw outputs are retained. `utility-summary.json` reports the results after all thirty trials finish.

The completed new cohort has 4/10 A failures, 7/10 B failures and 5/10 C failures. All thirty processes completed successfully, but only fourteen outputs passed the frozen utility oracle. This is not evidence of overall utility improvement: aggregation and chart defects remain despite the targeted serialization regression passing in all three configurations.

`raw/checks` retains command logs and exit statuses. Prebuilt formatting and lint passed; its complete test suite passed 3,870 tests and 16 snapshots. The eleven focused evaluation tests passed. Both security verification gates still fail, retaining forty SGV301 findings, thirty-four stale waivers and the SGV901–903 proof gaps. The permutation gate passes and does not discharge those findings.

## Remaining scope

Production persistent-container integration, Notebook's server boundary, OpenShell native runtime comparison, independent-host coverage, generalized SQLite alias discovery and the unbrokered native filesystem matrix remain open. Landlock metadata secrecy and Docker-equivalent process ceilings were not added. Historical provenance and engineering-hours gaps cannot be recovered by these new runs. All timing evidence is from a shared host; no idle-host performance comparison is made.
