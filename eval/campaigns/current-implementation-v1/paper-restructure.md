# Proposed evaluation section structure

1. **Frozen artifact and claims.** Put the exact revision, host, dependencies,
   model/dataset/task identities and the three configuration definitions before
   any number. State the runtime-MAC/Linux dispatcher gap here.
2. **Current route costs.** One table for cold setup/removal and one for reused
   calls. Use the same columns for absolute time, 95% CI, multiple and overhead;
   put the non-overlapping phase ledger directly below it.
3. **Application utility and latency.** Present the matched A/B/C Pandas matrix,
   then C-closed as a distinct configuration. Count refusal as utility failure.
   Explain the historical 29/50→50/50 configuration changes in a boxed
   change-analysis paragraph, not as an unexplained trend.
4. **Useful interpreter subworkflow.** Show the two-source decision and a compact
   supported / worker-or-broker / refused operation table.
5. **Alice/Bob worked comparison.** Make the single shared database the main
   baseline table: Alice utility, Bob confidentiality, file-bypass outcome and
   trusted-code requirement. Follow with SQLite and pump ablations.
6. **Coverage and engineering surface.** List protected/unsupported paths and
   adapter source size. Mark historical implementation effort unavailable rather
   than replacing it with retrospective guesses.
7. **Lean contribution.** State the five theorems verbatim, assumptions, model
   size, check command/cost, implementation connection and unproved refinement.
8. **Threats and change log.** Separate current measurements from older evidence,
   current implementation gaps from evaluation limitations, and modeling-driven
   obligations from test-discovered bugs.

The main text should carry the configuration definitions, headline numbers,
Alice/Bob comparison and Lean scope. Raw trial schemas, all commands, failure
transcripts, per-task timings and full coverage details can move to the artifact
appendix, with stable paths from every table row.
