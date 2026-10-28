# Investigation of the five closed Pandas refusals

The retained v21 cohort has one repeat-stable failure: all five
`monthly_mean` trials refuse at `OutputMediator` with
`output_data:nonfinite_float`. The other 45 task/repetition pairs pass. This is
a safe publication refusal and remains a utility failure.

The raw events show that dataset acquisition is authorized once and the missing
sales cell enters the compute payload as JSON `null`. The generated code calls
the general `aggregate_periods` helper with `operation='mean'` and
`complete=True`. The helper intentionally fills an absent period with NaN for
mean (zero would be a false mean). `recursive-json-v2` maps non-finite compute
results to `null`, but the vendor workflow subsequently reconstructs Pandas
state; Pandas represents that missing numeric value as NaN again. The closed
inner graph streams that state before the outer backend can serialize the final
response, and the output mediator correctly refuses the non-finite float.

Thus v21's controller-input normalization is working, and weakening
`validate_output_data` to admit NaN would be the wrong repair: NaN is not a
portable JSON number and would make digest/publication behavior ambiguous. The
minimal compatible fix is another explicit trusted transport boundary on the
data-wrangling node's returned state (NaN/Infinity to tagged/null missing data,
with string keys) before it reaches the graph output mediator, followed by an
unchanged-policy rerun. Alternatively, the vendor can keep a nullable JSON-native
representation rather than reconstructing a float DataFrame in graph state.
Neither change should substitute zero or change the mean oracle.

Evidence paths:

- refusal traceback: each
  `raw/pandas-closed-rerun/monthly_mean-C-closed-*/process.log`;
- generated code and JSON-null input: corresponding `events.jsonl`;
- input normalization: `eval/apps/pandas/integration_closed.py:118`;
- mean completion behavior: `eval/apps/pandas/sandbox_codec.py:79`;
- strict output rule: `libs/prebuilt/langgraph/prebuilt/security/output_data.py`.
