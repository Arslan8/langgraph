# Exploratory results

The historical LangGraph add-tools demo is runnable under the current full
Argus Linux route. All five Baseline tasks and all five Argus tasks returned the
correct city, country, and currency, and every trial executed `tavily_search`.

| Mode | Correct / attempts | Mean complete wall time | Security evidence |
|---|---:|---:|---|
| Baseline | 5 / 5 | 1,533.6 ms | no grants or activation receipts |
| Argus | 5 / 5 | 2,380.4 ms | one grant and one activation receipt per trial |

The observed one-repetition ratio was 1.552x, or 55.2% overhead (+846.8 ms).
This is a compatibility pilot, not a performance estimate: it has one paired
task block and therefore no confidence interval. It must not replace the
five-repetition protocol or be used as a paper headline.

The positive result is narrower than “ordinary LangGraph applications work.”
It demonstrates that an ordinary graph whose untrusted boundary is a stateless
tool can retain behavior through the protected worker route. The fixed D1–D5
campaign remains unchanged, including its unsupported full-Argus integrations.

Each Argus raw record retains the full message transcript, Cedar/audit chain,
authorization grant, lowered restriction record, and Linux activation receipt.
Baseline records show no security activation.

## Expanded compatibility survey

The expanded one-preflight survey attempted ten frozen upstream examples or
substantive documented variants in both modes. Six completed correctly under
Argus and four exposed one shared admission incompatibility.

| Upstream example | Baseline | Argus | Baseline ms | Argus ms | Evidence / boundary |
|---|---:|---:|---:|---:|---|
| Add tools | correct | correct | 1,511.7 | 2,292.1 | one tool grant and activation |
| Custom weather agent | correct | correct | 944.8 | 1,769.9 | one tool grant and activation |
| Fixed ToolNode weather call | correct | correct | 4.4 | 864.7 | one tool grant and activation |
| Parallel ToolNode calls | correct | correct | 5.2 | 936.8 | two grants and activations |
| Add memory | correct | correct | 2,487.6 | 3,928.2 | two turns; two grants and activations |
| Time travel | correct | correct | 1,637.7 | 3,039.8 | checkpoint replay; two grants and activations |
| Prebuilt multiply agent | correct | unsupported | 1,045.0 | — | `admission:unsupported_node_body` |
| Prebuilt return-direct agent | correct | unsupported | 606.2 | — | same prebuilt-agent coordinator boundary |
| Prebuilt forced-tool agent | correct | unsupported | 535.1 | — | same prebuilt-agent coordinator boundary |
| Prebuilt serial-tools agent | correct | unsupported | 1,549.4 | — | same prebuilt-agent coordinator boundary |

The two fixed-invocation baselines are only 4–5 ms, so their roughly 0.9-second
absolute protected costs produce ratios near 180–197x. Those ratios are not a
useful headline; the absolute cost and tiny denominator must remain adjacent.
All figures above are single preflights without confidence intervals.

The four unsupported rows are distinct selected upstream examples, but they do
not establish four distinct implementation defects. All stop before tool
execution because the current closed-admission capturer rejects the internal
model coordinator produced by `create_react_agent`. Admission was not disabled
and those trials have no grants or activation receipts.
