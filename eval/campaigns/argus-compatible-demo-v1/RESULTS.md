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
