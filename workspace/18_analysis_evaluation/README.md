# Demo 18: evaluating an analyzer offline

For plugin writers measuring their own analyzer. Call an ordinary function on
labeled examples and compare its answers with the expected labels:

```python
def analyze(text):
    return "secret" in text.lower()
```

This deliberately crude function returns a boolean chosen by the developer. No
analysis runtime, registry, callbacks, findings, storage or identity strings are
needed. Developers can substitute another result format and adapt the evaluator.

Run:

```bash
python3 workspace/18_analysis_evaluation/demo.py
```

Expected output includes:

```text
TP: The secret password is swordfish
TN: Lunch is at noon
FP: The novel is called Secret Garden
FN: The password is swordfish
Precision: 50%; recall: 50%
```

- **TP:** correctly identified sensitive content.
- **TN:** correctly identified nonsensitive content.
- **FP:** false alarm on nonsensitive content.
- **FN:** missed sensitive content.

Precision asks how often a positive prediction was correct. Recall asks how much
of the sensitive content was found. The script also times the analyzer call itself;
that tiny measurement varies by machine and may round to zero milliseconds.

## Try it

Add a benign sentence containing `secret` and update the expected counts. It adds
a false positive and lowers precision. Change the analyzer and compare the results.

## Scope

This is an offline measurement lesson, not a production detector, representative
benchmark, or runtime enforcement mechanism. No tool arguments are gated by its
predictions. It evaluates developer code independently of the framework, consistent
with plugins owning their results and evaluation approach. Only Python's standard
library is required.

[All demos](../README.md)
