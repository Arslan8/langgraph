# Repeat-After-Me runtime demonstration

See [the runnable demo guide](../../../docs/security/analysis/repeat-after-me-demo.md)
and [public developer API](../../../docs/security/analysis/developer-api.md).

From the repository root:

```sh
PYTHONPATH="$PWD" uv run --directory libs/prebuilt python -m examples.analysis.repeat_after_me.run_offline --output "$PWD/examples/analysis/repeat_after_me/output/trace.json"
PYTHONPATH="$PWD" uv run --directory libs/prebuilt python -m examples.analysis.repeat_after_me.evaluate
```

`run_live` supports optional `--mode replay` and `--mode agent`. Offline execution
requires no network, model downloads or credentials. The SQLite row count is the
execution oracle; quoted JSON is never executable. All fixtures are synthetic.

Live defense selection is available through `--classifier llm|predictive|both`.
See [demo 10's classifier guide](../../../workspace/10_repeat_after_me/README.md#choose-the-analysis-defense)
for training, held-out results, uncertainty behavior, and chat commands.

Offline classifier and policy checks:

```sh
libs/prebuilt/.venv/bin/python -m unittest examples.analysis.repeat_after_me.test_predictive -v
```
