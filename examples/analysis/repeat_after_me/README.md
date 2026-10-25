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
