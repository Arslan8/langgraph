# Configurations

This exploratory campaign evaluates the final prebuilt-`ToolNode` graph from
LangGraph's historical “Build a Basic Chatbot” add-tools tutorial.

`Baseline` runs the adapted graph and frozen search implementation directly.
It has no Argus admission, authorization, isolation, audit, or Lean checking.

`Argus` uses closed admission, authenticated principal `alice`, Cedar principal
authorization, a sealed operator policy, the Linux/bubblewrap worker route,
per-call Lean lifecycle checking, and the mandatory audit chain. The `chatbot`
model node and its routing predicate are explicit trusted orchestration. The
search tool is not trusted and executes through the protected worker.

Both modes use `qwen3:8b` digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`,
temperature 0, seed 20261005, no model retries, and `reasoning_effort=none`.

The frozen query-dependent backend is identical in both modes. It replaces the
external Tavily connection but preserves the upstream tool's name, query
argument, maximum of two results, and result shape.
