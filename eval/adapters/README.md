# Baseline adapters

Adapters in this directory may translate benchmark tool calls or model-provider
plumbing. They may not copy a defense's policy semantics into a new implementation
and call that a reproduction.

- Progent must execute its released `secagent` policy checker.
- CaMeL must execute its released `main.py`, interpreter, and policy replay.
- AgentDojo uses its `openai-compatible` provider with the local Ollama endpoint.
- InjecAgent and ASB adapters route tool calls through a LangGraph `ToolNode` and
  contain no defense logic.
- Bolt-ons execute their installed distributions at the versions in `PINS.md`.

Every adapter records its own source hash in the run audit. Vendor checkouts live in
ignored `vendor/` directories and are reconstructed with `scripts/fetch_pins.sh`.
