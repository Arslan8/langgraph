# Sources and adaptations

- Upstream repository: `langchain-ai/langgraph`
- Frozen revision: `23961cff61a42b52525f3b20b4094d8d2fba1744`
- Source: `docs/docs/tutorials/get-started/2-add-tools.md`, final Python
  prebuilt-`ToolNode` graph (approximately lines 656–691 in the frozen file)
- Full upstream source-file SHA-256:
  `48304a1522134006055bb991b1afe61f692521666d354fa90beec23972c3886b`
- This is a reproducible historical example, not the latest LangGraph API.

Adaptations are shared by both modes unless explicitly security-specific:

1. The provider wrapper is replaced with the Pandas campaign's pinned local
   `qwen3:8b` OpenAI-compatible endpoint and generation settings.
2. Tavily is replaced by a frozen, query-dependent corpus. There are no
   task-ID answers or predetermined tool sequences.
3. The upstream `tools_condition` predicate is mechanically expressed as the
   equivalent `tool_calls -> tools; otherwise -> END` function because closed
   admission cannot capture that helper. Graph nodes, edges, state, tool loop,
   and retry behavior are otherwise unchanged.
4. The Argus mode supplies the manifest, policies, authenticated principal,
   execution route, audit sink, and Lean lifecycle checker.

This campaign is exploratory and deliberately separate from
`langgraph-demos-v1`; it neither replaces nor increases the denominator of the
five fixed applications.
