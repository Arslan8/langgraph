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

## Expanded survey sources

- `docs/docs/how-tos/tool-calling.md`, SHA-256
  `869c7589b339e08fd606a43d20ad2ed75c020275488eeccdab8d246c9bdfb17a`:
  prebuilt multiply, custom weather agent, fixed and parallel `ToolNode`,
  return-direct, forced-tool, and serial-tools examples.
- `docs/docs/tutorials/get-started/3-add-memory.md`, SHA-256
  `441c575d3dcd60669c7ad156b7cb9adc080702d6f88e46627f2d3fc9929d48a6`:
  in-memory checkpointed conversation across two invocations.
- `docs/docs/tutorials/get-started/6-time-travel.md`, SHA-256
  `7fc8fe9ef8bb38331597ec5690cbfee9729bdfe3f842b925bfa80d287bf2bf97`:
  state-history enumeration and replay from a checkpoint whose next node is
  the tool node.

The provider and frozen-backend adaptations described above apply throughout.
The direct `ToolNode` snippets are wrapped only in a `START -> tools` graph so
the same graph-level admission configuration can be applied; their fixed tool
calls and outputs are unchanged. No admission bypass or trusted tool body was
added. The prebuilt-agent examples preserve `create_react_agent` and are
reported unsupported rather than rewritten as custom graphs.
