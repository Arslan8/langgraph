# Frozen sources and adaptations

All five examples come from official `langchain-ai/langgraph` revision
`23961cff61a42b52525f3b20b4094d8d2fba1744`. They are historical examples,
not claims about the latest LangGraph API. Exact source files are retained under
`upstream/`.

| ID | Frozen source | Executable source map |
|---|---|---|
| D1 | `docs/docs/tutorials/sql/sql-agent.md` | Setup/database/tool blocks plus section 3 custom-graph blocks, upstream lines 23–430; installation, rendering, and example invocation output omitted |
| D2 | `examples/rag/langgraph_agentic_rag.ipynb` | code cells 5, 7, 9, 11, 13; cells 1–2 installation/credentials, cell 14 visualization, and cell 15 interactive demonstration omitted |
| D3 | `docs/docs/tutorials/plan-and-execute/plan-and-execute.ipynb` | code cells 7, 9, 12, 15, 16, 19, 21, 22; installation, credentials, one-off probes, visualization, and demo runner omitted |
| D4 | `docs/docs/tutorials/multi_agent/multi-agent-collaboration.ipynb` | code cells 5, 8, 9, 11; installation, credentials, visualization, and demo runner omitted |
| D5 | `docs/docs/tutorials/customer-support/customer-support.ipynb` | shared tool cells 9, 11, 13, 15, 17 and Part 3 cells 37, 39, 42; cell 5 fixture/date setup and cell 7 policy retriever adapted; other tutorial parts omitted |

## Adaptations applied identically before condition selection

- Every provider-specific chat wrapper is replaced with the Pandas campaign's
  pinned `qwen3:8b` OpenAI-compatible endpoint, digest
  `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`,
  temperature 0, seed `20261005`, no model retries, and reasoning disabled.
- D2 loads the three frozen HTML documents locally. Because the pinned chat
  model does not supply the tutorial's OpenAI embedding API, the Chroma/OpenAI
  embedding backend is replaced by one prepared TF-IDF index. The retriever
  tool name, query schema, graph, relevance grade, rewrite branch, and answer
  branch are retained. The hub RAG prompt is frozen locally.
- D3 and D4 replace Tavily's connection with query-dependent TF-IDF search over
  frozen corpora while retaining the tutorial tool names and result schema.
  D3 remains async with its planner/executor/replanner and recursion limit.
- D4 uses Matplotlib's noninteractive `Agg` backend. An observer records plotted
  line data and saves the figure; it does not prescribe generated Python.
  The single `PythonREPL` instance and agent handoffs are retained.
- D5 freezes relative-date adjustment at
  `2026-11-15T12:05:03.561731-04:00`, replaces the embedding policy lookup with
  a local TF-IDF lookup over the frozen FAQ, and drives Part 3 approval/denial
  deterministically. The safe/sensitive split, checkpointer, interrupt, resume,
  and original mutable flight tools are retained.
- Deprecation warnings are retained. No graph is simplified solely for Argus.

## Fixture identities

| Fixture | URL | SHA-256 |
|---|---|---|
| Chinook | `https://storage.googleapis.com/benchmarks-artifacts/chinook/Chinook.db` | `84f5d9143ac4deebdb81650ab650e226d909e660106846b119a5c47c33f94c13` |
| Travel DB | `https://storage.googleapis.com/benchmarks-artifacts/travel-db/travel2.sqlite` | `7646259e80230dc9bd92914466e13874bba82f461473d6a66552e819898eb66b` |
| Swiss FAQ | `https://storage.googleapis.com/benchmarks-artifacts/travel-db/swiss_faq.md` | `864c718edfcf80ef46575a16180210ecb41c354a891bf397a0b29dcb96f585f1` |
| Weng agent article | `https://lilianweng.github.io/posts/2023-06-23-agent/` | `03b6ed75b1dc0dedd200a077367d1f7737f0a18e08c104e7f653115e1f52b0ef` |
| Weng prompting article | `https://lilianweng.github.io/posts/2023-03-15-prompt-engineering/` | `8f9fa3bda887450231845d9fd5367ee66d5d1b6dd9ad9420ef94c953ecf4edd4` |
| Weng adversarial article | `https://lilianweng.github.io/posts/2023-10-25-adv-attack-llm/` | `86612bf758100148105aea452ac1e0ea068f8d2dba7bd3caf9632d42fd2cd55c` |
| World Bank GDP response | World Bank API, indicator `NY.GDP.MKTP.CD`, 2019–2023 | `d67c7c415b35004aaa809a822d544495ce46649b2c422a11d78ca88f29726f39` |

The D3 corpus records its Olympics/ISO/central-bank source URLs in each retained
document. It is searched from the actual query and contains no task-ID answers.

## Runtime dependency versions

Python 3.13.11; LangGraph 1.2.17; LangChain 1.4.7; langchain-core 1.7.0;
langchain-openai 1.7.2; langchain-community 0.4.2;
langchain-experimental 0.4.2; Pydantic 2.14.1; Pandas 3.1.0; NumPy 2.5.4;
scikit-learn 1.9.1; Matplotlib 3.11.2; SQLAlchemy 2.1.6; pytz 2026.5.

Porting time was not separately clocked per application before work began, so
no retrospective per-demo hours are claimed. The campaign filesystem records a
suite construction interval beginning with fixture acquisition at
2026-10-28T20:11:37-04:00; changed application-adapter lines are reported from
the committed files.

| Adapter | New adapter lines | Upstream lines edited |
|---|---:|---:|
| D1 SQL | 199 | 0 |
| D2 RAG | 177 | 0 |
| D3 plan/execute | 160 | 0 |
| D4 multi-agent | 176 | 0 |
| D5 customer support | 271 | 0 |

These counts include harness, fixture wiring, output capture, and explicit
unsupported-boundary checks; they are not presented as core Argus changes.
