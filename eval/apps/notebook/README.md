# Open Notebook: local API baseline

Baseline smoke passed using native Ollama model selection, two synthetic collections,
text ingestion, and the existing source-chat workflow. **No completed B/C port or
isolation claim.** See `intake.json` and the `baseline_run` field for the exact pin
and result. The repository has an MIT license; source hashes and resolved packages
are recorded beside this file.

The tested path is `api/routers/sources.py:create_source_json` →
`commands/source_commands.py:process_source_command` →
`open_notebook/graphs/source.py:source_graph`, followed by
`api/routers/source_chat.py:send_message_to_source_chat` →
`open_notebook/graphs/source_chat.py:source_chat_graph`. These are upstream APIs
and graphs. No replacement graph or notebook feature is counted as another app.
Commit-pinned source links and symbols are in `intake.json`.

## Setup

Use the pinned separate checkout, never a personal Notebook database:

```sh
cd /data/slanggraph-eval-upstreams/open-notebook
uv sync --frozen
# The captured image can be fetched reproducibly with:
docker pull surrealdb/surrealdb@sha256:e5d7387e3727bbe2f7cd6d869e48cd34777272258572ead37c9656b25f745723
# The first pilot used this upstream command; it pulled the digest above:
docker compose -p slanggraph-eval-notebook up -d surrealdb
```

For exact reruns, pin that digest in a separate Compose override instead of relying
on the moving `:v2` tag. Do not apply schema migrations to an existing personal DB.
The dedicated pilot used namespace/database `slanggraph_eval`, default synthetic
root/root database credentials, and a public test-only encryption string.

Start the API and worker in two separate terminals with this environment:

```sh
export SURREAL_URL=ws://localhost:8000/rpc
export SURREAL_USER=root SURREAL_PASSWORD=root
export SURREAL_NAMESPACE=slanggraph_eval SURREAL_DATABASE=slanggraph_eval
export OPEN_NOTEBOOK_ENCRYPTION_KEY=synthetic-evaluation-only
export OLLAMA_API_BASE=http://localhost:11434
export LANGCHAIN_TRACING_V2=false LANGSMITH_TRACING=false
# API terminal:
API_PORT=15055 API_RELOAD=false .venv/bin/python run_api.py
# Worker terminal (same environment):
.venv/bin/surreal-commands-worker --import-modules commands
```

The upstream synchronous source endpoint still submits a queued command and waits
for its worker. The worker is required even though `async_processing=false`.
The first run's v2 manifest incorrectly excluded the worker; its saved
`scope-correction.json` records the discovery. V3 corrects the description without
changing permissions. Embeddings, vector search, transformations and frontend UI
are excluded through existing request options, not removed from the application.

```sh
cd /data/langgraph
uv run --project eval python eval/run.py --app notebook --configuration A --case smoke --repetition 1 --manifest-version v3 --checkouts /data/slanggraph-eval-upstreams --timeout 900
```

The adapter creates fresh named notebooks and sources for every attempt and records
the returned IDs. It selects installed local `llama3:latest`; the model manifest
digest is checked. The observed source-chat defaults are temperature 1.0, top_p 0.9,
max_tokens 8192, no explicit seed. No hosted model or real credential was used.
The oracle independently checks persisted source IDs and the expected synthetic
calibration code in the persisted AI answer. Failure to reveal the other collection's
canary is **not** evidence of isolation.

API/worker logs and the database image digest are preserved for the pilot. The
client's syscall trace does not cover the separately running API, worker or DB;
complete execution-host tracing remains pending. Checkpoints are managed by the
upstream source-chat graph in the checkout's `data/sqlite-db/` directory. This
selected-source workflow does not expose a model-controlled source-selection tool;
an adversarial retrieval path must be established from source before inventing a case.

Stop only the dedicated API/worker processes after testing and run
`docker compose -p slanggraph-eval-notebook down` in this checkout. The upstream
bind-mounted `surreal_data/` and SQLite checkpoints are retained for inspection.
Fresh IDs prevent reuse in the current pilot; a large study must verify a stronger
snapshot/reset procedure and independent effect oracle before attacks.
