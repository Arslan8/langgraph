# Application and route coverage

Source sizes are nonblank, non-comment physical lines at the frozen revision.
They describe review surface, not semantic complexity. The repository began
prospective effort tracking only after most adapters existed, so per-adapter
implementation hours are unavailable; this report does not invent
retrospective hours.

| Attempted application | Protected current path | Useful operations exercised | Unsupported or unprotected paths | Adapter/review surface | Effort evidence |
| --- | --- | --- | --- | ---: | --- |
| Dual-source compliance decision | Closed admission + sealed runtime MAC + Cedar + immutable-language dispatcher + durable audit | Two exact granted UTF-8 reads, local variables, equality, bounded branch, inert scalar result | Imports, `open`/`pathlib`, reflection, dynamic evaluation, undeclared paths; CSV/JSON libraries, DB, network and native code require a worker or broker | 8 task-function lines; built-in `read_text` adapter | New task/harness authored in this campaign; elapsed authoring time not logged |
| Pandas ten-task workflow | A upstream; B added dispatch; C Linux/Landlock + Cedar profile + Lean; C-closed adds exact D11 graph admission, dataset input and output mediation | Filtering, totals/means, groupings, missing/duplicate counts, monthly period aggregation, chart output | Backend only: no UI authentication/upload/rendering/history; arbitrary native/network/DB authority unsupported. Current direct Linux route is not accepted by sealed runtime MAC | 972 lines across `integration.py`, `integration_closed.py`, `workflow_contract.py`, `sandbox_codec.py`, `backend_closed.py` | No prospective per-file time; manifests retain the sequence of compatibility repairs |
| SQLite Alice/Bob records | Closed tool path can use the supported object broker under runtime MAC; exact record operation/selector is lowered to the parent-owned SQLite mediator; worker has no DB filename authority | Alice read/write/delete own row; Bob read own row; denial of cross-record writes/reads and raw DB/WAL/SHM access | General SQL, joins, arbitrary schemas, database aliases, triggers, extensions and concurrent hostile namespace writers | 207-line reusable SQLite mediator + 9-line worker | No prospective implementation-time record |
| Pump control | Closed tool path can use the supported object broker under runtime MAC; exact device/operation grant is lowered to parent socket adapter | inspect/start/stop/set-flow/calibrate according to principal; bounded numeric values | Arbitrary device IDs/operations, direct socket access and broker escalation denied; no claim for other device protocols | 58-line socket adapter + 21-line worker | No prospective implementation-time record |
| Docker file-read route | Closed admission + sealed runtime MAC + Cedar + exact read-only Docker bind activation + durable audit | Exact read of one authorized private file; identical-authority container reuse | Write/mutation, network, extra mounts, linked aliases, arbitrary images/runtimes; current Docker dispatcher is a read-only filesystem adapter, not a general broker | Generic production dispatcher (no application adapter); 3-line worker body | Existing framework component; no app-adapter effort |
| Typed counter broker micro-workload | Cedar + typed grant + object broker + parent-owned counter adapter | Exact increment with checked result/state transition | It is a route microbenchmark, not an application; no claim for unregistered classes/operations | Existing test resource adapter | Existing component; no new adapter effort |

The Pandas line count intentionally includes compatibility code because those
changes explain the utility change and are part of the current integration.
Counting only the final dispatch wrapper would understate the maintained review
surface. Conversely, demo/output formatting is excluded from the SQLite and
pump adapter counts.
