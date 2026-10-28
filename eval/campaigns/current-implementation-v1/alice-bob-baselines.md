# Alice/Bob central comparison

The frozen fixture is one SQLite database with both `alice` and `bob` rows.
Useful functionality requires Alice's permitted read/write/delete operations to
succeed. Under Alice's authority, `notes/bob` and the database, WAL and SHM files
must remain inaccessible. The separate demo also verifies that Bob can still
read his own row, so the result is not a whole-database deny.

| Baseline/configuration | Preserves Alice functionality? | Keeps Bob row inaccessible from Alice? | Direct DB-file bypass | Policy support |
| --- | --- | --- | --- | --- |
| Native database callback | Yes | Only if new trusted row-checking code is correct and cannot be bypassed | Available to the callback | Requires additional trusted application code |
| Cedar call authorization + native callback | Yes for declared requests | Declared `notes/bob` requests deny, but an authorized `notes/alice` call can substitute/read the file unless execution is confined | Not contained | Authorizes the call directly; does not enforce its effects |
| Filesystem sandbox with database directory exposed | Yes | No: SQLite needs the file and sidecars, which also expose Bob's row | Available inside the sandbox | Cannot express record semantics by filesystem paths alone |
| Filesystem sandbox with database directory denied | No | Yes | Denied | Fails the functionality criterion and is not counted as a solution |
| Incomplete record broker plus remaining native file access | Yes | Exact broker requests are checked, but the native bypass remains | Available | Requires closing the file-authority path |
| Current object broker + SQLite mediator + Landlock worker | Yes | Yes; exact operation/selector only | Database directory absent from worker authority | Direct support through reviewed mediator and worker confinement |

The composition cohort instantiates the middle four executable configurations
with the same policy, worker source, database contents and cases. Its raw rows
retain grants, lowering, receipts, broker decisions and before/after database
snapshots. The companion database demo uses the same two-user policy to show
Alice's allowed mutations, Alice's denied Bob read, Bob's allowed own-row read,
Bob's denied write and Mallory's denial.

External process/container sandboxes can contribute worker confinement, but they
cannot by themselves preserve Alice's record operations while hiding another row
in the same SQLite file. They need either a trusted record-aware proxy/mediator or
database-side credentials/views whose enforcement is outside the sandbox. This
is the fair baseline conclusion: denying the file is secure but nonfunctional;
granting it is functional but too broad.

Measured counts are generated in `composition-summary.json` from
`raw/sqlite-composition-v1/trials.jsonl` and
`raw/pump-composition-v1/trials.jsonl`.
