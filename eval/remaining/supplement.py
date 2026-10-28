# ruff: noqa: E501
# Retain evidence captions and policy literals verbatim.
"""Additional evidence indexes, resource contracts, and cost attribution."""

import argparse
import collections
import csv
import hashlib
import json
import statistics
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("root", type=Path)
root = p.parse_args().root
out = root / "summaries"


def dump(p, v):
    p.write_text(json.dumps(v, indent=2, sort_keys=True) + "\n")


def read(p):
    return [json.loads(line) for line in p.read_text().splitlines()]


def csvwrite(p, rows):
    with p.open("w") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


costs = []
for app in ["pandas-full", "sql-full"]:
    for r in read(root / "raw" / app / "trials.jsonl"):
        folder = root / "raw" / app / r["run_id"]
        events = read(folder / "events.jsonl") if (folder / "events.jsonl").exists() else []
        usage = []
        for e in events:
            if e.get("kind") == "model_end":
                usage.append(
                    (e.get("response", {}).get("llm_output") or {}).get("token_usage") or {}
                )
        costs.append(
            dict(
                application=app,
                run_id=r["run_id"],
                mode=r["mode"],
                case_id=r["case_id"],
                repeat=r["repeat"],
                wall_ms=r["wall_ms"],
                model_ms=r["model_ms"],
                model_calls=r["model_calls"],
                prompt_tokens=sum(x.get("prompt_tokens", 0) for x in usage),
                completion_tokens=sum(x.get("completion_tokens", 0) for x in usage),
                tokens_recorded=len(usage),
                remaining_wall_ms=r["wall_ms"] - r["model_ms"],
                remaining_scope="imports/setup/tool/policy/audit/cleanup and scheduling, NOT enforcement alone",
                tool_calls=r.get("computation_calls", "see resource/dispatch events"),
                audit="durable SQLite configured"
                if r["mode"] == "C" or (app == "pandas-full" and r["mode"] == "B")
                else "not configured durable workflow audit",
                policy_ms="not independently timed in uninstrumented cohort",
                execution_ms="nested dispatch spans for SQL; parent workflow remainder is not execution time",
                audit_ms="see separate intrusive profile; unavailable per uninstrumented run",
            )
        )
csvwrite(out / "workflow-cost-ledger.csv", costs)
profiles = []
for cohort in ["workflow-profiles", "workflow-profiles-v2", "workflow-profiles-v3"]:
    folder = root / "raw" / cohort
    if not (folder / "trials.jsonl").exists():
        continue
    for r in read(folder / "trials.jsonl"):
        path = folder / f"{r['application']}-{r['repeat']}" / "spans.json"
        if not path.exists():
            continue
        groups = collections.defaultdict(list)
        for span in json.loads(path.read_text()):
            groups[(Path(span["file"]).name, span["function"])].append(span["elapsed_ms"])
        for (file, function), vs in groups.items():
            profiles.append(
                dict(
                    cohort=cohort,
                    application=r["application"],
                    repeat=r["repeat"],
                    exit_status=r["exit_status"],
                    file=file,
                    function=function,
                    calls=len(vs),
                    inclusive_total_ms=sum(vs),
                    inclusive_mean_ms=statistics.mean(vs),
                    scope="intrusive nested attribution; no summation across functions or threads; failed profile runs excluded from success claims",
                )
            )
csvwrite(out / "workflow-profile-spans.csv", profiles)
# A complete raw ledger identifies omissions without inventing unavailable phases.
required = [
    "case_id",
    "session",
    "repeat",
    "mode",
    "concrete_executor",
    "source_revision",
    "host",
    "principal",
    "policy_identity",
    "manifest_identity",
    "grant_identity",
    "attempted_operation",
    "authorization",
    "lowering",
    "activation",
    "observed_effect",
    "legitimate_result",
]
missing = collections.Counter()
with (out / "raw-index.jsonl").open("w") as stream:
    for folder in sorted((root / "raw").iterdir()):
        if not folder.is_dir():
            continue
        paths = (
            [folder / "trials.jsonl"]
            if (folder / "trials.jsonl").exists()
            else sorted(folder.glob("session-*.jsonl"))
        )
        for path in paths:
            for i, row in enumerate(read(path), 1):
                absent = [key for key in required if key not in row]
                missing.update(absent)
                stream.write(
                    json.dumps(
                        dict(
                            raw_ref=f"{path.relative_to(root)}:{i}",
                            record_sha256=hashlib.sha256(
                                json.dumps(row, sort_keys=True).encode()
                            ).hexdigest(),
                            cohort=folder.name,
                            fields_not_recorded_inline=absent,
                            metadata_sources=[
                                str((folder / "plan.json").relative_to(root)),
                                "release.json",
                                "backend-map.csv",
                            ],
                            scope="missing inline fields are NOT inferred successful phases; use associated config or retain not-recorded",
                        )
                    )
                    + "\n"
                )
dump(
    out / "raw-schema-gaps.json",
    dict(
        missing_inline=dict(missing),
        meaning="Original records retained. Some fixture/projection/application records require plan/config joins. A universal self-contained raw trial schema was not achieved; do not silently fill absent fields with success or not-applicable.",
    ),
)
# Preserve both source-review and executed evidence instead of conflating them.
report = json.loads((root / "raw/library-gates/security-verify-regressions.json").read_text())
dump(
    out / "verification-reconciliation.json",
    dict(
        regression_checks_passed=report["regression_checks_passed"],
        complete=report["complete"],
        summary=report["summary"],
        proof_gaps=report["proof_gaps"],
        disposition="40 SGV301 source-review findings and 34 SGV302 stale-waiver findings remain; no automatic waiver refresh. These are not 74 executed bypasses. Existing dynamic composition evidence has narrower route scope.",
        host="historical bwrap unavailable; current end-of-campaign bwrap probe succeeds; older host placement conditions retained separately",
        source_changes_after_library_format=json.loads(
            (root / "raw/library-gates/source-changes.json").read_text()
        ),
    ),
)
# Correct the stale scope prose without altering its historical bytes.
dump(
    out / "producer-scope-correction.json",
    dict(
        raw="raw/producer-integrated/scope.json",
        correction="Typed record and pump fixtures were executed through unchanged production broker for both manual and produced requirements, as evidenced by 8 typed execution rows. The scope.json prose was stale and says output-only. Preserve it and use the trial evidence.",
        outcome="manual and produced each 9 authorized successes and 1 policy denial; under/overdeclared file outputs denied",
    ),
)
# Exact executable source correspondence for the SQL release, separate from report cleanups.
plan = json.loads((root / "raw/sql-full/plan.json").read_text())
checks = {}
for name in [
    "sql_application_backend.py",
    "sql_campaign.py",
    "sql_worker.py",
    "bounded_sql.py",
    "application_campaign.py",
    "evidence_utils.py",
]:
    path = root / "configurations/executed-sources" / name
    checks[name] = hashlib.sha256(path.read_bytes()).hexdigest() == plan["source_hashes"][name]
assert all(checks.values())
dump(out / "executed-source-correspondence.json", checks)
