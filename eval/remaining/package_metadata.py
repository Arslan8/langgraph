# ruff: noqa: E501
# Retain evidence captions and policy literals verbatim.
"""Package executed evidence and explicit scope/gap dispositions."""

import csv
import hashlib
import json
import platform
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "eval/campaigns/remaining-v1"


def dump(p, v):
    p.write_text(json.dumps(v, indent=2, sort_keys=True) + "\n")


def csvwrite(p, rows):
    with p.open("w") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def read(p):
    return [json.loads(line) for line in p.read_text().splitlines()]


# Current sources are explicitly separate from the bytes preserved at execution.
scripts = OUT / "scripts"
scripts.mkdir(exist_ok=True)
for p in (ROOT / "eval/remaining").glob("*.py"):
    shutil.copy2(p, scripts / p.name)
for name in ["mechanism_evidence_plugin.py", "repeat_mechanism_tests.py"]:
    shutil.copy2(ROOT / "eval/scripts" / name, scripts / name)
shutil.copytree(
    ROOT / "eval/remaining/apf_probe", OUT / "configurations/apf_probe", dirs_exist_ok=True
)
versions = {}
for name in ["progent", "camel", "apf", "nono", "sandlock"]:
    repo = ROOT / "eval/vendor" / name
    rev = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    p = OUT / "configurations" / (name + "-source.tar.gz")
    if not p.exists():
        with p.open("wb") as f:
            subprocess.run(
                ["git", "-C", str(repo), "archive", "--format=tar.gz", "HEAD"], stdout=f, check=True
            )
    versions[name] = {
        "commit": rev,
        "clean_source_archive": str(p.relative_to(OUT)),
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        "working_tree": subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain"], text=True
        ),
    }
base = OUT / "configurations/base-source.tar.gz"
if not base.exists():
    with base.open("wb") as f:
        subprocess.run(["git", "archive", "--format=tar.gz", "HEAD"], stdout=f, check=True)
# Capture all imported local library sources and relevant adapters, including untracked code.
paths = set()
for rel in [
    "libs/prebuilt",
    "libs/langgraph/langgraph",
    "libs/checkpoint/langgraph",
    "eval/src",
    "eval/apps",
    "eval/configs",
    "eval/remaining",
    "eval/tests",
    "eval/scripts",
    "workspace/05_custom_resource",
    "workspace/06_database",
    "workspace/07_manifest_verification",
    "workspace/09_no_internet",
]:
    for p in (ROOT / rel).rglob("*"):
        if (
            p.is_file()
            and not any(
                part
                in {
                    ".venv",
                    "__pycache__",
                    ".pytest_cache",
                    ".ruff_cache",
                    "target",
                    "node_modules",
                }
                for part in p.parts
            )
            and (
                p.suffix
                in {
                    ".py",
                    ".toml",
                    ".lock",
                    ".md",
                    ".slp",
                    ".cedar",
                    ".yaml",
                    ".yml",
                    ".rs",
                    ".json",
                    ".csv",
                    ".template",
                    ".patch",
                    ".txt",
                    ".sh",
                }
                or p.name == "Makefile"
            )
        ):
            paths.add(p)
with tarfile.open(OUT / "configurations/release-overlay.tar.gz", "w:gz") as tar:
    for p in sorted(paths):
        tar.add(p, arcname=str(p.relative_to(ROOT)), recursive=False)
dump(
    OUT / "configurations/release-source-hashes.json",
    {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)},
)
dump(
    OUT / "release.json",
    dict(
        base_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        source_state="dirty working tree; clean base plus explicit overlays; never label base alone experimental source",
        cohort_sources="configurations/executed-sources and original source-overlay; SQL plan hashes verified; original v2 sources remain in completed-v2",
        reporting_sources="scripts/; formatting-only cleanup after experimental freeze retained separately",
        host=platform.node(),
        host_capture="configurations/host-final.json",
        models="qwen3:8b 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41; temperature 0; seed 20261005; no graph retries",
        dependencies=[
            "configurations/prebuilt-dependencies.txt",
            "configurations/application-dependencies.txt",
            "Cargo.lock in comparator source archives",
            "matplotlib==3.10.7 for new figures",
        ],
        comparators=versions,
        historical_provenance_gaps="completed-v2/FAILURES.md",
    ),
)
rows = []
for name in [
    "grant-matrix",
    "capability-configurations",
    "container-lifecycle",
    "manifest-mac",
    "broker-mac",
    "sqlite-composition",
    "pump-composition",
    "typed-costs-v3",
    "cold-container",
    "pandas-full",
    "sql-full",
    "native-comparators",
    "progent-focused",
    "camel-interpreted",
]:
    folder = OUT / "raw" / name
    files = (
        [folder / "trials.jsonl"]
        if (folder / "trials.jsonl").exists()
        else sorted(folder.glob("session-*.jsonl"))
    )
    data = [r for p in files for r in read(p)]
    for mode in sorted({r.get("mode", "unknown") for r in data}):
        example = next(r for r in data if r.get("mode") == mode)
        production = (
            name in ["grant-matrix", "capability-configurations", "broker-mac", "manifest-mac"]
            or mode == "production_composition"
            or (name in ["sql-full", "pandas-full"] and mode == "C")
            or (name == "typed-costs-v3" and mode != "plain")
        )
        rows.append(
            dict(
                experiment=name,
                mode=mode,
                source_revision=example.get("source_revision", "see plan.json and release.json"),
                adapter=example.get("concrete_executor", "official selected adapter"),
                authorizer="production Cedar"
                if production and name not in ["grant-matrix", "capability-configurations"]
                else "fixture grant"
                if name in ["grant-matrix", "capability-configurations"]
                else "see archived source/policy",
                grant_input="production invocation grant"
                if production
                else "explicit fixture/configuration; not a production grant claim",
                lowering="production coordinator/resource support"
                if production
                else "evaluation/reference/official comparator configuration",
                enforcement_mechanisms="see activation receipts and source; bounded resource broker with host restrictions where selected",
                activation_evidence="production receipt when execution reached"
                if production
                else "parent observations/telemetry only; never a production receipt",
                lifetime="fresh worker; keyed container recreation where labeled",
                timer_boundary="see raw elapsed/wall/timer and summaries; setup excluded for tool timings, included in workflow walls",
            )
        )
csvwrite(OUT / "backend-map.csv", rows)
coverage = [
    (
        "grant/lowering",
        "production broker and coordinator",
        "enforced/refused",
        "want removal and need refusal distinct; 120 matrix trials + 2560 component tests",
        "fixture grants in grant matrix; concrete Cedar pipeline in composition",
    ),
    (
        "capability configuration",
        "Landlock syscalls denied by inherited real seccomp",
        "refused",
        "80 real-probe trials; normal controls succeed",
        "same Linux host, two capability configurations; not a second physical host/VM",
    ),
    (
        "container lifecycle",
        "evaluation adapter",
        "safe recreation",
        "60 key-change pairs; controls 60/60, no residual effects",
        "not a production container adapter; no in-place cross-principal reuse claim",
    ),
    (
        "manifest/MAC",
        "restricted runtime + confined broker worker",
        "enforced/refused",
        "360 restricted rows and 320 broker rows include paired controls",
        "restricted RPC route unsupported; unbrokered native eight-case matrix not separately implemented",
    ),
    (
        "SQLite composition",
        "fixed-record mediator + host confinement",
        "enforced",
        "60/60 controls; 0 observed forbidden effects in 200 negative trials",
        "fresh private DB/WAL/SHM directory; no external aliases/concurrent namespace writer",
    ),
    (
        "pump composition",
        "existing simulator + production broker + host confinement",
        "enforced",
        "60/60 controls; 0 observed forbidden effects in 60 negative trials",
        "simulated device only",
    ),
    (
        "Pandas",
        "LinuxSandboxExecutor + original upstream sandbox + Cedar/audit",
        "protected utility measured",
        "29/50 C successes; all tasks retained",
        "clean task utility corpus, not an application injection campaign",
    ),
    (
        "SQL",
        "separate bounded SELECT mediator + production broker",
        "protected utility/security measured",
        "50/50 C successes; zero model-input payroll canaries; 200 deterministic query probes",
        "single sales table; bounded templates; joins/subqueries/UNION/ATTACH/PRAGMA/writes/extensions unsupported",
    ),
    (
        "Open Notebook",
        "native server graph",
        "unsupported configuration",
        "50 preflight disposition rows, no protected execution",
        "source lookup/backing reads/restore/model input/publication not completely mediated",
    ),
    (
        "APF",
        "official Cedar evaluator + OpenShell projector",
        "decision/projection evidence",
        "proper grants and independent operator forbid; exact filesystem projection",
        "OpenShell runtime absent; no native confinement outcome claimed",
    ),
    (
        "nono/Sandlock",
        "official native CLI",
        "content enforced",
        "allowed controls and forbidden file/native chain cases; stat size observable",
        "finite filesystem corpus; metadata secrecy not supplied",
    ),
    (
        "CaMeL",
        "official interpreter + AgentDojoFunction",
        "interpreted policy enforced",
        "allowed paths pass; denied path/untrusted input refused",
        "native callee interior outside policy boundary",
    ),
    (
        "producer",
        "independent offline AST executable",
        "fixture producer validated",
        "10 manual/produced pairs equal; unknown forms rejected; executions match",
        "literal forms only; not general inference; no generated Cedar",
    ),
    (
        "stricter lowering",
        "production support contract",
        "contract evidence only",
        "component tests preserve exact/unsupported distinctions",
        "no demonstrated useful stricter production adapter",
    ),
    (
        "metadata secrecy",
        "Landlock-only configurations",
        "unsupported semantic guarantee",
        "original stat_metadata exposure retained; controls retained",
        "file-read content denial is not metadata secrecy",
    ),
]
csvwrite(
    OUT / "coverage.csv",
    [
        dict(path=a, implementation=b, disposition=c, evidence=d, gap=e)
        for a, b, c, d, e in coverage
    ],
)
csvwrite(
    OUT / "claims.csv",
    [
        dict(claim=a, experiment=b, raw_evidence=d, scope=e, disposition=c)
        for a, b, c, d, e in coverage
    ],
)
tasks = {}
for app in ["pandas-full", "sql-full", "notebook-disposition"]:
    p = OUT / "raw" / app / "plan.json"
    if p.exists():
        tasks[app] = json.loads(p.read_text())
dump(OUT / "tasks.json", tasks)
work = OUT / "worked-example"
work.mkdir(exist_ok=True)
data = read(OUT / "raw/sqlite-composition/trials.jsonl")
chosen = {}
for case in ["allowed_read", "selector_substitution"]:
    rs = [r for r in data if r["mode"] == "production_composition" and r["case_id"] == case]
    if rs:
        chosen[case] = rs[0]
if len(chosen) < 2:
    chosen["denied"] = next(
        r
        for r in data
        if r["mode"] == "production_composition" and r["case_id"].startswith("denied")
    )
dump(work / "alice-bob-traces.json", chosen)
for p in (OUT / "raw/sqlite-composition").glob("*"):
    if p.suffix in {".slp", ".cedar", ".py"}:
        shutil.copy2(p, work / p.name)
(work / "README.md").write_text(
    "Actual production SQLite invocation records, not an illustrative receipt. Each selected record contains manifest/policy identities, concrete grant, lowering, activation receipt, resource snapshots and result. Configuration literals are in configurations/executed-sources/composition.py and raw/sqlite-composition. Alice allowed; Bob denied. Resource fixture paths were ephemeral and are preserved as evidence.\n"
)
loc = sum(len(p.read_text().splitlines()) for p in (ROOT / "eval/remaining").glob("*.py"))
csvwrite(
    OUT / "integration.csv",
    [
        dict(
            component="new evaluation harnesses and bounded SQL application mediator",
            adapter_loc=loc,
            core_changes="none by this campaign; pre-existing repository overlay preserved",
            engineering_hours="unrecorded before prospective log; wall span is not labor hours",
            prospective_events="engineering-events.jsonl",
            functionality="original Pandas/SQL graphs retained; SQL generated query remains data; C generated Python replaced by trusted bounded SQL executor",
            restrictions="coverage.csv and bounded_sql.py accepted grammar",
        ),
        dict(
            component="manual host-plus-broker baseline",
            adapter_loc="see composition.py and pump_composition.py",
            core_changes="manual dispatcher/mediator/policy wiring",
            engineering_hours="not reconstructed",
            prospective_events="engineering-events.jsonl",
            functionality="same production mechanisms enforce same policy; credited as secure composition",
            restrictions="additional explicit trusted setup/wiring; no measured labor comparison",
        ),
    ],
)
print("Package source identities, backend map, claims, coverage and worked example generated.")
