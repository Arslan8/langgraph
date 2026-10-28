"""Recompute complete-cohort acceptance from preserved outputs and source identities."""

import argparse
import ast
import hashlib
import inspect
import json
from collections import Counter
from pathlib import Path

from application_campaign import TASKS, oracle

ROUTE_SOURCES = (
    "libs/prebuilt/langgraph/prebuilt/security/_linux_worker.py",
    "libs/prebuilt/langgraph/prebuilt/security/enforcement.py",
    "libs/prebuilt/langgraph/prebuilt/security/host_boundary.py",
    "libs/prebuilt/langgraph/prebuilt/security/landlock.py",
    "libs/prebuilt/langgraph/prebuilt/security/lean_grant.py",
    "libs/prebuilt/langgraph/prebuilt/security/lean_lifecycle.py",
    "libs/prebuilt/langgraph/prebuilt/security/linux.py",
)
HARNESS_ROUTE_SOURCES = {
    "eval/apps/pandas/integration.py": "pandas/integration.py",
    "eval/apps/pandas/sandbox_codec.py": "pandas/sandbox_codec.py",
    "eval/apps/pandas/worker.py": "pandas/worker.py",
    "eval/apps/pandas/workflow_contract.py": "pandas/workflow_contract.py",
    "eval/remaining/application_campaign.py": "application_campaign.py",
}


def verify(folder: Path) -> dict:
    plan = json.loads((folder / "plan.json").read_text())
    frozen = ast.parse((folder / "harness/application_campaign.py").read_text())
    functions = [
        node for node in frozen.body if isinstance(node, ast.FunctionDef) and node.name == "oracle"
    ]
    oracle_unchanged = len(functions) == 1 and ast.dump(functions[0]) == ast.dump(
        ast.parse(inspect.getsource(oracle)).body[0]
    )
    rows = [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
    tasks = {case: (expected, case == "monthly_chart") for case, _, expected in TASKS}
    issues = []
    if not oracle_unchanged:
        issues.append("Frozen oracle differs from the trusted unchanged utility oracle")
    if plan["repetitions"] != 5 or plan["conditions"] != ["A", "B", "C"]:
        issues.append("Full acceptance requires five repetitions across A/B/C")
    required_sources = {
        "application_campaign.py",
        "backend.py",
        "pandas/integration.py",
        "pandas/worker.py",
        "pandas/sandbox_codec.py",
        "pandas/workflow_contract.py",
    }
    if not required_sources.issubset(plan["sources"]):
        issues.append("Required harness source identities are missing")
    for name, digest in plan["sources"].items():
        source = folder / "harness" / name
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            issues.append(f"Harness source identity mismatch: {name}")
    if plan["tasks"] != [list(task) for task in TASKS]:
        issues.append("Plan task set differs from the frozen oracle")
    expected_keys = {
        (case, mode, repeat)
        for case in tasks
        for mode in ["A", "B", "C"]
        for repeat in range(plan["repetitions"])
    }
    keys = [(row["case_id"], row["mode"], row["repeat"]) for row in rows]
    if len(keys) != len(expected_keys) or set(keys) != expected_keys:
        issues.append("Missing, duplicate or unexpected trials")
    framework = json.loads((folder / "framework-sources.json").read_text())
    source_sha256 = {name: framework[name] for name in ROUTE_SOURCES if name in framework}
    if set(source_sha256) != set(ROUTE_SOURCES):
        issues.append("Linux worker route source identities are missing")
    for repository_name, snapshot_name in HARNESS_ROUTE_SOURCES.items():
        digest = plan["sources"].get(snapshot_name)
        if digest is None:
            issues.append(f"Pandas route source identity is missing: {snapshot_name}")
        else:
            source_sha256[repository_name] = digest
    actual_sources = {
        str(path.relative_to(folder / "framework")) for path in (folder / "framework").rglob("*.py")
    }
    if actual_sources != set(framework) or not all(
        any(name.startswith(f"libs/{library}/") for name in framework)
        for library in ["prebuilt", "langgraph", "checkpoint"]
    ):
        issues.append("Framework inventory is missing or differs from the retained source tree")
    for name, digest in framework.items():
        blob = folder / "framework-source-blobs" / digest
        source = folder / "framework" / name
        if (
            not blob.is_file()
            or hashlib.sha256(blob.read_bytes()).hexdigest() != digest
            or not source.is_file()
            or hashlib.sha256(source.read_bytes()).hexdigest() != digest
        ):
            issues.append(f"Framework source identity mismatch: {name}")
    passed = Counter()
    failures = []
    for row in rows:
        case, mode, repeat = row["case_id"], row["mode"], row["repeat"]
        trial = folder / row["run_id"]
        if row["run_id"] != f"{case}-{mode}-{repeat}":
            issues.append("Trial identity mismatch")
            continue
        if case not in tasks:
            continue
        expected, chart = tasks[case]
        output = (
            json.loads((trial / "output.json").read_text())
            if (trial / "output.json").exists()
            else {}
        )
        valid = (
            row["status"] == "completed"
            and row["exit_status"] == 0
            and oracle(output, expected, chart)
        )
        if valid:
            passed[mode] += 1
        else:
            failures.append(row["run_id"])
        if row["output_matches_oracle"] != oracle(output, expected, chart):
            issues.append(f"Recorded oracle result differs: {row['run_id']}")
        before = json.loads((trial / "framework-sources-before.json").read_text())
        after = json.loads((trial / "framework-sources-after.json").read_text())
        if before != framework or after != framework or row["framework_sources"] != framework:
            issues.append(f"Per-trial framework identity differs: {row['run_id']}")
        if row["model"] != plan["model"]:
            issues.append(f"Model configuration differs: {row['run_id']}")
    return {
        "passed": not issues and not failures,
        "trials": len(rows),
        "expected_trials": len(expected_keys),
        "passes_by_configuration": dict(passed),
        "failures": failures,
        "issues": issues,
        "source_sha256": source_sha256,
        "scope": "Frozen Pandas utility cohort only; no security or performance completeness claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    report = verify(args.folder)
    (args.folder / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
