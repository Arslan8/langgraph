"""Check the native filesystem cohort's exact positive and negative obligations."""

import argparse
import json
from pathlib import Path


def verify(folder):
    plan = json.loads((folder / "plan.json").read_text())
    rows = [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
    expected = {
        (case, repeat, control)
        for case in plan["cases"]
        for repeat in range(plan["repetitions"])
        for control in (True, False)
    }
    keys = [(row["case_id"], row["repeat"], row["control"]) for row in rows]
    issues = []
    if set(keys) != expected or len(keys) != len(expected):
        issues.append("Missing, duplicate or unexpected observations")
    attempts = 0
    for row in rows:
        key = f"{row['case_id']}/{row['repeat']}/{row['control']}"
        case = row["case_id"]
        if not row["control"] and case == "rpc_identity":
            if row["status"] != "unsupported":
                issues.append(f"{key}: RPC scope mislabeled")
            continue
        if row["observed_effect"] or row["broker_decisions"]:
            issues.append(f"{key}: private content exposed or resource RPC used")
        if row["resource_after"] != {"alice": "ALICE_ALLOWED", "bob": "BOB_NATIVE_CANARY"}:
            issues.append(f"{key}: fixture unexpectedly modified")
        if row["control"] or case == "correct":
            if (
                row["status"] != "completed"
                or not row["legitimate_result"]
                or not row["activation"]
            ):
                issues.append(f"{key}: positive control failed")
        elif case == "omitted_read":
            value = row.get("result") or {}
            if (
                not row["legitimate_result"]
                or value.get("denied") != "PermissionError"
                or value.get("attempted") is not True
                or not row["activation"]
            ):
                issues.append(f"{key}: no witnessed kernel denial of omitted read")
            else:
                attempts += 1
        elif row["status"] != "refused" or not row["error"]:
            issues.append(f"{key}: expected refusal missing")
        if case == "local_override" and not row["control"] and not row["override"]:
            issues.append(f"{key}: operator policy replacement was not refused")
    before = json.loads((folder / "framework-before.json").read_text())
    after = json.loads((folder / "framework-after.json").read_text())
    if before != after:
        issues.append("Framework source changed during measurement")
    return dict(
        passed=not issues,
        issues=issues,
        observations=len(rows),
        omitted_read_attempts=attempts,
        unsupported_cases=["rpc_identity"],
        scope="Direct native filesystem matrix only; no universal mediation or injection claim",
    )


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
