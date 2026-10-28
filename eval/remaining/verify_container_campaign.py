"""Recheck saved production-container observations without rerunning workers."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from container_dispatcher_campaign import verify


def verify_saved(directory: Path, repetitions: int = 20):
    rows = [
        json.loads(line) for line in (directory / "observations.jsonl").read_text().splitlines()
    ]
    report = json.loads((directory / "verification.json").read_text())
    errors = verify(rows, repetitions)
    before, after = report["source_before"], report["source_after"]
    if not before or before != after:
        errors.append("missing or changing source identities")
    for path, digest in before.items():
        source = directory / "sources" / digest
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            errors.append("missing or changed archived source: " + path)
    for row in rows:
        try:
            assert row["route"] == "production-DockerObjectDispatcher"
            assert [call["phase"] for call in row["calls"]] == ["seed", "reuse", "transition"]
            first, reuse, last = row["calls"]
            assert first["principal"] == reuse["principal"] == "alice"
            assert last["principal"] == ("bob" if row["case"] == "principal" else "alice")
            assert (first["policy"] != last["policy"]) == (row["case"] == "graph_local_policy")
            assert first["policy"] == reuse["policy"]
            assert [call["broad"] for call in row["calls"]] == (
                [True, True, False] if row["case"] == "broad_to_narrow" else [False] * 3
            )
            for call in row["calls"]:
                receipt, event = call["receipt"], call["execution"]
                assert re.fullmatch("[0-9a-f]{64}", event["container_id"])
                assert receipt["mode"] == "enforced"
                assert receipt["grant_digest"] == event["grant_digest"]
                assert receipt["plan_digest"] == event["identity_digest"]
                assert receipt["context_digest"] == event["context_digest"]
                obligations = ["compute:0", "compute:1"] if call["broad"] else ["compute:0"]
                assert sorted(receipt["activated_obligations"]) == obligations
                assert {rule["rule_id"] for rule in receipt["rule_enforcement"]} == set(obligations)
                assert all(rule["support"] == "exact" for rule in receipt["rule_enforcement"])
                assert len(receipt["evidence"]) == 1
                evidence = receipt["evidence"][0]
                assert evidence["nonce"] == receipt["nonce"]
                assert evidence["native_plan_digest"] == receipt["plan_digest"]
                assert evidence["context_digest"] == receipt["context_digest"]
                assert evidence["activated_at"] == event["activated_at"]
                assert sorted(evidence["obligation_ids"]) == obligations
        except (AssertionError, KeyError, ValueError):
            errors.append(f"identity/receipt mismatch: {row['case']}:{row['repetition']}")
    return {
        "passed": not errors,
        "pairs": len(rows),
        "errors": errors,
        "scope": "saved runtime observations and receipt consistency; not a composition proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = verify_saved(args.directory)
    (args.directory / "independent-verification.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result))
    raise SystemExit(not result["passed"])


if __name__ == "__main__":
    main()
