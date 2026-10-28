"""Recompute crash acceptance from saved observations and archived sources."""

import argparse
import hashlib
import json
from pathlib import Path

from container_crash_campaign import verify


def verify_saved(directory, repetitions=20):
    rows = [
        json.loads(line) for line in (directory / "observations.jsonl").read_text().splitlines()
    ]
    report = json.loads((directory / "verification.json").read_text())
    errors = verify(rows, repetitions)
    before = report["source_before"]
    if before != report["source_after"]:
        errors.append("source changed during cohort")
    for filename in (
        "container.py",
        "_container_guardian.py",
        "_container_guardian_client.py",
        "_container_lifecycle.py",
        "_linux_worker.py",
    ):
        if f"libs/prebuilt/langgraph/prebuilt/security/{filename}" not in before:
            errors.append("missing production source: " + filename)
    for name, digest in before.items():
        path = directory / "sources" / digest
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            errors.append("missing or changed source archive: " + name)
    payload = directory / "controller.py"
    if not payload.is_file() or hashlib.sha256(payload.read_bytes()).hexdigest() != report.get(
        "controller_sha256"
    ):
        errors.append("missing or changed executed controller payload")
    for row in rows:
        try:
            trial = directory / f"{row['repetition']:02d}-{row['phase']}"
            assert json.loads((trial / "observation.json").read_text()) == row
            assert row["route"] == "production-DockerObjectDispatcher"
            assert (trial / "stderr.log").exists()
            assert row["started_at"] <= row["killed_at"] <= row["ended_at"]
            assert all(p["at"] >= row["killed_at"] for p in row["absence_polls"])
            if row["phase"] == "creating":
                assert (
                    hashlib.sha256((trial / "fixture/client/docker").read_bytes()).hexdigest()
                    == row["wrapper_sha256"]
                )
            for receipt in row["ready"]["receipts"]:
                assert receipt["activated_obligations"] == ["work:0"]
                assert len(receipt["evidence"]) == 1
                evidence = receipt["evidence"][0]
                assert evidence["nonce"] == receipt["nonce"]
                assert evidence["native_plan_digest"] == receipt["plan_digest"]
                assert evidence["context_digest"] == receipt["context_digest"]
        except (OSError, ValueError, AssertionError, KeyError, TypeError):
            errors.append(f"invalid saved evidence: {row['phase']}:{row['repetition']}")
    return {
        "passed": not errors,
        "trials": len(rows),
        "errors": errors,
        "scope": "controller crash; guardian and daemon available; no composition proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    result = verify_saved(args.directory, args.repetitions)
    (args.directory / "independent-verification.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result))
    raise SystemExit(not result["passed"])


if __name__ == "__main__":
    main()
