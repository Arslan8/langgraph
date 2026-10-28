"""Validate the complete saved controller-restart cohort and source archive."""

import argparse
import hashlib
import json
from pathlib import Path

from container_mac_campaign import verify_pair


def verify_saved(directory, repetitions=20):
    rows = json.loads((directory / "observations.json").read_text())
    report = json.loads((directory / "verification.json").read_text())
    errors = []
    if len(rows) != repetitions or {r["repetition"] for r in rows} != set(range(repetitions)):
        errors.append("incomplete or duplicate restart matrix")
    before = report["source_before"]
    if before != report["source_after"]:
        errors.append("source changed during cohort")
    for filename in ("mac.py", "container.py", "_container_lifecycle.py", "_linux_worker.py"):
        if f"libs/prebuilt/langgraph/prebuilt/security/{filename}" not in before:
            errors.append("missing production source: " + filename)
    for name, digest in before.items():
        source = directory / "sources" / digest
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            errors.append("missing or changed source archive: " + name)
    for row in rows:
        try:
            assert verify_pair(row)
            assert row["async"] == bool(row["repetition"] % 2)
            for controller in row["controllers"]:
                phase, result = controller["phase"], controller["result"]
                output = directory / f"{row['repetition']:02d}-{phase}"
                assert json.loads((output / "result.json").read_text()) == result
                request = json.loads((output / "request.json").read_text())
                assert request["phase"] == phase and request["async"] == row["async"]
                expected = (
                    "forbid(principal, action, resource) when {false};"
                    if phase == "broad"
                    else 'forbid(principal, action == slangGraph::Action::"fs::read", resource) '
                    "when {resource.selector == "
                    + json.dumps(str(Path(request["root"]) / "private.txt"))
                    + "};"
                )
                assert (output / "operator.cedar").read_text() == expected
                assert len(result["cleanup"]) == len(result["calls"])
                assert (output / "stdout.log").exists() and (output / "stderr.log").exists()
        except (AssertionError, KeyError, ValueError, TypeError, OSError):
            errors.append(f"invalid controller evidence: {row['repetition']}")
    return {
        "passed": not errors,
        "pairs": len(rows),
        "errors": errors,
        "scope": "graceful controller restart; not crash reclamation or composition proof",
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
