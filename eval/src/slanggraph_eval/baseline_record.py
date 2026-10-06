"""Record a completed released-baseline validation in the audit chain."""

from __future__ import annotations

import argparse
from pathlib import Path

from .audit import AuditWriter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--check", required=True)
    parser.add_argument("--passed", type=int, required=True)
    parser.add_argument("--total", type=int, required=True)
    args = parser.parse_args()
    payload = {
        "baseline": args.name,
        "commit": args.commit,
        "check": args.check,
        "passed": args.passed,
        "total": args.total,
        "success": args.passed == args.total,
    }
    with AuditWriter(
        args.audit_db,
        experiment="E0",
        condition="released_artifact_validation",
        metadata={"hardware": "eval/HARDWARE.md", "model": None},
    ) as audit:
        audit.append("e0_baseline_test", payload)
    return 0 if payload["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
