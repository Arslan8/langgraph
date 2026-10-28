"""Summarize frozen SQLite and pump composition ablations from raw trials."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def summarize(path: Path) -> dict:
    grouped = defaultdict(list)
    for row in rows(path):
        grouped[row["mode"]].append(row)
    result = {}
    for mode, selected in sorted(grouped.items()):
        allowed = [row for row in selected if row["case_id"].startswith("allowed")]
        direct = [row for row in selected if row["case_id"].startswith("direct_")]
        result[mode] = {
            "trials": len(selected),
            "allowed_successes": sum(bool(row["legitimate_result"]) for row in allowed),
            "allowed_attempts": len(allowed),
            "forbidden_effects": sum(bool(row["observed_effect"]) for row in selected),
            "direct_bypass_effects": sum(bool(row["observed_effect"]) for row in direct),
            "direct_bypass_attempts": len(direct),
            "refusals": sum(row.get("classification") == "refused" for row in selected),
        }
    return result


def main() -> None:
    output = {
        "sqlite": summarize(ROOT / "raw/sqlite-composition-v1/trials.jsonl"),
        "pump": summarize(ROOT / "raw/pump-composition-v1/trials.jsonl"),
    }
    (ROOT / "composition-summary.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
