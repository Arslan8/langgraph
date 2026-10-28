# ruff: noqa: E501
"""Freeze and classify ACE case-study-1 tools against the language subset."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from langgraph.prebuilt.security import parse_security_manifest
from langgraph.prebuilt.security.manifest_consistency import (
    check_manifest_consistency,
)

ADAPTER_CANDIDATES = frozenset(
    {
        "create_gmail_draft",
        "delete_gmail_message",
        "get_gmail_message",
        "get_gmail_thread",
        "google_drive_retrieve",
        "health_companion",
        "search_gmail",
        "send_gmail_message",
        "travel_mate",
    }
)


def run(output: Path, ace_root: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    source_root = ace_root / "benchmarks/case_studies/case_1/tools/source"
    manifest_path = ace_root / "benchmarks/case_studies/case_1/tools/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    selected_names = {
        entry["path"]
        for entry in manifest
        if entry.get("enabled", True)
        and isinstance(entry.get("path"), str)
        and (source_root / f"{entry['path']}.py").exists()
    }
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ace_root, text=True
    ).strip()
    parsed = parse_security_manifest("tool census_tool {\n runs inprocess\n returns normal\n}")
    rows = []
    for path in sorted(source_root.glob("*.py")):
        name = path.stem
        if name not in selected_names:
            continue
        source = path.read_text()
        report = check_manifest_consistency(
            source,
            parsed,
            tool_name="census_tool",
            function="main",
        )
        if report["consistent"]:
            classification = "works_unchanged"
        elif name in ADAPTER_CANDIDATES:
            classification = "requires_resource_adapter"
        else:
            classification = "requires_host_isolation"
        rows.append(
            {
                "tool": name,
                "source": str(path.relative_to(ace_root)),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "classification": classification,
                "unchanged_admitted": report["consistent"],
                "rejection_reasons": [item["reason"] for item in report["issues"]],
                "report": report,
            }
        )
    (output / "trials.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    counts = {
        label: sum(row["classification"] == label for row in rows)
        for label in (
            "works_unchanged",
            "requires_resource_adapter",
            "requires_host_isolation",
        )
    }
    (output / "summary.json").write_text(
        json.dumps(
            {
                "collection": "ACE case-study-1 enabled tools with a checked-in source file",
                "selection_rule": "Every enabled manifest entry whose path has source/<path>.py",
                "ace_revision": revision,
                "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "total": len(rows),
                "counts": counts,
                "adapted_execution_count": 0,
                "note": "Adapter candidates are not counted as working until an adapter-backed execution is separately demonstrated.",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ace-root", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.output, arguments.ace_root)
