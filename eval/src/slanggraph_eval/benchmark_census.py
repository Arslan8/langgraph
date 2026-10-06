"""Run E1 on pinned benchmark tool samples without treating schemas as code."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .audit import AuditWriter
from .instrument import ToolSpec, analyze_tool


def generate(config_path: Path, root: Path, output: Path, audit_db: Path) -> None:
    """Write a benchmark sample census and record it in the audit chain."""
    config = json.loads(config_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for item in config["agentdojo"]:
        source = root / item["source"]
        if not source.exists():
            raise FileNotFoundError(f"missing pinned checkout file: {source}")
        report = analyze_tool(ToolSpec(source, item["function"]))
        rows.append(
            {
                "benchmark": "AgentDojo",
                "tool": item["function"],
                "analyzable": True,
                "static_sinks": len(report.attacker_reachable_sinks),
                "note": "in-memory benchmark implementation",
            }
        )
        report_data = report.to_dict()
        report_data["source"] = str(source.relative_to(root))
        for sink in report_data["sinks"]:
            sink["path"] = str(source.relative_to(root))
        evidence.append(report_data)
    injecagent = config["injecagent"]
    schema_path = root / injecagent["tool_schema"]
    schemas = json.loads(schema_path.read_text(encoding="utf-8"))
    declared_tools = sum(len(toolkit.get("tools", [])) for toolkit in schemas)
    rows.append(
        {
            "benchmark": "InjecAgent",
            "tool": f"{declared_tools} declared schemas",
            "analyzable": False,
            "static_sinks": "N/A",
            "note": injecagent["note"],
        }
    )
    payload = {
        "schema_version": "1.0.0",
        "experiment": "E1",
        "rows": rows,
        "evidence": evidence,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with AuditWriter(
        audit_db,
        experiment="E1",
        condition="benchmark_sample",
        metadata={"hardware": "eval/HARDWARE.md", "model": None},
    ) as audit:
        audit.append("e1_benchmark_sample", {"rows": rows})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    args = parser.parse_args()
    generate(args.config, args.root, args.output, args.audit_db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
