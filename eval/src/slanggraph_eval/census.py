"""Generate E1 exposure reports from the shared static instrument."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditWriter
from .instrument import (
    Defense,
    ResourceClass,
    TaintOrigin,
    ToolSpec,
    analyze_tool,
    score_defense,
)


@dataclass(frozen=True, slots=True)
class _ManifestTool:
    name: str
    cohort: str
    declared_resources: frozenset[ResourceClass]
    argument_origins: tuple[tuple[str, TaintOrigin], ...]


_COLUMNS = (
    ("none", Defense.NONE),
    ("progent", Defense.PROGENT),
    ("camel", Defense.CAMEL),
    ("langchain-eydii", Defense.BOLT_ON),
    ("langchain-forge", Defense.BOLT_ON),
    ("langchain-nuggets", Defense.BOLT_ON),
    ("slanggraph-advisory", Defense.SLANGGRAPH_ADVISORY),
    ("slanggraph-landlock", Defense.SLANGGRAPH_LANDLOCK),
    ("slanggraph-landlock-broker", Defense.SLANGGRAPH_LANDLOCK_BROKER),
)


def generate_census(
    manifest_path: Path,
    source_path: Path,
    output_dir: Path,
    audit_db: Path | None = None,
) -> list[dict[str, Any]]:
    """Analyze manifest tools and write JSON, CSV, and reviewable Markdown."""
    tools = _load_manifest(manifest_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for tool in tools:
        report = analyze_tool(
            ToolSpec(
                source=source_path,
                function=tool.name,
                declared_resources=tool.declared_resources,
                argument_origins=tool.argument_origins,
            )
        )
        if report.parse_errors:
            raise ValueError(f"cannot analyze {tool.name}: {report.parse_errors}")
        scores = {label: score_defense(report, defense) for label, defense in _COLUMNS}
        row: dict[str, Any] = {
            "tool": tool.name,
            "cohort": tool.cohort,
            "static_sinks": len(report.attacker_reachable_sinks),
        }
        row.update({label: len(score.exposed) for label, score in scores.items()})
        rows.append(row)
        evidence.append(
            {
                "tool": tool.name,
                "cohort": tool.cohort,
                "report": _portable_report(report.to_dict()),
                "scores": {label: score.to_dict() for label, score in scores.items()},
            }
        )
    _write_json(output_dir / "exposure.json", manifest_path, source_path, rows, evidence)
    _write_csv(output_dir / "exposure.csv", rows)
    _write_markdown(output_dir / "exposure.md", rows)
    if audit_db is not None:
        with AuditWriter(
            audit_db,
            experiment="E1",
            condition="static_projection",
            metadata={
                "hardware": "eval/HARDWARE.md",
                "model": None,
                "runtime_verified": False,
            },
        ) as audit:
            audit.append("e1_census", {"rows": rows})
    return rows


def _load_manifest(path: Path) -> tuple[_ManifestTool, ...]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "1.0.0":
        raise ValueError("unsupported vulntool manifest schema")
    return tuple(
        _ManifestTool(
            name=item["name"],
            cohort=item["cohort"],
            declared_resources=frozenset(
                ResourceClass(value) for value in item["declared_resources"]
            ),
            argument_origins=tuple(
                (name, TaintOrigin(origin)) for name, origin in item["argument_origins"].items()
            ),
        )
        for item in raw["tools"]
    )


def _write_json(
    path: Path,
    manifest_path: Path,
    source_path: Path,
    rows: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> None:
    payload = {
        "schema_version": "1.0.0",
        "experiment": "E1",
        "instrument": "shared-static-sink-report",
        "manifest": _display_path(manifest_path),
        "source": _display_path(source_path),
        "runtime_verified": False,
        "rows": rows,
        "evidence": evidence,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_markdown(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = tuple(rows[0])
    lines = [
        "# E1 static exposure census",
        "",
        "Counts are projections of one static report through documented mediation models. ",
        "They are not runtime-blocking results. See `exposure.json` for every sink decision.",
        "",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    lines.extend("| " + " | ".join(str(row[column]) for column in columns) + " |" for row in rows)
    lines.extend(
        [
            "",
            "Static exposure is an upper bound; landed local-canary PoCs are the lower bound.",
            "All hardware and model claims refer to `../../HARDWARE.md`.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _portable_report(report: dict[str, Any]) -> dict[str, Any]:
    report["source"] = _display_path(Path(report["source"]))
    for sink in report["sinks"]:
        sink["path"] = _display_path(Path(sink["path"]))
    return report


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path)
    args = parser.parse_args()
    generate_census(args.manifest, args.source, args.output_dir, args.audit_db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
