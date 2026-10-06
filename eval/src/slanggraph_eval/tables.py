"""Regenerate result tables strictly from verified audit databases."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .audit import AuditEvent, read_events


def generate_tables(audit_dir: Path, output_dir: Path) -> tuple[Path, ...]:
    """Verify audit chains and render every supported recorded result."""
    databases = sorted(audit_dir.glob("*.db"))
    if not databases:
        raise ValueError(f"no audit databases found in {audit_dir}")
    latest: dict[str, AuditEvent] = {}
    model_probes: dict[str, AuditEvent] = {}
    poc_events: dict[str, AuditEvent] = {}
    baseline_tests: dict[str, AuditEvent] = {}
    benchmark_sample: AuditEvent | None = None
    for database in databases:
        for event in read_events(database):
            if event.kind == "e1_census":
                latest[event.kind] = event
            elif event.kind == "e2_pocs":
                condition = event.payload["results"][0]["condition"]
                poc_events[condition] = event
            elif event.kind == "model_probe":
                model_probes[event.payload["tag"]] = event
            elif event.kind == "e0_baseline_test":
                baseline_tests[event.payload["baseline"]] = event
            elif event.kind == "e1_benchmark_sample":
                benchmark_sample = event
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if event := latest.get("e1_census"):
        path = output_dir / "e1-exposure.md"
        _write_table(
            path,
            "E1 static exposure census",
            event.payload["rows"],
            event,
            "Static projection, not runtime blocking evidence.",
        )
        written.append(path)
    if poc_events:
        path = output_dir / "e2-pocs.md"
        ordered_pocs = [poc_events[name] for name in sorted(poc_events)]
        _write_table(
            path,
            "E2 local canaries",
            [result for event in ordered_pocs for result in event.payload["results"]],
            ordered_pocs[-1],
            "Runtime evidence from disposable local canaries against `eval/vulntools` only.",
        )
        written.append(path)
    if model_probes:
        path = output_dir / "setup-model-probes.md"
        ordered = [model_probes[tag] for tag in sorted(model_probes)]
        _write_table(
            path,
            "Local model tool-call probes",
            [event.payload for event in ordered],
            ordered[-1],
            "Live calls through the loopback Ollama OpenAI-compatible endpoint.",
        )
        written.append(path)
    if baseline_tests:
        path = output_dir / "e0-baseline-validation.md"
        ordered = [baseline_tests[name] for name in sorted(baseline_tests)]
        _write_table(
            path,
            "E0 released baseline validation",
            [event.payload for event in ordered],
            ordered[-1],
            "Artifact tests and deterministic parity checks; not published-ASR reproduction.",
        )
        written.append(path)
    if benchmark_sample is not None:
        path = output_dir / "e1-benchmark-sample.md"
        _write_table(
            path,
            "E1 pinned benchmark sample",
            benchmark_sample.payload["rows"],
            benchmark_sample,
            "`N/A` means source implementations are absent, not that exposure is zero.",
        )
        written.append(path)
    if not written:
        raise ValueError("audit databases contain no supported table events")
    return tuple(written)


def _write_table(
    path: Path,
    title: str,
    rows: list[dict[str, Any]],
    event: AuditEvent,
    qualifier: str,
) -> None:
    columns = tuple(rows[0])
    lines = [
        f"# {title}",
        "",
        qualifier,
        "",
        f"Audit run `{event.run_id}`, terminal event hash `{event.event_hash}`. ",
        "Hardware: [`eval/HARDWARE.md`](../../HARDWARE.md).",
        "",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    lines.extend("| " + " | ".join(_cell(row[column]) for column in columns) + " |" for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _cell(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).replace("|", "\\|").replace("\n", " ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        generate_tables(args.audit_dir, args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
