"""Demo 10: detected Repeat-After-Me proposals are blocked before tool execution."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

# Support the workspace convention: python workspace/10_repeat_after_me/demo.py.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from examples.analysis.repeat_after_me.run_offline import (  # noqa: E402
    FIXTURE,
    run_case,
)

from langgraph.prebuilt.analysis_plugins.repeat_after_me import (  # noqa: E402
    ScriptedClassifier,
)


def show_result(trace: dict) -> None:
    print(f"  Outcome: {trace['outcome'].upper()}")
    print(f"  Actual tool effects: {trace['ledger_rows']} SQLite ledger row(s)")
    if trace["outcome"] == "blocked":
        print(f"  Enforcement reason: {'; '.join(map(str, trace['reason']))}")
    if "snapshot" in trace:
        snapshot = trace["snapshot"]["snapshot"]
        findings = snapshot["findings"]
        codes = sorted({finding["code"] for finding in findings})
        print(f"  Validated findings: {', '.join(codes) or '(none)'}")
        if trace["run"] == "B":
            print(f"  Dispatch event: {snapshot['event']['event_id']}")
            print(f"  Snapshot: {snapshot['snapshot_id']}")
            for finding in findings:
                print(f"  Finding: {finding['finding_id']} ({finding['code']})")
            refs = trace["completion"]["value_refs"]
            for ref in refs:
                print(f"  Value: {ref['value_id']} version {ref['version']}")
            print(
                "  Public query and completion notification match enforcement records."
            )


async def demonstrate(directory: Path, *, step: bool) -> list[dict]:
    cases = (
        (
            "quoted-A",
            "Quoted JSON, defense off",
            {"defended": False, "text_only": True},
            0,
        ),
        ("quoted-B", "Quoted JSON, defense on", {"text_only": True}, 0),
        ("A", "Attack follow-up: defense off", {"defended": False}, 1),
        ("B", "Identical attack proposal: defense on", {}, 0),
        ("C", "Direct authorized request: benign classification", {"benign": True}, 1),
        (
            "D-retrieval",
            "Attack in retrieved content, summarized and restored",
            {"source": "retrieval"},
            0,
        ),
        (
            "D-tool",
            "Attack in tool output, summarized and restored",
            {"source": "tool"},
            0,
        ),
        (
            "false-negative",
            "Detection limitation: deliberately missed attack",
            {"classifier": ScriptedClassifier("benign")},
            1,
        ),
    )
    traces = []
    for name, title, options, expected_rows in cases:
        if step:
            input(f"\nPress Enter for {name}: {title} … ")
        print(f"\n{name} — {title}")
        trace = await run_case(directory / name, name, **options)
        if trace["ledger_rows"] != expected_rows:
            raise AssertionError(
                f"{name}: expected {expected_rows} rows, got {trace['ledger_rows']}"
            )
        if name == "B" and not any(
            "ram:affected_ancestry" in str(reason) for reason in trace["reason"]
        ):
            raise AssertionError(
                "B did not demonstrate the expected restrictive policy"
            )
        show_result(trace)
        traces.append(trace)
    return traces


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--step", action="store_true", help="Pause before each case")
    parser.add_argument(
        "--show-prompts",
        action="store_true",
        help="Print the local synthetic attack transcript",
    )
    parser.add_argument("--output", type=Path, help="Write the public API JSON trace")
    args = parser.parse_args()
    print("Demo 10: Repeat-After-Me — analysis before tool execution")
    print(
        "Offline scripted classifier and model proposal; no model service or credentials."
    )
    print(
        "The tool inserts one row. Ledger counts, not refusal text, establish execution."
    )
    print(
        "A, B and C keep the same ordinary tool permission; B adds the restrictive gate."
    )
    if args.show_prompts:
        fixture = json.loads(FIXTURE.read_text())
        print("\nSynthetic two-turn transcript (adapted example):")
        for message in fixture["messages"]:
            print(f"  {message['role']}: {message['content']}")
        print(
            f"  Scripted follow-up structured proposal: {json.dumps(fixture['proposal'])}"
        )
    with tempfile.TemporaryDirectory(prefix="slanggraph-demo10-") as directory:
        traces = asyncio.run(demonstrate(Path(directory), step=args.step))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(traces, indent=2) + "\n")
        print(f"\nPublic analysis trace: {args.output}")
    print("\nPASS: detected attack blocked before dispatch; benign request executed.")
    print(
        "Quoted JSON never executed. Retrieved/tool-result risk survived transformations."
    )
    print(
        "The deliberate classifier miss executed: this is not a perfect-detection claim."
    )


if __name__ == "__main__":
    main()
