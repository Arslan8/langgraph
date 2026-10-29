"""Run the expanded ordinary-demo compatibility survey once per mode."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parent
ROOT = CAMPAIGN.parents[2]
RAW = CAMPAIGN / "raw/expanded"
WORKER = ROOT / "eval/campaigns/pandas-matched-v1/raw/workerRoute"
DEMOS = (
    ("add-tools", "add_tools_protected.py"),
    ("custom-weather", "tool_calling_protected.py"),
    ("fixed-weather", "tool_calling_protected.py"),
    ("parallel-weather", "tool_calling_protected.py"),
    ("prebuilt-multiply", "tool_calling_protected.py"),
    ("return-direct", "tool_calling_protected.py"),
    ("forced-tool", "tool_calling_protected.py"),
    ("serial-tools", "tool_calling_protected.py"),
    ("add-memory", "persistence_protected.py"),
    ("time-travel", "persistence_protected.py"),
)


def correct(demo: str, record: dict) -> bool:
    answer = str(record.get("answer", "")).lower()
    tools = record.get("executed_tools", [])
    messages = json.dumps(record.get("messages", [])).lower()
    checks = {
        "add-tools": all(item in answer for item in ("atlanta", "united states", "usd")),
        "custom-weather": "60" in answer and "foggy" in answer,
        "fixed-weather": "60" in messages and "foggy" in messages,
        "parallel-weather": all(item in messages for item in ("60", "foggy", "nyc", "sf")),
        "prebuilt-multiply": "294" in answer,
        "return-direct": answer.strip() == "8",
        "forced-tool": "hello bob" in answer,
        "serial-tools": all(item in messages for item in ('"8"', '"28"')),
        "add-memory": all(item in answer for item in ("united kingdom", "gbp")),
        "time-travel": bool(record.get("replayed"))
        and record.get("history_size", 0) >= 5
        and "london" in answer,
    }
    expected_tools = {
        "add-tools": {"tavily_search"},
        "custom-weather": {"get_weather"},
        "fixed-weather": {"get_weather"},
        "parallel-weather": {"get_weather", "get_coolest_cities"},
        "prebuilt-multiply": {"multiply"},
        "return-direct": {"add"},
        "forced-tool": {"greet"},
        "serial-tools": {"add", "multiply"},
        "add-memory": {"tavily_search"},
        "time-travel": {"tavily_search"},
    }
    return checks[demo] and set(tools) == expected_tools[demo]


def command(demo: str, script: str, mode: str, output: Path) -> list[str]:
    result = [
        sys.executable,
        str(ROOT / "eval/apps/demos" / script),
        "--mode",
        mode,
        "--output",
        str(output),
    ]
    if script != "add_tools_protected.py":
        result.extend(("--demo", demo))
    else:
        result.extend(
            (
                "--prompt",
                (
                    "You must use the search tool. Which city and country hosted "
                    "the 1996 Summer Olympics, and what currency did that country "
                    "use at the time?"
                ),
            )
        )
    if mode == "Argus":
        result.extend(("--worker-route", str(WORKER)))
    return result


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = ":".join(
        str(ROOT / path) for path in ("libs/prebuilt", "libs/langgraph", "libs/checkpoint")
    )
    records = []
    for demo, script in DEMOS:
        for mode in ("Baseline", "Argus"):
            output = RAW / f"{demo}-{mode}.json"
            if output.exists():
                output.unlink()
            completed = subprocess.run(
                command(demo, script, mode, output),
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            inner = json.loads(output.read_text()) if output.exists() else {}
            is_correct = completed.returncode == 0 and correct(demo, inner)
            record = {
                "demo": demo,
                "mode": mode,
                "status": "completed" if completed.returncode == 0 else "compatibility_failed",
                "correct": is_correct,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "raw_record": str(output.relative_to(ROOT)) if output.exists() else None,
                "wall_ms": inner.get("wall_ms"),
                "executed_tools": inner.get("executed_tools", []),
                "grant_count": len(inner.get("authorization_grants", [])),
                "activation_count": len(inner.get("activation_receipts", [])),
            }
            records.append(record)
            (RAW / f"{demo}-{mode}-process.json").write_text(json.dumps(record, indent=2) + "\n")
    by_demo = {}
    for demo, _ in DEMOS:
        by_demo[demo] = {
            mode: next(
                record for record in records if record["demo"] == demo and record["mode"] == mode
            )
            for mode in ("Baseline", "Argus")
        }
    result = {
        "design": "one preflight per demo and mode; compatibility survey, not performance campaign",
        "upstream_commit": "23961cff61a42b52525f3b20b4094d8d2fba1744",
        "records": records,
        "by_demo": by_demo,
    }
    (CAMPAIGN / "expanded_statistics.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
