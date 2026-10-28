"""Count first-party component lines under explicit, disjoint rules."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from pathlib import Path


def category(path: str) -> str | None:
    if not path.endswith((".py", ".lean")):
        return None
    if path.startswith("libs/prebuilt/tests/") or path.startswith("proofs/worker-route/Tests/"):
        return "tests"
    if path.startswith("libs/prebuilt/langgraph/prebuilt/security/"):
        return "enforcement"
    if path.startswith("proofs/worker-route/"):
        return "lean_model"
    if path.startswith("libs/prebuilt/langgraph/prebuilt/"):
        return "framework"
    if path.startswith("eval/distributed/") or path in {
        "eval/remaining/composition.py",
        "eval/remaining/pump_composition.py",
        "eval/remaining/record_worker.py",
    }:
        return "evaluation_harness"
    return None


def count(path: Path) -> tuple[int, int]:
    lines = path.read_text(errors="replace").splitlines()
    source = sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in lines)
    return len(lines), source


def run(root: Path, output: Path) -> None:
    names = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
    groups: dict[str, dict[str, object]] = defaultdict(
        lambda: {"files": 0, "physical_lines": 0, "nonblank_noncomment_lines": 0, "paths": []}
    )
    for name in names:
        selected = category(name)
        path = root / name
        if selected is None or not path.is_file():
            continue
        physical, source = count(path)
        group = groups[selected]
        group["files"] += 1
        group["physical_lines"] += physical
        group["nonblank_noncomment_lines"] += source
        group["paths"].append(name)
    result = {
        "counting_rules": {
            "scope": "git-tracked first-party .py and .lean files at the evaluated revision",
            "source_lines": "nonblank physical lines whose first non-space character is not #",
            "disjoint": True,
            "external_dependencies": "excluded; recorded by dependency lock/freeze",
            "generated_code": "excluded because no generated paths enter these categories",
            "vendored_baselines": "excluded and identified by their own commit hashes",
        },
        "categories": dict(sorted(groups.items())),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.root, arguments.output)
