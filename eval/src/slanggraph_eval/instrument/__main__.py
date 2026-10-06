"""Command-line interface for producing per-tool sink reports and scores."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import ToolSpec, analyze_tool
from .schema import Defense, ResourceClass, TaintOrigin
from .scoring import score_defense


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("function")
    parser.add_argument(
        "--declares",
        action="append",
        default=[],
        choices=[item.value for item in ResourceClass],
    )
    parser.add_argument(
        "--origin",
        action="append",
        default=[],
        metavar="ARG=ORIGIN",
        help="set an argument origin (for example payload=untrusted_tag)",
    )
    parser.add_argument(
        "--score",
        action="append",
        default=[],
        choices=[item.value for item in Defense],
    )
    args = parser.parse_args()
    origins = tuple(_origin(value, parser) for value in args.origin)
    report = analyze_tool(
        ToolSpec(
            source=args.source,
            function=args.function,
            declared_resources=frozenset(ResourceClass(value) for value in args.declares),
            argument_origins=origins,
        )
    )
    output = {
        "report": report.to_dict(),
        "scores": [score_defense(report, value).to_dict() for value in args.score],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 2 if report.parse_errors else 0


def _origin(value: str, parser: argparse.ArgumentParser) -> tuple[str, TaintOrigin]:
    name, separator, origin = value.partition("=")
    if not separator or not name:
        parser.error(f"invalid origin {value!r}; expected ARG=ORIGIN")
    try:
        return name, TaintOrigin(origin)
    except ValueError:
        parser.error(
            f"invalid origin {origin!r}; choose from "
            + ", ".join(item.value for item in TaintOrigin)
        )


if __name__ == "__main__":
    raise SystemExit(main())
