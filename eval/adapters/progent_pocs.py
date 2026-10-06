"""Run E2 against Progent's released deterministic policy checker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from progent_style import ProgentStyle
from secagent import check_tool_call, update_security_policy

from slanggraph_eval.pocs import (
    load_replay_calls,
    replay_details,
    run_pocs,
    write_audit,
    write_results,
)

_ALLOW = 0
_RETURN_ERROR = 0
_PRIORITY = 1
_module = ProgentStyle(check_tool_call)


def _schema(value_type: str) -> dict[str, str]:
    return {"type": value_type}


def _install_shared_policy() -> None:
    policy = {
        "read_file": [(_PRIORITY, _ALLOW, {"user_path": _schema("string")}, _RETURN_ERROR)],
        "write_file": [(_PRIORITY, _ALLOW, {"filename": _schema("string")}, _RETURN_ERROR)],
        "run_shell": [
            (
                _PRIORITY,
                _ALLOW,
                {"allowed_argv0": {"type": "string", "const": "/usr/bin/true"}},
                _RETURN_ERROR,
            )
        ],
        "sql_query": [(_PRIORITY, _ALLOW, {"account_id": _schema("string")}, _RETURN_ERROR)],
        "web_fetch": [(_PRIORITY, _ALLOW, {"url": _schema("string")}, _RETURN_ERROR)],
        "send_email": [(_PRIORITY, _ALLOW, {"recipient": _schema("string")}, _RETURN_ERROR)],
        "post_to_slack": [(_PRIORITY, _ALLOW, {"message": _schema("object")}, _RETURN_ERROR)],
        "delegate_to_subagent": [
            (_PRIORITY, _ALLOW, {"requested_tools": _schema("array")}, _RETURN_ERROR)
        ],
    }
    update_security_policy(policy)


def _guard(tool: str, arguments: dict[str, Any]) -> None:
    call = SimpleNamespace(tool=SimpleNamespace(name=tool), normalized=arguments)
    decision = _module.tool_call_permission(None, call)
    if decision.verdict.value != "allow":
        raise RuntimeError(decision.reason)


def _parity_corpus() -> list[dict[str, Any]]:
    cases = [
        ("allow", "read_file", {"user_path": "report.txt"}),
        ("deny_unknown", "unknown_tool", {}),
        ("deny_type", "read_file", {"user_path": 42}),
    ]
    outcomes: list[dict[str, Any]] = []
    for name, tool, arguments in cases:
        try:
            check_tool_call(tool, arguments)
            released = "allow"
        except Exception:
            released = "deny"
        call = SimpleNamespace(tool=SimpleNamespace(name=tool), normalized=arguments)
        wrapped = _module.tool_call_permission(None, call).verdict.value
        outcomes.append(
            {
                "case": name,
                "released": released,
                "wrapped": wrapped,
                "equal": released == wrapped,
            }
        )
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--transcript", type=Path, required=True)
    args = parser.parse_args()
    _install_shared_policy()
    parity = _parity_corpus()
    if not all(item["equal"] for item in parity):
        parser.error("progent_style disagrees with the released checker")
    results = run_pocs("progent", _guard, load_replay_calls(args.transcript))
    write_results(results, args.output)
    write_audit(
        results,
        args.audit_db,
        details={
            **replay_details(args.transcript),
            "defense_commit": "5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565",
            "checker": "secagent.check_tool_call",
            "module": "progent_style",
            "parity": parity,
            "policy_generation": False,
        },
    )
    print(
        json.dumps(
            {
                "parity": parity,
                "pocs": [{"tool": item.tool, "landed": item.landed} for item in results],
            }
        )
    )
    return 0 if all(item.landed for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
