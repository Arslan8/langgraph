"""Run the developer acceptance checks and print an actionable repair queue.

Default success requires system verification. Regression-pattern absence is
reported separately and never turns missing evidence into an acceptance pass.
--require-complete remains a compatibility alias for the default behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.adapter_verification import RULES
from langgraph.prebuilt.security.layered_verification import verify_layers


def _task(
    rule: str,
    owner: str,
    message: str,
    fix: str,
    *,
    path: str = "",
    line: int = 1,
    evidence: str = "",
) -> dict[str, Any]:
    identity = "\0".join((rule, path, evidence or message))
    return {
        "rule": rule,
        "owner": owner,
        "status": "unresolved",
        "path": path,
        "line": line,
        "symbol": "",
        "message": message,
        "fix": fix,
        "fingerprint": hashlib.sha256(identity.encode()).hexdigest(),
    }


def developer_report(evidence: dict[str, Any]) -> dict[str, Any]:
    """Project fresh evidence into repair tasks; never accept saved pass flags."""
    tasks = list(evidence["adapters"]["diagnostics"])
    for issue in evidence["placement"]["issues"]:
        tasks.append(
            _task(
                "SGV190",
                "verifier",
                issue,
                "Restore the input or extend the operation/adaptor inventory and its regression tests.",
            )
        )
    router = evidence["router"]
    if not router["complete"]:
        for issue in router["issues"] + router.get("runtime_binding", {}).get(
            "issues", []
        ):
            tasks.append(
                _task(
                    "SGV201",
                    "implementation",
                    issue,
                    "Restore the required router authorization protocol and exact input/effect binding.",
                )
            )
        for entry in router.get("source_proof", {}).get("entries", []):
            if entry["status"] != "verified":
                tasks.append(
                    _task(
                        "SGV201",
                        "implementation",
                        f"{entry['entry']}: {entry['status']}",
                        "Resolve the source-proof issues; see evidence.router.source_proof.entries.",
                        evidence=entry["entry"],
                    )
                )
        if not any(task["rule"] == "SGV201" for task in tasks):
            tasks.append(
                _task(
                    "SGV201",
                    "verifier",
                    "Router certificate is incomplete",
                    "Inspect the source proof and runtime-binding evidence.",
                )
            )
    for finding in evidence["escape_discovery"]["unwaived_findings"]:
        tasks.append(
            _task(
                "SGV301",
                "implementation",
                finding["message"],
                "Mediate or reject the path. If it is a false positive, review this exact finding; a waiver is not a proof.",
                path="libs/" + finding["path"],
                line=finding["line"],
                evidence=finding["fingerprint"],
            )
        )
    for issue in evidence["escape_discovery"]["errors"]:
        tasks.append(
            _task(
                "SGV302",
                "implementation",
                issue,
                "Reconcile stale/malformed waivers against current source. Do not shift fingerprints or accept new paths automatically.",
                path="docs/security/escape-waivers.json",
            )
        )
    gaps = []
    if not evidence["placement"]["path_cover_proved"]:
        gaps.append(
            _task(
                "SGV901",
                "verifier",
                "Complete placement proof is not implemented",
                "Extend the placement checker to prove all effect paths, supported shapes, inherited APIs, callbacks and exceptional exits. Regression-pattern absence is insufficient.",
            )
        )
    if not evidence["adapters"]["proof"] or not evidence.get("publications", {}).get(
        "complete", False
    ):
        gaps.append(
            _task(
                "SGV902",
                "verifier",
                "Adapter composition proof is not implemented",
                "Resolve source-bound API obligations and publication transfer issues in evidence.obligations and evidence.publications. Prove authoritative identity, labels, approval semantics and effect atomicity; passing review patterns is insufficient.",
            )
        )
    # The router explicitly assumes these adapter properties. They are not
    # discharged by trusting kernel MAC or by a passing source inventory.
    gaps.append(
        _task(
            "SGV903",
            "verifier",
            "Host adapter/isolation contract lacks composition evidence",
            "Bind confinement activation, worker-channel identity and lifetime to the exact request. Trust MAC correctness; do not infer adapter correctness from that premise.",
        )
    )
    complete = bool(evidence["complete"] and not tasks and not gaps)
    return {
        "schema_version": 2,
        "kind": "slanggraph-developer-verification",
        "regression_checks_passed": not tasks,
        "acceptance_passed": complete,
        "complete": complete,
        "tasks": sorted(
            tasks,
            key=lambda item: (
                item["rule"],
                item["path"],
                item["line"],
                item["fingerprint"],
            ),
        ),
        "proof_gaps": gaps,
        "summary": {
            "implementation_tasks": sum(
                task["owner"] == "implementation" for task in tasks
            ),
            "verifier_tasks": sum(task["owner"] == "verifier" for task in tasks)
            + len(gaps),
            "router": router["summary"],
            "declared_api_obligations": len(evidence.get("obligations", [])),
            "publication_model_closed": evidence.get("publications", {}).get(
                "complete", False
            ),
            "publication_analysis": evidence.get("publications", {})
            .get("proof", {})
            .get("summary", {}),
        },
        "evidence": evidence,
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def compare_reports(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, list[str]]:
    """Compare task identities only; the previous report never grants approval."""
    if previous.get("kind") != "slanggraph-developer-verification" or previous.get(
        "schema_version"
    ) not in {1, 2}:
        raise ValueError(
            "comparison file must be a developer-verification report (schema 1 or 2)"
        )
    before = {item["fingerprint"] for item in previous["tasks"]}
    after = {item["fingerprint"] for item in current["tasks"]}
    return {
        "new": sorted(after - before),
        "resolved": sorted(before - after),
        "remaining": sorted(after & before),
    }


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    router = summary["router"]
    lines = [
        f"Router: {router['verified']}/{router['discovered']} verified.",
        f"Acceptance: {'PASS' if report['acceptance_passed'] else 'FAIL'}. System completeness: {'PROVED' if report['complete'] else 'NOT ESTABLISHED'}.",
        f"Known regression checks: {'PASS' if report['regression_checks_passed'] else 'FAIL'} (not a proof).",
        f"Declared definition obligations: {summary['declared_api_obligations']}; conditional publication entry results: {summary['publication_analysis']}.",
        f"Publication source model closed: {summary['publication_model_closed']} (entry results alone do not establish closure).",
    ]
    for rule in sorted({task["rule"] for task in report["tasks"]}):
        tasks = [task for task in report["tasks"] if task["rule"] == rule]
        lines.append(f"\n{rule}: {len(tasks)} finding(s)")
        for task in tasks:
            location = (
                f"{task['path']}:{task['line']}" if task["path"] else task["symbol"]
            )
            lines.append(f"  [{task['owner']}] {location} {task['message']}")
        for fix in dict.fromkeys(task["fix"] for task in tasks):
            lines.append(f"  Fix: {fix}")
    lines.append(
        "\nVerifier-owned proof work (blocks acceptance; not assigned to implementation authors):"
    )
    for gap in report["proof_gaps"]:
        lines.extend((f"  {gap['rule']}: {gap['message']}", f"  Next: {gap['fix']}"))
    if "comparison" in report:
        lines.append(
            "\nCompared with previous run: "
            + ", ".join(
                f"{len(values)} {name}" for name, values in report["comparison"].items()
            )
        )
    lines.append(
        "\nAcceptance requires all proof obligations. Unknown analysis, missing evidence and budget exhaustion cannot pass. JSON includes the source-bound API ledger and raw evidence."
    )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", type=Path, default=Path(__file__).resolve().parents[5]
    )
    parser.add_argument(
        "--output", type=Path, help="write full JSON evidence and repair tasks"
    )
    parser.add_argument(
        "--compare", type=Path, help="compare task fingerprints with a previous report"
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="compatibility alias; outstanding system-proof work fails by default",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="describe the shipped adapter checks without running them",
    )
    args = parser.parse_args(argv)
    if args.list_checks:
        for rule in RULES:
            print(f"{rule.id}: {rule.title}\n  {rule.fix}")
        print(
            "SGV201: Router proof; SGV301/302: Escape findings/waivers; SGV901–903: Verifier-owned proof gaps."
        )
        return 0
    try:
        report = developer_report(verify_layers(args.repo.resolve()))
        if args.compare:
            report["comparison"] = compare_reports(
                report, json.loads(args.compare.read_text())
            )
        if args.output:
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"SGV190: Verification input/report error: {exc}")
        return 2
    print(render_text(report), end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
