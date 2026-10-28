"""Rebuild pilot counts without treating blocked/unsupported runs as prevention."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def summarize(root):
    groups = defaultdict(list)
    for path in sorted(root.glob("*/result.json")):
        result = json.loads(path.read_text())
        correction = path.parent / "oracle-correction.json"
        if correction.exists():
            revised = json.loads(correction.read_text())
            result = {**result, "enforcement_outcome": revised["enforcement_outcome"]}
        # Earlier adapter-debug runs lacked model-error callbacks. Retain their raw
        # status while separating observed provider timeouts in derived tables.
        stderr = path.parent / "stderr.txt"
        if (
            result["status"] == "application_error"
            and stderr.exists()
            and "OpenAITimeoutError: Request timed out." in stderr.read_text()
        ):
            result = {**result, "status": "provider_failure"}
        groups[
            (
                result["app"],
                result["configuration"],
                result["service_mode"],
                result["manifest_hash"],
                result["policy_hash"],
            )
        ].append(result)
    rows = []
    for (app, configuration, mode, manifest_hash, policy_hash), results in sorted(groups.items()):
        statuses = Counter(run["status"] for run in results)
        rows.append(
            {
                "app": app,
                "configuration": configuration,
                "service_mode": mode,
                "manifest_hash": manifest_hash,
                "policy_hash": policy_hash,
                "recorded_attempts": len(results),
                "statuses": dict(statuses),
                "successful_clean_attempts": sum(
                    run["case_kind"] == "clean" and run["task_success"] is True for run in results
                ),
                "clean_attempts": sum(run["case_kind"] == "clean" for run in results),
                "enforcement_outcomes": dict(
                    Counter(run["enforcement_outcome"] for run in results)
                ),
            }
        )
    return {
        "phase": "pilot",
        "groups": rows,
        "qualification": "Attempt counts only. No scheduled-study denominator, paired utility "
        "estimate, clustered uncertainty, ASR or overhead claim. Retries retained.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()
    print(json.dumps(summarize(args.results), indent=2))
