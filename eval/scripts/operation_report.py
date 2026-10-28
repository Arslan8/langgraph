"""Validate per-operation observations and export reusable numeric tables."""

import csv
import hashlib
import json
import tarfile
from pathlib import Path

from slanggraph_eval.isolation.operations import report, summarize

EVAL = Path(__file__).resolve().parents[1]
METRICS = json.loads((EVAL / "reports/evaluation-metrics.json").read_text())
ROOT = EVAL / (
    "reports/repeated-v2/operations"
    if METRICS.get("standardized_protocol_complete")
    else "reports/e6/operations-v1"
)


def validate_effect(row):
    name = row["case"]
    evidence = row["evidence"]
    token = evidence["expected_token"]
    expected = {
        "write": "effect",
        "append": token + "effect",
        "truncate": "",
    }
    if name in expected:
        assert evidence["target_sha256"] == hashlib.sha256(expected[name].encode()).hexdigest()
    elif name == "unlink":
        assert evidence["target_exists"] is False
    elif name == "write_4kib":
        assert evidence["output_size"] == 4096
        assert evidence["output_sha256"] == hashlib.sha256(b"x" * 4096).hexdigest()
    elif name == "fsync":
        assert evidence["output_sha256"] == hashlib.sha256(b"effect").hexdigest()
    elif name == "listdir_names":
        assert set(row["response"]["value"]) == {"target", "result", "link"}
    elif name in {"create", "mkdir"}:
        assert evidence["new_exists"]
    elif name == "stat_metadata":
        assert row["response"]["value"] == len(token)
    elif name == "compute_control":
        assert row["response"]["value"] == 42
    else:
        assert row["response"]["value"] == token
    assert row["effect_observed"]
    assert abs(sum(row["stages_ms"].values()) - row["elapsed_ms"]) < 1e-6
    if row["condition"] == "host":
        assert row["activation_receipt"]


def main():
    plan = json.loads((ROOT / "plan.json").read_text())
    rows = [json.loads(line) for line in (ROOT / "samples.jsonl").read_text().splitlines()]
    for row in rows:
        validate_effect(row)
    summary = summarize(rows, tuple(c["name"] for c in plan["operations"]), plan["samples"])
    assert summary == json.loads((ROOT / "summary.json").read_text())
    assert (
        hashlib.sha256((ROOT / "sources.tar.gz").read_bytes()).hexdigest() == plan["archive_sha256"]
    )
    with tarfile.open(ROOT / "sources.tar.gz") as archive:
        for name, expected in plan["source_hashes"].items():
            stream = archive.extractfile(name)
            assert stream is not None
            assert hashlib.sha256(stream.read()).hexdigest() == expected
    flat = []
    for name, row in summary.items():
        record = {
            "operation": name,
            "ratio": row["ratio_of_means"],
            "overhead_percent": row["overhead_percent"],
        }
        for condition, data in row["conditions"].items():
            for scope in ("dispatch_ms", "body_ms", "setup_ms"):
                for key, value in data[scope].items():
                    record[f"{condition}_{scope}_{key}"] = value
        for scope in ("paired_dispatch_ms", "paired_body_ms"):
            for key, value in row[scope].items():
                record[f"{scope}_{key}"] = value
        flat.append(record)
    with (ROOT / "operations.csv").open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(flat[0]))
        writer.writeheader()
        writer.writerows(flat)
    if not plan.get("sessions"):
        report(ROOT, summary, plan)
    inputs = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ("plan.json", "samples.jsonl", "summary.json", "sources.tar.gz")
    }
    (ROOT / "validation.json").write_text(
        json.dumps(
            {
                "validated_rows": len(rows),
                "source_archive_verified": True,
                "sha256": inputs,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Verified {len(rows)} observations and source archive; exported operations.csv")


if __name__ == "__main__":
    main()
