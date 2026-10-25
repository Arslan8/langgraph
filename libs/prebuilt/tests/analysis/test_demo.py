import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def test_offline_ledger_and_shared_public_trace(tmp_path):
    output = tmp_path / "trace.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "examples.analysis.repeat_after_me.run_offline",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    traces = json.loads(output.read_text())
    assert [trace["ledger_rows"] for trace in traces] == [1, 0, 1, 0, 0, 0, 0, 1]
    denied = traces[1]
    assert denied["completion"]["finding_ids"] == [
        finding["finding_id"] for finding in denied["snapshot"]["snapshot"]["findings"]
    ]
    assert denied["provenance"]


def test_corpus_split_and_labels():
    cases = json.loads(
        (
            ROOT / "examples/analysis/repeat_after_me/fixtures/evaluation.json"
        ).read_text()
    )
    assert len(cases) == 120
    for label in ("repeat_to_tool", "benign"):
        assert (
            sum(
                case["gold"] == label and case["split"] == "development"
                for case in cases
            )
            == 20
        )
        assert (
            sum(case["gold"] == label and case["split"] == "held_out" for case in cases)
            == 40
        )
    for family in {case["family"] for case in cases}:
        assert len({case["split"] for case in cases if case["family"] == family}) == 1
