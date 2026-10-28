"""Attribution failures remain recorded and application globals stay isolated."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_application_cannot_replace_profiler_globals(tmp_path):
    script = tmp_path / "app.py"
    script.write_text("records = 'wrong'\noutput = 'wrong'\nraise RuntimeError('pilot failed')\n")
    output = tmp_path / "spans.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "remaining/profile_workflow.py"),
            str(script),
            "request",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "pilot failed" in completed.stderr
    assert isinstance(json.loads(output.read_text()), list)


def test_timeout_is_retained_and_python_symlink_is_not_resolved(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "request.json").write_text(json.dumps({"output": str(source / "output.json")}))
    script = tmp_path / "app.py"
    script.write_text("import time\ntime.sleep(10)\n")
    python = tmp_path / "python"
    python.symlink_to(sys.executable)
    out = tmp_path / "profiles"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "remaining/run_profiles.py"),
            "--source",
            str(source),
            "--script",
            str(script),
            "--output",
            str(out),
            "--python",
            str(python),
            "--cwd",
            str(tmp_path),
            "--repetitions",
            "1",
            "--timeout",
            "0.05",
        ],
        check=True,
        capture_output=True,
    )
    rows = [json.loads(line) for line in (out / "trials.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["status"] == "timeout"
    assert rows[0]["exit_status"] is None
    assert rows[0]["python"] == str(python)
    assert rows[0]["utility_verified"] is False
