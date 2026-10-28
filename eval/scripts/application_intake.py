"""Capture pinned source evidence without mistaking source inspection for reproduction."""

import argparse
import csv
import ctypes.util
import hashlib
import json
import platform
import re
import shutil
import subprocess
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def command(argv, cwd=None):
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=30)
        return {
            "argv": argv,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "returncode": None, "error": str(exc)}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkouts", type=Path, required=True)
    args = parser.parse_args()
    captured = datetime.now(UTC).isoformat()
    destination = ROOT / "intake"
    destination.mkdir(exist_ok=True)
    host = {
        "captured_at": captured,
        "platform": platform.platform(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "slanggraph_sha": command(["git", "rev-parse", "HEAD"], ROOT)["stdout"].strip(),
        "working_tree": command(["git", "status", "--porcelain"], ROOT)["stdout"],
        "tracked_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD", "--", "libs"], cwd=ROOT.parent)
        ).hexdigest(),
        "untracked_library_files": {
            name: digest(ROOT.parent / name)
            for name in subprocess.check_output(
                ["git", "ls-files", "--others", "--exclude-standard", "libs"],
                cwd=ROOT.parent,
                text=True,
            ).splitlines()
            if (ROOT.parent / name).is_file()
        },
        "node": command(["node", "--version"]),
        "os_release": Path("/etc/os-release").read_text(),
        "ollama": command(["ollama", "--version"]),
        "gpu": command(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv"]
        ),
        "bubblewrap": command(["bwrap", "--version"]),
        "namespace_probe": command(
            ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"]
        ),
        "libseccomp": ctypes.util.find_library("seccomp"),
        "strace": shutil.which("strace"),
        "container_image_digest": None,
        "capability_claim": "Prerequisite probes only; no activation receipt or enforced clause.",
        "unsupported_reference_adapter_authority": [
            "network",
            "mail",
            "database",
            "credentials",
            "executable",
            "delegation",
        ],
    }
    (destination / "host.json").write_text(json.dumps(host, indent=2) + "\n")
    rows = []
    for item in json.loads((ROOT / "apps/catalog.json").read_text()):
        checkout = args.checkouts / item["repository"].split("/")[1]
        sha = command(["git", "rev-parse", "HEAD"], checkout)["stdout"].strip()
        app_dir = ROOT / "apps" / item["id"]
        app_dir.mkdir(exist_ok=True)
        evidence = []
        for name in item["graph_files"]:
            source = checkout / name
            if not source.is_file():
                evidence.append({"path": name, "status": "missing"})
                continue
            lines = source.read_text().splitlines()
            evidence.append(
                {
                    "path": name,
                    "sha256": digest(source),
                    "url": f"https://github.com/{item['repository']}/blob/{sha}/{name}",
                    "matches": [
                        {"line": number, "text": line.strip()}
                        for number, line in enumerate(lines, 1)
                        if re.search(
                            r"StateGraph|compile\(|invoke\(|def |subprocess|exec\(|send\(|"
                            r"define_deep_agent|SqliteSaver|write_text|requests\.",
                            line,
                        )
                    ],
                }
            )
        archives = {}
        if item["id"] in {"email", "research"}:
            with urllib.request.urlopen(
                "https://api.github.com/repos/" + item["repository"], timeout=15
            ) as response:
                data = json.load(response)
            archives = {key: data[key] for key in ["archived", "pushed_at", "html_url"]}
        locks = {
            name: digest(checkout / name)
            for name in ["poetry.lock", "uv.lock", "requirements.txt", "pyproject.toml", "setup.py"]
            if (checkout / name).is_file()
        }
        python = checkout / ".venv/bin/python"
        environment = command([str(python), "--version"])
        freeze = command(["uv", "pip", "freeze", "--python", str(python)])
        (app_dir / "resolved.txt").write_text(freeze.get("stdout", ""))
        previous_path = app_dir / "intake.json"
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
        if previous.get("baseline_run") and previous.get("sha") != sha:
            raise ValueError("Version the intake before replacing a reproduced upstream revision")
        intake = {
            **item,
            "sha": sha,
            "license": "MIT (see captured LICENSE text)",
            "retrieved_at": captured,
            "checkout": str(checkout),
            "archive": archives,
            "source_evidence": evidence,
            "dependency_inputs": locks,
            "python": environment,
            "license_sha256": digest(checkout / "LICENSE"),
            "license_text": (checkout / "LICENSE").read_text(),
            "intake_status": previous.get("intake_status", "blocked"),
            "baseline_run": previous.get("baseline_run"),
            "effect_inventory_kind": "source inspection; not a runtime trace",
            "environment_freeze_returncode": freeze["returncode"],
        }
        (app_dir / "intake.json").write_text(json.dumps(intake, indent=2) + "\n")
        rows.append(
            {
                "id": item["id"],
                "repository": "https://github.com/" + item["repository"],
                "sha": sha,
                "license": "MIT (see captured LICENSE text)",
                "subdirectory": item["subdirectory"],
                "retrieved_at": captured,
                "archived": archives.get("archived", ""),
                "historical": item.get("historical", False),
                "intake_status": intake["intake_status"],
                "baseline_run": intake["baseline_run"] or "",
                "completed_port": False,
                "evidence": f"apps/{item['id']}/intake.json",
                "next_action": item["next_action"],
            }
        )
    with (ROOT / "apps.csv").open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
