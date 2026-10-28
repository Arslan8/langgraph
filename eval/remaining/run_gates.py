"""Retain each required prebuilt gate's complete log and exact exit status."""

import hashlib
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "eval/campaigns/remaining-v1/raw/library-gates"
OUT.mkdir(exist_ok=False)


def hashes():
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / "libs/prebuilt").rglob("*.py")
        if ".venv" not in p.parts
    }


while (
    len(
        (ROOT / "eval/campaigns/remaining-v1/raw/pandas-full/trials.jsonl").read_text().splitlines()
    )
    < 150
):
    time.sleep(5)
before = hashes()
(OUT / "sources-before.json").write_text(json.dumps(before, indent=2))
for target in [
    "format",
    "lint",
    "test",
    "security-verify",
    "security-verify-regressions",
    "security-verify-permutations",
]:
    cmd = ["make", "-C", "libs/prebuilt", target]
    if target.startswith("security-verify"):
        cmd += [
            "SECURITY_REPORT=" + str(OUT / (target + ".json")),
            "SECURITY_PERMUTATION_REPORT=" + str(OUT / (target + ".json")),
        ]
    start = time.time()
    with (OUT / (target + ".log")).open("w") as log:
        p = subprocess.run(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    with (OUT / "exit-statuses.jsonl").open("a") as stream:
        stream.write(
            json.dumps(dict(command=cmd, exit_status=p.returncode, elapsed_s=time.time() - start))
            + "\n"
        )
    print(target, p.returncode, flush=True)
after = hashes()
(OUT / "sources-after.json").write_text(json.dumps(after, indent=2))
(OUT / "source-changes.json").write_text(
    json.dumps(
        {
            k: [before.get(k), after.get(k)]
            for k in before.keys() | after.keys()
            if before.get(k) != after.get(k)
        },
        indent=2,
    )
)
