"""Verify packaged bytes against the frozen SHA-256 inventory."""

import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("root", type=Path)
root = parser.parse_args().root
manifest = json.loads((root / "package-hashes.json").read_text())
failures = []
for name, expected in manifest.items():
    path = root / name
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    if actual != expected:
        failures.append(name)
if failures:
    raise SystemExit("Integrity failures: " + ", ".join(failures))
print(f"Validated {len(manifest)} packaged files.")
