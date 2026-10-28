"""Explicit filesystem-only ablation; not a production secure executor."""

import json
import sqlite3  # noqa: F401 -- preload SQLite before confinement
import sys
from pathlib import Path  # noqa: F401 -- preload before confinement

from slanggraph_eval.isolation.alternative_worker import landlock

request = json.load(sys.stdin)
abi = landlock(request["readable"], request["writable"])
namespace = {"p": request["parameters"]}
try:
    exec(request["source"], namespace)
    result = {"value": namespace["result"], "phase": "executed"}
except Exception as error:
    result = {"error": type(error).__name__, "message": str(error), "phase": "operation"}
print(json.dumps({**result, "landlock_abi": abi, "seccomp": False}))
