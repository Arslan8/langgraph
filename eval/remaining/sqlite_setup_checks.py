# ruff: noqa: E501
# Retain evidence captions and policy literals verbatim.
"""Trusted fixture setup assumptions, distinct from production runtime enforcement."""

import json
import os
import sqlite3
import tempfile
from pathlib import Path

OUT = Path("eval/campaigns/remaining-v1/raw/sqlite-alias-setup")
OUT.mkdir(exist_ok=False)
with (OUT / "trials.jsonl").open("w") as stream:
    for repeat in range(20):
        for case in ["regular_database", "hardlink_alias", "symlink_database"]:
            with tempfile.TemporaryDirectory(prefix="slg-alias-") as tmp:
                root = Path(tmp)
                private = root / "private"
                private.mkdir(mode=0o700)
                db = private / "records.sqlite"
                with sqlite3.connect(db) as conn:
                    conn.execute("CREATE TABLE records(owner TEXT,value TEXT)")
                    conn.execute("INSERT INTO records VALUES ('bob','ALIAS_CANARY')")
                target = db
                if case == "hardlink_alias":
                    os.link(db, root / "alias.sqlite")
                if case == "symlink_database":
                    target = root / "alias.sqlite"
                    target.symlink_to(db)
                before = db.read_bytes()
                reason = None
                if target.is_symlink():
                    reason = "symlink database configuration rejected"
                elif target.stat().st_nlink != 1:
                    reason = "multiply-linked database configuration rejected"
                allowed = reason is None
                stream.write(
                    json.dumps(
                        dict(
                            case_id=case,
                            repeat=repeat,
                            mode="trusted evaluation setup preflight",
                            concrete_executor="setup only; no worker released",
                            admission="accepted" if allowed else "refused",
                            reason=reason,
                            stat={"nlink": target.stat().st_nlink, "symlink": target.is_symlink()},
                            observed_effect=db.read_bytes() != before,
                            legitimate_result=allowed if case == "regular_database" else None,
                            assumptions="fresh private directory; no untrusted concurrent namespace writer; database/WAL/SHM contained together",
                            scope="fixture setup check, not new production alias detection; runtime composition measured separately",
                        )
                    )
                    + "\n"
                )
