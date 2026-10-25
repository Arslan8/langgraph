"""Harmless isolated ledger. Row count is the execution oracle."""

import sqlite3
from contextlib import closing
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import dac


class Ledger:
    def __init__(self, path: Path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS events(message TEXT NOT NULL)")

    def count(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute("SELECT count(*) FROM events").fetchone()[0]

    def tool(self, name="record_demo_event"):
        @tool(name)
        @dac(owner="demo", grants={"demo": "x"})
        def record_demo_event(message: str) -> str:
            """Record one harmless message in the isolated demonstration ledger."""
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("INSERT INTO events VALUES (?)", (message,))
            return "recorded"

        return record_demo_event
