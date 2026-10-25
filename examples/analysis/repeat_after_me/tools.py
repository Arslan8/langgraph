"""Harmless isolated ledger. Row count is the execution oracle."""

import sqlite3
from pathlib import Path

from langchain_core.tools import tool

from langgraph.prebuilt.security import dac


class Ledger:
    def __init__(self, path: Path):
        self.path = path
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS events(message TEXT NOT NULL)")

    def count(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT count(*) FROM events").fetchone()[0]

    def tool(self, name="record_demo_event"):
        @tool(name)
        @dac(owner="demo", grants={"demo": "x"})
        def record_demo_event(message: str) -> str:
            """Record one harmless message in the isolated demonstration ledger."""
            with sqlite3.connect(self.path) as db:
                db.execute("INSERT INTO events VALUES (?)", (message,))
            return "recorded"

        return record_demo_event
