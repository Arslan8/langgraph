"""The application SELECT mediator must bind ownership and reject unknown shapes."""

import importlib.util
import sqlite3
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "bounded_sql", Path(__file__).resolve().parents[1] / "remaining/bounded_sql.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "data.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE sales(id INTEGER,owner TEXT,date TEXT,region TEXT,"
            "product TEXT,sales INTEGER)"
        )
        conn.executemany(
            "INSERT INTO sales VALUES (?,?,?,?,?,?)",
            [
                (1, "alice", "2026-01-01", "North", "A", 10),
                (2, "bob", "2026-01-02", "North", "CANARY", 999),
            ],
        )
    return path


def test_row_bound_and_metadata(database):
    trace = []
    assert module.execute(database, "alice", "SELECT SUM(sales) AS total FROM sales", trace)[
        "rows"
    ] == [(10,)]
    assert "CANARY" not in str(module.metadata(database, "alice", trace))
    assert all(t["bound_values"][0] == "alice" for t in trace)


@pytest.mark.parametrize(
    "query",
    [
        "SELECT sales FROM sales UNION SELECT sales FROM sales",
        "SELECT sales FROM sales JOIN sales ON 1=1",
        "SELECT sales FROM sales WHERE id IN (SELECT id FROM sales)",
        "ATTACH 'x' AS y",
        "PRAGMA table_info(sales)",
        "DROP TABLE sales",
        "UPDATE sales SET sales=0",
        "SELECT load_extension('x') FROM sales",
        "SELECT * FROM sales",
        "SELECT sales FROM sales; DELETE FROM sales",
        "SELECT sales FROM payroll",
    ],
)
def test_unsupported_has_no_effect(database, query):
    before = database.read_bytes()
    with pytest.raises(module.UnsupportedQuery):
        module.execute(database, "alice", query, [])
    assert database.read_bytes() == before


def test_generated_ownership_never_grants_other_rows(database):
    assert (
        module.execute(database, "alice", "SELECT sales FROM sales WHERE owner='bob'", [])["rows"]
        == []
    )
