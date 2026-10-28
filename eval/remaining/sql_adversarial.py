"""Bounded SQL mediator through production grant, native worker and host confinement."""

import hashlib
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

import bounded_sql
from evidence_utils import serial
from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    ResourceMediatorAdapter,
    ResourceSupport,
    SupportLevel,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
)
from sql_application_backend import CLASSES, MANIFEST, POLICY

OUT = Path("eval/campaigns/remaining-v1/raw/sql-adversarial-v2")
OUT.mkdir(exist_ok=False)


@tool("sql_access")
def sql_access(operation: str, query: str, selector: str) -> dict:
    """Request bounded SQL."""
    raise RuntimeError("no fallback")


queries = {
    "allowed": "SELECT SUM(sales) FROM sales",
    "owner_substitution": "SELECT product FROM sales WHERE owner = 'bob'",
    "join": "SELECT a.id FROM sales a JOIN sales b ON a.id=b.id",
    "subquery": "SELECT id FROM sales WHERE id IN (SELECT id FROM sales)",
    "union": "SELECT product FROM sales UNION SELECT product FROM sales",
    "attach": "ATTACH '/tmp/bob' AS bob",
    "pragma": "PRAGMA database_list",
    "schema_change": "DROP TABLE sales",
    "write": "UPDATE sales SET sales = 0",
    "extension": "SELECT load_extension('/tmp/no')",
}
with (OUT / "trials.jsonl").open("w") as stream:
    for repeat in range(20):
        for case, query in queries.items():
            with tempfile.TemporaryDirectory(prefix="slg-sql-negative-") as tmp:
                db = Path(tmp) / "sales.sqlite"
                trace = []
                with sqlite3.connect(db) as conn:
                    conn.execute(
                        "CREATE TABLE sales(id INTEGER,owner TEXT,date TEXT,regi"
                        "on TEXT,product TEXT,sales INTEGER)"
                    )
                    conn.executemany(
                        "INSERT INTO sales VALUES (?,?,?,?,?,?)",
                        [
                            (1, "alice", "2026-01-01", "North", "A", 100),
                            (2, "bob", "2026-01-01", "South", "PAYROLL_FORBIDDEN", 99991),
                        ],
                    )
                before = db.read_bytes()

                def assess(line, host, db=db):
                    if (
                        line.class_name != "sales"
                        or line.selector != "sales/alice"
                        or line.operation not in {"schema", "select"}
                        or line.attributes
                    ):
                        return ResourceSupport(SupportLevel.UNSUPPORTED, "selector/conditions")
                    return ResourceSupport(
                        SupportLevel.EXACT,
                        "bounded SQL",
                        witness="eval/tests/test_bounded_sql_evaluation.py",
                        protected_paths=(str(db.parent),),
                        required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
                    )

                def dispatch(line, payload, context, db=db, trace=trace):
                    if set(payload) != {"query"} or context.principal_id != "alice":
                        raise PermissionError("identity")
                    try:
                        return bounded_sql.execute(
                            db, context.principal_id, payload["query"], trace
                        )
                    except bounded_sql.UnsupportedQuery as e:
                        return {"unsupported": str(e)}

                worker = Path(__file__).with_name("sql_worker.py").resolve()
                dispatcher = ObjectBrokerDispatcher(
                    {
                        "sql_access": LinuxToolSpec(
                            "sql_worker:run",
                            worker,
                            hashlib.sha256(worker.read_bytes()).hexdigest(),
                        )
                    },
                    runtime_roots=tuple(
                        Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
                    ),
                    mediators=(ResourceMediatorAdapter("sqlite.select.v1", assess, dispatch),),
                )
                security = cedar_security(
                    sql_access,
                    manifest=MANIFEST,
                    classes=CLASSES,
                    policy=POLICY,
                    dispatcher=dispatcher,
                )
                call = ToolCall(
                    Tool("sql_access", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                    dict(operation="select", query=query, selector="sales/alice"),
                    {},
                    f"{case}-{repeat}",
                    0,
                )
                error = None
                response = None
                t = time.perf_counter()
                try:
                    response = security.host_executor.invoke(
                        Principal("alice", frozenset(), frozenset(), "sql-negative"), call, ()
                    )
                except Exception as e:
                    error = str(e)
                value = serial(response.value) if response else None
                row = dict(
                    case_id=case,
                    repeat=repeat,
                    session=repeat,
                    mode="C",
                    concrete_executor=(
                        "ObjectPolicyHostExecutor/ObjectBrokerDispatcher/sqlite.select.v1"
                    ),
                    query=query,
                    result=value,
                    error=error,
                    grant=serial(security.host_executor.authorization_grants()),
                    activation=serial(response.receipt) if response else None,
                    effect_trace=trace,
                    database_changed=before != db.read_bytes(),
                    observed_effect="PAYROLL_FORBIDDEN" in json.dumps(value)
                    or before != db.read_bytes(),
                    legitimate_result=value == {"columns": ["SUM(sales)"], "rows": [[100]]}
                    if case == "allowed"
                    else None,
                    elapsed_ms=(time.perf_counter() - t) * 1000,
                )
                stream.write(json.dumps(row) + "\n")
                stream.flush()
        print("SQL adversarial repeat", repeat, flush=True)
