"""Trusted application mediator for a bounded SELECT grammar; not fixed-record CRUD.

Identifiers are allowlisted AST nodes. All values are bound parameters. Ownership
comes exclusively from the installed principal mapping, never generated SQL.
"""

import re
import sqlite3
import time
from pathlib import Path

COLUMNS = {"id", "owner", "date", "region", "product", "sales"}
AGGREGATES = {"COUNT", "SUM", "AVG", "MIN", "MAX"}
TOKEN = re.compile(
    "\\s*(>=|<=|!=|<>|[=><(),*;]|'(?:[^']|'')*'|\\\"[A-Za-z_][A"
    '-Za-z_0-9]*\\"|[A-Za-z_][A-Za-z_0-9]*|[0-9]+(?:\\.[0-9]+)'
    "?)"
)


class UnsupportedQuery(ValueError):  # noqa: N818 - retained public fixture exception
    pass


class Parser:
    def __init__(self, query):
        if not isinstance(query, str) or len(query) > 4096:
            raise UnsupportedQuery("query length/type")
        self.tokens = []
        position = 0
        while position < len(query.rstrip()):
            match = TOKEN.match(query, position)
            if not match:
                raise UnsupportedQuery("unsupported token")
            self.tokens.append(match.group(1))
            position = match.end()
        self.position = 0

    def pop(self):
        if self.position == len(self.tokens):
            raise UnsupportedQuery("incomplete query")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def accept(self, token):
        if self.position < len(self.tokens) and self.tokens[self.position].upper() == token:
            self.position += 1
            return True
        return False

    def need(self, token):
        if not self.accept(token):
            raise UnsupportedQuery("expected " + token)

    def identifier(self, allowed):
        token = self.pop().strip('"').lower()
        if token not in allowed:
            raise UnsupportedQuery("unsupported identifier " + token)
        return token

    def expression(self):
        if self.position < len(self.tokens) and self.tokens[self.position].upper() in AGGREGATES:
            function = self.pop().upper()
            self.need("(")
            column = "*" if self.accept("*") else self.identifier(COLUMNS)
            if column == "*" and function != "COUNT":
                raise UnsupportedQuery("aggregate star")
            self.need(")")
            return function + "(" + column + ")"
        return self.identifier(COLUMNS)

    def parse(self):
        self.need("SELECT")
        projection = []
        aliases = set()
        while True:
            expression = self.expression()
            if self.accept("AS"):
                alias = self.pop().strip('"').lower()
                if not re.fullmatch("[a-z_][a-z_0-9]{0,31}", alias):
                    raise UnsupportedQuery("alias")
                if alias in aliases:
                    raise UnsupportedQuery("duplicate alias")
                aliases.add(alias)
                expression += ' AS "' + alias + '"'
            projection.append(expression)
            if len(projection) > 8:
                raise UnsupportedQuery("projection width")
            if not self.accept(","):
                break
        self.need("FROM")
        self.identifier({"sales"})
        filters = []
        values = []
        if self.accept("WHERE"):
            while True:
                column = self.identifier(COLUMNS)
                operator = self.pop()
                if operator not in {"=", ">", "<", ">=", "<=", "!=", "<>"}:
                    raise UnsupportedQuery("comparison")
                value = self.pop()
                if value.startswith("'"):
                    value = value[1:-1].replace("''", "'")
                elif re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
                    value = float(value) if "." in value else int(value)
                else:
                    raise UnsupportedQuery("literal required")
                filters.append(column + " " + operator + " ?")
                values.append(value)
                if len(filters) > 3:
                    raise UnsupportedQuery("at most three conditions")
                if not self.accept("AND"):
                    break
        group = None
        order = None
        direction = "ASC"
        limit = None
        if self.accept("GROUP"):
            self.need("BY")
            group = self.identifier({"region", "product"})
        if self.accept("ORDER"):
            self.need("BY")
            order = []
            while True:
                column = self.identifier(COLUMNS | aliases)
                direction = "DESC" if self.accept("DESC") else "ASC"
                if direction == "ASC":
                    self.accept("ASC")
                order.append('"' + column + '" ' + direction)
                if len(order) > 2:
                    raise UnsupportedQuery("at most two order keys")
                if not self.accept(","):
                    break
        if self.accept("LIMIT"):
            literal = self.pop()
            if not literal.isdigit() or not 1 <= int(literal) <= 100:
                raise UnsupportedQuery("limit 1..100")
            limit = int(literal)
        self.accept(";")
        if self.position != len(self.tokens):
            raise UnsupportedQuery("unsupported query shape")
        # Reconstruct only recognized nodes; generated ownership conditions are impossible.
        statement = "SELECT " + ", ".join(projection) + " FROM sales WHERE owner = ?"
        if filters:
            statement += " AND " + " AND ".join("(" + f + ")" for f in filters)
        if group:
            statement += " GROUP BY " + group
        if order:
            statement += " ORDER BY " + ", ".join(order)
        if limit:
            statement += " LIMIT ?"
            values.append(limit)
        return statement, values


def execute(database, principal, query, trace):
    if principal not in {"alice", "bob"}:
        raise PermissionError("unknown principal")
    statement, values = Parser(query).parse()
    with sqlite3.connect(Path(database).as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        deadline = time.monotonic() + 1.0
        connection.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
        cursor = connection.execute(statement, [principal, *values])
        rows = cursor.fetchmany(1001)
        if len(rows) > 1000:
            raise UnsupportedQuery("result bound")
        trace.append(
            dict(
                principal=principal,
                generated_query=query,
                trusted_statement=statement,
                bound_values=[principal, *values],
                rows=rows,
            )
        )
        return {"columns": [d[0] for d in cursor.description], "rows": rows}


def metadata(database, principal, trace):
    sample = execute(
        database,
        principal,
        "SELECT id, owner, date, region, product, sales FROM sales ORDER BY id LIMIT 3",
        trace,
    )
    return {
        "dialect": "sqlite",
        "driver": "pysqlite",
        "connection_url": "broker://sales",
        "schemas": [
            {
                "schema_name": "main",
                "tables": [
                    {
                        "table_name": "sales",
                        "columns": [
                            {
                                "name": column,
                                "type": "INTEGER" if column in {"id", "sales"} else "TEXT",
                                "sample_values": [row[i] for row in sample["rows"]],
                            }
                            for i, column in enumerate(sample["columns"])
                        ],
                        "primary_key": ["id"],
                        "foreign_keys": [],
                        "indexes": [],
                    }
                ],
            }
        ],
    }
