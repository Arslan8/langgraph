"""Bounded authorization-state analysis of trusted Python execution paths.

This checks successful authorization and subject/request identity at catalogued
operations. It is not a Python confinement proof. Call summaries and the
operation inventory are explicit, reviewed assumptions, not inferred facts.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Authorizer:
    """A trusted decision producer; selectors refer to arguments or results.

    `arg:0` means the first positional argument; `result:1.principal` means
    the principal attribute of the second tuple result. `decision` selects
    the decision result itself, or a tuple member such as `0`.
    """

    target: str
    bindings: tuple[str, ...]
    decision: str = ""
    permission: str = "tool_call"


@dataclass(frozen=True)
class Operation:
    """A controlled operation requiring matching subject/request authorization."""

    target: str
    bindings: tuple[str, ...]
    permission: str = "tool_call"


@dataclass(frozen=True)
class Contract:
    """A function's explicit operation and trusted-call model."""

    function: str
    authorizers: tuple[Authorizer, ...]
    operations: tuple[Operation, ...]
    trusted_calls: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        summaries: tuple[Authorizer | Operation, ...] = (
            *self.authorizers,
            *self.operations,
        )
        targets = [item.target for item in summaries]
        if not self.function or not self.operations:
            raise ValueError("a contract needs a function and controlled operations")
        if len(set(targets)) != len(targets) or set(targets).intersection(
            self.trusted_calls
        ):
            raise ValueError("call summaries must have distinct targets")
        if any(
            not item.target or not item.bindings or not item.permission
            for item in summaries
        ):
            raise ValueError("authorization and operation bindings must be nonempty")


@dataclass
class _State:
    env: dict[str, str] = field(default_factory=dict)
    pending: dict[str, tuple[str, ...]] = field(default_factory=dict)
    approved: set[tuple[str, ...]] = field(default_factory=set)
    verdicts: dict[str, frozenset[str]] = field(default_factory=dict)
    predicates: dict[str, bool] = field(default_factory=dict)
    exit: str = "normal"

    def clone(self) -> _State:
        return _State(
            dict(self.env),
            dict(self.pending),
            set(self.approved),
            dict(self.verdicts),
            dict(self.predicates),
            self.exit,
        )


_VERDICTS = frozenset({"ALLOW", "DENY", "ESCALATE", "TRANSFORM"})


class _Analyzer:
    def __init__(self, contract: Contract, max_states: int) -> None:
        self.contract = contract
        self.max_states = max_states
        self.authorizers = {item.target: item for item in contract.authorizers}
        self.operations = {item.target: item for item in contract.operations}
        self.issues: set[tuple[int, str]] = set()
        self.sites: dict[tuple[int, int, str], list[bool]] = {}

    def issue(self, node: ast.AST, message: str) -> None:
        self.issues.add((getattr(node, "lineno", 0), message))

    def term(self, node: ast.AST, state: _State) -> str:
        if isinstance(node, ast.Name):
            return state.env.get(node.id, f"input:{node.id}")
        if isinstance(node, ast.Attribute):
            return f"{self.term(node.value, state)}.{node.attr}"
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.Subscript):
            return f"{self.term(node.value, state)}[{self.term(node.slice, state)}]"
        return (
            type(node).__name__
            + "("
            + ",".join(self.term(child, state) for child in ast.iter_child_nodes(node))
            + ")"
        )

    def select(
        self, selector: str, arguments: list[str], result: str, node: ast.AST
    ) -> str:
        kind, _, path = selector.partition(":")
        first, dot, rest = path.partition(".")
        if kind == "arg" and first.isdigit() and int(first) < len(arguments):
            value = arguments[int(first)]
        elif kind == "result":
            value = result + (f".{first}" if first else "")
        else:
            self.issue(node, f"unresolved binding selector: {selector}")
            return f"unresolved:{selector}"
        return value + (f".{rest}" if dot else "")

    def expression(self, node: ast.AST, state: _State) -> str:
        if isinstance(node, ast.Await):
            return self.expression(node.value, state)
        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value, state)
            self.assign(node.target, value, state)
            return value
        if isinstance(node, ast.Call):
            target = ast.unparse(node.func)
            # Computed receivers/callees cannot be treated as ordinary attributes.
            if any(isinstance(part, ast.Call) for part in ast.walk(node.func)):
                self.issue(node, "computed call target")
            arguments = [self.expression(arg, state) for arg in node.args]
            for keyword in node.keywords:
                self.expression(keyword.value, state)
            result = f"result:{node.lineno}:{node.col_offset}"
            if target in self.authorizers:
                summary = self.authorizers[target]
                if node.keywords or any(
                    isinstance(arg, ast.Starred) for arg in node.args
                ):
                    self.issue(
                        node, "authorizer requires explicit positional arguments"
                    )
                decision = result + (f".{summary.decision}" if summary.decision else "")
                bindings = (summary.permission,) + tuple(
                    self.select(item, arguments, result, node)
                    for item in summary.bindings
                )
                # A new policy decision supersedes older authority for this
                # operation; retaining an earlier ALLOW would mask a new denial.
                state.approved.discard(bindings)
                state.pending = {
                    key: value
                    for key, value in state.pending.items()
                    if value != bindings
                }
                state.pending[decision] = bindings
                state.verdicts[decision] = _VERDICTS
            elif target in self.operations:
                operation = self.operations[target]
                if node.keywords or any(
                    isinstance(arg, ast.Starred) for arg in node.args
                ):
                    self.issue(node, "operation requires explicit positional arguments")
                bindings = (operation.permission,) + tuple(
                    self.select(item, arguments, result, node)
                    for item in operation.bindings
                )
                key = (node.lineno, node.col_offset, target)
                self.sites.setdefault(key, []).append(bindings in state.approved)
                # A physical retry needs a new decision, even for the same request.
                state.approved.discard(bindings)
                state.pending = {
                    key: value
                    for key, value in state.pending.items()
                    if value != bindings
                }
            elif target not in self.contract.trusted_calls:
                self.issue(node, f"call has no reviewed summary: {target}")
                state.approved.clear()
                state.pending.clear()
            return result
        if isinstance(node, (ast.BoolOp, ast.IfExp, ast.Lambda)) or isinstance(
            node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            self.issue(node, f"unsupported expression: {type(node).__name__}")
            state.approved.clear()
            state.pending.clear()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.expression(child, state)
        return self.term(node, state)

    def branch(self, node: ast.expr, state: _State, truth: bool) -> list[_State]:
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.branch(node.operand, state, not truth)
        if isinstance(node, ast.BoolOp):
            all_required = isinstance(node.op, ast.And) == truth
            active = [state]
            results: list[_State] = []
            for value in node.values:
                if not all_required:
                    results.extend(
                        child
                        for current in active
                        for child in self.branch(value, current.clone(), truth)
                    )
                active = [
                    child
                    for current in active
                    for child in self.branch(
                        value, current.clone(), truth if all_required else not truth
                    )
                ]
            return active if all_required else results
        if isinstance(node, ast.Constant):
            return [state] if bool(node.value) == truth else []
        if isinstance(node, ast.NamedExpr):
            self.expression(node, state)
            return self.branch(node.target, state, truth)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = node.left, node.comparators[0]
            operator = node.ops[0]
            equal = truth != isinstance(operator, (ast.IsNot, ast.NotEq))
            if (
                isinstance(operator, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
                and isinstance(left, ast.Attribute)
                and left.attr == "verdict"
                and isinstance(right, ast.Attribute)
                and isinstance(right.value, ast.Name)
                and right.value.id == "Verdict"
                and right.attr in _VERDICTS
            ):
                token = self.expression(left.value, state)
                # Only an authorizer contract guarantees a valid Decision.
                # Other values may have a missing/malformed enum value; do not
                # eliminate their paths by assuming an exhaustive four-way enum.
                domain = _VERDICTS | {"UNKNOWN"}
                values = state.verdicts.get(token, domain)
                allowed = {right.attr} if equal else domain - {right.attr}
                remaining = values.intersection(allowed)
                if not remaining:
                    return []
                state.verdicts[token] = frozenset(remaining)
                if remaining == {"ALLOW"} and token in state.pending:
                    state.approved.add(state.pending[token])
                return [state]
        # Only stable, side-effect-free conditions can be correlated.
        if any(isinstance(part, (ast.Call, ast.Await)) for part in ast.walk(node)):
            self.expression(node, state)
            return [state]
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
        ):
            key = (
                ("is:" if isinstance(node.ops[0], (ast.Is, ast.IsNot)) else "eq:")
                + self.term(node.left, state)
                + ":"
                + self.term(node.comparators[0], state)
            )
            truth = truth != isinstance(node.ops[0], (ast.IsNot, ast.NotEq))
        else:
            key = self.term(node, state)
        previous = state.predicates.get(key)
        if previous is not None and previous != truth:
            return []
        state.predicates[key] = truth
        return [state]

    def assign(self, target: ast.expr, value: str, state: _State) -> None:
        if isinstance(target, ast.Name):
            roots = {
                item.split(".", 1)[0] for item in (*self.authorizers, *self.operations)
            }
            if target.id in roots:
                self.issue(target, "reassignment of a summarized call target")
            state.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, item in enumerate(target.elts):
                self.assign(item, f"{value}.{index}", state)
        else:
            # Heap alias analysis is outside this model; never retain a proof
            # across an attribute/subscript write, even through another alias.
            self.issue(target, "heap mutation requires an alias-aware summary")
            state.approved.clear()
            state.pending.clear()
            state.predicates.clear()

    def block(self, body: list[ast.stmt], states: list[_State]) -> list[_State]:
        for statement in body:
            following: list[_State] = []
            for state in states:
                following.extend(
                    [state]
                    if state.exit != "normal"
                    else self.statement(statement, state)
                )
            unique = {}
            for item in following:
                key = (
                    tuple(sorted(item.env.items())),
                    tuple(sorted(item.pending.items())),
                    frozenset(item.approved),
                    tuple(sorted(item.verdicts.items())),
                    tuple(sorted(item.predicates.items())),
                    item.exit,
                )
                unique[key] = item
            following = list(unique.values())
            if len(following) > self.max_states:
                self.issue(statement, "path budget exceeded; coverage is unresolved")
                following = following[: self.max_states]
            states = following
        return states

    def statement(self, node: ast.stmt, state: _State) -> list[_State]:
        if isinstance(node, ast.If):
            return self.block(
                node.body, self.branch(node.test, state.clone(), True)
            ) + self.block(node.orelse, self.branch(node.test, state.clone(), False))
        if isinstance(node, ast.Try):
            body = self.block(node.body, [state.clone()])
            normal = self.block(
                node.orelse, [item for item in body if item.exit == "normal"]
            )
            exits = [item for item in body if item.exit != "normal"]
            # A call can fail at any prefix. Forget all authorization and local
            # identities at handler entry instead of guessing exception timing.
            exceptional = _State(
                env={key: f"exception:{node.lineno}:{key}" for key in state.env}
            )
            for handler in node.handlers:
                exits.extend(self.block(handler.body, [exceptional.clone()]))
            exceptional.exit = "raise"
            exits.append(exceptional)
            results: list[_State] = []
            for item in normal + exits:
                previous_exit, item.exit = item.exit, "normal"
                for final in self.block(node.finalbody, [item]):
                    if final.exit == "normal":
                        final.exit = previous_exit
                    results.append(final)
            return results
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value is not None:
                value = self.expression(node.value, state)
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    self.assign(target, value, state)
        elif isinstance(node, ast.Expr):
            self.expression(node.value, state)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.expression(node.value, state)
            state.exit = "return"
        elif isinstance(node, ast.Raise):
            if node.exc is not None:
                self.expression(node.exc, state)
            if node.cause is not None:
                self.expression(node.cause, state)
            state.exit = "raise"
        elif isinstance(node, ast.Assert):
            # Assertions disappear under -O, so they cannot establish authority.
            if any(isinstance(part, ast.Call) for part in ast.walk(node)):
                self.issue(node, "effectful assertion has optional execution")
        elif not isinstance(node, ast.Pass):
            self.issue(node, f"unsupported statement: {type(node).__name__}")
            state.approved.clear()
            state.pending.clear()
        return [state]


def analyze_function(
    source: str, contract: Contract, *, max_states: int = 512
) -> dict[str, Any]:
    """Check one named function under explicit trusted summary assumptions.

    `verified_under_contract` proves only the modelled dispatch property. Any
    unsupported construct, unknown call, missing site, or exhausted path budget
    prevents that status. No source is imported or executed.
    """
    if max_states < 1:
        raise ValueError("max_states must be positive")
    report: dict[str, Any] = {
        "function": contract.function,
        "max_states": max_states,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "assumptions": list(contract.assumptions),
        "trusted_calls": list(contract.trusted_calls),
        "authorizer_summaries": [
            {
                "target": item.target,
                "bindings": item.bindings,
                "decision": item.decision,
                "permission": item.permission,
            }
            for item in contract.authorizers
        ],
        "status": "unresolved",
        "operation_summaries": [
            {
                "target": item.target,
                "bindings": item.bindings,
                "permission": item.permission,
            }
            for item in contract.operations
        ],
        "operations": [],
        "issues": [],
    }
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        report["issues"] = [{"line": exc.lineno, "reason": "source does not parse"}]
        return report
    selected: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    def find(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if prefix + node.name == contract.function:
                    selected.append(node)
            elif isinstance(node, ast.ClassDef):
                find(node.body, prefix + node.name + ".")

    find(tree.body)
    if len(selected) != 1:
        report["issues"] = [{"line": 0, "reason": "function missing or ambiguous"}]
        return report
    analyzer = _Analyzer(contract, max_states)
    function = selected[0]
    analyzer.block(function.body, [_State()])
    # Syntax inventory prevents unreachable/unvisited sites being silently lost.
    inventory = {
        (node.lineno, node.col_offset, ast.unparse(node.func))
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and ast.unparse(node.func) in analyzer.operations
    }
    for key in sorted(inventory):
        evidence = analyzer.sites.get(key, [])
        status = (
            "unresolved"
            if analyzer.issues or not evidence
            else "verified_under_contract"
            if all(evidence)
            else "unverified"
        )
        report["operations"].append(
            {"line": key[0], "column": key[1], "target": key[2], "status": status}
        )
    for operation in contract.operations:
        if not any(key[2] == operation.target for key in inventory):
            analyzer.issues.add(
                (function.lineno, f"operation missing: {operation.target}")
            )
    report["issues"] = [
        {"line": line, "reason": reason} for line, reason in sorted(analyzer.issues)
    ]
    if (
        report["issues"]
        or not inventory
        or any(item["status"] == "unresolved" for item in report["operations"])
    ):
        report["status"] = "unresolved"
    elif all(
        item["status"] == "verified_under_contract" for item in report["operations"]
    ):
        report["status"] = "verified_under_contract"
    else:
        report["status"] = "unverified"
    return report


def _main() -> int:
    from langgraph.prebuilt.security._mediation_catalog import framework_report

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--check-claims",
        action="store_true",
        help="Gate only the enumerated dispatch claims, not overall completeness.",
    )
    args = parser.parse_args()
    report = framework_report(args.source_root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["claims_passed" if args.check_claims else "complete"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
