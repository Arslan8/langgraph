"""Conservative, source-only capability checks for open-class tool manifests.

This checks declared effects, not runtime enforcement or return classifications.
Operation models are trusted API contracts; unsupported source stays unknown.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from langgraph.prebuilt.security.object_policy import SecurityManifest

_TEMPLATE = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Keep literals and argument references distinct, even for literal '@{path}'.
_Value = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ManifestOperation:
    """Reviewed terminal API with one resource argument and a fixed operation.

    `target` is the fully qualified imported name (or an explicitly trusted
    global name). `parameter` and `position` identify the same resource argument.
    The contract assumes other arguments and the return value are inert data,
    with no additional effects, callbacks, or delayed execution.
    """

    target: str
    class_name: str
    operation: str
    parameter: str
    position: int = 0

    def __post_init__(self) -> None:
        if (
            not self.target
            or not all(part.isidentifier() for part in self.target.split("."))
            or not self.parameter.isidentifier()
            or type(self.position) is not int
            or self.position < 0
        ):
            raise ValueError("invalid operation target or resource argument")


def _literal(value: str) -> _Value:
    return (("literal", value),) if value else ()


def _join(parts: list[_Value]) -> _Value:
    result: list[tuple[str, str]] = []
    for part in parts:
        for kind, value in part:
            if result and kind == result[-1][0] == "literal":
                result[-1] = (kind, result[-1][1] + value)
            else:
                result.append((kind, value))
    return tuple(result)


def _pattern(pattern: str, selected: dict[str, str]) -> _Value:
    parts: list[_Value] = []
    start = 0
    for match in _TEMPLATE.finditer(pattern):
        parts.append(_literal(pattern[start : match.start()]))
        name = match[1]
        parts.append(
            _literal(selected[name]) if name in selected else (("argument", name),)
        )
        start = match.end()
    parts.append(_literal(pattern[start:]))
    return _join(parts)


def check_manifest_consistency(
    source: str,
    manifest: SecurityManifest,
    *,
    tool_name: str,
    function: str | None = None,
    operations: tuple[ManifestOperation, ...] = (),
) -> dict[str, Any]:
    """Compare a top-level Python function's effects with its parsed manifest.

    Source is never imported or executed. Supports straight-line expressions,
    local aliases, and branches on the manifest's closed operation selector.
    Unused declarations are reported but do not invalidate capability coverage.
    Unknown calls, control flow, or resource values prevent a consistent result.
    Input values must be inert strings; module initialization, decorators,
    normalizer equivalence, `runs`, `returns`, and enforcement are outside scope.
    """
    tool = manifest.tools[tool_name]
    models = {item.target: item for item in operations}
    if len(models) != len(operations):
        raise ValueError("operation targets must be unique")
    for model in operations:
        cls = manifest.registry.classes.get(model.class_name)
        if cls is None or model.operation not in cls.operations:
            raise ValueError(
                f"unknown modeled operation: {model.class_name}::{model.operation}"
            )
    issues: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    used: set[int] = set()

    def issue(node: ast.AST, kind: str, reason: str) -> None:
        item = {"line": getattr(node, "lineno", 0), "kind": kind, "reason": reason}
        if item not in issues:
            issues.append(item)

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        tree = ast.Module(body=[], type_ignores=[])
        issues.append({"line": exc.lineno, "kind": "unknown", "reason": str(exc)})
    entries = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == (function or tool_name)
    ]
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    if len(entries) != 1:
        issue(tree, "unknown", "expected exactly one top-level entry function")
    else:
        entry = entries[0]
        parameters = {
            arg.arg
            for arg in (
                *entry.args.posonlyargs,
                *entry.args.args,
                *entry.args.kwonlyargs,
            )
        }
        if entry.args.vararg or entry.args.kwarg:
            issue(entry, "unknown", "variadic entry arguments are unsupported")
        for rule in tool.rules:
            names = set(_TEMPLATE.findall(rule.pattern))
            if rule.selector_arg:
                names.add(rule.selector_arg)
            for name in sorted(names - parameters):
                issue(entry, "mismatch", f"manifest refers to missing argument: {name}")
        selectors = sorted(
            {
                (rule.selector_arg, rule.selector_value)
                for rule in tool.rules
                if rule.selector_arg is not None and rule.selector_value is not None
            }
        )
        cases = [dict([pair]) for pair in selectors] or [{}]
        for selected in cases:
            env: dict[str, _Value | None] = {
                name: _literal(selected[name])
                if name in selected
                else (("argument", name),)
                for name in parameters
            }
            # Python assignments make a name local throughout the function.
            locals_ = parameters | {
                node.id
                for node in ast.walk(entry)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            }
            active = [
                (index, rule)
                for index, rule in enumerate(tool.rules)
                if rule.selector_arg is None
                or selected.get(rule.selector_arg) == rule.selector_value
            ]

            def expression(node: ast.AST) -> _Value | None:
                if isinstance(node, ast.Constant):
                    return _literal(node.value) if isinstance(node.value, str) else None
                if isinstance(node, ast.Name) and node.id in env:
                    return env[node.id]
                if isinstance(node, ast.JoinedStr):
                    values = []
                    for value in node.values:
                        if isinstance(value, ast.FormattedValue):
                            if value.conversion != -1 or value.format_spec is not None:
                                issue(
                                    value,
                                    "unknown",
                                    "formatted conversions are unsupported",
                                )
                                return None
                            value = value.value
                        resolved = expression(value)
                        if resolved is None:
                            return None
                        values.append(resolved)
                    return _join(values)
                if isinstance(node, ast.Call):
                    target = ast.unparse(node.func)
                    root, dot, rest = target.partition(".")
                    target = aliases.get(root, root) + (dot + rest if dot else "")
                    values = [expression(arg) for arg in node.args]
                    keywords = {kw.arg: expression(kw.value) for kw in node.keywords}
                    model = models.get(target) if root not in locals_ else None
                    if model is None:
                        issue(node, "unknown", f"unmodeled call: {target}")
                        return None
                    if None in keywords or any(
                        isinstance(arg, ast.Starred) for arg in node.args
                    ):
                        issue(
                            node, "unknown", "expanded call arguments are unsupported"
                        )
                        return None
                    resource = keywords.get(model.parameter)
                    if model.position < len(values):
                        if model.parameter in keywords:
                            issue(node, "unknown", "duplicate resource argument")
                            return None
                        resource = values[model.position]
                    if resource is None:
                        issue(node, "unknown", f"unresolved resource for {target}")
                        return None
                    matches = [
                        index
                        for index, rule in active
                        if rule.class_name == model.class_name
                        and rule.operation == model.operation
                        and _pattern(rule.pattern, selected) == resource
                    ]
                    observed.append(
                        {
                            "line": node.lineno,
                            "target": target,
                            "class_name": model.class_name,
                            "operation": model.operation,
                            "resource": resource,
                            "selector": selected,
                            "rules": matches,
                        }
                    )
                    used.update(matches)
                    if not matches:
                        issue(
                            node,
                            "mismatch",
                            f"undeclared effect or resource: {model.class_name}::{model.operation}",
                        )
                    return None
                issue(node, "unknown", f"unsupported expression: {type(node).__name__}")
                return None

            def statements(body: list[ast.stmt]) -> bool:
                for node in body:
                    if isinstance(node, ast.Return):
                        if node.value:
                            expression(node.value)
                        return True
                    if isinstance(node, ast.Expr):
                        expression(node.value)
                    elif isinstance(node, ast.Assign) and all(
                        isinstance(t, ast.Name) for t in node.targets
                    ):
                        value = expression(node.value)
                        for target in node.targets:
                            assert isinstance(target, ast.Name)
                            env[target.id] = value
                    elif isinstance(node, ast.If):
                        test = node.test
                        if (
                            isinstance(test, ast.Compare)
                            and len(test.ops) == 1
                            and isinstance(test.ops[0], (ast.Eq, ast.NotEq))
                            and isinstance(test.left, ast.Name)
                            and test.left.id in selected
                            and env.get(test.left.id)
                            == _literal(selected[test.left.id])
                            and isinstance(test.comparators[0], ast.Constant)
                            and isinstance(test.comparators[0].value, str)
                        ):
                            equal = selected[test.left.id] == test.comparators[0].value
                            taken = (
                                equal if isinstance(test.ops[0], ast.Eq) else not equal
                            )
                            if statements(node.body if taken else node.orelse):
                                return True
                        else:
                            issue(
                                node,
                                "unknown",
                                "branch is not a closed manifest selector comparison",
                            )
                    elif isinstance(node, ast.Pass):
                        continue
                    else:
                        issue(
                            node,
                            "unknown",
                            f"unsupported statement: {type(node).__name__}",
                        )
                return False

            statements(entry.body)
    status = (
        "mismatch"
        if any(i["kind"] == "mismatch" for i in issues)
        else "unknown"
        if issues
        else "consistent"
    )
    return {
        "schema_version": 1,
        "tool": tool_name,
        "status": status,
        "consistent": status == "consistent",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "issues": issues,
        "observed": observed,
        "unused_rules": [
            index for index in range(len(tool.rules)) if index not in used
        ],
        "scope": "Declared capability coverage under reviewed terminal models and inert string inputs; excludes module initialization, decorators, run locus, return classification, normalization equivalence, and runtime enforcement.",
    }


def _main() -> int:
    import argparse
    import json
    from pathlib import Path

    from langgraph.prebuilt.security.object_policy import parse_security_manifest

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--function")
    parser.add_argument(
        "--operations", type=Path, help="JSON array of reviewed API models"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        models = (
            tuple(
                ManifestOperation(**item)
                for item in json.loads(args.operations.read_text())
            )
            if args.operations
            else ()
        )
        report = check_manifest_consistency(
            args.source.read_text(encoding="utf-8"),
            parse_security_manifest(args.manifest.read_text(encoding="utf-8")),
            tool_name=args.tool,
            function=args.function,
            operations=models,
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = {
            "consistent": False,
            "status": "unknown",
            "issues": [{"reason": str(exc)}],
        }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["consistent"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
