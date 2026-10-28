"""Route evidence for the `dataset_read` runtime operation.

Claim: a dataset is read only by operator-pinned id, only after the policy
returns an exact unconstrained allow, only through the no-symlink pinned open,
and the returned bytes are exactly the bytes whose digest matched the pin. The
check derives the ordering from the source of `dataset_operation.py` and runs
fixed controls against the live module. Kernel `openat2` semantics and the
operator's registry are premises (docs/security/threat-model.md).
"""

from __future__ import annotations

import ast
import hashlib
import tempfile
from pathlib import Path
from typing import Any

PREMISES = (
    "Kernel openat2/RESOLVE_NO_SYMLINKS and descriptor semantics behave as documented.",
    "The dataset registry (ids, paths, digests, caps) is configured by the operator.",
    "The caller is trusted application code (D11); the authorize callable is the runtime's policy hook.",
)


def _function(
    tree: ast.Module, name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ):
            return node
    return None


def _calls(node: ast.AST) -> list[str]:
    return [ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)]


def _order_issues(function: ast.AST | None, name: str) -> list[str]:
    if function is None:
        return [f"{name} is missing"]
    issues = []
    body = [
        s
        for s in function.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]
    text = [ast.unparse(s) for s in body]
    try:
        prepare = next(
            i for i, t in enumerate(text) if t.startswith("entry, request = _prepare(")
        )
        ask = next(
            i
            for i, t in enumerate(text)
            if t == "decision = authorize(principal, request)"
        )
        allow = next(i for i, t in enumerate(text) if t == "_require_allow(decision)")
    except StopIteration:
        return [
            f"{name} does not prepare, ask the policy and require allow in sequence"
        ]
    if not prepare < ask < allow:
        issues.append(f"{name} does not ask the policy before requiring allow")
    reads = [
        i
        for i, s in enumerate(body)
        if "_read_pinned" in _calls(s) or "_read_pinned" in ast.unparse(s)
    ]
    if not reads or min(reads) <= allow:
        issues.append(f"{name} reads before the allow check")
    if not isinstance(body[-1], ast.Return) or "_read_pinned" not in ast.unparse(
        body[-1]
    ):
        issues.append(f"{name} does not return the pinned read")
    for statement in body[:allow]:
        for call in _calls(statement):
            if call in {"open", "os.open", "open_path_descriptor", "_read_pinned"}:
                issues.append(f"{name} opens a file before the allow check")
    return issues


def _source_issues(source: str) -> list[str]:
    tree = ast.parse(source)
    issues = []
    issues += _order_issues(_function(tree, "read_dataset"), "read_dataset")
    issues += _order_issues(_function(tree, "aread_dataset"), "aread_dataset")
    allow = _function(tree, "_require_allow")
    if (
        allow is None
        or ast.unparse(allow).count("Verdict.ALLOW") != 1
        or (
            "type(decision) is not Decision" not in ast.unparse(allow)
            or "decision.constraints != ()" not in ast.unparse(allow)
        )
    ):
        issues.append("_require_allow does not demand an exact unconstrained allow")
    pinned = _function(tree, "_read_pinned")
    if pinned is None:
        return [*issues, "_read_pinned is missing"]
    opens = [
        n
        for n in ast.walk(pinned)
        if isinstance(n, ast.Call)
        and ast.unparse(n.func) in {"open", "io.open", "pathlib.Path.open"}
    ]
    if opens:
        issues.append("_read_pinned uses a path open other than the pinned descriptor")
    pinned_opens = [
        n
        for n in ast.walk(pinned)
        if isinstance(n, ast.Call) and ast.unparse(n.func) == "open_path_descriptor"
    ]
    if not pinned_opens or any(
        not any(
            k.arg == "no_symlinks"
            and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in n.keywords
        )
        for n in pinned_opens
    ):
        issues.append(
            "_read_pinned does not open through open_path_descriptor(no_symlinks=True)"
        )
    tail = [ast.unparse(s) for s in pinned.body[-2:]]
    if not (
        len(tail) == 2
        and "hmac.compare_digest(hashlib.sha256(data).hexdigest(), entry.sha256)"
        in tail[0]
        and tail[1] == "return data"
    ):
        issues.append(
            "_read_pinned does not verify the digest of exactly the returned bytes"
        )
    callers = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name != "_read_pinned"
        and "_read_pinned" in ast.unparse(node)
    }
    if callers - {"read_dataset", "aread_dataset"}:
        issues.append(f"_read_pinned is reachable from {sorted(callers)}")
    return issues


def _controls() -> tuple[dict[str, Any], list[str]]:
    from langgraph.prebuilt.security import dataset_operation as op
    from langgraph.prebuilt.security.types import Decision, Principal, Verdict

    results: dict[str, Any] = {}
    issues = []
    principal = Principal("alice", frozenset(), frozenset(), session_id="s")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "sales.csv"
        data = b"month,total\n2026-01,10\n"
        path.write_bytes(data)
        entry = op.DatasetEntry(
            "sales", str(path), hashlib.sha256(data).hexdigest(), 1024
        )
        registry = op.DatasetRegistry((entry,))
        allow = lambda p, r: Decision(Verdict.ALLOW, "control:allow")  # noqa: E731
        deny = lambda p, r: Decision(Verdict.DENY, "control:deny")  # noqa: E731
        results["allowed_read_exact"] = (
            op.read_dataset(principal, "sales", registry=registry, authorize=allow)
            == data
        )
        opened = []
        original = op.open_path_descriptor
        op.open_path_descriptor = lambda *a, **k: opened.append(a) or original(*a, **k)
        try:
            try:
                op.read_dataset(principal, "sales", registry=registry, authorize=deny)
                results["deny_refused"] = False
            except op.UnsupportedFeatureError as exc:
                results["deny_refused"] = str(exc) == "dataset:denied"
            results["deny_opens"] = len(opened)
        finally:
            op.open_path_descriptor = original
        for name, dataset, reg in (
            ("unknown_refused", "missing", registry),
            (
                "changed_refused",
                "sales",
                op.DatasetRegistry(
                    (op.DatasetEntry("sales", str(path), "0" * 64, 1024),)
                ),
            ),
            (
                "oversize_refused",
                "sales",
                op.DatasetRegistry(
                    (op.DatasetEntry("sales", str(path), entry.sha256, 4),)
                ),
            ),
        ):
            try:
                op.read_dataset(principal, dataset, registry=reg, authorize=allow)
                results[name] = False
            except op.UnsupportedFeatureError:
                results[name] = True
    for key, value in results.items():
        if (key == "deny_opens" and value != 0) or (
            key != "deny_opens" and value is not True
        ):
            issues.append(f"control failed: {key}={value}")
    return results, issues


def verify_dataset_route(source: str) -> dict[str, Any]:
    """Check the dataset_read ordering in `source` and run the fixed controls."""
    report: dict[str, Any] = {
        "kind": "dataset-route",
        "schema_version": 1,
        "proved": False,
        "claim": "A dataset is read only by pinned id, only after an exact unconstrained policy allow, only through the no-symlink pinned open, and the returned bytes match the pinned digest.",
        "premises": list(PREMISES),
        "system_complete": False,
        "source_sha256": {
            "langgraph.prebuilt.security.dataset_operation": hashlib.sha256(
                source.encode()
            ).hexdigest()
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "issues": [],
    }
    try:
        report["issues"].extend(_source_issues(source))
    except SyntaxError as exc:
        report["issues"].append(f"unparsable source: {exc.lineno}")
        return report
    report["controls"], issues = _controls()
    report["issues"].extend(issues)
    report["proved"] = not report["issues"]
    return report
