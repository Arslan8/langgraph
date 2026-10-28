"""Finite runtime operation catalog for the pandas application.

`docs/security/runtime-operations.json` lists every operation the runtime
exposes to the pandas application (advisor decisions D8 to D11). This module
loads the catalog and checks it against the current sources only:

- cited request classes exist in `security/objects.py`;
- cited router methods exist on `HostRouter` in `security/host_router.py`;
- cited functions and classes exist, found with `ast` (candidate code is never
  imported; only `security/unsupported.py` is imported for its registry);
- refusal codes are registered in `unsupported.REGISTRY` or `PREFIXES`, or are
  string literals in the cited source file;
- every supported route in `docs/security/supported-surface.json` maps only to
  catalogued operations, and every proof check id belongs to that route;
- every entry of `layered_verification.OPERATIONS` is mapped or excluded.

`complete` is true only when there are no issues and no operation is
`missing` or `in_progress` (in status or proof). The catalog is evidence for
readers; it is not wired into the route gate.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

CATALOG_PATH = "docs/security/runtime-operations.json"
SURFACE_PATH = "docs/security/supported-surface.json"
DESIGN_PATH = "eval/scope/pandas-route-design.md"
SOURCE_ROOT = "libs/prebuilt/langgraph/prebuilt"
_SECURITY = "security/"

STATUSES = frozenset({"implemented", "in_progress", "missing"})
PROOF_STATUSES = frozenset({"proved", "premise", "missing"})
TRUST_CLASSES = frozenset({"contained", "hooked", "proved-egress", "trusted-runtime"})
_PENDING = frozenset({"in_progress", "missing"})
_STEP = re.compile(r"^\|\s*([A-Z][0-9]+)\s*\|", re.MULTILINE)


def load_catalog(repo: Path) -> dict[str, Any]:
    """Return the parsed runtime operation catalog under `repo`."""
    return json.loads((Path(repo) / CATALOG_PATH).read_text(encoding="utf-8"))


class _Sources:
    """Parsed source files under the prebuilt package, cached per run."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._trees: dict[str, ast.Module | None] = {}

    def tree(self, relative: str) -> ast.Module | None:
        if relative not in self._trees:
            path = self.root / relative
            try:
                self._trees[relative] = ast.parse(
                    path.read_text(encoding="utf-8"), filename=str(path)
                )
            except (OSError, SyntaxError):
                self._trees[relative] = None
        return self._trees[relative]

    def resolve(self, citation: str) -> bool:
        """Whether `path::Qualified.name` names a top-level or nested definition."""
        relative, sep, qualname = citation.partition("::")
        if not sep or not qualname:
            return False
        tree = self.tree(relative)
        if tree is None:
            return False
        body: list[ast.stmt] = tree.body
        for part in qualname.split("."):
            found = next(
                (
                    node
                    for node in body
                    if isinstance(
                        node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                    )
                    and node.name == part
                ),
                None,
            )
            if found is None:
                return False
            body = found.body
        return True

    def literal(self, relative: str, value: str) -> bool:
        tree = self.tree(relative)
        if tree is None:
            return False
        return any(
            isinstance(node, ast.Constant) and node.value == value
            for node in ast.walk(tree)
        )


def _framework_operations(sources: _Sources) -> set[str] | None:
    """`layered_verification.OPERATIONS` read from source as `Class.op` names."""
    tree = sources.tree(_SECURITY + "layered_verification.py")
    if tree is None:
        return None
    for node in tree.body:
        target = (
            node.target
            if isinstance(node, ast.AnnAssign)
            else node.targets[0]
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            else None
        )
        if (
            isinstance(target, ast.Name)
            and target.id == "OPERATIONS"
            and node.value is not None
        ):
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                return None
            return {
                f"{name}.{operation}"
                for name, operations in value.items()
                for operation in operations
            }
    return None


def _registry() -> tuple[set[str], set[str]] | None:
    try:
        from langgraph.prebuilt.security import unsupported
    except Exception:
        return None
    return set(unsupported.REGISTRY), set(unsupported.PREFIXES)


def _registered(code: str, registry: tuple[set[str], set[str]]) -> bool:
    exact, prefixes = registry
    if code in exact or code in prefixes:
        return True
    return any(code.startswith(prefix) for prefix in prefixes)


def _check_refusal(
    where: str,
    code: Any,
    kind: str,
    source: Any,
    sources: _Sources,
    registry: tuple[set[str], set[str]] | None,
    issues: list[str],
) -> None:
    if type(code) is not str or not code:
        issues.append(f"{where}: refusal code must be a non-empty string")
        return
    if kind == "registered":
        if registry is None:
            issues.append(f"{where}: unsupported registry unavailable for {code}")
        elif not _registered(code, registry):
            issues.append(f"{where}: refusal code not registered: {code}")
    elif kind == "literal":
        if type(source) is not str or not sources.literal(source, code):
            issues.append(f"{where}: refusal literal {code} not found in {source}")
    else:
        issues.append(f"{where}: unknown refusal kind {kind!r} for {code}")


def verify_catalog(repo: Path, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check the catalog against the current sources; never trust saved results."""
    repo = Path(repo)
    if catalog is None:
        catalog = load_catalog(repo)
    sources = _Sources(repo / SOURCE_ROOT)
    issues: list[str] = []
    pending: list[str] = []
    registry = _registry()
    if registry is None:
        issues.append("security/unsupported.py could not be imported")

    surface = json.loads((repo / SURFACE_PATH).read_text(encoding="utf-8"))
    routes = {route["id"]: route for route in surface.get("routes", [])}
    supported = {rid for rid, route in routes.items() if route["status"] == "supported"}
    try:
        design = (repo / DESIGN_PATH).read_text(encoding="utf-8")
        steps = set(_STEP.findall(design))
    except OSError:
        steps = set()
        issues.append(f"{DESIGN_PATH} unreadable")

    objects = sources.tree(_SECURITY + "objects.py")
    request_classes = (
        {node.name for node in objects.body if isinstance(node, ast.ClassDef)}
        if objects is not None
        else set()
    )
    router_tree = sources.tree(_SECURITY + "host_router.py")
    router_class = (
        next(
            (
                node
                for node in router_tree.body
                if isinstance(node, ast.ClassDef) and node.name == "HostRouter"
            ),
            None,
        )
        if router_tree is not None
        else None
    )
    router_methods = (
        {
            node.name
            for node in router_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if router_class is not None
        else set()
    )
    if router_class is None:
        issues.append("HostRouter not found in security/host_router.py")

    operations = catalog.get("operations", [])
    ids = [op.get("id") for op in operations]
    if len(ids) != len(set(ids)):
        issues.append("duplicate operation ids")
    catalogued = set(ids)
    route_operations: dict[str, list[str]] = catalog.get("route_operations", {})
    summary: dict[str, dict[str, Any]] = {}
    mapped: set[str] = set()

    for op in operations:
        oid = op.get("id")
        where = f"operation {oid}"
        status = op.get("status")
        proof = op.get("proof") or {}
        in_progress = status in _PENDING
        if status not in STATUSES:
            issues.append(f"{where}: unknown status {status!r}")
        if proof.get("status") not in PROOF_STATUSES:
            issues.append(f"{where}: unknown proof status {proof.get('status')!r}")
        if op.get("trust") not in TRUST_CLASSES:
            issues.append(f"{where}: unknown trust class {op.get('trust')!r}")
        if status in _PENDING or proof.get("status") == "missing":
            pending.append(f"{where}: status {status}, proof {proof.get('status')}")

        for name in op.get("request_classes", []):
            if name not in request_classes:
                issues.append(f"{where}: request class {name} not in objects.py")
        for method in op.get("router_methods", []):
            if method not in router_methods:
                issues.append(f"{where}: HostRouter has no method {method}")
        citations = list(op.get("functions", []))
        shape_type = (op.get("request_shape") or {}).get("type")
        if shape_type:
            citations.append(shape_type)
        for citation in dict.fromkeys(citations):
            if not sources.resolve(citation):
                message = f"{where}: cited definition not found: {citation}"
                (pending if in_progress else issues).append(message)
        for refusal in op.get("refusals", []):
            _check_refusal(
                where,
                refusal.get("code"),
                refusal.get("kind", ""),
                refusal.get("source"),
                sources,
                registry,
                issues,
            )
        if not in_progress and not op.get("refusals"):
            issues.append(f"{where}: implemented operation lists no refusal")

        for rid in op.get("routes", []):
            if oid not in route_operations.get(rid, []):
                issues.append(f"{where}: route {rid} does not map back to it")
        if proof.get("status") == "proved":
            rid = proof.get("route")
            route = routes.get(rid)
            if route is None or rid not in supported:
                issues.append(f"{where}: proved on unsupported or unknown route {rid}")
            else:
                evidence = {
                    check
                    for obligation in route.get("obligations", {}).values()
                    if obligation.get("applicable")
                    for check in obligation.get("required_evidence", [])
                }
                for check in proof.get("checks", []):
                    if check not in evidence:
                        issues.append(f"{where}: check {check} not required by {rid}")
                if not proof.get("checks"):
                    issues.append(f"{where}: proved without check ids")
        for step in op.get("needed_by", []) + op.get("may_use", []):
            if step not in steps:
                issues.append(f"{where}: unknown pandas step {step}")
        mapped.update(op.get("framework_operations", []))
        summary[oid] = {"status": status, "proof": proof.get("status")}

    for rid, op_ids in route_operations.items():
        if rid not in routes:
            issues.append(f"route_operations: unknown route {rid}")
        for oid in op_ids:
            if oid not in catalogued:
                issues.append(f"route {rid} uses uncatalogued operation {oid}")
    unmapped_routes = catalog.get("unmapped_routes", {})
    for rid in sorted(supported):
        if rid not in route_operations:
            issues.append(f"supported route {rid} maps to no catalogued operation")
    for rid in unmapped_routes:
        if rid in supported:
            issues.append(f"supported route {rid} cannot be left unmapped")

    universe = _framework_operations(sources)
    excluded: set[str] = set()
    for entry in catalog.get("excluded", []):
        name = entry.get("operation")
        excluded.add(name)
        if not entry.get("reason"):
            issues.append(f"excluded {name}: missing reason")
        if entry.get("refusal") is not None:
            kind = "literal" if entry.get("refusal_source") else "registered"
            _check_refusal(
                f"excluded {name}",
                entry["refusal"],
                kind,
                entry.get("refusal_source"),
                sources,
                registry,
                issues,
            )
    if universe is None:
        issues.append("layered_verification.OPERATIONS not readable from source")
    else:
        for name in sorted(universe - mapped - excluded):
            issues.append(f"framework operation {name} neither mapped nor excluded")
        for name in sorted((mapped | excluded) - universe):
            issues.append(f"unknown framework operation {name}")
        for name in sorted(mapped & excluded):
            issues.append(f"framework operation {name} both mapped and excluded")

    return {
        "complete": not issues and not pending,
        "issues": issues,
        "pending": pending,
        "operations": summary,
        "gate_wired": False,
    }
