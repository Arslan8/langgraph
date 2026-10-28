"""Source-bound assurance report for ADR 0007's layered reference monitor.

The router has an executable source proof. Placement discovery is a syntactic
inventory, not a path-cover proof. Host MAC correctness is a premise; adapter
correctness is a separate obligation. Neither observed calls nor reviewed
waivers are promoted to system completeness.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.adapter_verification import check_adapters
from langgraph.prebuilt.security.admission_verification import (
    verify_admission_surface,
)
from langgraph.prebuilt.security.boundary_verification import verify_host_router
from langgraph.prebuilt.security.output_data_verification import (
    verify_output_data_primitives,
)
from langgraph.prebuilt.security.output_verification import verify_output_correspondence
from langgraph.prebuilt.security.publication_verification import verify_publications
from langgraph.prebuilt.security.taint import analyze_source, apply_waivers

# The protected operation universe is independent of which hooks exist today.
OPERATIONS: dict[str, tuple[str, ...]] = {
    "Principal": ("bind", "transfer", "attenuate"),
    "ToolCall": ("prepare", "invoke", "post"),
    "Dispatch": ("subgraph", "send", "parallel_branch", "subagent", "nested_agent"),
    "ToolRegistry": ("register", "override"),
    "State": (
        "write",
        "restore",
        "tool_read",
        "model_read",
        "store_read",
        "store_write",
        "checkpoint_read",
        "checkpoint_write",
    ),
    "Approval": ("resume",),
    "FrameworkOp": ("guard_operation",),
    "ModelInvocation": ("invoke",),
    "Output": ("emit",),
    "HostResource": ("file", "socket", "exec", "syscalls", "limits"),
}

_REQUESTS = {
    "DispatchRequest",
    "ToolRegistryRequest",
    "StateRequest",
    "ModelInvocationRequest",
    "OutputRequest",
}
_SECURITY = "libs/prebuilt/langgraph/prebuilt/security/"
_REQUIRED = (
    *(
        _SECURITY + name + ".py"
        for name in (
            "host_router",
            "host_boundary",
            "objects",
            "object_manager",
            "output_data",
            "stack",
            "config",
            "placement",
            "checkpoint_security",
            "guarded",
            "binding",
            "linux",
            "_linux_worker",
            "landlock",
            "cgroup",
        )
    ),
    "libs/prebuilt/langgraph/prebuilt/tool_node.py",
    "libs/langgraph/langgraph/graph/state.py",
    "libs/langgraph/langgraph/pregel/main.py",
)


class _Sites(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.scope: list[str] = []
        self.methods: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        self.methods.append(
            {"path": self.path, "line": node.lineno, "symbol": ".".join(self.scope)}
        )
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        target = ast.unparse(node.func)
        receiver = target.rsplit(".", 1)[0]
        kind = None
        if "router" in receiver or target.endswith(
            ("_output_filter", "_aoutput_filter")
        ):
            kind = "route_candidate"
        elif receiver in {
            "self.inner",
            "self._store",
            "self.runnable",
            "self.untrusted_host",
        }:
            kind = "effect_candidate"
        if kind is not None:
            self.calls.append(
                {
                    "path": self.path,
                    "line": node.lineno,
                    "function": ".".join(self.scope),
                    "target": target,
                    "kind": kind,
                }
            )
        self.generic_visit(node)


def inventory_sources(sources: dict[str, str]) -> dict[str, Any]:
    """Inventory supplied text without importing or executing candidate code.

    Calls are spelling-based candidates, including possible false positives.
    This does not resolve aliases, inheritance, callbacks, or path dominance.
    Unknown behavior therefore remains a placement obligation even with no
    candidate calls. The required input set prevents an empty-input success.
    """
    issues = [
        f"missing required source: {path}" for path in _REQUIRED if path not in sources
    ]
    digests = {}
    methods: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    objects: ast.Module | None = None
    for path, source in sorted(sources.items()):
        digests[path] = hashlib.sha256(source.encode()).hexdigest()
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            issues.append(f"unparsed source: {path}:{exc.lineno}")
            continue
        if path == _SECURITY + "objects.py":
            objects = tree
        # Index every supplied definition, including new files. A fixed list of
        # familiar adapter filenames must not become the coverage denominator.
        sites = _Sites(path)
        sites.visit(tree)
        methods.extend(sites.methods)
        calls.extend(sites.calls)
    if objects is not None:
        classes = {
            node.name: node for node in objects.body if isinstance(node, ast.ClassDef)
        }
        for enum, object_class in (
            ("DispatchKind", "Dispatch"),
            ("StateOperation", "State"),
        ):
            declaration = classes.get(enum)
            values = (
                {
                    node.value.value
                    for node in declaration.body
                    if isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                }
                if declaration
                else set()
            )
            if values != set(OPERATIONS[object_class]):
                issues.append(f"operation inventory differs: {enum}")
        requests = {name for name in classes if name.endswith("Request")}
        if requests != _REQUESTS:
            issues.append("framework request inventory differs")
    return {
        "issues": issues,
        "source_sha256": digests,
        "declared_methods": methods,
        "call_candidates": calls,
        "discovery_only": True,
        "path_cover_proved": False,
    }


def verify_layers(repo: Path) -> dict[str, Any]:
    """Recompute evidence; never accept a saved certificate as authority."""
    roots = [
        repo / "libs" / library / "langgraph"
        for library in ("prebuilt", "langgraph", "checkpoint")
    ]
    sources = {
        path.relative_to(repo).as_posix(): path.read_text(encoding="utf-8")
        for root in roots
        for path in sorted(root.rglob("*.py"))
    }
    inventory = inventory_sources(sources)
    adapters = check_adapters(sources)
    publications = verify_publications(sources)
    router = verify_host_router()
    output_correspondence = verify_output_correspondence(
        sources.get(_SECURITY + "object_manager.py", ""),
        sources.get(_SECURITY + "objects.py", ""),
        output_data_source=sources.get(_SECURITY + "output_data.py", ""),
    )
    output_data_primitives = verify_output_data_primitives(
        sources.get(_SECURITY + "output_data.py", ""),
        sources.get(_SECURITY + "objects.py", ""),
    )
    # Evidence only: the closed admission surface never changes `complete`,
    # `path_cover_proved` or any SGV diagnostic.
    admission_surface = verify_admission_surface(
        sources.get(_SECURITY + "admission.py", ""),
        sources.get(_SECURITY + "config.py", ""),
        sources.get(_SECURITY + "placement.py", ""),
        sources.get(_SECURITY + "mac.py", ""),
    )
    router_path = _SECURITY + "host_router.py"
    if (
        inventory["source_sha256"].get(router_path)
        != router["runtime_binding"]["source_sha256"]
    ):
        inventory["issues"].append("loaded router does not match audited repository")
    # The validator contract consumed by the host-output derivation must come
    # from the audited output_data.py, never from a differently supplied source.
    audited = inventory["source_sha256"].get(_SECURITY + "output_data.py")
    for component in (output_correspondence, output_data_primitives):
        derived = component["source_sha256"].get(
            "langgraph.prebuilt.security.output_data"
        )
        if derived is not None and derived != audited:
            inventory["issues"].append(
                "output validator derivation does not match audited repository"
            )
    escapes = analyze_source(
        repo / "libs/prebuilt/langgraph/prebuilt", repo / "libs/langgraph/langgraph"
    )
    waiver_path = repo / "docs/security/escape-waivers.json"
    disposition = apply_waivers(escapes, waiver_path)
    operations = [
        {
            "class": name,
            "operation": operation,
            "enforcement_layer": "host" if name == "HostResource" else "framework",
        }
        for name, values in OPERATIONS.items()
        for operation in values
    ]
    ledger = obligation_ledger(inventory, publications, router)
    return {
        "schema_version": 2,
        "complete": bool(
            router["complete"]
            and output_correspondence["proved"]
            and inventory["path_cover_proved"]
            and adapters["proof"]
            and publications["complete"]
            and adapters["checks_passed"]
            and not inventory["issues"]
            and not escapes.parse_errors
            and not disposition.errors
            and not disposition.unwaived
        ),
        "claim": "System completeness is not established by this report. Router proof and discovery evidence are separate.",
        "operations": operations,
        "router": router,
        "host_output_correspondence": output_correspondence,
        "output_data_primitives": output_data_primitives,
        "admission_surface": admission_surface,
        "placement": inventory,
        "adapters": adapters,
        "publications": publications,
        "obligations": ledger,
        "escape_discovery": {
            "findings": len(escapes.findings),
            "waived": len(disposition.waived),
            "unwaived": len(disposition.unwaived),
            "errors": [*escapes.parse_errors, *disposition.errors],
            "waiver_sha256": hashlib.sha256(waiver_path.read_bytes()).hexdigest()
            if waiver_path.is_file()
            else None,
            "waivers_are_proof": False,
            "unwaived_findings": [
                {
                    "fingerprint": finding.fingerprint,
                    "path": finding.path,
                    "line": finding.line,
                    "symbol": finding.symbol,
                    "message": finding.message,
                    "kind": finding.kind.value,
                }
                for finding in disposition.unwaived
            ],
        },
        "remaining_proof_obligations": [
            "Every protected effect reaches a refusing route, including inherited APIs, every supported input shape, callbacks, exceptional paths, and publication channels.",
            "Object policy and effects preserve authoritative identity, labels, transformations, approval bindings, and atomicity across each adapter.",
            "Untrusted workers have no coordinator capabilities and use authenticated object channels; node-host protocol conformance alone does not prove process isolation.",
            "Host adapters install exactly or tighter grants before execution and preserve confinement through cancellation and descendant lifetime. MAC/LSM correctness is assumed.",
        ],
        "summary": {
            "object_classes": len(OPERATIONS),
            "operations": len(operations),
            "router": router["summary"],
            "source_files": len(sources),
            "declared_api_obligations": len(ledger),
            "route_candidates": sum(
                site["kind"] == "route_candidate"
                for site in inventory["call_candidates"]
            ),
            "effect_candidates": sum(
                site["kind"] == "effect_candidate"
                for site in inventory["call_candidates"]
            ),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def obligation_ledger(
    inventory: dict[str, Any], publications: dict[str, Any], router: dict[str, Any]
) -> list[dict[str, Any]]:
    """Account for every declaration without promoting partial proofs.

    The ledger is a conservative superset of APIs, including private and nested
    functions. Imported/inherited surfaces additionally live in the transfer
    report; unresolved bases prevent its closure. A discovered declaration is
    never silently accepted because no spelling-based finding mentions it.
    """
    flows = {entry["entry"]: entry for entry in publications["entries"]}
    routed = {
        entry["entry"]: entry
        for entry in router.get("source_proof", {}).get("entries", [])
    }
    ledger = []
    for site in inventory["declared_methods"]:
        parts = list(Path(site["path"]).with_suffix("").parts[2:])
        if parts[-1] == "__init__":
            parts.pop()
        symbol = ".".join([*parts, site["symbol"]])
        source_hash = inventory["source_sha256"][site["path"]]
        flow = flows.get(symbol)
        route = routed.get(symbol)
        ledger.append(
            {
                **site,
                "qualified_symbol": symbol,
                "source_sha256": source_hash,
                "fingerprint": hashlib.sha256(
                    f"{site['path']}\0{site['symbol']}\0{source_hash}".encode()
                ).hexdigest(),
                "owner": "verifier",
                "status": "unresolved",
                "router_protocol": route["status"]
                if route and router["complete"]
                else "not_proved",
                "publication_transfer": flow["status"] if flow else "not_analyzed",
                "publication_model_closed": bool(publications["complete"]),
                "remaining": [
                    "placement and refusing-route dominance",
                    "authoritative principal/resource/label binding",
                    "effect and host composition",
                ],
            }
        )
    return ledger


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", type=Path, default=Path(__file__).resolve().parents[5]
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Compatibility alias; missing system proof now fails by default.",
    )
    args = parser.parse_args()
    report = verify_layers(args.repo.resolve())
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    invalid = (
        not report["router"]["complete"]
        or not report["adapters"]["checks_passed"]
        or report["placement"]["issues"]
        or report["escape_discovery"]["errors"]
        or report["escape_discovery"]["unwaived"]
    )
    return 1 if invalid or not report["complete"] else 0


if __name__ == "__main__":
    raise SystemExit(_main())
