"""Source-only adapter publication obligations using the transfer engine.

This checks effective-result propagation under explicit router contracts. It
does not establish ownership, integrity, acquisition authorization or placement.
Unknown source behavior blocks the proof, including missing inherited APIs.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import replace
from importlib.util import resolve_name
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.verification import (
    ReadSource,
    Requirement,
    VerificationSpec,
    verify,
)

_PREFIX = "langgraph.prebuilt.security."
SURFACES = (
    _PREFIX + "object_manager.MediatedStore",
    _PREFIX + "checkpoint_security.MediatedCheckpointer",
    _PREFIX + "placement.OutputMediator",
)


def publication_spec(sources: dict[str, str]) -> VerificationSpec:
    """Use explicit boundary contracts, never trust ordinary helper functions.

    Sources use Python module names. Acquisition is opaque only for the narrow
    publication property; it is not certified as an authorized read or write.
    """
    reads = []
    asynchronous = []
    for surface, backing, methods in (
        (SURFACES[0], "_store", ("batch", "abatch")),
        (SURFACES[1], "inner", ("get_tuple", "aget_tuple", "list", "alist")),
    ):
        for method in methods:
            target = f"{surface}.{backing}.{method}"
            reads.append(ReadSource(target))
            if method.startswith("a"):
                asynchronous.append(target)
    return VerificationSpec(
        sources=sources,
        surfaces=SURFACES,
        # Do not pretend HostRouter.state/output_emit are refusing-return
        # authorizers: they can return an ESCALATE ObjectAuthorization. Until
        # receiver binding and that result protocol are modeled, calls remain
        # unresolved. Merely spelling a call "router" cannot grant evidence.
        authorizers=(),
        operations=(),
        read_sources=tuple(reads),
        async_terminals=tuple(asynchronous),
        return_requirements=(Requirement("routed_result", ("result:",)),),
        # This proof is about protected data propagation, not authorization of
        # publishing an absence marker or constructor completion. All calls and
        # effects are still analyzed; other composition obligations stay open.
        allow_none_return=True,
        max_steps=5_000,
        max_paths=64,
        max_depth=16,
    )


def verify_publications(sources: dict[str, str]) -> dict[str, Any]:
    """Analyze the supplied repository snapshot without importing its modules."""
    modules = {}
    issues = []
    packages = []
    for path, source in sorted(sources.items()):
        parts = Path(path).with_suffix("").parts
        if len(parts) < 4 or parts[0] != "libs" or parts[2] != "langgraph":
            issues.append(f"unrecognized source root: {path}")
            continue
        relative = list(parts[2:])
        package = relative[-1] == "__init__"
        if package:
            relative.pop()
        module = ".".join(relative)
        if module in modules:
            issues.append(f"duplicate source module: {module}")
        modules[module] = source
        if package:
            packages.append(module)
    if not modules:
        return {"complete": False, "issues": ["no source modules"], "entries": []}
    # Close over statically named imports and package initializers. Dynamic
    # imports are not guessed: the transfer engine marks them unresolved.
    pending = [surface.rsplit(".", 1)[0] for surface in SURFACES]
    selected: dict[str, str] = {}
    while pending:
        name = pending.pop()
        if name in selected or name not in modules:
            continue
        selected[name] = modules[name]
        parent = name.rpartition(".")[0]
        if parent:
            pending.append(parent)
        try:
            tree = ast.parse(modules[name])
        except SyntaxError:
            continue  # The transfer engine reports the original parse error.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                pending.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    try:
                        module = resolve_name(
                            "." * node.level + module,
                            name if name in packages else parent,
                        )
                    except (ImportError, ValueError):
                        continue  # The engine diagnoses invalid relative imports.
                pending.append(module)
                pending.extend(f"{module}.{alias.name}" for alias in node.names)
    if not selected:
        return {
            "complete": False,
            "issues": ["required adapter modules missing"],
            "entries": [],
        }
    spec = replace(
        publication_spec(selected),
        package_modules=tuple(name for name in packages if name in selected),
    )
    proof = verify(spec)
    return {
        "complete": proof["complete"] and not issues,
        "scope": "Effective-return obligations, not adapter or system completeness. Backing acquisition is opaque for this property only. Unmodeled router receivers/results remain unresolved, including escalation; no routed-value grant is assumed.",
        "issues": issues,
        "proof": proof,
        "entries": proof["entries"],
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
