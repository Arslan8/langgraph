"""Source-only regression checks for object-manager adapter obligations.

These checks detect specific structural violations. A clear check means that
its counter-pattern was not found, not that arbitrary Python paths are proved.
Candidate source is parsed, never imported or executed. Missing required
adapters and unresolved local delegation are reported rather than waived.
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_BASE = "libs/prebuilt/langgraph/prebuilt/security/"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    fix: str


RULES = (
    Rule(
        "SGV101",
        "Authorized result discarded",
        "Apply the effective authorized value to the real effect, or reject unsupported transformations before authorization. An assignment alone is not sufficient evidence of propagation.",
    ),
    Rule(
        "SGV102",
        "Object resume omits constructive DAC",
        "Run current object DAC and the full mandatory-policy chain on resume, before dispatch; approval cannot replace either check.",
    ),
    Rule(
        "SGV103",
        "Input shape can leave placement unchanged",
        "Normalize every supported state/model value shape before mediation, or reject unsupported shapes. Preserve no-op and non-model semantics explicitly.",
    ),
    Rule(
        "SGV104",
        "Completion callback receives raw graph output",
        "Mediate callback publication and use its effective result, including denial/redaction/escalation, before invoking the callback.",
    ),
    Rule(
        "SGV105",
        "State key omits invocation identity",
        "Bind authoritative state keys to graph/principal/session identity as well as channel, and use the same key on reads and writes.",
    ),
    Rule(
        "SGV106",
        "Checkpoint API delegates without a visible refusing route",
        "Mediate history and administrative effects, or enforce a separate explicit trusted-administrator admission boundary. A comment declaring trust is not admission.",
    ),
    Rule(
        "SGV107",
        "Backing-store read results returned directly",
        "Bind read authorization to authoritative backing values, owners, and labels, then return the effective read results. Authorizing an input GetOp with a placeholder value is insufficient.",
    ),
    Rule(
        "SGV108",
        "Checkpoint history yields unverified backing tuples",
        "Authenticate and principal-bind every history tuple and its pending writes before publication, and apply effective read values. Use non-consuming verification so history reads do not consume restore replay state.",
    ),
    Rule(
        "SGV190",
        "Required adapter source is unavailable or unresolved",
        "Restore the required source/method or update this check with a source-only regression test for the new boundary; do not mark missing analysis as passed.",
    ),
)
_RULES = {rule.id: rule for rule in RULES}


@dataclass(frozen=True)
class Diagnostic:
    rule: str
    path: str
    line: int
    symbol: str
    message: str
    evidence: str
    status: str = "failed"
    owner: str = "implementation"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        # Stable across line shifts, narrow to the exact structural evidence.
        identity = "\0".join((self.rule, self.path, self.symbol, self.evidence))
        value["fingerprint"] = hashlib.sha256(identity.encode()).hexdigest()
        value["fix"] = _RULES[self.rule].fix
        return value


def _nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Walk one executable scope without treating nested bodies as executed."""
    yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(
            child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            yield from _nodes(child)


def _call(node: ast.AST) -> ast.Call | None:
    if isinstance(node, ast.Await):
        node = node.value
    return node if isinstance(node, ast.Call) else None


def check_adapters(sources: dict[str, str]) -> dict[str, Any]:
    """Evaluate the shipped adapter regression rules on the supplied snapshot."""
    diagnostics: list[Diagnostic] = []
    classes: dict[str, tuple[str, ast.ClassDef]] = {}
    required = {
        _BASE + "object_manager.py": (
            "MediatedStore",
            "ObjectManagerPolicy",
            "ObjectManagerHost",
        ),
        _BASE + "checkpoint_security.py": ("MediatedCheckpointer",),
        _BASE + "placement.py": ("MediatedNode",),
        _BASE + "host_boundary.py": ("StackBoundaryPolicy",),
        "libs/langgraph/langgraph/pregel/main.py": ("Pregel",),
    }

    def emit(
        rule: str,
        path: str,
        node: ast.AST,
        symbol: str,
        message: str,
        *,
        unresolved: bool = False,
    ) -> None:
        diagnostics.append(
            Diagnostic(
                rule,
                path,
                getattr(node, "lineno", 1),
                symbol,
                message,
                ast.dump(node, include_attributes=False),
                "unresolved" if unresolved else "failed",
                "verifier" if unresolved else "implementation",
            )
        )

    for path, names in required.items():
        try:
            tree = ast.parse(sources[path], filename=path)
        except (KeyError, SyntaxError) as exc:
            emit(
                "SGV190",
                path,
                ast.Module(body=[], type_ignores=[]),
                "<module>",
                f"Cannot check required source: {type(exc).__name__}",
                unresolved=True,
            )
            continue
        found = {
            node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
        }
        for name in names:
            if name not in found:
                emit(
                    "SGV190",
                    path,
                    tree,
                    name,
                    "Required class missing",
                    unresolved=True,
                )
            else:
                classes[name] = (path, found[name])

    def method(
        owner: str, name: str, seen: frozenset[str] = frozenset()
    ) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if owner not in classes or owner in seen:
            return None
        path, cls = classes[owner]
        definitions = [
            node
            for node in cls.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        if len(definitions) == 1:
            return path, definitions[0]
        if definitions:
            return None
        # Only the ordinary single source base used by these adapters is modeled.
        if len(cls.bases) == 1 and isinstance(cls.bases[0], ast.Name):
            return method(cls.bases[0].id, name, seen | {owner})
        return None

    def reachable_calls(
        owner: str, name: str, seen: frozenset[str] = frozenset()
    ) -> tuple[set[str], bool]:
        resolved = method(owner, name)
        if resolved is None or name in seen:
            return set(), False
        targets: set[str] = set()
        resolved_all = True
        for node in _nodes(resolved[1]):
            if not isinstance(node, ast.Call):
                continue
            target = ast.unparse(node.func)
            targets.add(target)
            if (
                target.startswith("self.")
                and target.count(".") == 1
                and target != "self._dac"
            ):
                children, known = reachable_calls(
                    owner, target.split(".")[1], seen | {name}
                )
                targets.update(children)
                resolved_all &= known
        return targets, resolved_all

    required_methods = {
        "MediatedStore": ("batch", "abatch", "_authorize"),
        "MediatedCheckpointer": (
            "get_tuple",
            "aget_tuple",
            "list",
            "alist",
            "put",
            "aput",
            "put_writes",
            "aput_writes",
            "_metadata",
            "_ametadata",
            "_verify",
            "_averify",
        ),
        "ObjectManagerPolicy": ("object_permission", "aobject_permission", "_dac"),
        "ObjectManagerHost": ("_state_operation",),
        "Pregel": ("stream", "astream"),
    }
    for owner, names in required_methods.items():
        if owner not in classes:
            continue
        for name in names:
            # Overloads are inventory declarations; the final implementation is
            # checked by the publication walk rather than this local resolver.
            if owner == "Pregel":
                present = any(
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == name
                    for node in classes[owner][1].body
                )
            else:
                present = method(owner, name) is not None
            if not present:
                emit(
                    "SGV190",
                    classes[owner][0],
                    classes[owner][1],
                    f"{owner}.{name}",
                    "Required method missing or ambiguous",
                    unresolved=True,
                )

    # Discarding a value-returning authorization defeats effective-value binding.
    for owner in ("MediatedStore", "MediatedCheckpointer"):
        if owner not in classes:
            continue
        path, cls = classes[owner]
        for member in cls.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in _nodes(member):
                call = _call(node.value) if isinstance(node, ast.Expr) else None
                if call is not None and ast.unparse(call.func) in {
                    "self.router.state",
                    "self.router.astate",
                    "self._router.state",
                    "self._router.astate",
                    "self._authorize",
                }:
                    emit(
                        "SGV101",
                        path,
                        node,
                        f"{owner}.{member.name}",
                        "The effective authorization result is discarded.",
                    )

    for name in ("object_resume_permission", "aobject_resume_permission"):
        resolved = method("ObjectManagerPolicy", name)
        if resolved is None:
            path = _BASE + "object_manager.py"
            emit(
                "SGV190",
                path,
                ast.Pass(),
                f"ObjectManagerPolicy.{name}",
                "Cannot resolve resume implementation",
                unresolved=True,
            )
            continue
        calls, known = reachable_calls("ObjectManagerPolicy", name)
        if "self._dac" not in calls:
            emit(
                "SGV102",
                *resolved,
                f"ObjectManagerPolicy.{name}",
                "No object DAC call is reachable through the resolved local resume chain.",
                unresolved=not known,
            )

    for name, value in (
        ("_model_input", "value"),
        ("_amodel_input", "value"),
        ("_state_writes", "result"),
        ("_astate_writes", "result"),
    ):
        resolved = method("MediatedNode", name)
        if resolved is None:
            emit(
                "SGV190",
                _BASE + "placement.py",
                ast.Pass(),
                f"MediatedNode.{name}",
                "Cannot resolve placement method",
                unresolved=True,
            )
            continue
        path, fn = resolved
        # Review patterns, not a symbolic path proof. Restrict model findings to
        # the known non-mapping early exit; non-model nodes may pass through.
        candidates: list[ast.Return] = []
        if value == "value":
            for node in _nodes(fn):
                if (
                    isinstance(node, ast.If)
                    and isinstance(node.test, ast.BoolOp)
                    and isinstance(node.test.op, ast.Or)
                ):
                    if any(
                        ast.unparse(part) == "not isinstance(value, Mapping)"
                        for part in node.test.values
                    ):
                        candidates.extend(
                            child
                            for statement in node.body
                            for child in _nodes(statement)
                            if isinstance(child, ast.Return)
                        )
        elif fn.body and isinstance(fn.body[-1], ast.Return):
            candidates.append(fn.body[-1])
        for node in candidates:
            if isinstance(node.value, ast.Name) and node.value.id == value:
                emit(
                    "SGV103",
                    path,
                    node,
                    f"MediatedNode.{name}",
                    "A supported non-mapping input/update shape needs a refusing route or an explicit rejection.",
                )

    if "Pregel" in classes:
        path, cls = classes["Pregel"]
        for member in cls.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in _nodes(member):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "on_chain_end"
                    and any(ast.unparse(arg) == "loop.output" for arg in node.args)
                ):
                    emit(
                        "SGV104",
                        path,
                        node,
                        f"Pregel.{member.name}",
                        "Callback publication uses raw loop.output independently of the final stream filter.",
                    )

    if "ObjectManagerHost" in classes:
        path, cls = classes["ObjectManagerHost"]
        for node in ast.walk(cls):
            key = None
            if (
                isinstance(node, ast.Subscript)
                and ast.unparse(node.value) == "self._state"
            ):
                key = node.slice
            elif (
                isinstance(node, ast.Call)
                and ast.unparse(node.func) == "self._state.get"
                and node.args
            ):
                key = node.args[0]
            if key is not None and ast.unparse(key) == "request.resource":
                emit(
                    "SGV105",
                    path,
                    node,
                    "ObjectManagerHost._state",
                    "Channel-only key does not identify the principal/session owning state.",
                )

    if "MediatedCheckpointer" in classes:
        path, cls = classes["MediatedCheckpointer"]
        for member in cls.body:
            if (
                not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                or member.name.startswith("_")
                or member.name in {"get_next_version", "config_specs"}
            ):
                continue
            calls, known = reachable_calls("MediatedCheckpointer", member.name)
            effects = sorted(
                target for target in calls if target.startswith("self.inner.")
            )
            if effects and not any(
                target.startswith("self.router.") for target in calls
            ):
                emit(
                    "SGV106",
                    path,
                    member,
                    f"MediatedCheckpointer.{member.name}",
                    "Backing effects have no visible router call in the local helper chain: "
                    + ", ".join(effects),
                    unresolved=not known,
                )

    # Narrow review patterns: routing query arguments does not establish that
    # the backing results are authenticated or transformed. Indirect returns
    # still require the separate, unfinished composition proof.
    for owner in ("MediatedStore", "MediatedCheckpointer"):
        if owner not in classes:
            continue
        path, cls = classes[owner]
        for member in cls.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in _nodes(member):
                if owner == "MediatedStore" and isinstance(node, ast.Return):
                    call = _call(node.value) if node.value is not None else None
                    if call is not None and ast.unparse(call.func) in {
                        "self._store.batch",
                        "self._store.abatch",
                    }:
                        emit(
                            "SGV107",
                            path,
                            node,
                            f"{owner}.{member.name}",
                            "Backing batch results are returned directly; effective read values and backing ownership need mediation.",
                        )
                if owner != "MediatedCheckpointer":
                    continue
                if isinstance(node, ast.YieldFrom):
                    call = _call(node.value)
                    if call is not None and ast.unparse(call.func) == "self.inner.list":
                        emit(
                            "SGV108",
                            path,
                            node,
                            f"{owner}.{member.name}",
                            "History delegates raw tuples after authorizing query options only.",
                        )
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    call = _call(node.iter)
                    if call is None or ast.unparse(call.func) not in {
                        "self.inner.list",
                        "self.inner.alist",
                    }:
                        continue
                    for statement in node.body:
                        for child in _nodes(statement):
                            if (
                                isinstance(child, ast.Yield)
                                and isinstance(child.value, ast.Name)
                                and isinstance(node.target, ast.Name)
                                and child.value.id == node.target.id
                            ):
                                emit(
                                    "SGV108",
                                    path,
                                    child,
                                    f"{owner}.{member.name}",
                                    "History yields the backing tuple directly without per-tuple verification.",
                                )

    serialized = sorted(
        (item.to_dict() for item in diagnostics),
        key=lambda item: (item["rule"], item["path"], item["line"], item["symbol"]),
    )
    return {
        "schema_version": 1,
        "checks_passed": not serialized,
        "proof": False,
        "scope": "Source-only review-pattern regression checks; no claim of complete path coverage or dataflow correctness.",
        "rules": [asdict(rule) for rule in RULES],
        "diagnostics": serialized,
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
