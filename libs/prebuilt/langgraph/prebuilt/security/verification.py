"""Interprocedural authorization verification over a closed Python source universe.

Sources are parsed, never imported. Unknown behavior prevents verification.
Only terminal policy/dispatch contracts are trusted; helper bodies are analyzed.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import copy
import hashlib
import inspect
import json
import operator
import sys
import warnings
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from importlib.util import resolve_name
from pathlib import Path
from types import ModuleType
from typing import Any

from langgraph.prebuilt.security.mediation import Authorizer, Operation

_Function = ast.FunctionDef | ast.AsyncFunctionDef
_VERDICTS = frozenset({"ALLOW", "DENY", "ESCALATE", "TRANSFORM", "REDACT"})
_TYPE_CHECKING_NAMES = frozenset(
    {"typing.TYPE_CHECKING", "typing_extensions.TYPE_CHECKING"}
)
_CAST_NAMES = frozenset({"typing.cast", "typing_extensions.cast"})
# These are isinstance relationships, including the standard virtual ABC
# registrations. They do not authorize calls to methods on an unknown value.
_TYPE_BASES: dict[str, tuple[str, ...]] = {
    "object": (),
    "bool": ("int",),
    "int": ("object",),
    "float": ("object",),
    "complex": ("object",),
    "str": ("collections.abc.Sequence",),
    "bytes": ("collections.abc.Sequence",),
    "list": ("collections.abc.Sequence",),
    "tuple": ("collections.abc.Sequence",),
    "dict": ("collections.abc.MutableMapping",),
    "frozenset": ("collections.abc.Set",),
    "types.MappingProxyType": ("collections.abc.Mapping",),
    "types.NoneType": ("object",),
    "collections.abc.MutableMapping": ("collections.abc.Mapping",),
    "collections.abc.Mapping": ("object",),
    "collections.abc.Sequence": ("object",),
    "collections.abc.Set": ("object",),
    "BaseException": ("object",),
    "Exception": ("BaseException",),
    "OSError": ("Exception",),
    "PermissionError": ("OSError",),
    "TimeoutError": ("OSError",),
    "ValueError": ("Exception",),
    "RuntimeError": ("Exception",),
    "NotImplementedError": ("RuntimeError",),
    "TypeError": ("Exception",),
    "LookupError": ("Exception",),
    "KeyError": ("LookupError",),
}


@dataclass(frozen=True)
class Requirement:
    """One additional authorization domain required at a terminal dispatch."""

    permission: str
    bindings: tuple[str, ...]


def _valid_selector(selector: str, *, result: bool) -> bool:
    kind, colon, path = selector.partition(":")
    parts = path.split(".")
    if not colon:
        return False
    if kind == "arg":
        return parts[0].isdigit() and all(part.isidentifier() for part in parts[1:])
    return (
        result
        and kind == "result"
        and (not path or all(part.isidentifier() for part in parts))
    )


@dataclass(frozen=True)
class VerificationSpec:
    """Sources, root tool classes and trusted terminals; no helper exemptions.

    Module names map to source text. Every method of a surface and its source
    descendants is an entry point, including inherited and private methods.
    """

    sources: dict[str, str]
    surfaces: tuple[str, ...]
    authorizers: tuple[Authorizer, ...]
    operations: tuple[Operation, ...]
    async_terminals: tuple[str, ...] = ()
    terminal_parameters: dict[str, tuple[str, ...]] = field(default_factory=dict)
    requirements: dict[str, tuple[Requirement, ...]] = field(default_factory=dict)
    max_steps: int = 100_000
    max_paths: int = 512
    max_depth: int = 32
    package_modules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.sources or not self.surfaces or not self.operations:
            raise ValueError("sources, surfaces and operations are required")
        if min(self.max_steps, self.max_paths, self.max_depth) < 1:
            raise ValueError("analysis budgets must be positive")
        if (
            len(set(self.package_modules)) != len(self.package_modules)
            or set(self.package_modules) - self.sources.keys()
        ):
            raise ValueError("package modules must uniquely name supplied sources")
        terminals: tuple[Authorizer | Operation, ...] = (
            *self.authorizers,
            *self.operations,
        )
        if len({item.target for item in terminals}) != len(terminals):
            raise ValueError("terminal targets must be distinct")
        if set(self.async_terminals) - {item.target for item in terminals}:
            raise ValueError("async terminals must name declared terminal contracts")
        if set(self.terminal_parameters) - {item.target for item in terminals}:
            raise ValueError("terminal parameter models must name declared terminals")
        if any(
            not names
            or len(set(names)) != len(names)
            or not all(name.isidentifier() for name in names)
            for names in self.terminal_parameters.values()
        ):
            raise ValueError("terminal parameter names must be nonempty and unique")
        for item in terminals:
            if not item.bindings or not item.permission or not item.target:
                raise ValueError("terminal contracts must be nonempty")
            if any(
                not _valid_selector(selector, result=isinstance(item, Authorizer))
                for selector in item.bindings
            ):
                raise ValueError("bindings must use explicit argument/result selectors")
        operation_map = {item.target: item for item in self.operations}
        if set(self.requirements) - operation_map.keys():
            raise ValueError("requirements must name declared operation targets")
        for target, requirements in self.requirements.items():
            domains = [operation_map[target].permission]
            for requirement in requirements:
                if (
                    not requirement.permission
                    or not requirement.bindings
                    or any(
                        not _valid_selector(selector, result=False)
                        for selector in requirement.bindings
                    )
                ):
                    raise ValueError("invalid dispatch requirement")
                domains.append(requirement.permission)
            if len(set(domains)) != len(domains):
                raise ValueError("dispatch permission domains must be distinct")
        if any(
            item.decision
            and not all(part.isidentifier() for part in item.decision.split("."))
            for item in self.authorizers
        ):
            raise ValueError("authorizer decision selectors must be attribute paths")


@dataclass
class _MappingTail:
    origin: str
    absent: set[str] = field(default_factory=set)


@dataclass
class _State:
    env: dict[str, str] = field(default_factory=dict)
    pending: dict[str, tuple[str, ...]] = field(default_factory=dict)
    approved: set[tuple[str, ...]] = field(default_factory=set)
    verdicts: dict[str, frozenset[str]] = field(default_factory=dict)
    decision_scopes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    grant_scopes: dict[tuple[str, ...], tuple[str, ...]] = field(default_factory=dict)
    exit: str = "normal"
    result: str = "constant:None"
    tuples: dict[str, tuple[str, ...]] = field(default_factory=dict)
    lists: dict[str, list[str]] = field(default_factory=dict)
    list_versions: dict[str, int] = field(default_factory=dict)
    unknown_lists: set[str] = field(default_factory=set)
    frozen_sets: dict[str, tuple[str, ...]] = field(default_factory=dict)
    mappings: dict[str, dict[str, str]] = field(default_factory=dict)
    mapping_origins: dict[str, str] = field(default_factory=dict)
    mapping_views: dict[str, tuple[str, str]] = field(default_factory=dict)
    mapping_versions: dict[str, int] = field(default_factory=dict)
    open_mappings: dict[str, _MappingTail] = field(default_factory=dict)
    mapping_presence: dict[tuple[str, str], bool] = field(default_factory=dict)
    unknown_mappings: set[str] = field(default_factory=set)
    objects: dict[str, str] = field(default_factory=dict)
    fields: dict[str, dict[str, str]] = field(default_factory=dict)
    unknown_objects: set[str] = field(default_factory=set)
    predicates: dict[tuple[str, ...], bool] = field(default_factory=dict)
    contents: dict[str, tuple[str, ...]] = field(default_factory=dict)
    locks: set[str] = field(default_factory=set)
    context_defaults: dict[str, str | None] = field(default_factory=dict)
    context_values: dict[str, str | None] = field(default_factory=dict)
    context_tokens: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    used_context_tokens: set[str] = field(default_factory=set)
    unknown_contexts: set[str] = field(default_factory=set)
    supers: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    exception: str = "constant:None"

    def clone(self) -> _State:
        return copy.deepcopy(self)

    def revoke(self, receiver: str | None = None) -> None:
        """Forget grants whose bound object graph can be changed by a write."""
        if receiver is not None:
            if receiver in self.lists:
                self.list_versions[receiver] = self.list_versions.get(receiver, 0) + 1
            if receiver in self.mappings:
                for alias, values in self.mappings.items():
                    if values is self.mappings[receiver]:
                        self.mapping_versions[alias] = (
                            self.mapping_versions.get(alias, 0) + 1
                        )
            affected = {
                fact
                for fact in (*self.approved, *self.pending.values())
                if any(self.depends_on(value, receiver) for value in fact[1:])
            }
            self.approved.difference_update(affected)
            for decision, fact in tuple(self.pending.items()):
                if fact in affected:
                    self.pending.pop(decision)
                    self.verdicts.pop(decision, None)
                    self.decision_scopes.pop(decision, None)
            for fact in affected:
                self.grant_scopes.pop(fact, None)
            for decision in tuple(self.verdicts):
                if self.depends_on(decision, receiver):
                    self.verdicts.pop(decision)
            self.predicates.clear()
            return
        self.pending.clear()
        self.approved.clear()
        self.verdicts.clear()
        self.decision_scopes.clear()
        self.grant_scopes.clear()
        self.predicates.clear()

    def depends_on(self, value: str, receiver: str) -> bool:
        pending, seen = [value], set()
        while pending:
            token = pending.pop()
            if token == receiver or token.startswith(receiver + "."):
                return True
            # Attribute selectors still depend on the containing object.
            root = token
            while (
                root not in self.fields
                and root not in self.mappings
                and root not in self.tuples
                and root not in self.lists
                and root not in self.contents
                and "." in root
            ):
                root = root.rsplit(".", 1)[0]
            if root in seen:
                continue
            seen.add(root)
            if (
                root in self.unknown_objects
                or root in self.unknown_lists
                or root in self.unknown_mappings
                or root in self.open_mappings
                or root in self.unknown_contexts
            ):
                return True
            pending.extend(self.fields.get(root, {}).values())
            pending.extend(self.mappings.get(root, {}).values())
            if root in self.mapping_origins:
                pending.append(self.mapping_origins[root])
            pending.extend(self.tuples.get(root, ()))
            pending.extend(self.lists.get(root, ()))
            pending.extend(self.contents.get(root, ()))
        return False


@dataclass
class _Info:
    module: str
    owner: str | None
    node: _Function


@dataclass(frozen=True)
class _Record:
    fields: tuple[tuple[str, ast.expr | None], ...]
    frozen: bool
    slots: bool
    factories: tuple[tuple[str, ast.expr], ...] = ()


def _literal_default(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) or (
        isinstance(node, ast.Tuple)
        and all(_literal_default(item) for item in node.elts)
    )


class _Limit(Exception):
    pass


def _import_parent(module: str, node: ast.ImportFrom, packages: set[str]) -> str:
    """Resolve import spelling without importing or inspecting candidate code."""
    if not node.level:
        return node.module or ""
    package = module if module in packages else module.rpartition(".")[0]
    if not package:
        raise ValueError("relative import has no containing package")
    try:
        return resolve_name("." * node.level + (node.module or ""), package)
    except ImportError as exc:
        raise ValueError("relative import goes beyond the containing package") from exc


def _export_literal(node: ast.expr) -> bool:
    """Literal tables have no user-defined evaluation, equality or hashing."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Tuple):
        return all(_export_literal(value) for value in node.elts)
    return isinstance(node, ast.Dict) and all(
        isinstance(key, ast.Constant)
        and type(key.value) is str
        and _export_literal(value)
        for key, value in zip(node.keys, node.values)
    )


class _Program:
    def __init__(self, spec: VerificationSpec) -> None:
        self.spec = spec
        self.functions: dict[str, _Info] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.records: dict[str, _Record] = {}
        self.typed_dicts: set[str] = set()
        self.context_variables: dict[str, ast.Constant | None] = {}
        self.constants: dict[str, ast.Constant] = {}
        self.export_literals: dict[str, ast.expr] = {}
        self.aliases: dict[str, dict[str, str]] = {}
        self.binding_lines: dict[tuple[str, str], int] = {}
        self.postponed_modules: set[str] = set()
        self.issues: list[dict[str, Any]] = []
        self.terminals = {item.target for item in spec.authorizers} | {
            item.target for item in spec.operations
        }
        self.lazy_exports: dict[tuple[str, str], str | None] = {}
        self.export_evidence: list[dict[str, Any]] = []
        self.import_bindings: list[tuple[str, str]] = []
        definitions: list[tuple[str, _Function, bool]] = []
        for module, source in sorted(spec.sources.items()):
            if module in {
                "builtins",
                "types",
                "collections",
                "collections.abc",
                "dataclasses",
                "threading",
                "_thread",
                "typing",
                "typing_extensions",
                "importlib",
                "contextvars",
                "_contextvars",
            } or module.startswith("importlib."):
                self.issues.append(
                    {
                        "module": module,
                        "line": 0,
                        "reason": "source overrides a standard type-model module",
                    }
                )
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                self.issues.append(
                    {
                        "module": module,
                        "line": exc.lineno,
                        "reason": "source does not parse",
                    }
                )
                continue
            aliases: dict[str, str] = {}
            self.aliases[module] = aliases
            postponed_annotations = any(
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                and any(alias.name == "annotations" for alias in node.names)
                for node in tree.body
            )
            if postponed_annotations:
                self.postponed_modules.add(module)
            for node in self.module_statements(tree.body, aliases):
                for definition in ast.walk(node):
                    if isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        definitions.append((module, definition, postponed_annotations))
                context_definition = self.context_definition(
                    node, aliases, postponed_annotations
                )
                if context_definition is not None:
                    variable, default = context_definition
                    name = f"{module}.{variable}"
                    self.bind(module, aliases, variable, name, node)
                    self.context_variables[name] = default
                elif (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and node.value is not None
                    and _export_literal(node.value)
                    and (isinstance(node, ast.Assign) or postponed_annotations)
                    and all(
                        isinstance(target, ast.Name)
                        for target in (
                            node.targets
                            if isinstance(node, ast.Assign)
                            else [node.target]
                        )
                    )
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for target in targets:
                        assert isinstance(target, ast.Name)
                        name = f"{module}.{target.id}"
                        self.bind(module, aliases, target.id, name, node)
                        if isinstance(node.value, ast.Constant):
                            self.constants[name] = node.value
                        else:
                            self.export_literals[name] = node.value
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.bind(
                            module,
                            aliases,
                            alias.asname or alias.name.split(".")[0],
                            alias.name if alias.asname else alias.name.split(".")[0],
                            node,
                        )
                elif isinstance(node, ast.ImportFrom):
                    try:
                        prefix = _import_parent(module, node, set(spec.package_modules))
                    except ValueError as exc:
                        self.issues.append(
                            {
                                "module": module,
                                "line": node.lineno,
                                "reason": str(exc),
                            }
                        )
                        continue
                    for alias in node.names:
                        if alias.name == "*":
                            self.issues.append(
                                {
                                    "module": module,
                                    "line": node.lineno,
                                    "reason": "wildcard import leaves symbols unresolved",
                                }
                            )
                        else:
                            self.bind(
                                module,
                                aliases,
                                alias.asname or alias.name,
                                f"{prefix}.{alias.name}",
                                node,
                            )
                            self.import_bindings.append(
                                (module, alias.asname or alias.name)
                            )
                elif isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    name = f"{module}.{node.name}"
                    self.bind(module, aliases, node.name, name, node)
                    if isinstance(node, ast.ClassDef):
                        self.classes[name] = node
                        for member in node.body:
                            if isinstance(
                                member, (ast.FunctionDef, ast.AsyncFunctionDef)
                            ):
                                key = f"{name}.{member.name}"
                                if key in self.functions:
                                    self.issues.append(
                                        {
                                            "module": module,
                                            "line": member.lineno,
                                            "reason": f"duplicate method: {key}",
                                        }
                                    )
                                self.functions[key] = _Info(module, name, member)
                    else:
                        self.functions[name] = _Info(module, None, node)
                elif not isinstance(node, ast.Pass) and (
                    not isinstance(node, ast.Expr)
                    or not isinstance(node.value, ast.Constant)
                ):
                    # Module mutation, conditional definitions and executable
                    # initialization cannot be inferred from a frozen symbol map.
                    self.issues.append(
                        {
                            "module": module,
                            "line": node.lineno,
                            "reason": "module initialization/binding requires a model",
                        }
                    )
        self.method_cache: dict[str, dict[str, str]] = {}
        self.mro_cache: dict[str, tuple[str, ...] | None] = {}
        self.qualification_cache: dict[tuple[str, str], str] = {}
        self.type_cache: dict[str, frozenset[str] | None] = {}
        self.method_kinds: dict[str, str] = {}
        # Importing an otherwise unused lazy attribute still evaluates its hook.
        # Resolve every source import, not just names later used by a tool API.
        for module, name in self.import_bindings:
            self.qualify(module, name)
        for owner, node in self.classes.items():
            module = owner.rsplit(".", 1)[0]
            bound_names: set[str] = set()
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = self.descriptor_kind(module, member, bound_names)
                    if member.decorator_list and kind is not None:
                        self.method_kinds[f"{owner}.{member.name}"] = kind
                    bound_names.add(member.name)
                elif isinstance(member, (ast.Assign, ast.AnnAssign)):
                    if isinstance(member, ast.Assign) or member.value is not None:
                        targets = (
                            member.targets
                            if isinstance(member, ast.Assign)
                            else [member.target]
                        )
                        for target_node in targets:
                            bound_names.update(
                                part.id
                                for part in ast.walk(target_node)
                                if isinstance(part, ast.Name)
                                and isinstance(part.ctx, ast.Store)
                            )
        for name, info in self.functions.items():
            if (
                info.owner is None
                and info.node.decorator_list
                and self.descriptor_kind(info.module, info.node, set()) == "instance"
            ):
                self.method_kinds[name] = "instance"
        recognized = {id(self.functions[name].node) for name in self.method_kinds}
        for module, definition, postponed_annotations in definitions:
            defaults = [*definition.args.defaults, *definition.args.kw_defaults]
            annotations = [
                definition.returns,
                *(
                    arg.annotation
                    for arg in [
                        *definition.args.posonlyargs,
                        *definition.args.args,
                        *definition.args.kwonlyargs,
                        *([definition.args.vararg] if definition.args.vararg else []),
                        *([definition.args.kwarg] if definition.args.kwarg else []),
                    ]
                ),
            ]
            if (
                (definition.decorator_list and id(definition) not in recognized)
                or any(
                    default is not None and not isinstance(default, ast.Constant)
                    for default in defaults
                )
                or (
                    not postponed_annotations
                    and any(item is not None for item in annotations)
                )
            ):
                self.issues.append(
                    {
                        "module": module,
                        "line": definition.lineno,
                        "reason": "definition-time decorators/defaults/annotations require a model",
                    }
                )
        for owner, node in self.classes.items():
            record = self.record_model(owner, node)
            if record is not None:
                self.records[owner] = record
        for owner in self.classes:
            self.typed_dict_model(owner)
        # Every class body executes when its module is loaded, even when no API
        # constructs it. Unsupported definition effects cannot hide in an
        # otherwise unreachable helper class.
        for owner in self.classes:
            self.methods(owner)

    def context_definition(
        self, node: ast.stmt, aliases: dict[str, str], postponed: bool
    ) -> tuple[str, ast.Constant | None] | None:
        """Capture only native module ContextVar construction with inert arguments."""
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign) and postponed:
            target = node.target
        else:
            return None
        call = node.value
        if (
            not isinstance(target, ast.Name)
            or not isinstance(call, ast.Call)
            or not isinstance(call.func, (ast.Name, ast.Attribute))
            or len(call.args) != 1
            or not isinstance(call.args[0], ast.Constant)
            or type(call.args[0].value) is not str
            or len(call.keywords) > 1
            or any(
                keyword.arg != "default" or not isinstance(keyword.value, ast.Constant)
                for keyword in call.keywords
            )
        ):
            return None
        root, dot, tail = ast.unparse(call.func).partition(".")
        constructor = aliases.get(root, root) + (dot + tail if dot else "")
        if constructor != "contextvars.ContextVar" or constructor in self.terminals:
            return None
        default = call.keywords[0].value if call.keywords else None
        assert default is None or isinstance(default, ast.Constant)
        return target.id, default

    def typed_dict_model(self, owner: str, trail: tuple[str, ...] = ()) -> bool:
        """Recognize inert TypedDict declarations, never infer input schemas."""
        if owner in self.typed_dicts:
            return True
        if owner in trail or owner not in self.classes:
            return False
        node = self.classes[owner]
        module = owner.rsplit(".", 1)[0]
        if (
            len(node.bases) != 1
            or node.decorator_list
            or getattr(node, "type_params", False)
            or any(
                keyword.arg != "total"
                or not isinstance(keyword.value, ast.Constant)
                or type(keyword.value.value) is not bool
                for keyword in node.keywords
            )
            or len(node.keywords) > 1
        ):
            return False
        base = node.bases[0]
        if not isinstance(base, (ast.Name, ast.Attribute)):
            return False
        spelling = ast.unparse(base)
        root = spelling.split(".", 1)[0]
        if (
            root not in self.aliases[module]
            or self.binding_lines.get((module, root), 0) >= node.lineno
        ):
            return False
        parent = self.qualify(module, spelling)
        if parent in self.terminals or not (
            parent in {"typing.TypedDict", "typing_extensions.TypedDict"}
            or self.typed_dict_model(parent, (*trail, owner))
        ):
            return False
        for member in node.body:
            if isinstance(member, ast.AnnAssign):
                if (
                    module not in self.postponed_modules
                    or not isinstance(member.target, ast.Name)
                    or member.value is not None
                ):
                    return False
            elif not isinstance(member, ast.Pass) and not (
                isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
            ):
                return False
        self.typed_dicts.add(owner)
        return True

    def module_statements(
        self, body: list[ast.stmt], aliases: dict[str, str]
    ) -> Iterator[ast.stmt]:
        """Select only branches with a known inert runtime condition.

        The caller updates aliases after each yielded statement, preserving
        import order. Type-only definitions cannot supply runtime bindings.
        Unknown conditions remain ordinary unsupported module initialization.
        """
        for node in body:
            if isinstance(node, ast.If):
                condition = self.module_condition(node.test, aliases)
                if condition is not None:
                    yield from self.module_statements(
                        node.body if condition else node.orelse, aliases
                    )
                    continue
            yield node

    def module_condition(self, node: ast.expr, aliases: dict[str, str]) -> bool | None:
        if isinstance(node, ast.Constant) and type(node.value) is bool:
            return bool(node.value)
        if isinstance(node, (ast.Name, ast.Attribute)):
            spelling = ast.unparse(node)
            root, dot, tail = spelling.partition(".")
            target = aliases.get(root, root) + (dot + tail if dot else "")
            if (
                root in aliases
                and target in _TYPE_CHECKING_NAMES
                and target not in self.terminals
            ):
                return False
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.module_condition(node.operand, aliases)
            return None if value is None else not value
        if isinstance(node, ast.BoolOp):
            continuing = isinstance(node.op, ast.And)
            for expression in node.values:
                value = self.module_condition(expression, aliases)
                if value is None or value != continuing:
                    return value
            return continuing
        return None

    def descriptor_kind(
        self, module: str, node: _Function, bound_names: set[str]
    ) -> str | None:
        """Recognize native binding and identity-preserving override metadata."""
        kind = "instance"
        for decorator in node.decorator_list:
            if not isinstance(decorator, (ast.Name, ast.Attribute)):
                return None
            spelling = ast.unparse(decorator)
            target = self.qualify(module, spelling)
            root = spelling.split(".", 1)[0]
            if (
                root in bound_names
                or self.binding_lines.get((module, root), 0) >= node.lineno
                or target in self.terminals
                or target
                in (self.functions.keys() | self.classes.keys() | self.constants.keys())
            ):
                return None
            if target in {"typing.override", "typing_extensions.override"}:
                continue
            if (
                target.removeprefix("builtins.") not in {"staticmethod", "classmethod"}
                or kind != "instance"
            ):
                return None
            kind = target.removeprefix("builtins.")
        return kind

    def record_model(self, owner: str, node: ast.ClassDef) -> _Record | None:
        """Recognize the supported standard dataclass constructor semantics."""
        if len(node.decorator_list) != 1:
            return None
        module = owner.rsplit(".", 1)[0]
        decorator = node.decorator_list[0]
        function = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = self.qualify(module, ast.unparse(function))
        if (
            self.binding_lines.get((module, ast.unparse(function).split(".", 1)[0]), 0)
            >= node.lineno
        ):
            return None
        if name != "dataclasses.dataclass" or name in (
            self.functions.keys() | self.classes.keys() | self.constants.keys()
        ):
            return None
        if node.bases or node.keywords or module not in self.postponed_modules:
            return None
        options: dict[str, bool] = {}
        if isinstance(decorator, ast.Call):
            if decorator.args:
                return None
            for keyword in decorator.keywords:
                if (
                    keyword.arg not in {"frozen", "slots"}
                    or not isinstance(keyword.value, ast.Constant)
                    or type(keyword.value.value) is not bool
                    or keyword.arg in options
                ):
                    return None
                options[keyword.arg] = keyword.value.value
        fields: list[tuple[str, ast.expr | None]] = []
        factories: list[tuple[str, ast.expr]] = []
        optional = False
        method_names = {
            member.name
            for member in node.body
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if member.name == "__init__":
                    return None
            elif isinstance(member, ast.AnnAssign):
                if not isinstance(member.target, ast.Name):
                    return None
                if (
                    member.target.id.startswith("__")
                    or member.target.id in method_names
                ):
                    return None
                annotation = member.annotation
                if isinstance(annotation, ast.Constant) and isinstance(
                    annotation.value, str
                ):
                    try:
                        annotation = ast.parse(annotation.value, mode="eval").body
                    except SyntaxError:
                        return None
                # Dataclasses recognize special annotations by looking up the
                # outer name in the defining module. An unresolved import could
                # re-export InitVar/ClassVar and change the constructor layout.
                head = annotation
                while isinstance(head, (ast.Subscript, ast.BinOp)):
                    head = head.value if isinstance(head, ast.Subscript) else head.left
                if not isinstance(head, (ast.Name, ast.Attribute)):
                    return None
                spelling = ast.unparse(head)
                qualified = self.qualify(module, spelling)
                root_name = spelling.split(".", 1)[0]
                if (
                    root_name in self.aliases[module]
                    and qualified not in self.classes
                    and qualified not in self.functions
                    and not qualified.startswith(
                        ("typing.", "collections.abc.", "typing_extensions.")
                    )
                    and spelling != "Verdict"
                ):
                    return None
                for part in ast.walk(annotation):
                    if isinstance(part, (ast.Name, ast.Attribute)) and self.qualify(
                        module, ast.unparse(part)
                    ) in {
                        "typing.ClassVar",
                        "typing_extensions.ClassVar",
                        "dataclasses.InitVar",
                        "dataclasses.KW_ONLY",
                    }:
                        return None
                default_info = self.record_default(
                    module,
                    member.value,
                    {node.name, *method_names, *(name for name, _ in fields)},
                )
                if default_info is None:
                    return None
                default, factory = default_info
                if default is not None or factory is not None:
                    optional = True
                elif optional:
                    return None
                if any(field == member.target.id for field, _ in fields):
                    return None
                fields.append((member.target.id, default))
                if factory is not None:
                    factories.append((member.target.id, factory))
            elif not isinstance(member, ast.Pass) and not (
                isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
            ):
                return None
        return _Record(
            tuple(fields),
            options.get("frozen", False),
            options.get("slots", False),
            tuple(factories),
        )

    def record_default(
        self, module: str, value: ast.expr | None, class_names: set[str]
    ) -> tuple[ast.expr | None, ast.expr | None] | None:
        """Capture standard field metadata without executing a factory at definition."""
        if value is None or _literal_default(value):
            return value, None
        if not isinstance(value, ast.Call) or value.args:
            return None
        spelling = ast.unparse(value.func)
        name = self.qualify(module, spelling)
        if (
            name != "dataclasses.field"
            or name
            in (self.functions.keys() | self.classes.keys() | self.constants.keys())
            or spelling.split(".", 1)[0] in class_names
            or self.binding_lines.get((module, spelling.split(".", 1)[0]), 0)
            >= value.lineno
        ):
            return None
        options = {}
        for keyword in value.keywords:
            if (
                keyword.arg not in {"default", "default_factory", "compare", "repr"}
                or keyword.arg in options
            ):
                return None
            if keyword.arg in {"compare", "repr"} and (
                not isinstance(keyword.value, ast.Constant)
                or type(keyword.value.value) is not bool
            ):
                return None
            options[keyword.arg] = keyword.value
        if "default" in options and "default_factory" in options:
            return None
        default = options.get("default")
        if default is not None and not _literal_default(default):
            return None
        factory = options.get("default_factory")
        if factory is not None:
            if not isinstance(factory, (ast.Name, ast.Attribute)):
                return None
            spelling = ast.unparse(factory)
            target = self.qualify(module, spelling)
            if spelling.split(".", 1)[0] in class_names or (
                target not in self.functions
                and target not in self.classes
                and target
                not in {
                    "dict",
                    "tuple",
                    "list",
                    "frozenset",
                    "builtins.dict",
                    "builtins.tuple",
                    "builtins.list",
                    "builtins.frozenset",
                }
            ):
                return None
            if (
                self.binding_lines.get((module, spelling.split(".", 1)[0]), 0)
                >= value.lineno
            ):
                return None
        return default, factory

    def bind(
        self, module: str, aliases: dict[str, str], key: str, value: str, node: ast.AST
    ) -> None:
        if key in aliases:
            self.issues.append(
                {
                    "module": module,
                    "line": getattr(node, "lineno", 0),
                    "reason": f"ambiguous symbol: {key}",
                }
            )
        aliases[key] = value
        self.binding_lines[(module, key)] = getattr(node, "lineno", 0)

    def qualify(self, module: str, name: str) -> str:
        key = (module, name)
        if key in self.qualification_cache:
            return self.qualification_cache[key]
        root, dot, tail = name.partition(".")
        qualified = self.aliases.get(module, {}).get(root, root) + (
            dot + tail if dot else ""
        )
        # Follow source-defined re-exports. A subclass imported through a package
        # facade must be discovered just like one using its defining module.
        # Never import candidate code to resolve it.
        seen: set[str] = set()
        while qualified not in seen and len(seen) < 64 and len(qualified) < 65536:
            seen.add(qualified)
            parts = qualified.split(".")
            for index in range(len(parts) - 1, 0, -1):
                namespace = ".".join(parts[:index])
                exported = self.aliases.get(namespace, {}).get(parts[index])
                if (
                    exported is None
                    and f"{namespace}.__getattr__" in self.functions
                    and not (
                        ".".join(parts[: index + 1]) in self.spec.sources
                        and index + 1 < len(parts)
                    )
                ):
                    exported = self.lazy_export(namespace, parts[index])
                if exported is not None:
                    resolved = ".".join((exported, *parts[index + 1 :]))
                    if resolved != qualified:
                        if qualified in self.terminals:
                            self.issues.append(
                                {
                                    "module": module,
                                    "line": 0,
                                    "reason": f"terminal contract names a rebound import alias: {qualified}",
                                }
                            )
                        qualified = resolved
                        break
            else:
                self.qualification_cache[key] = qualified
                return qualified
        self.issues.append(
            {
                "module": module,
                "line": 0,
                "reason": "cyclic import alias or alias resolution budget exceeded",
            }
        )
        unresolved = f"unresolved-alias:{module}:{name}"
        self.qualification_cache[key] = unresolved
        return unresolved

    def lazy_export(self, module: str, name: str) -> str | None:
        key = (module, name)
        if key in self.lazy_exports:
            return self.lazy_exports[key]
        # Recursive/cyclic exports cannot bootstrap a binding from a snapshot.
        self.lazy_exports[key] = None
        resolver = _ExportResolver(self, module, name)
        try:
            value = resolver.invoke(f"{module}.__getattr__", [name], {})
            if not isinstance(value, _ExportRef) or value.kind not in {
                "symbol",
                "module",
            }:
                raise _ExportUnresolved("export does not resolve to a source reference")
            if any(
                key != (module, name) or cached != value
                for key, cached in resolver.cache_writes
            ):
                raise _ExportUnresolved("export cache changes another binding")
            child = f"{module}.{name}"
            if child in self.spec.sources and value != _ExportRef("module", child):
                raise _ExportUnresolved("export conflicts with a source submodule")
        except _ExportUnresolved as exc:
            self.issues.append(
                {
                    "module": module,
                    "line": self.functions[f"{module}.__getattr__"].node.lineno,
                    "reason": f"lazy export {name} is unresolved: {exc}",
                }
            )
            return None
        self.lazy_exports[key] = value.target
        self.export_evidence.append(
            {
                "module": module,
                "name": name,
                "target": value.target,
                "visited_functions": sorted(resolver.visited),
                "steps": resolver.steps,
                "cache_writes": len(resolver.cache_writes),
            }
        )
        return value.target

    def linearization(
        self, owner: str, trail: tuple[str, ...] = ()
    ) -> tuple[str, ...] | None:
        """Compute native C3 order only for statically named source bases."""
        if owner in {"object", "builtins.object"}:
            return ("object",)
        if owner in self.mro_cache:
            return self.mro_cache[owner]
        if owner in trail or owner not in self.classes or owner in self.typed_dicts:
            return None
        node = self.classes[owner]
        if node.keywords or (node.decorator_list and owner not in self.records):
            self.mro_cache[owner] = None
            return None
        module = owner.rsplit(".", 1)[0]
        bases = []
        for base in node.bases:
            if not isinstance(base, (ast.Name, ast.Attribute)):
                self.mro_cache[owner] = None
                return None
            spelling = ast.unparse(base)
            root = spelling.split(".", 1)[0]
            if self.binding_lines.get((module, root), 0) >= node.lineno:
                self.mro_cache[owner] = None
                return None
            name = self.qualify(module, spelling)
            bases.append("object" if name == "builtins.object" else name)
        bases = bases or ["object"]
        if len(set(bases)) != len(bases):
            self.mro_cache[owner] = None
            return None
        parents = [self.linearization(base, (*trail, owner)) for base in bases]
        if any(parent is None for parent in parents):
            self.mro_cache[owner] = None
            return None
        sequences = [list(parent) for parent in parents if parent is not None]
        sequences.append(list(bases))
        result = [owner]
        while any(sequences):
            sequences = [sequence for sequence in sequences if sequence]
            candidate = next(
                (
                    sequence[0]
                    for sequence in sequences
                    if not any(sequence[0] in other[1:] for other in sequences)
                ),
                None,
            )
            if candidate is None:
                self.mro_cache[owner] = None
                return None
            result.append(candidate)
            for sequence in sequences:
                if sequence[0] == candidate:
                    sequence.pop(0)
        self.mro_cache[owner] = tuple(result)
        return tuple(result)

    def methods(self, owner: str, trail: tuple[str, ...] = ()) -> dict[str, str]:
        if owner in self.method_cache:
            return self.method_cache[owner]
        if owner in self.typed_dicts:
            self.method_cache[owner] = {}
            return {}
        if owner in trail or owner not in self.classes:
            self.issues.append(
                {
                    "module": owner,
                    "line": 0,
                    "reason": "unresolved or cyclic base class",
                }
            )
            return {}
        node = self.classes[owner]
        module = owner.rsplit(".", 1)[0]
        result: dict[str, str] = {}
        order = self.linearization(owner)
        if order is None:
            self.issues.append(
                {
                    "module": module,
                    "line": node.lineno,
                    "reason": "base-class order, metaclasses or class decorators require a model",
                }
            )
        for base in node.bases:
            name = self.qualify(module, ast.unparse(base))
            if name in self.typed_dicts:
                self.issues.append(
                    {
                        "module": module,
                        "line": node.lineno,
                        "reason": "unsupported TypedDict subclass requires a metaclass model",
                    }
                )
            if name in self.records:
                self.issues.append(
                    {
                        "module": module,
                        "line": node.lineno,
                        "reason": "dataclass inheritance requires a generated-method model",
                    }
                )
            if name not in {"object", "builtins.object"}:
                result.update(self.methods(name, (*trail, owner)))
        if order is not None:
            result = {
                member.name: f"{parent}.{member.name}"
                for parent in reversed(order[1:])
                if parent in self.classes
                for member in self.classes[parent].body
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if member.name in {
                    "__getattribute__",
                    "__getattr__",
                    "__setattr__",
                    "__delattr__",
                    "__new__",
                    "__init_subclass__",
                    "__class_getitem__",
                    "__bool__",
                    "__len__",
                    "__del__",
                    "__eq__",
                    "__ne__",
                    "__hash__",
                }:
                    self.issues.append(
                        {
                            "module": module,
                            "line": member.lineno,
                            "reason": "custom Python object protocol requires a model",
                        }
                    )
                result[member.name] = f"{owner}.{member.name}"
            elif (
                isinstance(member, ast.AnnAssign)
                and (member.value is None or owner in self.records)
                and isinstance(member.target, ast.Name)
                and module in self.postponed_modules
            ):
                continue
            elif not isinstance(member, ast.Pass) and not (
                isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
            ):
                self.issues.append(
                    {
                        "module": module,
                        "line": member.lineno,
                        "reason": "class-body binding/effect requires a model",
                    }
                )
        self.method_cache[owner] = result
        return result

    def type_lineage(
        self, name: str, trail: tuple[str, ...] = ()
    ) -> frozenset[str] | None:
        """Resolve nominal types only where the standard metaclass is known."""
        name = name.removeprefix("builtins.")
        if name in self.type_cache:
            return self.type_cache[name]
        if name in trail:
            return None
        if name in _TYPE_BASES:
            bases = _TYPE_BASES[name]
        elif name in self.classes:
            node = self.classes[name]
            if node.keywords or (node.decorator_list and name not in self.records):
                return None
            module = name.rsplit(".", 1)[0]
            bases = tuple(
                self.qualify(module, ast.unparse(base)) for base in node.bases
            ) or ("object",)
        else:
            return None
        lineage = {name}
        for base in bases:
            parent = self.type_lineage(base, (*trail, name))
            if parent is None:
                self.type_cache[name] = None
                return None
            lineage.update(parent)
        result = frozenset(lineage)
        self.type_cache[name] = result
        return result

    def surfaces(self) -> dict[str, dict[str, str]]:
        selected = set(self.spec.surfaces)
        changed = True
        while changed:
            changed = False
            for name, node in self.classes.items():
                if name not in selected and any(
                    self.qualify(name.rsplit(".", 1)[0], ast.unparse(base)) in selected
                    for base in node.bases
                ):
                    selected.add(name)
                    changed = True
        for name in selected & self.records.keys():
            self.issues.append(
                {
                    "module": name,
                    "line": 0,
                    "reason": "dataclass API surface requires generated-method verification",
                }
            )
        for name in selected & self.typed_dicts:
            self.issues.append(
                {
                    "module": name,
                    "line": 0,
                    "reason": "TypedDict API surface requires native dictionary method verification",
                }
            )
        return {name: self.methods(name) for name in sorted(selected)}


@dataclass(frozen=True)
class _ExportRef:
    kind: str
    target: str


class _ExportUnresolved(Exception):
    pass


class _ExportRaises(Exception):
    """A fully analyzed, inert import failure; not an unresolved operation."""


class _ExportResolver:
    """Interpret a constant import lookup; never execute a candidate hook.

    This is deliberately effect-free except for caching the requested export.
    Source helper bodies are followed. The program's initialization checks still
    apply to every imported source module and every helper definition.
    """

    def __init__(self, program: _Program, module: str, name: str) -> None:
        self.program = program
        self.request = (module, name)
        self.stack: tuple[str, ...] = ()
        self.visited: set[str] = set()
        self.steps = 0
        self.cache_writes: list[tuple[tuple[str, str], _ExportRef]] = []
        self.exception_returns: list[Any] = []

    def tick(self) -> None:
        self.steps += 1
        if self.steps > self.program.spec.max_steps:
            raise _ExportUnresolved("import lookup budget exhausted")

    def reference(self, target: str) -> Any:
        if target in self.program.constants:
            return self.program.constants[target].value
        if target in self.program.export_literals:
            return ast.literal_eval(self.program.export_literals[target])
        if target in (
            self.program.functions.keys()
            | self.program.classes.keys()
            | self.program.terminals
        ):
            return _ExportRef("symbol", target)
        if target.removeprefix("builtins.") in {"globals", "getattr"}:
            return _ExportRef("builtin", target.removeprefix("builtins."))
        if target.removeprefix("builtins.") in {
            "ImportError",
            "ModuleNotFoundError",
            "AttributeError",
        }:
            return _ExportRef("exception-class", target.removeprefix("builtins."))
        if target == "importlib.import_module":
            return _ExportRef("builtin", target)
        if target in self.program.spec.sources or target in {"importlib", "builtins"}:
            return _ExportRef("module", target)
        raise _ExportUnresolved(f"source binding unavailable: {target}")

    def truth(self, value: Any) -> bool:
        if type(value) not in {str, bool, int, float, tuple, dict, type(None)}:
            raise _ExportUnresolved("import predicate requires an inert value")
        return bool(value)

    def attribute(self, receiver: Any, name: str) -> Any:
        if (
            isinstance(receiver, _ExportRef)
            and receiver.kind == "spec"
            and name == "parent"
        ):
            module = receiver.target
            if module == "__main__":
                raise _ExportUnresolved("the main module has no guaranteed import spec")
            return (
                module
                if module in self.program.spec.package_modules
                else module.rpartition(".")[0]
            )
        if (
            isinstance(receiver, _ExportRef)
            and receiver.kind == "module"
            and not name.startswith("__")
        ):
            target = self.program.qualify("", f"{receiver.target}.{name}")
            return self.reference(target)
        raise _ExportUnresolved("import attribute requires a source module")

    def expr(self, node: ast.expr, env: dict[str, Any], info: _Info) -> Any:
        self.tick()
        if _export_literal(node):
            return ast.literal_eval(node)
        if isinstance(node, ast.Name):
            if node.id in env:
                value = env[node.id]
                if isinstance(value, _ExportRef) and value.kind == "unbound":
                    raise _ExportUnresolved(f"unbound import local: {node.id}")
                return value
            if node.id == "__spec__" and node.id not in self.program.aliases.get(
                info.module, {}
            ):
                return _ExportRef("spec", info.module)
            return self.reference(self.program.qualify(info.module, node.id))
        if isinstance(node, ast.Attribute):
            return self.attribute(self.expr(node.value, env, info), node.attr)
        if isinstance(node, ast.Subscript):
            receiver = self.expr(node.value, env, info)
            key = self.expr(node.slice, env, info)
            if type(receiver) is dict and type(key) is str and key in receiver:
                return receiver[key]
            raise _ExportUnresolved("import subscript requires an existing literal key")
        if isinstance(node, ast.JoinedStr):
            parts = []
            opaque = False
            for item in node.values:
                if isinstance(item, ast.Constant) and type(item.value) is str:
                    parts.append(item.value)
                elif isinstance(item, ast.FormattedValue) and item.format_spec is None:
                    value = self.expr(item.value, env, info)
                    if (
                        isinstance(value, _ExportRef)
                        and value.kind in {"exception-value", "opaque-text"}
                        and item.conversion in {-1, 115, 114, 97}
                    ):
                        opaque = True
                        continue
                    if type(value) is not str or item.conversion not in {
                        -1,
                        115,
                        114,
                        97,
                    }:
                        raise _ExportUnresolved(
                            "import formatting requires an inert string"
                        )
                    parts.append(
                        repr(value)
                        if item.conversion == 114
                        else ascii(value)
                        if item.conversion == 97
                        else value
                    )
                else:
                    raise _ExportUnresolved(
                        "import format specification is unsupported"
                    )
            if sum(len(part) for part in parts) > 65536:
                raise _ExportUnresolved("import string budget exhausted")
            return (
                _ExportRef("opaque-text", "import diagnostic")
                if opaque
                else "".join(parts)
            )
        if isinstance(node, ast.BoolOp):
            value = None
            for item in node.values:
                value = self.expr(item, env, info)
                if self.truth(value) != isinstance(node.op, ast.And):
                    break
            return value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self.truth(self.expr(node.operand, env, info))
        if isinstance(node, ast.Compare):
            left = self.expr(node.left, env, info)
            for operation, item in zip(node.ops, node.comparators):
                right = self.expr(item, env, info)
                if isinstance(operation, (ast.Is, ast.IsNot)) and (
                    left is None
                    or right is None
                    or type(left) is bool
                    or type(right) is bool
                ):
                    equal = left is right
                    matched = equal if isinstance(operation, ast.Is) else not equal
                elif isinstance(operation, (ast.Eq, ast.NotEq)) and all(
                    type(value) in {str, bool, int, float, type(None)}
                    for value in (left, right)
                ):
                    equal = left == right
                    matched = equal if isinstance(operation, ast.Eq) else not equal
                else:
                    raise _ExportUnresolved(
                        "import comparison requires inert scalar values"
                    )
                if not matched:
                    return False
                left = right
            return True
        if isinstance(node, ast.Call):
            receiver = None
            if isinstance(node.func, ast.Attribute):
                receiver = self.expr(node.func.value, env, info)
                callee = (
                    None
                    if type(receiver) is dict
                    else self.attribute(receiver, node.func.attr)
                )
            else:
                callee = self.expr(node.func, env, info)
            if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
                kw.arg is None for kw in node.keywords
            ):
                raise _ExportUnresolved(
                    "import argument expansion requires another model"
                )
            args = [self.expr(arg, env, info) for arg in node.args]
            kwargs: dict[str, Any] = {}
            for kw in node.keywords:
                assert kw.arg is not None
                value = self.expr(kw.value, env, info)
                if kw.arg in kwargs:
                    raise _ExportUnresolved("duplicate import keyword")
                kwargs[kw.arg] = value
            if type(receiver) is dict and isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr == "get"
                    and len(args) in {1, 2}
                    and not kwargs
                    and type(args[0]) is str
                ):
                    return receiver.get(args[0], args[1] if len(args) == 2 else None)
                raise _ExportUnresolved(
                    "only literal-table get is supported during imports"
                )
            if not isinstance(callee, _ExportRef):
                raise _ExportUnresolved("import call target is not a source reference")
            if callee.kind == "symbol":
                return self.invoke(callee.target, args, kwargs)
            if (
                callee.kind == "exception-class"
                and not kwargs
                and all(
                    type(value) in {str, bool, int, float, type(None)}
                    or isinstance(value, _ExportRef)
                    and value.kind in {"opaque-text", "exception-value"}
                    for value in args
                )
            ):
                return _ExportRef("exception-value", callee.target)
            if callee.kind != "builtin":
                raise _ExportUnresolved("import call requires a source function")
            if callee.target == "globals" and not args and not kwargs:
                return _ExportRef("globals", info.module)
            if (
                callee.target == "getattr"
                and len(args) == 2
                and not kwargs
                and type(args[1]) is str
            ):
                return self.attribute(args[0], args[1])
            if callee.target == "importlib.import_module":
                parameters = ("name", "package")
                if len(args) > 2 or any(
                    key not in parameters or key in parameters[: len(args)]
                    for key in kwargs
                ):
                    raise _ExportUnresolved("import_module argument mismatch")
                bound = dict(zip(parameters, args))
                bound.update(kwargs)
                name, package = bound.get("name"), bound.get("package")
                if type(name) is not str or (
                    package is not None and type(package) is not str
                ):
                    raise _ExportUnresolved("import_module requires literal names")
                try:
                    target = (
                        resolve_name(name, package) if name.startswith(".") else name
                    )
                except (ImportError, ValueError):
                    raise _ExportUnresolved("invalid relative module import") from None
                if target not in self.program.spec.sources:
                    raise _ExportUnresolved(
                        f"imported module source unavailable: {target}"
                    )
                return _ExportRef("module", target)
            raise _ExportUnresolved("unsupported import primitive or argument binding")
        raise _ExportUnresolved(f"unsupported import expression: {type(node).__name__}")

    def block(
        self, body: list[ast.stmt], env: dict[str, Any], info: _Info
    ) -> tuple[bool, Any]:
        for node in body:
            self.tick()
            if isinstance(node, ast.Return):
                return True, self.expr(node.value, env, info) if node.value else None
            if isinstance(node, ast.Assign):
                value = self.expr(node.value, env, info)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
                    elif isinstance(target, ast.Subscript):
                        receiver = self.expr(target.value, env, info)
                        key = self.expr(target.slice, env, info)
                        if not (
                            isinstance(receiver, _ExportRef)
                            and receiver.kind == "globals"
                            and type(key) is str
                            and (receiver.target, key) == self.request
                            and isinstance(value, _ExportRef)
                        ):
                            raise _ExportUnresolved(
                                "import mutation is not its own export cache"
                            )
                        self.cache_writes.append(((receiver.target, key), value))
                    else:
                        raise _ExportUnresolved(
                            "import assignment target is unsupported"
                        )
            elif isinstance(node, ast.If):
                result = self.block(
                    node.body
                    if self.truth(self.expr(node.test, env, info))
                    else node.orelse,
                    env,
                    info,
                )
                if result[0]:
                    return result
            elif isinstance(node, ast.Try):
                # A failed import may enter a handler from any prefix. Only
                # inspected, unconditionally raising handlers are supported.
                # Unknown operations cannot become harmless caught exceptions.
                prefix = dict(env)
                for statement in [*node.body, *node.orelse]:
                    for part in ast.walk(statement):
                        if isinstance(part, ast.Name) and isinstance(
                            part.ctx, ast.Store
                        ):
                            prefix[part.id] = _ExportRef("unknown", part.id)
                # Finalizers also run for exceptions not caught by a handler.
                self.exceptional_final(node.finalbody, dict(prefix), info)
                for handler in node.handlers:
                    if handler.type is None:
                        raise _ExportUnresolved(
                            "catch-all import handler requires another model"
                        )
                    caught = self.expr(handler.type, env, info)
                    if not (
                        isinstance(caught, _ExportRef)
                        and caught.kind == "exception-class"
                        and caught.target in {"ImportError", "ModuleNotFoundError"}
                    ):
                        raise _ExportUnresolved(
                            "import handler requires a native import exception"
                        )
                    exceptional = dict(prefix)
                    if handler.name:
                        exceptional[handler.name] = _ExportRef(
                            "exception-value", caught.target
                        )
                    try:
                        self.block(handler.body, exceptional, info)
                    except _ExportRaises:
                        self.exceptional_final(node.finalbody, exceptional, info)
                    else:
                        raise _ExportUnresolved("import handler can return or continue")
                result = self.block(node.body, env, info)
                if not result[0]:
                    result = self.block(node.orelse, env, info)
                final = self.block(node.finalbody, env, info)
                if final[0] or result[0]:
                    return final if final[0] else result
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env, info)
            elif isinstance(node, ast.Raise):
                if node.exc is not None:
                    raised = self.expr(node.exc, env, info)
                    if not (
                        isinstance(raised, _ExportRef)
                        and raised.kind in {"exception-class", "exception-value"}
                    ):
                        raise _ExportUnresolved(
                            "raised import error is not a native exception"
                        )
                if node.cause is not None:
                    cause = self.expr(node.cause, env, info)
                    if cause is not None and not (
                        isinstance(cause, _ExportRef)
                        and cause.kind in {"exception-class", "exception-value"}
                    ):
                        raise _ExportUnresolved(
                            "import error cause is not a native exception"
                        )
                raise _ExportRaises
            elif not isinstance(node, ast.Pass):
                raise _ExportUnresolved(
                    f"unsupported import statement: {type(node).__name__}"
                )
        return False, None

    def exceptional_final(
        self, body: list[ast.stmt], env: dict[str, Any], info: _Info
    ) -> None:
        try:
            returned, value = self.block(body, env, info)
        except _ExportRaises:
            return
        if returned:
            self.exception_returns.append(value)

    def invoke(self, target: str, args: list[Any], kwargs: dict[str, Any]) -> Any:
        self.tick()
        if target in self.program.terminals:
            raise _ExportUnresolved(
                "an effect terminal cannot be used as an import helper"
            )
        info = self.program.functions.get(target)
        if (
            info is None
            or info.owner is not None
            or not isinstance(info.node, ast.FunctionDef)
            or info.node.decorator_list
        ):
            raise _ExportUnresolved(f"ordinary source helper unavailable: {target}")
        if target in self.stack or len(self.stack) >= self.program.spec.max_depth:
            raise _ExportUnresolved(
                "recursive export or import call-depth budget exhausted"
            )
        signature = info.node.args
        positional = [a.arg for a in [*signature.posonlyargs, *signature.args]]
        keyword_names = [a.arg for a in [*signature.args, *signature.kwonlyargs]]
        if (
            signature.vararg
            or signature.kwarg
            or len(args) > len(positional)
            or any(
                key not in keyword_names or key in positional[: len(args)]
                for key in kwargs
            )
        ):
            raise _ExportUnresolved("source import helper argument mismatch")
        bound = dict(zip(positional, args))
        bound.update(kwargs)
        defaults = dict(
            zip(
                positional[len(positional) - len(signature.defaults) :],
                signature.defaults,
            )
        )
        defaults.update(
            {
                arg.arg: default
                for arg, default in zip(signature.kwonlyargs, signature.kw_defaults)
                if default is not None
            }
        )
        for name in [*positional, *(a.arg for a in signature.kwonlyargs)]:
            if name not in bound:
                default = defaults.get(name)
                if not isinstance(default, ast.Constant):
                    raise _ExportUnresolved(
                        "missing or nonliteral import helper argument"
                    )
                bound[name] = default.value
        local_names: set[str] = set()
        for node in ast.walk(info.node):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                raise _ExportUnresolved("import helper changes lexical binding scope")
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                local_names.add(node.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                local_names.add(node.name)
            elif (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node is not info.node
            ):
                local_names.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                local_names.update(
                    alias.asname or alias.name.split(".")[0] for alias in node.names
                )
        env: dict[str, Any] = {
            name: _ExportRef("unbound", name) for name in local_names
        }
        env.update(bound)
        previous = self.stack
        previous_returns = self.exception_returns
        self.exception_returns = []
        self.stack = (*previous, target)
        self.visited.add(target)
        try:
            try:
                value = self.block(info.node.body, env, info)[1]
                if any(alternative != value for alternative in self.exception_returns):
                    raise _ExportUnresolved(
                        "exceptional finalizer selects a different export value"
                    )
                return value
            except _ExportRaises:
                raise _ExportUnresolved(
                    "source import helper raises without establishing an export"
                ) from None
        finally:
            self.stack = previous
            self.exception_returns = previous_returns


class _Engine:
    def __init__(self, program: _Program, entry: str, owner: str) -> None:
        self.program, self.spec = program, program.spec
        self.entry, self.owner = entry, owner
        self.authorizers = {item.target: item for item in self.spec.authorizers}
        self.operations = {item.target: item for item in self.spec.operations}
        self.issues: list[dict[str, Any]] = []
        self.dispatches: list[dict[str, Any]] = []
        self.edges: set[tuple[str, str]] = set()
        self.visited: set[str] = set()
        self.calls: set[tuple[str, int, int]] = set()
        self.pruned_calls: set[tuple[str, int, int]] = set()
        self.steps = 0
        self.serial = 0
        self.stack: tuple[str, ...] = ()
        self.exception_continuations = 0
        self.loop_depth = 0
        self.settled_exceptions = 0

    def issue(self, node: ast.AST, reason: str) -> None:
        self.issues.append(
            {
                "function": self.stack[-1] if self.stack else self.entry,
                "line": getattr(node, "lineno", 0),
                "reason": reason,
                "call_path": list(self.stack),
            }
        )

    def tick(self, size: int = 1) -> None:
        self.steps += 1
        if self.steps > self.spec.max_steps or size > self.spec.max_paths:
            raise _Limit("analysis budget exhausted")

    def symbol(self, node: ast.Name, state: _State, info: _Info) -> str:
        if node.id in state.env:
            return state.env[node.id]
        if node.id == "__class__" and info.owner is not None:
            record = self.program.records.get(info.owner)
            if record is not None and record.slots:
                self.issue(node, "generated dataclass class cell requires a model")
                return "unknown:class-cell"
            return "class:" + info.owner
        name = self.program.qualify(info.module, node.id)
        if name in self.program.constants:
            return "constant:" + repr(self.program.constants[name].value)
        if name in self.program.functions or name in self.program.terminals:
            return "callable:" + name
        if name in self.program.classes:
            return "class:" + name
        if name in self.program.context_variables:
            return "context-var:global:" + name
        if name in _TYPE_CHECKING_NAMES:
            return "constant:False"
        if name in _CAST_NAMES:
            return "builtin:" + name
        builtin = name.removeprefix("builtins.")
        if builtin in {"isinstance", "len", "super"}:
            return "builtin:" + builtin
        if name == "types.MappingProxyType":
            return "builtin:" + name
        if name in {"threading.RLock", "_thread.RLock"}:
            return "builtin:" + name
        if name == "contextvars.ContextVar":
            return "builtin:" + name
        if (
            node.id
            in {
                "BaseException",
                "Exception",
                "PermissionError",
                "ValueError",
                "RuntimeError",
                "TypeError",
                "KeyError",
                "LookupError",
                "OSError",
                "TimeoutError",
                "NotImplementedError",
            }
            and name == node.id
        ):
            return "exception:" + node.id
        if builtin == "dict":
            return "mapping-constructor:dict"
        if builtin in _TYPE_BASES:
            return "builtin:" + builtin
        if node.id in self.program.aliases.get(info.module, {}) or node.id == "Verdict":
            return "namespace:" + name
        self.issue(node, f"unresolved global: {node.id}")
        return "unknown:" + node.id

    def method_arguments(self, owner: str, target: str, receiver: str) -> list[str]:
        kind = self.program.method_kinds.get(target)
        if kind == "staticmethod":
            return []
        return ["class:" + owner if kind == "classmethod" else receiver]

    def method_value(
        self, owner: str, target: str, receiver: str | None, state: _State
    ) -> str:
        kind = self.program.method_kinds.get(target)
        if kind == "classmethod":
            token = f"class-bound:{owner}|{target}"
            state.contents[token] = ("class:" + owner,)
            return token
        if receiver is None or kind == "staticmethod":
            return "callable:" + target
        token = f"object-bound:{receiver}|{target}"
        state.contents[token] = (receiver,)
        return token

    def super_value(
        self,
        args: list[str],
        kwargs: dict[str, str],
        state: _State,
        node: ast.Call,
        info: _Info,
    ) -> str:
        if kwargs or len(args) > 2:
            state.exit, state.result = "raise", "constant:None"
            return "unknown:exception"
        if not args:
            parameters = [*info.node.args.posonlyargs, *info.node.args.args]
            if (
                info.owner is None
                or not parameters
                or parameters[0].arg not in state.env
            ):
                state.exit, state.result = "raise", "constant:None"
                return "unknown:exception"
            if not any(
                isinstance(part, ast.Name)
                and part.id in {"super", "__class__"}
                and isinstance(part.ctx, ast.Load)
                for statement in info.node.body
                for part in ast.walk(statement)
            ):
                state.exit, state.result = "raise", "constant:None"
                return "unknown:exception"
            record = self.program.records.get(info.owner)
            if record is not None and record.slots:
                self.issue(node, "generated dataclass class cell requires a model")
                return "unknown:super"
            if any(
                isinstance(part, ast.Name)
                and part.id == "__class__"
                and isinstance(part.ctx, (ast.Store, ast.Del))
                for part in ast.walk(info.node)
            ) or any(parameter.arg == "__class__" for parameter in parameters):
                self.issue(node, "super requires an unchanged lexical class cell")
                return "unknown:super"
            anchor, receiver = info.owner, state.env[parameters[0].arg]
        elif len(args) == 1:
            self.issue(node, "unbound super requires a descriptor model")
            return "unknown:super"
        else:
            kind, _, anchor = args[0].partition(":")
            if kind != "class" and args[0] != "builtin:object":
                self.issue(node, "super starting class requires a known source type")
                return "unknown:super"
            receiver = args[1]
        owner = (
            receiver.removeprefix("class:")
            if receiver.startswith("class:")
            else state.objects.get(receiver)
        )
        if owner is None:
            self.issue(node, "super receiver requires a known source type")
            return "unknown:super"
        order = self.program.linearization(owner)
        if order is None:
            self.issue(node, "super receiver has unresolved method resolution order")
            return "unknown:super"
        if anchor not in order:
            state.exit, state.result = "raise", "constant:None"
            return "unknown:exception"
        self.serial += 1
        token = f"super:{self.serial}"
        state.supers[token] = (anchor, receiver, owner)
        state.contents[token] = (receiver,)
        return token

    def super_attribute(
        self, value: str, name: str, state: _State, node: ast.AST
    ) -> str:
        anchor, receiver, owner = state.supers[value]
        if name == "__self__":
            return receiver
        if name in {"__thisclass__", "__self_class__"}:
            return "class:" + (anchor if name == "__thisclass__" else owner)
        order = self.program.linearization(owner)
        assert order is not None
        for parent in order[order.index(anchor) + 1 :]:
            target = f"{parent}.{name}"
            if target in self.program.functions:
                return self.method_value(
                    owner,
                    target,
                    None if receiver.startswith("class:") else receiver,
                    state,
                )
            if (
                parent == "object"
                and name == "__init__"
                and not receiver.startswith("class:")
            ):
                token = "object-init:" + receiver
                state.contents[token] = (receiver,)
                return token
        if name.startswith("__"):
            self.issue(node, "native super attribute requires a protocol model")
            return "unknown:super-attribute"
        state.exit, state.result = "raise", "constant:None"
        return "unknown:attribute"

    def attribute(self, value: str, name: str, state: _State) -> str:
        if value.startswith("instance:"):
            owner = value.removeprefix("instance:")
            methods = self.program.methods(owner)
            if name in methods:
                return self.method_value(owner, methods[name], value, state)
            return "namespace:" + owner + "." + name
        if value.startswith(("namespace:", "class:")):
            owner = value.partition(":")[2]
            if owner in self.program.classes:
                methods = self.program.methods(owner)
                if name in methods:
                    return self.method_value(owner, methods[name], None, state)
            target = owner + "." + name
            if owner in self.spec.sources:
                target = self.program.qualify("", target)
            if target in self.program.functions or target in self.program.terminals:
                return "callable:" + target
            if target in self.program.classes:
                return "class:" + target
            if target in self.program.context_variables:
                return "context-var:global:" + target
            if target in self.program.constants:
                return "constant:" + repr(self.program.constants[target].value)
            if target in _TYPE_CHECKING_NAMES:
                return "constant:False"
            if target in _CAST_NAMES:
                return "builtin:" + target
            builtin = target.removeprefix("builtins.")
            if builtin == "dict":
                return "mapping-constructor:dict"
            if builtin in _TYPE_BASES or builtin in {"isinstance", "len", "super"}:
                return "builtin:" + builtin
            if target in {"threading.RLock", "_thread.RLock"}:
                return "builtin:" + target
            if target == "contextvars.ContextVar":
                return "builtin:" + target
            return "namespace:" + target
        return value + "." + name

    def mapping(self, state: _State, values: dict[str, str]) -> str:
        self.serial += 1
        token = f"mapping:{self.serial}"
        state.mappings[token] = dict(values)
        return token

    def context_contents(self, state: _State, receiver: str) -> None:
        state.contents[receiver] = tuple(
            value
            for value in (
                state.context_defaults[receiver],
                state.context_values.get(receiver),
            )
            if value is not None
        )

    def context_states(self, state: _State, receiver: str) -> list[_State]:
        """An existing module variable may be bound in the entering context."""
        if receiver in state.context_values:
            return [state]
        missing = state.clone()
        missing.context_values[receiver] = None
        self.context_contents(missing, receiver)
        state.context_values[receiver] = "context-input:" + receiver
        self.context_contents(state, receiver)
        return [missing, state]

    def context_method(
        self,
        receiver: str,
        method: str,
        args: list[str],
        kwargs: dict[str, str],
        state: _State,
        node: ast.Call,
    ) -> list[tuple[_State, str]]:
        valid_arity = len(args) <= 1 if method == "get" else len(args) == 1
        if kwargs or not valid_arity:
            state.exit, state.result = "raise", "constant:None"
            return [(state, "unknown:exception")]
        if receiver in state.unknown_contexts:
            self.issue(node, "exceptional context state requires a restoration model")
            return [(state, "unknown:context")]
        if method == "reset":
            token = args[0]
            if token not in state.context_tokens:
                self.issue(node, "context reset requires a token from this execution")
                return [(state, "unknown:context")]
            variable, previous = state.context_tokens[token]
            if variable != receiver or token in state.used_context_tokens:
                state.exit, state.result = "raise", "constant:None"
                return [(state, "unknown:exception")]
            state.revoke(receiver)
            state.revoke(token)
            state.used_context_tokens.add(token)
            state.context_values[receiver] = previous
            self.context_contents(state, receiver)
            return [(state, "constant:None")]
        result = []
        for current in self.context_states(state, receiver):
            previous = current.context_values[receiver]
            if method == "get":
                value = previous
                if value is None:
                    value = args[0] if args else current.context_defaults[receiver]
                if value is None:
                    current.exit, current.result = "raise", "constant:None"
                    value = "unknown:exception"
                result.append((current, value))
            else:
                value = args[0]
                if self.escapes(value, current):
                    self.issue(
                        node,
                        "context assignment exposes an executable or receiver capability",
                    )
                current.revoke(receiver)
                current.context_values[receiver] = value
                self.context_contents(current, receiver)
                self.serial += 1
                token = f"context-token:{self.serial}"
                current.context_tokens[token] = (receiver, previous)
                current.contents[token] = (receiver,) + (
                    () if previous is None else (previous,)
                )
                result.append((current, token))
        return result

    def list_value(self, state: _State, values: tuple[str, ...] | list[str]) -> str:
        self.serial += 1
        token = f"list:{self.serial}"
        state.lists[token] = list(values)
        return token

    def list_key(
        self, node: ast.expr, state: _State, info: _Info
    ) -> list[tuple[_State, int | slice | None]]:
        parts = (
            [node.lower, node.upper, node.step]
            if isinstance(node, ast.Slice)
            else [node]
        )
        active: list[tuple[_State, list[str]]] = [(state, [])]
        for expression in parts:
            active = [
                (child, [*values, token])
                for current, values in active
                for child, token in (
                    self.expr(expression, current, info)
                    if expression is not None
                    else [(current, "constant:None")]
                )
            ]
            self.tick(len(active))
        results: list[tuple[_State, int | slice | None]] = []
        for current, tokens in active:
            values: list[int | None] = []
            if current.exit != "normal":
                results.append((current, None))
                continue
            for token in tokens:
                if not token.startswith("constant:"):
                    self.issue(node, "list index requires an inert integer protocol")
                    break
                try:
                    value = ast.literal_eval(token.removeprefix("constant:"))
                except (ValueError, SyntaxError):
                    self.issue(node, "list index constant requires a model")
                    break
                if type(value) in {int, bool}:
                    values.append(int(value))
                elif value is None and isinstance(node, ast.Slice):
                    values.append(None)
                else:
                    current.exit, current.result = "raise", "constant:None"
                    break
            else:
                results.append(
                    (
                        current,
                        slice(*values) if isinstance(node, ast.Slice) else values[0],
                    )
                )
                continue
            results.append((current, None))
        return results

    def copy_mapping(
        self, state: _State, receiver: str, *, remainder: bool = False
    ) -> str:
        token = self.mapping(state, {} if remainder else state.mappings[receiver])
        if receiver in state.open_mappings:
            tail = copy.deepcopy(state.open_mappings[receiver])
            if remainder:
                tail.absent.update(state.mappings[receiver])
            state.open_mappings[token] = tail
        if receiver in state.unknown_mappings:
            state.unknown_mappings.add(token)
        return token

    def list_method(
        self,
        receiver: str,
        method: str,
        args: list[str],
        kwargs: dict[str, str],
        state: _State,
        node: ast.Call,
    ) -> str:
        if receiver in state.unknown_lists:
            self.issue(node, "exceptional list method is unresolved")
            return "unknown:list"
        counts = {
            "append": {1},
            "extend": {1},
            "insert": {2},
            "pop": {0, 1},
            "clear": {0},
            "reverse": {0},
            "copy": {0},
        }
        if kwargs or len(args) not in counts[method]:
            state.exit, state.result = "raise", "constant:None"
            return "unknown:exception"
        if method == "copy":
            return self.list_value(state, state.lists[receiver])
        index = -1
        if method in {"insert", "pop"} and args:
            if not args[0].startswith("constant:"):
                self.issue(node, "list index requires an inert integer protocol")
                return "unknown:list"
            try:
                value = ast.literal_eval(args[0].removeprefix("constant:"))
            except (ValueError, SyntaxError):
                self.issue(node, "list index constant requires a model")
                return "unknown:list"
            if type(value) not in {int, bool}:
                state.exit, state.result = "raise", "constant:None"
                return "unknown:exception"
            index = int(value)
        updated = list(state.lists[receiver])
        result = "constant:None"
        try:
            if method == "append":
                updated.append(args[0])
            elif method == "extend":
                values = self.sequence_values(args[0], state, node)
                if values is None:
                    return "unknown:list"
                updated.extend(values)
            elif method == "insert":
                updated.insert(index, args[1])
            elif method == "pop":
                result = updated.pop(index)
            elif method == "reverse":
                updated.reverse()
            elif method == "clear":
                updated.clear()
        except (IndexError, OverflowError):
            state.exit, state.result = "raise", "constant:None"
            return "unknown:exception"
        state.revoke(receiver)
        state.lists[receiver][:] = updated
        return result

    def mapping_lookup(
        self, state: _State, receiver: str, key: str
    ) -> list[tuple[_State, bool, str]]:
        if state.exit != "normal":
            return [(state, False, "unknown:exception")]
        if key in state.mappings[receiver]:
            return [(state, True, state.mappings[receiver][key])]
        tail = state.open_mappings.get(receiver)
        if tail is None or key in tail.absent:
            return [(state, False, "constant:None")]
        predicate = (tail.origin, key)
        outcomes = []
        choices = (
            (state.mapping_presence[predicate],)
            if predicate in state.mapping_presence
            else (False, True)
        )
        for present in choices:
            child = state.clone()
            child.mapping_presence[predicate] = present
            value = f"input-value:{tail.origin}|{key!r}"
            if present:
                child.mappings[receiver][key] = value
            outcomes.append((child, present, value))
        self.tick(len(outcomes))
        return outcomes

    def mapping_delete(self, state: _State, receiver: str, key: str) -> None:
        state.mappings[receiver].pop(key, None)
        if receiver in state.open_mappings:
            state.open_mappings[receiver].absent.add(key)
        state.revoke(receiver)

    @staticmethod
    def string_key(token: str) -> str | None:
        if token.startswith("constant:"):
            try:
                value = ast.literal_eval(token.removeprefix("constant:"))
            except (ValueError, SyntaxError):
                return None
            if type(value) is str:
                return value
        return None

    def inert_hash_value(self, token: str, state: _State) -> Any:
        """Materialize only built-in immutable data, never candidate objects."""
        self.tick()
        if token.startswith("constant:"):
            return ast.literal_eval(token.removeprefix("constant:"))
        if token in state.mappings or token in state.lists:
            raise TypeError("an exact mutable container is unhashable")
        if token in state.tuples:
            return tuple(
                self.inert_hash_value(item, state) for item in state.tuples[token]
            )
        if token in state.frozen_sets:
            return frozenset(
                self.inert_hash_value(item, state) for item in state.frozen_sets[token]
            )
        raise ValueError("hashing or equality may invoke an unmodeled protocol")

    def sequence_values(
        self, token: str, state: _State, node: ast.AST
    ) -> tuple[str, ...] | None:
        """Read a known finite sequence without invoking custom iteration."""
        if token in state.tuples:
            return state.tuples[token]
        if token in state.lists:
            if token in state.unknown_lists:
                self.issue(node, "exceptional list iteration is unresolved")
                return None
            return tuple(state.lists[token])
        if token in state.frozen_sets:
            values = state.frozen_sets[token]
            if len(values) <= 1:
                return values
            self.issue(node, "unordered collection iteration requires an order model")
            return None
        if token in state.mappings or token in state.mapping_views:
            receiver, method = state.mapping_views.get(token, (token, "keys"))
            if receiver in state.open_mappings:
                self.issue(
                    node, "open mapping iteration requires an unbounded-key model"
                )
                return None
            if receiver in state.unknown_mappings:
                self.issue(node, "exceptional mapping iteration is unresolved")
                return None
            items = []
            for key, value in state.mappings[receiver].items():
                key_token = "constant:" + repr(key)
                if method == "items":
                    self.serial += 1
                    item = f"tuple:{self.serial}"
                    state.tuples[item] = (key_token, value)
                    items.append(item)
                else:
                    items.append(value if method == "values" else key_token)
            return tuple(items)
        if token.startswith("constant:"):
            try:
                literal = ast.literal_eval(token.removeprefix("constant:"))
            except (ValueError, SyntaxError):
                pass
            else:
                if isinstance(literal, (str, bytes)):
                    return tuple("constant:" + repr(item) for item in literal)
                state.exit, state.result = "raise", "constant:None"
                return None
        self.issue(node, "collection conversion requires a known inert iterable")
        return None

    def frozen_set(self, values: tuple[str, ...], state: _State, node: ast.AST) -> str:
        # Keep the first equal member's identity, just as the native constructor
        # does (for example True and 1 compare equal but are distinct objects).
        members: dict[Any, str] = {}
        for value in values:
            try:
                literal = self.inert_hash_value(value, state)
                members.setdefault(literal, value)
            except TypeError:
                state.exit, state.result = "raise", "constant:None"
                return "unknown:exception"
            except (ValueError, SyntaxError):
                self.issue(node, "frozenset member hashing/equality requires a model")
                return "unknown:frozenset"
        self.serial += 1
        token = f"frozenset:{self.serial}"
        state.frozen_sets[token] = tuple(members.values())
        state.contents[token] = state.frozen_sets[token]
        return token

    def collection_length(self, token: str, state: _State, node: ast.AST) -> str:
        if token in state.tuples:
            return "constant:" + repr(len(state.tuples[token]))
        if token in state.lists and token not in state.unknown_lists:
            return "constant:" + repr(len(state.lists[token]))
        if token in state.frozen_sets:
            return "constant:" + repr(len(state.frozen_sets[token]))
        receiver = state.mapping_views.get(token, (token, ""))[0]
        if receiver in state.mappings and receiver not in state.unknown_mappings:
            if receiver in state.open_mappings:
                return f"mapping-length:{receiver}:{state.mapping_versions.get(receiver, 0)}"
            return "constant:" + repr(len(state.mappings[receiver]))
        if token.startswith("constant:"):
            try:
                value = ast.literal_eval(token.removeprefix("constant:"))
            except (ValueError, SyntaxError):
                pass
            else:
                if isinstance(value, (str, bytes)):
                    return "constant:" + repr(len(value))
                state.exit, state.result = "raise", "constant:None"
                return "unknown:exception"
        self.issue(node, "length requires a known inert collection")
        return "unknown:length"

    def comprehension(
        self, node: ast.DictComp | ast.ListComp, state: _State, info: _Info
    ) -> list[tuple[_State, str]]:
        """Lower eager finite comprehensions while preserving their local scope."""
        if any(generator.is_async for generator in node.generators) or any(
            isinstance(part, ast.NamedExpr) for part in ast.walk(node)
        ):
            self.issue(
                node,
                "async or assignment-expression comprehension requires a scope model",
            )
            return [(state, "unknown:comprehension")]
        self.serial += 1
        # These are internal AST bindings, never valid Python identifiers.
        temporary = f"\0comprehension:{self.serial}"
        iterable_name, result_name, key_name = (
            temporary + suffix for suffix in (":iterable", ":result", ":key")
        )
        targets = {
            part.id
            for generator in node.generators
            for part in ast.walk(generator.target)
            if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)
        }
        if isinstance(node, ast.DictComp):
            body: list[ast.stmt] = [
                ast.Assign(
                    targets=[ast.Name(id=key_name, ctx=ast.Store())], value=node.key
                ),
                ast.Assign(
                    targets=[
                        ast.Subscript(
                            value=ast.Name(id=result_name, ctx=ast.Load()),
                            slice=ast.Name(id=key_name, ctx=ast.Load()),
                            ctx=ast.Store(),
                        )
                    ],
                    value=node.value,
                ),
            ]
        else:
            body = [
                ast.Expr(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id=result_name, ctx=ast.Load()),
                            attr="append",
                            ctx=ast.Load(),
                        ),
                        args=[node.elt],
                        keywords=[],
                    )
                )
            ]
        for index in reversed(range(len(node.generators))):
            generator = node.generators[index]
            for condition in reversed(generator.ifs):
                body = [ast.If(test=condition, body=body, orelse=[])]
            body = [
                ast.For(
                    target=generator.target,
                    iter=generator.iter
                    if index
                    else ast.Name(id=iterable_name, ctx=ast.Load()),
                    body=body,
                    orelse=[],
                )
            ]
        lowered = ast.fix_missing_locations(ast.copy_location(body[0], node))
        results = []
        # Python evaluates the first iterable in the surrounding scope.
        evaluated = self.expr(node.generators[0].iter, state, info)
        if not evaluated:
            self.prune_calls([lowered])
        for current, iterable in evaluated:
            if current.exit != "normal":
                self.prune_calls([lowered])
                results.append((current, "unknown:exception"))
                continue
            outer = dict(current.env)
            current.env = {
                **outer,
                **{name: "comprehension-unbound:" + name for name in targets},
                iterable_name: iterable,
            }
            result = (
                self.mapping(current, {})
                if isinstance(node, ast.DictComp)
                else self.list_value(current, [])
            )
            current.env[result_name] = result
            for child in self.block([lowered], [current], info):
                child.env = dict(outer)
                results.append((child, result))
        return results

    def expr(
        self, node: ast.expr, state: _State, info: _Info
    ) -> list[tuple[_State, str]]:
        self.tick()
        if state.exit != "normal":
            for part in ast.walk(node):
                if isinstance(part, ast.Call):
                    self.pruned_calls.add(
                        (self.stack[-1], part.lineno, part.col_offset)
                    )
            return [(state, "unknown:exception")]
        if isinstance(node, ast.Name):
            value = self.symbol(node, state, info)
            if value.startswith("comprehension-unbound:"):
                state.exit, state.result = "raise", "constant:None"
            return [(state, value)]
        if isinstance(node, ast.Constant):
            return [(state, "constant:" + repr(node.value))]
        if isinstance(node, ast.UnaryOp) and isinstance(
            node.op, (ast.USub, ast.UAdd, ast.Invert)
        ):
            results = []
            for child, token in self.expr(node.operand, state, info):
                if token.startswith("constant:"):
                    try:
                        value = ast.literal_eval(token.removeprefix("constant:"))
                    except (ValueError, SyntaxError):
                        pass
                    else:
                        if type(value) in {int, bool}:
                            number = int(value)
                            computed = (
                                -number
                                if isinstance(node.op, ast.USub)
                                else ~number
                                if isinstance(node.op, ast.Invert)
                                else number
                            )
                            results.append((child, "constant:" + repr(computed)))
                            continue
                self.issue(node, "unary integer operation requires an inert value")
                results.append((child, "unknown:unary"))
            return results
        if isinstance(node, ast.NamedExpr):
            return [
                (child, token)
                for current, token in self.expr(node.value, state, info)
                for child in self.assign(node.target, token, current, info)
            ]
        if isinstance(node, (ast.DictComp, ast.ListComp)):
            return self.comprehension(node, state, info)
        if isinstance(node, ast.Attribute):
            results = []
            for child, value in self.expr(node.value, state, info):
                if value in child.supers:
                    results.append(
                        (child, self.super_attribute(value, node.attr, child, node))
                    )
                    continue
                if value in child.context_defaults:
                    if node.attr in {"get", "set", "reset"}:
                        token = f"context-method:{value}|{node.attr}"
                        child.contents[token] = (value,)
                        results.append((child, token))
                        continue
                    self.issue(node, "context variable attribute requires a model")
                if value in child.context_tokens:
                    self.issue(node, "context token attribute requires a model")
                if value in child.objects:
                    if value in child.unknown_objects:
                        self.issue(
                            node, "exceptional object fields require an alias model"
                        )
                    if node.attr in child.fields[value]:
                        results.append((child, child.fields[value][node.attr]))
                        continue
                    record = self.program.records.get(child.objects[value])
                    if record is not None and not record.slots:
                        default = dict(record.fields).get(node.attr)
                        if default is not None:
                            results.extend(self.expr(default, child, info))
                            continue
                    methods = self.program.methods(child.objects[value])
                    if node.attr in methods:
                        results.append(
                            (
                                child,
                                self.method_value(
                                    child.objects[value],
                                    methods[node.attr],
                                    value,
                                    child,
                                ),
                            )
                        )
                        continue
                    if node.attr.startswith("__"):
                        # Builtin object metadata/descriptors exist even when
                        # absent from the source method table. Treating them as
                        # missing would incorrectly prune a live continuation.
                        self.issue(node, "object protocol attribute requires a model")
                        results.append((child, "unknown:object-protocol"))
                        continue
                    if not value.startswith("instance:"):
                        child.exit, child.result = "raise", "constant:None"
                        results.append((child, "unknown:attribute"))
                        continue
                if value in child.lists:
                    if node.attr in {
                        "append",
                        "extend",
                        "insert",
                        "pop",
                        "clear",
                        "reverse",
                        "copy",
                    }:
                        token = f"list-method:{value}|{node.attr}"
                        child.contents[token] = (value,)
                        results.append((child, token))
                        continue
                    self.issue(node, "list attribute requires a method model")
                if value in child.mappings:
                    if value in child.unknown_mappings:
                        self.issue(
                            node, "exceptional mapping contents require an alias model"
                        )
                    if (
                        node.attr in {"setdefault", "pop", "update"}
                        and value in child.mapping_origins
                    ):
                        child.exit, child.result = "raise", "constant:None"
                        results.append((child, "unknown:attribute"))
                        continue
                    if node.attr in {
                        "get",
                        "copy",
                        "keys",
                        "values",
                        "items",
                        "setdefault",
                        "pop",
                        "update",
                    }:
                        token = f"mapping-method:{value}|{node.attr}"
                        child.contents[token] = (value,)
                        results.append((child, token))
                        continue
                    self.issue(node, "mapping attribute requires a method model")
                if value in child.tuples or value in child.contents:
                    self.issue(
                        node, "aggregate attribute requires an object projection model"
                    )
                results.append((child, self.attribute(value, node.attr, child)))
            return results
        if isinstance(node, (ast.Tuple, ast.List)):
            items: list[tuple[_State, tuple[str, ...]]] = [(state, ())]
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    if isinstance(node, ast.Tuple):
                        self.issue(
                            element, "tuple expansion requires an iterator model"
                        )
                        return [(state, "unknown:tuple")]
                    expanded = []
                    for current, values in items:
                        for child, value in self.expr(element.value, current, info):
                            extra = self.sequence_values(value, child, element)
                            expanded.append((child, (*values, *(extra or ()))))
                    items = expanded
                    self.tick(len(items))
                    continue
                items = [
                    (child, (*values, value))
                    for current, values in items
                    for child, value in self.expr(element, current, info)
                ]
                self.tick(len(items))
            results = []
            for current, values in items:
                if isinstance(node, ast.List):
                    results.append((current, self.list_value(current, values)))
                    continue
                self.serial += 1
                token = f"tuple:{self.serial}"
                current.tuples[token] = values
                results.append((current, token))
            return results
        if isinstance(node, ast.Dict):
            dict_states: list[tuple[_State, dict[str, str]]] = [(state, {})]
            for key_expr, expression in zip(node.keys, node.values, strict=True):
                following = []
                for current, dict_values in dict_states:
                    if key_expr is None:
                        for child, value in self.expr(expression, current, info):
                            if value not in child.mappings:
                                self.issue(
                                    expression, "mapping expansion requires known keys"
                                )
                                following.append((child, dict_values))
                            else:
                                if value in child.open_mappings:
                                    self.issue(
                                        expression,
                                        "open mapping merge requires a remainder model",
                                    )
                                if value in child.unknown_mappings:
                                    self.issue(
                                        expression,
                                        "exceptional mapping expansion is unresolved",
                                    )
                                following.append(
                                    (child, {**dict_values, **child.mappings[value]})
                                )
                    else:
                        for keyed, token in self.expr(key_expr, current, info):
                            literal = self.string_key(token)
                            if literal is None:
                                self.issue(
                                    key_expr, "mapping keys must be known strings"
                                )
                            for child, value in self.expr(expression, keyed, info):
                                following.append(
                                    (child, {**dict_values, str(literal): value})
                                )
                dict_states = following
                self.tick(len(dict_states))
            return [
                (current, self.mapping(current, dict_values))
                for current, dict_values in dict_states
            ]
        if isinstance(node, ast.Subscript):
            results = []
            for current, value in self.expr(node.value, state, info):
                if value in current.lists:
                    for child, list_index in self.list_key(node.slice, current, info):
                        if value in child.unknown_lists:
                            self.issue(
                                node, "exceptional list projection is unresolved"
                            )
                            results.append((child, "unknown:subscript"))
                        elif list_index is None or child.exit != "normal":
                            results.append((child, "unknown:subscript"))
                        else:
                            try:
                                selected = child.lists[value][list_index]
                            except (IndexError, ValueError):
                                child.exit, child.result = "raise", "constant:None"
                                results.append((child, "unknown:exception"))
                            else:
                                results.append(
                                    (
                                        child,
                                        self.list_value(child, selected)
                                        if isinstance(selected, list)
                                        else selected,
                                    )
                                )
                    continue
                if value in current.mappings:
                    if value in current.unknown_mappings:
                        self.issue(node, "exceptional mapping projection is unresolved")
                    for child, key in self.expr(node.slice, current, info):
                        literal = self.string_key(key)
                        if literal is None:
                            self.issue(
                                node, "mapping subscript requires a known string"
                            )
                            results.append((child, "unknown:subscript"))
                        else:
                            for projected, present, item in self.mapping_lookup(
                                child, value, literal
                            ):
                                if not present and projected.exit == "normal":
                                    projected.exit, projected.result = (
                                        "raise",
                                        "constant:None",
                                    )
                                results.append((projected, item))
                    continue
                if (
                    value not in current.tuples
                    or not isinstance(node.slice, ast.Constant)
                    or type(node.slice.value) is not int
                ):
                    self.issue(
                        node, "subscript requires a known tuple and constant index"
                    )
                    results.append((current, "unknown:subscript"))
                else:
                    tuple_items = current.tuples[value]
                    index = node.slice.value
                    if -len(tuple_items) <= index < len(tuple_items):
                        results.append((current, tuple_items[index]))
                    else:
                        current.exit = "raise"
                        results.append((current, "unknown:exception"))
            return results
        if isinstance(node, ast.IfExp):
            return [
                outcome
                for truth, expression in ((True, node.body), (False, node.orelse))
                for current in self.branch(node.test, state.clone(), info, truth)
                for outcome in self.expr(expression, current, info)
            ]
        if isinstance(node, ast.BoolOp):
            active = [(state, "constant:None")]
            finished = []
            for index, operand in enumerate(node.values):
                evaluated = [
                    outcome
                    for current, _ in active
                    for outcome in self.expr(operand, current, info)
                ]
                if index == len(node.values) - 1:
                    finished.extend(evaluated)
                else:
                    active = []
                    keep_going = isinstance(node.op, ast.And)
                    for current, token in evaluated:
                        active.extend(
                            (child, token)
                            for child in self.truth(token, current.clone(), keep_going)
                        )
                        finished.extend(
                            (child, token)
                            for child in self.truth(token, current, not keep_going)
                        )
                self.tick(len(active) + len(finished))
            return finished
        if isinstance(node, ast.Compare) or (
            isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
        ):
            return [
                (current, "constant:" + repr(truth))
                for truth in (True, False)
                for current in self.branch(node, state.clone(), info, truth)
            ]
        if isinstance(node, ast.Await):
            if isinstance(node.value, ast.Call):
                return self.call(node.value, state, info, awaited=True)
            self.issue(node, "only statically resolved coroutine calls can be awaited")
        elif isinstance(node, ast.Call):
            return self.call(node, state, info, awaited=False)
        else:
            self.issue(node, f"unsupported expression: {type(node).__name__}")
        return [(state, "unknown:expression")]

    def call(
        self, node: ast.Call, state: _State, info: _Info, *, awaited: bool
    ) -> list[tuple[_State, str]]:
        self.calls.add((self.stack[-1], node.lineno, node.col_offset))
        evaluated: list[tuple[_State, str, list[str], dict[str, str], str | None]] = [
            (child, callee, [], {}, None)
            for child, callee in self.expr(node.func, state, info)
        ]
        for arg in node.args:
            expanded = []
            for current, callee, args, kwargs, tail in evaluated:
                expression = arg.value if isinstance(arg, ast.Starred) else arg
                for child, value in self.expr(expression, current, info):
                    if isinstance(arg, ast.Starred):
                        if value in child.lists:
                            extra = self.sequence_values(value, child, arg) or ()
                        elif value not in child.tuples:
                            self.issue(arg, "argument expansion requires a known tuple")
                            extra = ()
                        else:
                            extra = child.tuples[value]
                    else:
                        extra = (value,)
                    expanded.append((child, callee, [*args, *extra], kwargs, tail))
            evaluated = expanded
            self.tick(len(evaluated))
        for kw in node.keywords:
            expanded = []
            for current, callee, args, kwargs, tail in evaluated:
                for child, value in self.expr(kw.value, current, info):
                    remainder = tail
                    if kw.arg is None:
                        if value not in child.mappings:
                            self.issue(
                                kw.value,
                                "keyword expansion requires known mapping keys",
                            )
                        if value in child.unknown_mappings:
                            self.issue(
                                kw.value, "exceptional keyword expansion is unresolved"
                            )
                        extra_kwargs = child.mappings.get(value, {})
                        if value in child.open_mappings:
                            if remainder is not None:
                                self.issue(
                                    node,
                                    "multiple open keyword expansions require a merge model",
                                )
                            else:
                                remainder = self.copy_mapping(
                                    child, value, remainder=True
                                )
                    else:
                        extra_kwargs = {kw.arg: value}
                    if kwargs.keys() & extra_kwargs.keys():
                        child.exit, child.result = "raise", "constant:None"
                    expanded.append(
                        (child, callee, args, {**kwargs, **extra_kwargs}, remainder)
                    )
            evaluated = expanded
            self.tick(len(evaluated))
        normalized = []
        for current, callee, args, kwargs, tail in evaluated:
            normalized.extend(
                self.expand_keywords(current, callee, args, kwargs, tail, node)
            )
            self.tick(len(normalized))
        result: list[tuple[_State, str]] = []
        for current, callee, args, kwargs, tail in normalized:
            if current.exit != "normal":
                result.append((current, "unknown:exception"))
                continue
            kind, _, target = callee.partition(":")
            if kind == "bound":
                receiver, target = target.split("|", 1)
                args = ["instance:" + receiver, *args]
            elif kind == "object-bound":
                receiver, target = target.split("|", 1)
                args = [receiver, *args]
            elif kind == "class-bound":
                owner, target = target.split("|", 1)
                args = ["class:" + owner, *args]
            if kind == "class" and target in self.program.typed_dicts:
                kind = "mapping-constructor"
            if kind == "class":
                if awaited:
                    self.issue(node, "class construction cannot be awaited")
                methods = self.program.methods(target)
                self.serial += 1
                instance = f"object:{self.serial}"
                current.objects[instance] = target
                current.fields[instance] = {}
                initializer = methods.get("__init__")
                if target in self.program.records:
                    result.extend(
                        self.construct_record(
                            target, instance, args, kwargs, current, node
                        )
                    )
                elif initializer is None:
                    if args or kwargs:
                        self.issue(
                            node, "constructor arguments require a source initializer"
                        )
                    result.append((current, instance))
                elif isinstance(
                    self.program.functions[initializer].node, ast.AsyncFunctionDef
                ):
                    self.issue(
                        node, "async initializer requires an object protocol model"
                    )
                    result.append((current, "unknown:object"))
                else:
                    self.edges.add((self.stack[-1], initializer))
                    for child, returned in self.invoke(
                        initializer,
                        [*self.method_arguments(target, initializer, instance), *args],
                        kwargs,
                        current,
                    ):
                        if child.exit == "normal" and returned != "constant:None":
                            self.issue(node, "initializer must return None")
                        result.append((child, instance))
                continue
            if kind == "builtin":
                if awaited:
                    self.issue(node, "builtin data operations cannot be awaited")
                if target == "super":
                    result.append(
                        (current, self.super_value(args, kwargs, current, node, info))
                    )
                elif target == "contextvars.ContextVar":
                    if len(args) != 1 or kwargs.keys() - {"default"}:
                        current.exit, current.result = "raise", "constant:None"
                        result.append((current, "unknown:exception"))
                    elif self.string_key(args[0]) is None:
                        self.issue(
                            node, "context variable name requires a native string"
                        )
                        result.append((current, "unknown:context"))
                    else:
                        self.serial += 1
                        token = f"context-var:local:{self.serial}"
                        current.context_defaults[token] = kwargs.get("default")
                        current.context_values[token] = None
                        self.context_contents(current, token)
                        result.append((current, token))
                elif (
                    target in {"threading.RLock", "_thread.RLock"}
                    and not args
                    and not kwargs
                ):
                    self.serial += 1
                    token = f"lock:{self.serial}"
                    current.locks.add(token)
                    current.contents[token] = ()
                    result.append((current, token))
                elif target == "isinstance":
                    if len(args) != 2 or kwargs:
                        current.exit, current.result = "raise", "constant:None"
                        result.append((current, "unknown:exception"))
                    else:
                        result.extend(
                            self.instance_check(args[0], args[1], current, node)
                        )
                elif target in _CAST_NAMES:
                    cast_parameters = ("typ", "val")
                    if (
                        len(args) > 2
                        or any(
                            key not in cast_parameters
                            or key in cast_parameters[: len(args)]
                            for key in kwargs
                        )
                        or len(args) + len(kwargs) != 2
                    ):
                        current.exit, current.result = "raise", "constant:None"
                        result.append((current, "unknown:exception"))
                    else:
                        bound = dict(zip(cast_parameters, args))
                        bound.update(kwargs)
                        result.append((current, bound["val"]))
                elif (
                    target == "types.MappingProxyType" and len(args) == 1 and not kwargs
                ):
                    if args[0] not in current.mappings:
                        self.issue(node, "mapping proxy requires a known mapping")
                        result.append((current, "unknown:proxy"))
                    else:
                        self.serial += 1
                        token = f"mapping:{self.serial}"
                        current.mappings[token] = current.mappings[args[0]]
                        current.mapping_origins[token] = args[0]
                        if args[0] in current.open_mappings:
                            current.open_mappings[token] = current.open_mappings[
                                args[0]
                            ]
                        if args[0] in current.unknown_mappings:
                            current.unknown_mappings.add(token)
                        result.append((current, token))
                elif target == "list":
                    if len(args) > 1 or kwargs:
                        current.exit, current.result = "raise", "constant:None"
                        result.append((current, "unknown:exception"))
                    else:
                        values = (
                            self.sequence_values(args[0], current, node) if args else ()
                        )
                        result.append(
                            (
                                current,
                                self.list_value(current, values)
                                if values is not None
                                else "unknown:list",
                            )
                        )
                elif target == "tuple" and len(args) <= 1 and not kwargs:
                    if not args:
                        self.serial += 1
                        token = f"tuple:{self.serial}"
                        current.tuples[token] = ()
                        result.append((current, token))
                    elif args[0] in current.tuples:
                        result.append((current, args[0]))
                    else:
                        converted = self.sequence_values(args[0], current, node)
                        if converted is None:
                            result.append((current, "unknown:tuple"))
                        else:
                            self.serial += 1
                            token = f"tuple:{self.serial}"
                            current.tuples[token] = converted
                            result.append((current, token))
                elif target == "frozenset" and len(args) <= 1 and not kwargs:
                    if args and args[0] in current.frozen_sets:
                        result.append((current, args[0]))
                    else:
                        converted = (
                            self.sequence_values(args[0], current, node) if args else ()
                        )
                        result.append(
                            (
                                current,
                                "unknown:frozenset"
                                if converted is None
                                else self.frozen_set(converted, current, node),
                            )
                        )
                elif target == "len" and len(args) == 1 and not kwargs:
                    result.append(
                        (current, self.collection_length(args[0], current, node))
                    )
                elif target == "object.__setattr__" and len(args) == 3 and not kwargs:
                    receiver, key, value = args
                    field_name = self.string_key(key)
                    if (
                        receiver not in current.objects
                        or field_name is None
                        or field_name.startswith("__")
                    ):
                        self.issue(
                            node,
                            "object setter requires a known receiver and ordinary field",
                        )
                    elif receiver in current.unknown_objects:
                        self.issue(node, "exceptional object setter is unresolved")
                    else:
                        current.revoke(receiver)
                        current.fields[receiver][field_name] = value
                    result.append((current, "constant:None"))
                else:
                    self.issue(
                        node, "builtin data operation requires an argument model"
                    )
                    result.append((current, "unknown:builtin"))
                continue
            if kind == "list-method":
                if awaited:
                    self.issue(node, "list operations cannot be awaited")
                receiver, method = target.split("|", 1)
                result.append(
                    (
                        current,
                        self.list_method(receiver, method, args, kwargs, current, node),
                    )
                )
                continue
            if kind == "object-init":
                if awaited:
                    self.issue(node, "native object initialization cannot be awaited")
                if args or kwargs:
                    current.exit, current.result = "raise", "constant:None"
                result.append((current, "constant:None"))
                continue
            if kind == "context-method":
                if awaited:
                    self.issue(node, "context variable methods cannot be awaited")
                receiver, method = target.split("|", 1)
                result.extend(
                    self.context_method(receiver, method, args, kwargs, current, node)
                )
                continue
            if kind in {"mapping-constructor", "mapping-method"}:
                if awaited:
                    self.issue(node, "mapping operations cannot be awaited")
                if kind == "mapping-constructor":
                    if len(args) > 1 or (args and args[0] not in current.mappings):
                        self.issue(node, "dict construction requires a known mapping")
                        result.append((current, "unknown:mapping"))
                    else:
                        if args and args[0] in current.unknown_mappings:
                            self.issue(node, "exceptional mapping copy is unresolved")
                        copied = (
                            self.copy_mapping(current, args[0])
                            if args
                            else self.mapping(current, {})
                        )
                        current.mappings[copied].update(kwargs)
                        result.append((current, copied))
                else:
                    receiver, method = target.split("|", 1)
                    if receiver in current.unknown_mappings:
                        self.issue(node, "exceptional mapping method is unresolved")
                    if method == "update":
                        if len(args) > 1:
                            current.exit, current.result = "raise", "constant:None"
                        elif args and (
                            args[0] not in current.mappings
                            or args[0] in current.open_mappings
                            or args[0] in current.unknown_mappings
                        ):
                            self.issue(
                                node, "mapping update requires a known finite mapping"
                            )
                        else:
                            updates = {
                                **(current.mappings[args[0]] if args else {}),
                                **kwargs,
                            }
                            if updates:
                                current.revoke(receiver)
                                current.mappings[receiver].update(updates)
                        result.append((current, "constant:None"))
                    elif method == "copy" and not args and not kwargs:
                        result.append((current, self.copy_mapping(current, receiver)))
                    elif (
                        method in {"keys", "values", "items"}
                        and not args
                        and not kwargs
                    ):
                        self.serial += 1
                        view = f"mapping-view:{self.serial}"
                        current.mapping_views[view] = (receiver, method)
                        # Views retain the live mapping, including capability
                        # aliases and dependencies used when revoking grants.
                        current.contents[view] = (receiver,)
                        result.append((current, view))
                    elif (
                        method in {"get", "pop", "setdefault"}
                        and 1 <= len(args) <= 2
                        and not kwargs
                    ):
                        literal = self.string_key(args[0])
                        if literal is None:
                            self.issue(
                                node, f"mapping {method} requires a known string"
                            )
                            result.append((current, "unknown:projection"))
                        else:
                            default = args[1] if len(args) == 2 else "constant:None"
                            for child, present, item in self.mapping_lookup(
                                current, receiver, literal
                            ):
                                if method == "pop" and present:
                                    self.mapping_delete(child, receiver, literal)
                                elif method == "pop" and not present and len(args) == 1:
                                    child.exit, child.result = "raise", "constant:None"
                                elif method == "setdefault" and not present:
                                    child.mappings[receiver][literal] = default
                                    child.revoke(receiver)
                                result.append((child, item if present else default))
                    else:
                        self.issue(node, "mapping method argument mismatch")
                        result.append((current, "unknown:mapping"))
                continue
            if kind == "exception":
                if awaited or kwargs:
                    self.issue(
                        node,
                        "builtin exception construction requires an ordinary positional call",
                    )
                self.serial += 1
                token = f"exception-value:{self.serial}"
                current.contents[token] = (*args, *kwargs.values())
                result.append((current, token))
                continue
            if kind not in {"bound", "object-bound", "class-bound", "callable"}:
                self.issue(node, f"unresolved call target: {ast.unparse(node.func)}")
                result.append((current, "unknown:call"))
                continue
            self.edges.add((self.stack[-1], target))
            if target in self.authorizers or target in self.operations:
                if awaited != (target in self.spec.async_terminals):
                    self.issue(node, "terminal await mode does not match its contract")
                primitive = self.authorizers.get(target) or self.operations[target]
                self.serial += 1
                token = f"result:{self.serial}"
                if kwargs or target in self.spec.terminal_parameters:
                    parameters = self.spec.terminal_parameters.get(target)
                    if parameters is None:
                        self.issue(
                            node,
                            "terminal keyword binding requires a declared signature",
                        )
                        result.append((current, "unknown:binding"))
                        continue
                    if len(args) > len(parameters) or any(
                        key not in parameters or key in parameters[: len(args)]
                        for key in kwargs
                    ):
                        self.issue(node, "terminal keyword argument binding mismatch")
                        result.append((current, "unknown:binding"))
                        continue
                    named = dict(zip(parameters, args))
                    named.update(kwargs)
                    args = [named.get(name, "missing:argument") for name in parameters]
                binding = self.binding(
                    primitive.permission, primitive.bindings, args, token, node
                )
                if target in self.authorizers:
                    decision_token = token + (
                        f".{primitive.decision}" if primitive.decision else ""
                    )
                    # Result-derived constraints refine the grant but must not
                    # stop a fresh decision superseding earlier authority.
                    scope = self.binding(
                        primitive.permission,
                        tuple(
                            item
                            for item in primitive.bindings
                            if item.startswith("arg:")
                        ),
                        args,
                        token,
                        node,
                    )
                    revoked = {
                        fact
                        for fact, old_scope in current.grant_scopes.items()
                        if old_scope == scope
                    }
                    current.approved.difference_update(revoked)
                    current.pending = {
                        key: value
                        for key, value in current.pending.items()
                        if current.decision_scopes.get(key) != scope
                    }
                    current.pending[decision_token] = binding
                    current.decision_scopes[decision_token] = scope
                    current.verdicts[decision_token] = _VERDICTS
                else:
                    required = [
                        binding,
                        *(
                            self.binding(
                                item.permission, item.bindings, args, token, node
                            )
                            for item in self.spec.requirements.get(target, ())
                        ),
                    ]
                    self.dispatches.append(
                        {
                            "function": self.stack[-1],
                            "line": node.lineno,
                            "target": target,
                            "bindings": list(binding),
                            "requirements": [
                                {
                                    "permission": fact[0],
                                    "bindings": list(fact[1:]),
                                    "authorized": fact in current.approved,
                                }
                                for fact in required
                            ],
                            "authorized": all(
                                fact in current.approved for fact in required
                            ),
                            "call_path": list(self.stack),
                        }
                    )
                    current.approved.difference_update(required)
                    current.pending = {
                        key: value
                        for key, value in current.pending.items()
                        if value not in required
                    }
                result.append((current, token))
            elif target in self.program.functions:
                child_info = self.program.functions[target]
                if isinstance(child_info.node, ast.AsyncFunctionDef) != awaited:
                    self.issue(
                        node,
                        "coroutine creation/scheduling requires an explicit await model",
                    )
                    result.append((current, "unknown:coroutine"))
                else:
                    result.extend(
                        self.invoke(target, args, kwargs, current, keyword_tail=tail)
                    )
            else:
                self.issue(node, f"source unavailable for call: {target}")
                result.append((current, "unknown:call"))
        return result

    def expand_keywords(
        self,
        state: _State,
        callee: str,
        args: list[str],
        kwargs: dict[str, str],
        tail: str | None,
        node: ast.Call,
    ) -> list[tuple[_State, str, list[str], dict[str, str], str | None]]:
        if tail is None or state.exit != "normal":
            return [(state, callee, args, kwargs, tail)]
        kind, _, target = callee.partition(":")
        implicit = 0
        if kind in {"bound", "object-bound", "class-bound"}:
            _, target = target.split("|", 1)
            implicit = 1
        if target in self.program.terminals:
            parameters = self.spec.terminal_parameters.get(target)
            if parameters is None:
                self.issue(node, "open terminal keywords require a declared signature")
                return [(state, callee, args, kwargs, None)]
            allowed = list(parameters)
            positional = list(parameters)
            accepts_extra = False
        elif (
            kind in {"callable", "bound", "object-bound", "class-bound"}
            and target in self.program.functions
        ):
            signature = self.program.functions[target].node.args
            allowed = [arg.arg for arg in [*signature.args, *signature.kwonlyargs]]
            positional = [arg.arg for arg in [*signature.posonlyargs, *signature.args]]
            accepts_extra = signature.kwarg is not None
        elif kind == "builtin" and target in _CAST_NAMES:
            allowed = ["typ", "val"]
            positional = list(allowed)
            accepts_extra = False
        else:
            self.issue(
                node, "open keyword expansion requires a source callable signature"
            )
            return [(state, callee, args, kwargs, None)]
        occupied = set(positional[: len(args) + implicit]) & set(allowed)
        active = [(state, dict(kwargs))]
        finished: list[tuple[_State, str, list[str], dict[str, str], str | None]] = []
        for key in dict.fromkeys([*kwargs, *allowed]):
            following = []
            for current, named in active:
                for child, present, value in self.mapping_lookup(current, tail, key):
                    if present and (key in kwargs or key in occupied):
                        child.exit, child.result = "raise", "constant:None"
                        finished.append((child, callee, args, named, None))
                    else:
                        updated = {**named, key: value} if present else named
                        following.append((child, updated))
            active = following
            self.tick(len(active) + len(finished))
        for current, named in active:
            if not accepts_extra:
                # An unenumerated extra key can raise before the callee starts.
                failed = current.clone()
                failed.exit, failed.result = "raise", "constant:None"
                finished.append((failed, callee, args, named, None))
            finished.append(
                (current, callee, args, named, tail if accepts_extra else None)
            )
        return finished

    def instance_check(
        self, value: str, classinfo: str, state: _State, node: ast.Call
    ) -> list[tuple[_State, str]]:
        """Model standard isinstance without trusting arbitrary type hooks."""
        self.tick()
        if classinfo in state.tuples:
            active = [state]
            finished: list[tuple[_State, str]] = []
            for item in state.tuples[classinfo]:
                remaining = []
                for current in active:
                    for child, checked in self.instance_check(
                        value, item, current, node
                    ):
                        if child.exit != "normal":
                            finished.append((child, checked))
                            continue
                        finished.extend(
                            (matched, "constant:True")
                            for matched in self.truth(checked, child.clone(), True)
                        )
                        remaining.extend(self.truth(checked, child, False))
                active = remaining
                self.tick(len(active) + len(finished))
            return [*finished, *((current, "constant:False") for current in active)]

        kind, _, name = classinfo.partition(":")
        if kind == "class" and name in self.program.typed_dicts:
            state.exit, state.result = "raise", "constant:None"
            return [(state, "unknown:exception")]
        if kind not in {"class", "builtin", "exception", "mapping-constructor"}:
            if (
                classinfo in state.objects
                and "__instancecheck__"
                in self.program.methods(state.objects[classinfo])
            ):
                # Python also accepts an ordinary object implementing this
                # protocol as classinfo; it is not necessarily a TypeError.
                self.issue(node, "custom instance-check protocol requires a model")
                return [(state, "unknown:isinstance")]
            if (
                classinfo.startswith("constant:")
                or classinfo in state.objects
                or classinfo in state.mappings
                or classinfo in state.lists
                or kind
                in {
                    "callable",
                    "bound",
                    "object-bound",
                    "class-bound",
                    "mapping-method",
                    "list-method",
                }
            ):
                state.exit, state.result = "raise", "constant:None"
                return [(state, "unknown:exception")]
            self.issue(
                node, "isinstance class information requires a static type model"
            )
            return [(state, "unknown:isinstance")]
        if kind == "builtin" and name in {"isinstance", "len"}:
            state.exit, state.result = "raise", "constant:None"
            return [(state, "unknown:exception")]
        if self.program.type_lineage(name) is None:
            self.issue(node, "isinstance type has an unresolved metaclass or ancestry")
            return [(state, "unknown:isinstance")]

        nominal = state.objects.get(value)
        if value in state.tuples:
            nominal = "tuple"
        elif value in state.lists:
            nominal = "list"
        elif value in state.frozen_sets:
            nominal = "frozenset"
        elif value in state.mappings:
            nominal = (
                "types.MappingProxyType" if value in state.mapping_origins else "dict"
            )
        elif value.startswith("constant:"):
            try:
                literal = ast.literal_eval(value.removeprefix("constant:"))
            except (ValueError, SyntaxError):
                pass
            else:
                nominal = (
                    "types.NoneType" if literal is None else type(literal).__name__
                )
        if nominal is not None:
            lineage = self.program.type_lineage(nominal)
            if lineage is None:
                self.issue(node, "isinstance value has an unresolved type ancestry")
            else:
                return [(state, "constant:" + repr(name in lineage))]
        if name == "object":
            return [(state, "constant:True")]
        # A positive test does not imply an exact builtin receiver: subclasses
        # may override methods. Preserve identity and leave those calls unknown.
        return [(state, f"instance-test:{value}|{name}")]

    def construct_record(
        self,
        owner: str,
        instance: str,
        args: list[str],
        kwargs: dict[str, str],
        state: _State,
        node: ast.Call,
    ) -> list[tuple[_State, str]]:
        record = self.program.records[owner]
        names = [name for name, _ in record.fields]
        if len(args) > len(names) or any(
            key not in names or key in names[: len(args)] for key in kwargs
        ):
            self.issue(node, "dataclass constructor argument mismatch")
            return [(state, "unknown:record")]
        supplied = {**dict(zip(names, args)), **kwargs}
        factories = dict(record.factories)
        default_scope = _Info(
            owner.rsplit(".", 1)[0], owner, self.program.functions[self.stack[-1]].node
        )
        states = [state]
        for name, default in record.fields:
            following = []
            for current in states:
                if current.exit != "normal":
                    following.append(current)
                elif name in factories:
                    factory_call = ast.copy_location(
                        ast.Call(
                            func=copy.deepcopy(factories[name]), args=[], keywords=[]
                        ),
                        node,
                    )
                    for selected, use_factory in self.factory_paths(
                        supplied.get(name), current
                    ):
                        if not use_factory:
                            selected.fields[instance][name] = supplied[name]
                            following.append(selected)
                            continue
                        caller_env = selected.env
                        selected.env = {}
                        for child, value in self.call(
                            factory_call, selected, default_scope, awaited=False
                        ):
                            child.env = dict(caller_env)
                            if child.exit == "normal":
                                child.fields[instance][name] = value
                            following.append(child)
                elif name in supplied:
                    current.fields[instance][name] = supplied[name]
                    following.append(current)
                elif default is None:
                    self.issue(node, f"required dataclass field unavailable: {name}")
                    following.append(current)
                else:
                    for child, value in self.expr(default, current, default_scope):
                        if child.exit == "normal":
                            child.fields[instance][name] = value
                        following.append(child)
            states = following
            self.tick(len(states))
        exited = [(current, instance) for current in states if current.exit != "normal"]
        states = [current for current in states if current.exit == "normal"]
        if not states:
            return exited
        post_init = self.program.methods(owner).get("__post_init__")
        if post_init is None:
            return [*exited, *((current, instance) for current in states)]
        if isinstance(self.program.functions[post_init].node, ast.AsyncFunctionDef):
            self.issue(node, "asynchronous dataclass post-initializer requires a model")
            return [*exited, *((current, "unknown:record") for current in states)]
        self.edges.add((self.stack[-1], post_init))
        return exited + [
            (child, instance)
            for current in states
            for child, _ in self.invoke(
                post_init,
                self.method_arguments(owner, post_init, instance),
                {},
                current,
            )
        ]

    def factory_paths(
        self, value: str | None, state: _State
    ) -> list[tuple[_State, bool]]:
        """A supplied unknown may still be the generated initializer's sentinel."""
        sentinel = "namespace:dataclasses._HAS_DEFAULT_FACTORY"
        if value is None or value == sentinel:
            return [(state, True)]
        if (
            value in state.objects
            or value in state.tuples
            or value in state.lists
            or value in state.mappings
            or value in state.contents
            or value.startswith(
                (
                    "constant:",
                    "callable:",
                    "bound:",
                    "object-bound:",
                    "class-bound:",
                    "class:",
                    "builtin:",
                    "mapping-method:",
                    "list-method:",
                    "mapping-constructor:",
                    "exception:",
                )
            )
        ):
            return [(state, False)]
        key = ("is", *sorted((value, sentinel)))
        if key in state.predicates:
            return [(state, state.predicates[key])]
        results = []
        for use_factory in (False, True):
            current = state.clone()
            current.predicates[key] = use_factory
            results.append((current, use_factory))
        return results

    def binding(
        self,
        permission: str,
        selectors: tuple[str, ...],
        args: list[str],
        result: str,
        node: ast.AST,
    ) -> tuple[str, ...]:
        values = [permission]
        for selector in selectors:
            kind, _, path = selector.partition(":")
            if kind == "result":
                values.append(result + ("." + path if path else ""))
            else:
                index, dot, suffix = path.partition(".")
                if int(index) >= len(args) or args[int(index)] == "missing:argument":
                    self.issue(node, "terminal binding argument unavailable")
                    values.append("unknown:binding")
                else:
                    values.append(args[int(index)] + (dot + suffix if dot else ""))
        return tuple(values)

    def branch(
        self, node: ast.expr, state: _State, info: _Info, truth: bool
    ) -> list[_State]:
        if isinstance(node, ast.Constant):
            return [state] if bool(node.value) == truth else []
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.branch(node.operand, state, info, not truth)
        if isinstance(node, ast.BoolOp):
            all_required = isinstance(node.op, ast.And) == truth
            active = [state]
            results: list[_State] = []
            for value in node.values:
                if not all_required:
                    results.extend(
                        child
                        for current in active
                        for child in self.branch(value, current.clone(), info, truth)
                    )
                active = [
                    child
                    for current in active
                    for child in self.branch(
                        value, current, info, truth if all_required else not truth
                    )
                ]
                self.tick(len(active) + len(results))
            return active if all_required else results
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.In, ast.NotIn))
        ):
            results = []
            for current, needle in self.expr(node.left, state, info):
                for child, container in self.expr(node.comparators[0], current, info):
                    if child.exit != "normal":
                        results.append(child)
                        continue
                    receiver, view = child.mapping_views.get(
                        container, (container, "keys")
                    )
                    hashed = container in child.frozen_sets or (
                        receiver in child.mappings and view == "keys"
                    )
                    try:
                        member = self.inert_hash_value(needle, child)
                        if container in child.frozen_sets:
                            collection = self.inert_hash_value(container, child)
                        elif (
                            receiver in child.mappings
                            and view == "keys"
                            and receiver not in child.unknown_mappings
                        ):
                            if receiver in child.open_mappings and isinstance(
                                member, str
                            ):
                                for projected, present, _ in self.mapping_lookup(
                                    child, receiver, member
                                ):
                                    if present == (
                                        truth != isinstance(node.ops[0], ast.NotIn)
                                    ):
                                        results.append(projected)
                                continue
                            collection = child.mappings[receiver]
                        elif container in child.tuples:
                            collection = self.inert_hash_value(container, child)
                        else:
                            raise ValueError("unmodeled membership receiver")
                        matches = member in collection
                    except TypeError:
                        if hashed:
                            child.exit, child.result = "raise", "constant:None"
                        else:
                            self.issue(
                                node,
                                "membership equality requires an inert collection model",
                            )
                        results.append(child)
                    except (ValueError, SyntaxError):
                        self.issue(node, "membership requires known inert values")
                        results.append(child)
                    else:
                        if matches == (truth != isinstance(node.ops[0], ast.NotIn)):
                            results.append(child)
            return results
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Is, ast.IsNot))
        ):
            left, right = node.left, node.comparators[0]
            if (
                isinstance(left, ast.Attribute)
                and left.attr == "verdict"
                and isinstance(right, ast.Attribute)
                and right.attr in _VERDICTS
                and isinstance(right.value, ast.Name)
                and right.value.id == "Verdict"
                and "Verdict" not in state.env
                and self.program.qualify(info.module, "Verdict")
                not in self.program.constants
            ):
                results = []
                for current, token in self.expr(left.value, state, info):
                    equal = truth != isinstance(node.ops[0], (ast.NotEq, ast.IsNot))
                    domain = current.verdicts.get(token, _VERDICTS | {"UNKNOWN"})
                    if token in current.objects:
                        if token in current.unknown_objects:
                            self.issue(node, "exceptional object verdict is unresolved")
                        field_value = current.fields[token].get(
                            "verdict", "unknown:verdict"
                        )
                        prefix = (
                            "namespace:"
                            + self.program.qualify(info.module, "Verdict")
                            + "."
                        )
                        if (
                            field_value.startswith(prefix)
                            and field_value[len(prefix) :] in _VERDICTS
                        ):
                            domain = frozenset({field_value[len(prefix) :]})
                    remaining = domain & (
                        {right.attr}
                        if equal
                        else (_VERDICTS | {"UNKNOWN"}) - {right.attr}
                    )
                    if remaining:
                        current.verdicts[token] = frozenset(remaining)
                        if remaining == {"ALLOW"} and token in current.pending:
                            current.approved.add(current.pending[token])
                            current.grant_scopes[current.pending[token]] = (
                                current.decision_scopes[token]
                            )
                        results.append(current)
                return results
            if isinstance(node.ops[0], (ast.Is, ast.IsNot)):
                results = []
                equal = truth != isinstance(node.ops[0], ast.IsNot)
                for current, a in self.expr(left, state, info):
                    for child, b in self.expr(right, current, info):
                        # Distinct abstract inputs may alias; only identical
                        # identities or the singleton literals settle identity.
                        if a == b:
                            if equal:
                                results.append(child)
                        elif a in {
                            "constant:None",
                            "constant:True",
                            "constant:False",
                        } and b in {"constant:None", "constant:True", "constant:False"}:
                            if not equal:
                                results.append(child)
                        else:
                            key = ("is", *sorted((a, b)))
                            if child.predicates.get(key, equal) == equal:
                                child.predicates[key] = equal
                                results.append(child)
                return results
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(
                node.ops[0], (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
            )
        ):
            compare = {
                ast.Eq: operator.eq,
                ast.NotEq: operator.ne,
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.Gt: operator.gt,
                ast.GtE: operator.ge,
            }[type(node.ops[0])]
            results = []
            for current, a in self.expr(node.left, state, info):
                for child, b in self.expr(node.comparators[0], current, info):
                    if not all(
                        value.startswith("constant:") or value in child.frozen_sets
                        for value in (a, b)
                    ):
                        self.issue(
                            node,
                            "ordered/equality comparison requires known inert values",
                        )
                        results.append(child)
                        continue
                    try:
                        first = self.inert_hash_value(a, child)
                        second = self.inert_hash_value(b, child)
                    except (TypeError, ValueError, SyntaxError):
                        self.issue(node, "scalar comparison value is unresolved")
                        results.append(child)
                        continue
                    try:
                        matches = compare(first, second)
                    except (TypeError, ValueError):
                        child.exit, child.result = "raise", "constant:None"
                        results.append(child)
                    else:
                        if matches == truth:
                            results.append(child)
            return results
        if isinstance(
            node,
            (
                ast.Name,
                ast.Attribute,
                ast.Call,
                ast.Await,
                ast.Subscript,
                ast.Tuple,
                ast.List,
                ast.IfExp,
                ast.NamedExpr,
            ),
        ):
            return [
                child
                for current, token in self.expr(node, state, info)
                for child in self.truth(token, current, truth)
            ]
        self.issue(node, "branch predicate requires a model")
        return [state]

    def truth(self, token: str, state: _State, truth: bool) -> list[_State]:
        """Split inert values without evaluating user-defined Python coercions."""
        if state.exit != "normal":
            return [state]
        if token.startswith("constant:"):
            try:
                value = ast.literal_eval(token.removeprefix("constant:"))
            except (ValueError, SyntaxError):
                pass
            else:
                return [state] if bool(value) == truth else []
        if token in state.tuples:
            return [state] if bool(state.tuples[token]) == truth else []
        if token in state.lists and token not in state.unknown_lists:
            return [state] if bool(state.lists[token]) == truth else []
        if token in state.frozen_sets:
            return [state] if bool(state.frozen_sets[token]) == truth else []
        if (
            token in state.mappings
            and token not in state.unknown_mappings
            and (token not in state.open_mappings or state.mappings[token])
        ):
            return [state] if bool(state.mappings[token]) == truth else []
        if token in state.mapping_views:
            receiver, _ = state.mapping_views[token]
            if receiver not in state.unknown_mappings and (
                receiver not in state.open_mappings or state.mappings[receiver]
            ):
                return [state] if bool(state.mappings[receiver]) == truth else []
        receiver = state.mapping_views.get(token, (token, ""))[0]
        if (
            receiver in state.open_mappings
            and receiver not in state.unknown_mappings
            and not truth
        ):
            # A false builtin mapping truth test proves that this concrete map
            # is empty. Its independent shallow copies may still have keys.
            for alias, values in state.mappings.items():
                if values is state.mappings[receiver]:
                    state.open_mappings.pop(alias, None)
        key = ("truth", token)
        if state.predicates.get(key, truth) != truth:
            return []
        state.predicates[key] = truth
        return [state]

    def assign(
        self, target: ast.expr, token: str | None, state: _State, info: _Info
    ) -> list[_State]:
        if state.exit != "normal":
            return [state]
        if isinstance(target, ast.Name):
            if token is None:
                if target.id not in state.env:
                    state.exit, state.result = "raise", "constant:None"
                state.env.pop(target.id, None)
            else:
                state.env[target.id] = token
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = (
                tuple(state.lists[token])
                if token in state.lists and token not in state.unknown_lists
                else state.tuples.get(token)
                if token is not None
                else None
            )
            if values is None:
                self.issue(target, "unpacking requires a known immutable tuple")
            elif len(target.elts) != len(values):
                state.exit, state.result = "raise", "constant:None"
            else:
                states = [state]
                for item, value in zip(target.elts, values, strict=True):
                    states = [
                        outcome
                        for current in states
                        for outcome in self.assign(item, value, current, info)
                    ]
                return states
        elif isinstance(target, ast.Subscript):
            results = []
            for current, receiver in self.expr(target.value, state, info):
                if receiver in current.lists:
                    for child, index in self.list_key(target.slice, current, info):
                        if child.exit != "normal" or index is None:
                            results.append(child)
                            continue
                        if receiver in child.unknown_lists:
                            self.issue(
                                target, "exceptional list mutation is unresolved"
                            )
                            results.append(child)
                            continue
                        updated = list(child.lists[receiver])
                        try:
                            if token is None:
                                del updated[index]
                            elif isinstance(index, slice):
                                values = self.sequence_values(token, child, target)
                                if values is None:
                                    results.append(child)
                                    continue
                                updated[index] = values
                            else:
                                updated[index] = token
                        except (IndexError, ValueError):
                            child.exit, child.result = "raise", "constant:None"
                        else:
                            child.revoke(receiver)
                            child.lists[receiver][:] = updated
                        results.append(child)
                    continue
                for child, key in self.expr(target.slice, current, info):
                    if child.exit != "normal":
                        results.append(child)
                        continue
                    literal = self.string_key(key)
                    if receiver not in child.mappings or literal is None:
                        self.issue(
                            target,
                            "mapping mutation requires known receiver and string key",
                        )
                    elif receiver in child.unknown_mappings:
                        self.issue(target, "exceptional mapping mutation is unresolved")
                    elif receiver in child.mapping_origins:
                        child.exit, child.result = "raise", "constant:None"
                    elif token is None:
                        for deleted, present, _ in self.mapping_lookup(
                            child, receiver, literal
                        ):
                            if not present:
                                deleted.exit, deleted.result = "raise", "constant:None"
                            else:
                                self.mapping_delete(deleted, receiver, literal)
                            results.append(deleted)
                        continue
                    else:
                        child.mappings[receiver][literal] = token
                        child.revoke(receiver)
                    results.append(child)
            return results
        elif isinstance(target, ast.Attribute):
            results = []
            for child, receiver in self.expr(target.value, state, info):
                if child.exit != "normal":
                    results.append(child)
                    continue
                if receiver not in child.objects:
                    self.issue(target, "object mutation requires a known receiver")
                elif receiver in child.unknown_objects:
                    self.issue(target, "exceptional object mutation is unresolved")
                elif (
                    child.objects[receiver] in self.program.records
                    and self.program.records[child.objects[receiver]].frozen
                ):
                    child.exit, child.result = "raise", "constant:None"
                elif target.attr.startswith("__"):
                    self.issue(target, "object protocol mutation requires a model")
                elif token is None:
                    if target.attr not in child.fields[receiver]:
                        child.exit, child.result = "raise", "constant:None"
                    else:
                        del child.fields[receiver][target.attr]
                        child.revoke(receiver)
                else:
                    child.fields[receiver][target.attr] = token
                    child.revoke(receiver)
                results.append(child)
            return results
        else:
            self.issue(target, "heap assignment requires an alias model")
        return [state]

    def try_block(self, node: ast.Try, state: _State, info: _Info) -> list[_State]:
        # A callee's exception remains live while any enclosing handler or
        # finalizer can observe it. The depth crosses source-function calls.
        self.exception_continuations += 1
        try:
            outcomes = self._try_block(node, state, info)
        finally:
            self.exception_continuations -= 1
        outcomes = self.settle_exceptions(outcomes, node)
        self.tick(len(outcomes))
        return outcomes

    def _try_block(self, node: ast.Try, state: _State, info: _Info) -> list[_State]:
        body = self.block(node.body, [state.clone()], info)
        normal = self.block(
            node.orelse, [item for item in body if item.exit == "normal"], info
        )
        exits = [item for item in body if item.exit != "normal"]
        # Any prefix can fail. Havoc assigned locals and forget all authority at
        # exceptional entry; a handler/finalizer must establish fresh authority.
        # This is an overapproximation, not a guess at exception timing or type.
        exceptional = state.clone()
        exceptional.revoke()
        exceptional.unknown_mappings.update(exceptional.mappings)
        exceptional.unknown_lists.update(exceptional.lists)
        exceptional.unknown_objects.update(exceptional.objects)
        exceptional.unknown_contexts.update(exceptional.context_defaults)
        causes = []
        for outcome in body:
            if outcome.exit == "raise":
                exceptional.tuples.update(outcome.tuples)
                exceptional.lists.update(outcome.lists)
                exceptional.list_versions.update(outcome.list_versions)
                exceptional.unknown_lists.update(outcome.lists)
                exceptional.frozen_sets.update(outcome.frozen_sets)
                exceptional.contents.update(outcome.contents)
                exceptional.locks.update(outcome.locks)
                exceptional.mappings.update(outcome.mappings)
                exceptional.mapping_origins.update(outcome.mapping_origins)
                exceptional.mapping_views.update(outcome.mapping_views)
                exceptional.mapping_versions.update(outcome.mapping_versions)
                exceptional.open_mappings.update(outcome.open_mappings)
                exceptional.unknown_mappings.update(outcome.mappings)
                exceptional.objects.update(outcome.objects)
                exceptional.fields.update(outcome.fields)
                exceptional.unknown_objects.update(outcome.objects)
                exceptional.context_defaults.update(outcome.context_defaults)
                exceptional.supers.update(outcome.supers)
                exceptional.context_values.update(outcome.context_values)
                exceptional.context_tokens.update(outcome.context_tokens)
                exceptional.used_context_tokens.update(outcome.used_context_tokens)
                exceptional.unknown_contexts.update(outcome.context_defaults)
                causes.append(outcome.result)
        self.serial += 1
        exception_token = f"exception-union:{self.serial}"
        exceptional.contents[exception_token] = tuple(causes)
        exceptional.exception = exception_token
        exceptional.result = exception_token
        # A finalizer also runs after failures inside else/handler suites.
        # Include their prefixes in the conservative exceptional environment.
        prefix_suites = [*node.body, *node.orelse, *node.handlers]
        for statement in prefix_suites:
            for part in ast.walk(statement):
                if isinstance(part, ast.Name) and isinstance(
                    part.ctx, (ast.Store, ast.Del)
                ):
                    self.serial += 1
                    exceptional.env[part.id] = f"exception-local:{self.serial}"
        for handler in node.handlers:
            entries = [exceptional.clone()]
            if handler.type is not None:
                entries = []
                for child, token in self.expr(handler.type, exceptional.clone(), info):
                    types = child.tuples.get(token, (token,))
                    if not all(item.startswith("exception:") for item in types):
                        self.issue(
                            handler, "exception type requires a builtin exception model"
                        )
                    entries.append(child)
            for entry in entries:
                if handler.name:
                    entry.env[handler.name] = exception_token
            handled = self.block(handler.body, entries, info)
            for child in handled:
                if handler.name:
                    child.env.pop(handler.name, None)
            exits.extend(handled)
        exceptional.exit = "raise"
        exits.append(exceptional)
        results = []
        for current in (*normal, *exits):
            previous_exit, previous_result = current.exit, current.result
            current.exit = "normal"
            for final in self.block(node.finalbody, [current], info):
                if final.exit == "normal":
                    final.exit, final.result = previous_exit, previous_result
                results.append(final)
        return results

    def settle_exceptions(self, states: list[_State], node: ast.AST) -> list[_State]:
        """Check uncaught payloads before retiring paths with no continuation."""
        if self.exception_continuations:
            return states
        remaining = []
        for state in states:
            if state.exit != "raise":
                remaining.append(state)
                continue
            self.settled_exceptions += 1
            if self.escapes(state.result, state):
                self.issue(
                    node,
                    "executable, receiver or unresolved capability escapes through uncaught exception",
                )
        return remaining

    def with_block(self, node: ast.With, state: _State, info: _Info) -> list[_State]:
        """Follow synchronous native RLock suites, including all body effects."""
        states = [state]
        for item in node.items:
            following = []
            for current in states:
                for child, manager in self.expr(item.context_expr, current, info):
                    if child.exit != "normal":
                        following.append(child)
                        continue
                    if manager in child.locks:
                        entered = "constant:True"
                    else:
                        self.issue(node, "context manager requires a protocol model")
                        child.revoke()
                        child.unknown_objects.update(child.objects)
                        child.unknown_mappings.update(child.mappings)
                        child.unknown_lists.update(child.lists)
                        child.unknown_contexts.update(child.context_defaults)
                        entered = "unknown:context-result"
                    if item.optional_vars is None:
                        following.append(child)
                    else:
                        following.extend(
                            self.assign(item.optional_vars, entered, child, info)
                        )
            states = following
            self.tick(len(states))
        # A standard RLock exit has no user callbacks, never suppresses an
        # exception, and does not replace return/break/continue. A failed
        # acquisition has no normal continuation. Unknown managers above
        # remain unresolved regardless of the body result.
        return self.block(node.body, states, info)

    def for_block(self, node: ast.For, state: _State, info: _Info) -> list[_State]:
        """Expand known finite iterables without assuming an effect-free body."""
        results: list[_State] = []
        for current, iterable in self.expr(node.iter, state, info):
            if current.exit != "normal":
                self.prune_calls([*node.body, *node.orelse])
                results.append(current)
                continue
            receiver: str | None = None
            list_receiver: str | None = None
            method = "keys"
            if iterable in current.tuples:
                elements = current.tuples[iterable]
            elif iterable in current.lists:
                list_receiver = iterable
                sequence = self.sequence_values(iterable, current, node)
                if sequence is None:
                    results.append(current)
                    continue
                elements = sequence
            elif iterable in current.frozen_sets or iterable.startswith("constant:"):
                sequence = self.sequence_values(iterable, current, node)
                if sequence is None:
                    if current.exit != "normal":
                        self.prune_calls([*node.body, *node.orelse])
                    results.append(current)
                    continue
                elements = sequence
            elif iterable in current.mappings or iterable in current.mapping_views:
                receiver, method = current.mapping_views.get(
                    iterable, (iterable, "keys")
                )
                if receiver in current.unknown_mappings:
                    self.issue(node, "exceptional mapping iteration is unresolved")
                if receiver in current.open_mappings:
                    self.issue(
                        node, "open mapping iteration requires an unbounded-key model"
                    )
                elements = tuple(current.mappings[receiver])
            else:
                self.issue(node, "iteration requires a known tuple or mapping")
                # Preserve an explicit unresolved result. Do not assert that
                # user-defined iteration has no side effects or is empty.
                results.append(current)
                continue
            version = current.mapping_versions.get(receiver, 0) if receiver else 0
            list_version = (
                current.list_versions.get(list_receiver, 0) if list_receiver else 0
            )
            active = [current]
            finished: list[_State] = []
            if not elements:
                self.prune_calls(node.body)
            for index in range(len(elements) + 1):
                self.tick(len(active) + len(finished))
                for child in active:
                    if list_receiver is not None and (
                        list_receiver in child.unknown_lists
                        or child.list_versions.get(list_receiver, 0) != list_version
                    ):
                        self.issue(node, "list changed during active iteration")
                    if receiver is not None and (
                        receiver in child.unknown_mappings
                        or child.mapping_versions.get(receiver, 0) != version
                    ):
                        self.issue(node, "mapping changed during active iteration")
                if index == len(elements):
                    break
                assigned: list[_State] = []
                for child in active:
                    element = elements[index]
                    if receiver is not None:
                        key = "constant:" + repr(element)
                        value = child.mappings[receiver].get(element, "unknown:item")
                        if method == "items":
                            self.serial += 1
                            element = f"tuple:{self.serial}"
                            child.tuples[element] = (key, value)
                        else:
                            element = value if method == "values" else key
                    assigned.extend(self.assign(node.target, element, child, info))
                self.loop_depth += 1
                try:
                    outcomes = self.block(node.body, assigned, info)
                finally:
                    self.loop_depth -= 1
                active = []
                for child in outcomes:
                    if child.exit in {"normal", "continue"}:
                        child.exit = "normal"
                        active.append(child)
                    else:
                        if child.exit == "break":
                            child.exit = "normal"
                        finished.append(child)
            results.extend(finished)
            results.extend(self.block(node.orelse, active, info))
        return results

    def block(
        self, body: list[ast.stmt], states: list[_State], info: _Info
    ) -> list[_State]:
        if not states:
            self.prune_calls(body)
            return []
        for node in body:
            if isinstance(node, ast.AnnAssign):
                # Function-local annotations are never evaluated, including
                # without a future import. The target/value still may be.
                for part in ast.walk(node.annotation):
                    if isinstance(part, ast.Call):
                        self.pruned_calls.add(
                            (self.stack[-1], part.lineno, part.col_offset)
                        )
            if not states:
                self.prune_calls([node])
                continue
            following: list[_State] = []
            for state in states:
                self.tick(len(states))
                if state.exit != "normal":
                    self.prune_calls([node])
                    following.append(state)
                elif isinstance(node, ast.If):
                    following.extend(
                        self.block(
                            node.body,
                            self.branch(node.test, state.clone(), info, True),
                            info,
                        )
                    )
                    following.extend(
                        self.block(
                            node.orelse,
                            self.branch(node.test, state.clone(), info, False),
                            info,
                        )
                    )
                elif isinstance(node, ast.Try):
                    following.extend(self.try_block(node, state, info))
                elif isinstance(node, ast.For):
                    following.extend(self.for_block(node, state, info))
                elif isinstance(node, ast.With):
                    following.extend(self.with_block(node, state, info))
                elif isinstance(node, (ast.Break, ast.Continue)):
                    if not self.loop_depth:
                        self.issue(node, "loop control outside a modeled loop")
                    else:
                        state.exit = (
                            "break" if isinstance(node, ast.Break) else "continue"
                        )
                    following.append(state)
                elif isinstance(node, (ast.Return, ast.Raise, ast.Expr)):
                    value = node.exc if isinstance(node, ast.Raise) else node.value
                    evaluated = (
                        self.expr(value, state, info)
                        if value is not None
                        else [
                            (
                                state,
                                state.exception
                                if isinstance(node, ast.Raise)
                                else "constant:None",
                            )
                        ]
                    )
                    for current, token in evaluated:
                        if current.exit == "normal":
                            if isinstance(node, ast.Raise) and node.cause is not None:
                                # Evaluate the cause before exiting: it may call
                                # a helper, and cannot hide an effectful path.
                                causes = self.expr(node.cause, current, info)
                                for child, cause in causes:
                                    if child.exit == "normal":
                                        self.serial += 1
                                        envelope = f"exception-cause:{self.serial}"
                                        child.contents[envelope] = (token, cause)
                                        child.result = envelope
                                        child.exit = "raise"
                                    following.append(child)
                                continue
                            current.result = token
                            current.exit = (
                                "raise"
                                if isinstance(node, ast.Raise)
                                else "return"
                                if isinstance(node, ast.Return)
                                else "normal"
                            )
                        following.append(current)
                elif (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and node.value is not None
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for current, token in self.expr(node.value, state, info):
                        assigned = [current]
                        for target in targets:
                            assigned = [
                                outcome
                                for child in assigned
                                for outcome in self.assign(target, token, child, info)
                            ]
                        following.extend(assigned)
                elif isinstance(node, ast.Delete):
                    deleted = [state]
                    for target in node.targets:
                        deleted = [
                            outcome
                            for child in deleted
                            for outcome in self.assign(target, None, child, info)
                        ]
                    following.extend(deleted)
                elif isinstance(node, ast.AnnAssign) and isinstance(
                    node.target, ast.Name
                ):
                    # A declaration does not initialize or clear a local.
                    following.append(state)
                elif isinstance(node, ast.Pass):
                    following.append(state)
                else:
                    self.issue(node, f"unsupported statement: {type(node).__name__}")
                    following.append(state)
            states = self.settle_exceptions(following, node)
            self.tick(len(states))
        return states

    def prune_calls(self, body: list[ast.stmt]) -> None:
        """Account for calls eliminated by a modeled guard or terminal exit."""
        for statement in body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Call):
                    self.pruned_calls.add(
                        (self.stack[-1], node.lineno, node.col_offset)
                    )

    def invoke(
        self,
        name: str,
        args: list[str],
        kwargs: dict[str, str],
        state: _State,
        *,
        keyword_tail: str | None = None,
    ) -> list[tuple[_State, str]]:
        if name in self.stack or len(self.stack) >= self.spec.max_depth:
            raise _Limit("recursive call or call-depth budget exhausted")
        info = self.program.functions[name]
        node = info.node
        self.visited.add(name)
        previous_stack = self.stack
        previous_loop_depth = self.loop_depth
        self.stack = (*self.stack, name)
        self.loop_depth = 0
        try:
            if node.decorator_list and name not in self.program.method_kinds:
                self.issue(node, "decorated function requires a model")
            parameters = [*node.args.posonlyargs, *node.args.args]
            if len(args) > len(parameters) and node.args.vararg is None:
                state.exit, state.result = "raise", "constant:None"
                self.prune_calls(node.body)
                return [(state, "unknown:exception")]
            bound = dict(zip((arg.arg for arg in parameters), args))
            allowed_names = {
                arg.arg for arg in [*node.args.args, *node.args.kwonlyargs]
            }
            extra_keywords = {}
            for key, value in kwargs.items():
                if key in allowed_names:
                    if key in bound:
                        state.exit, state.result = "raise", "constant:None"
                        self.prune_calls(node.body)
                        return [(state, "unknown:exception")]
                    bound[key] = value
                elif node.args.kwarg is not None:
                    extra_keywords[key] = value
                else:
                    state.exit, state.result = "raise", "constant:None"
                    self.prune_calls(node.body)
                    return [(state, "unknown:exception")]
            if node.args.vararg is not None:
                if len(self.stack) == 1:
                    bound[node.args.vararg.arg] = (
                        "input:variadic:" + node.args.vararg.arg
                    )
                else:
                    self.serial += 1
                    token = f"tuple:{self.serial}"
                    state.tuples[token] = tuple(args[len(parameters) :])
                    bound[node.args.vararg.arg] = token
            if node.args.kwarg is not None:
                keyword_map = self.mapping(state, extra_keywords)
                bound[node.args.kwarg.arg] = keyword_map
                if len(self.stack) == 1:
                    state.open_mappings[keyword_map] = _MappingTail(
                        keyword_map, set(allowed_names)
                    )
                elif keyword_tail is not None and keyword_tail in state.open_mappings:
                    remainder = copy.deepcopy(state.open_mappings[keyword_tail])
                    remainder.absent.update(allowed_names | extra_keywords.keys())
                    state.open_mappings[keyword_map] = remainder
            defaults = (
                dict(
                    zip(
                        (arg.arg for arg in parameters[-len(node.args.defaults) :]),
                        node.args.defaults,
                    )
                )
                if node.args.defaults
                else {}
            )
            defaults.update(
                {
                    arg.arg: value
                    for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults)
                    if value is not None
                }
            )
            for parameter in [*parameters, *node.args.kwonlyargs]:
                if parameter.arg not in bound:
                    default = defaults.get(parameter.arg)
                    if isinstance(default, ast.Constant):
                        bound[parameter.arg] = "constant:" + repr(default.value)
                    elif default is None:
                        state.exit, state.result = "raise", "constant:None"
                        self.prune_calls(node.body)
                        return [(state, "unknown:exception")]
                    else:
                        self.issue(
                            node,
                            f"missing or dynamic default argument: {parameter.arg}",
                        )
                        bound[parameter.arg] = "unknown:argument"
            caller_env = state.env
            state.env = bound
            outcomes = self.block(node.body, [state], info)
            results = []
            for outcome in outcomes:
                value = outcome.result if outcome.exit == "return" else "constant:None"
                if outcome.exit == "return":
                    outcome.exit = "normal"
                outcome.env = dict(caller_env)
                results.append((outcome, value))
            return results
        finally:
            self.stack = previous_stack
            self.loop_depth = previous_loop_depth

    def run(self) -> dict[str, Any]:
        node = self.program.functions[self.entry].node
        params = [*node.args.posonlyargs, *node.args.args]
        args = ["input:" + arg.arg for arg in params]
        method_kind = self.program.method_kinds.get(self.entry)
        if params and method_kind != "staticmethod":
            args[0] = (
                "class:" if method_kind == "classmethod" else "instance:"
            ) + self.owner
        kwargs = {arg.arg: "input:" + arg.arg for arg in node.args.kwonlyargs}
        try:
            initial = _State()
            for name, default in self.program.context_variables.items():
                token = "context-var:global:" + name
                initial.context_defaults[token] = (
                    None if default is None else "constant:" + repr(default.value)
                )
                self.context_contents(initial, token)
            if params and method_kind not in {"staticmethod", "classmethod"}:
                initial.objects[args[0]] = self.owner
                initial.fields[args[0]] = {}
            outcomes = self.invoke(self.entry, args, kwargs, initial)
            for outcome, value in outcomes:
                exposed = outcome.result if outcome.exit == "raise" else value
                if self.escapes(exposed, outcome):
                    self.issue(
                        node,
                        "executable, receiver or unresolved capability escapes through API exit",
                    )
        except _Limit as exc:
            self.issue(node, str(exc))
        for name in sorted(self.visited):
            for call in ast.walk(self.program.functions[name].node):
                if (
                    isinstance(call, ast.Call)
                    and (name, call.lineno, call.col_offset) not in self.calls
                    and (name, call.lineno, call.col_offset) not in self.pruned_calls
                ):
                    self.issues.append(
                        {
                            "function": name,
                            "line": call.lineno,
                            "reason": "call not covered by transfer analysis",
                            "call_path": [],
                        }
                    )
        status = (
            "unresolved"
            if self.issues
            else "violated"
            if any(not site["authorized"] for site in self.dispatches)
            else "verified"
        )
        return {
            "entry": f"{self.owner}.{node.name}",
            "implementation": self.entry,
            "status": status,
            "issues": self.issues,
            "dispatches": self.dispatches,
            "visited_functions": sorted(self.visited),
            "call_graph": [{"caller": a, "callee": b} for a, b in sorted(self.edges)],
            "steps": self.steps,
            "settled_exceptions": self.settled_exceptions,
        }

    def escapes(self, token: str, state: _State) -> bool:
        pending, seen = [token], set()
        while pending:
            self.tick()
            value = pending.pop()
            if value in seen:
                continue
            seen.add(value)
            if (
                value in state.objects
                or value in state.locks
                or value in state.unknown_mappings
                or value in state.unknown_lists
                or value in state.open_mappings
                or value in state.context_defaults
                or value in state.context_tokens
                or value in state.supers
                or value.startswith(
                    (
                        "callable:",
                        "bound:",
                        "object-bound:",
                        "class-bound:",
                        "instance:",
                        "class:",
                        "namespace:",
                        "exception-local:",
                        "mapping-method:",
                        "list-method:",
                        "mapping-constructor:",
                        "builtin:",
                        "context-method:",
                        "context-input:",
                        "object-init:",
                    )
                )
            ):
                return True
            pending.extend(state.tuples.get(value, ()))
            pending.extend(state.lists.get(value, ()))
            pending.extend(state.contents.get(value, ()))
            pending.extend(state.mappings.get(value, {}).values())
        return False


def verify(spec: VerificationSpec) -> dict[str, Any]:
    """Verify all discovered APIs and emit unresolved/violating call paths."""
    program = _Program(spec)
    surfaces = program.surfaces()
    entries = [
        _Engine(program, method, owner).run()
        for owner, methods in surfaces.items()
        for method in methods.values()
    ]
    dispatch_count = sum(len(entry["dispatches"]) for entry in entries)
    complete = (
        bool(entries)
        and dispatch_count > 0
        and not program.issues
        and all(entry["status"] == "verified" for entry in entries)
    )
    return {
        "schema_version": 1,
        "property": "Every reachable terminal dispatch on every modelled path consumes a fresh ALLOW decision for identical principal/request bindings.",
        "complete": complete,
        "scope": "Closed-world supported Python subset under explicit terminal and object-model contracts; not arbitrary Python or policy semantics.",
        "assumptions": [
            "Authorizer primitives authenticate inputs and return the declared Decision for exactly their bound arguments.",
            "Operation primitives are the complete terminal effect boundary in the supplied source universe.",
            "Imports, builtin data operations, standard dataclass construction, native method binding, override metadata, builtin exceptions and Verdict identity have their declared meanings; custom descriptors and monkeypatching are outside the model.",
            "Standard typing and typing_extensions TYPE_CHECKING is False at runtime; cast returns its val argument unchanged after evaluating and binding all arguments. A cast establishes no runtime type or authorization.",
            "Supported inert TypedDict declarations use the native typing/typing_extensions metaclass: construction produces an ordinary dict without schema validation and isinstance against the declaration raises TypeError. Annotations grant no runtime types or authority.",
            "Native ContextVar get/set/reset operates in one current execution context across direct source calls and awaits. Module variables may contain inherited values; local variables start unset. Task creation, context copying/switching, external context mutation, token context managers and arbitrary context introspection require separate models.",
            "Statically named ordinary source bases follow native C3 method resolution. Bound super proxies use the lexical starting class and the actual receiver's method order; custom metaclasses, dynamic bases, unbound super descriptors and generated dataclass class cells require additional models.",
            "Lazy export resolution uses ordinary source-module imports with native importlib semantics and inert native import-error diagnostics; custom import hooks and external mutation of module bindings/export tables are outside the model. Every source initializer is still checked.",
            "Standard reentrant locks use the native _thread.RLock context protocol: enter returns True and exit does not suppress exceptions or invoke user callbacks. This is not a concurrency proof.",
            "Security inputs change only through modeled writes; external concurrent mutation, including across awaits, is outside the model.",
            "Terminal return values and exception payloads contain inert data, never executable or receiver capabilities.",
            "Input truth tests and keyword-key hashing/equality are stable and inert; custom input protocols and concurrent mutation require another model. Python keyword packing alone does not establish inert key protocols.",
            "Ordinary helper bodies are analyzed, never accepted through opaque reviewed-call exemptions.",
        ],
        "source_hashes": {
            module: hashlib.sha256(source.encode()).hexdigest()
            for module, source in sorted(spec.sources.items())
        },
        "package_modules": sorted(spec.package_modules),
        "export_resolutions": program.export_evidence,
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "terminals": {
            "authorizers": [vars(item) for item in spec.authorizers],
            "operations": [vars(item) for item in spec.operations],
        },
        "async_terminals": list(spec.async_terminals),
        "terminal_parameters": {
            key: list(value) for key, value in spec.terminal_parameters.items()
        },
        "requirements": {
            target: [vars(item) for item in items]
            for target, items in spec.requirements.items()
        },
        "budgets": {
            "steps_per_entry": spec.max_steps,
            "paths_per_entry": spec.max_paths,
            "call_depth": spec.max_depth,
        },
        "surfaces": surfaces,
        "method_resolution_order": {
            owner: list(order)
            if (order := program.linearization(owner)) is not None
            else None
            for owner in surfaces
        },
        "issues": program.issues,
        "entries": entries,
        "summary": {
            "entries": len(entries),
            "verified": sum(entry["status"] == "verified" for entry in entries),
            "violated": sum(entry["status"] == "violated" for entry in entries),
            "unresolved": sum(entry["status"] == "unresolved" for entry in entries),
            "dispatch_obligations": dispatch_count,
        },
    }


def load_spec(path: Path) -> VerificationSpec:
    """Read a JSON specification with source paths relative to its directory."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    allowed = {
        "sources",
        "source_roots",
        "package_modules",
        "async_terminals",
        "terminal_parameters",
        "requirements",
        "surfaces",
        "authorizers",
        "operations",
        "max_steps",
        "max_paths",
        "max_depth",
    }
    if set(payload) - allowed:
        raise ValueError("unknown verification specification fields")
    sources = {
        module: (path.parent / file).read_text(encoding="utf-8")
        for module, file in payload.get("sources", {}).items()
    }
    packages = set(payload.get("package_modules", []))
    for module, file in payload.get("sources", {}).items():
        if Path(file).name == "__init__.py":
            packages.add(module)
    for package, directory in payload.get("source_roots", {}).items():
        root = path.parent / directory
        files = sorted(root.rglob("*.py"))
        if not files:
            raise ValueError(f"empty source root: {directory}")
        for file in files:
            parts = list(file.relative_to(root).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
                packages.add(".".join([package, *parts]))
            module = ".".join([package, *parts])
            if module in sources:
                raise ValueError(f"duplicate source module: {module}")
            sources[module] = file.read_text(encoding="utf-8")
    return VerificationSpec(
        sources=sources,
        package_modules=tuple(sorted(packages)),
        surfaces=tuple(payload["surfaces"]),
        async_terminals=tuple(payload.get("async_terminals", [])),
        terminal_parameters={
            key: tuple(value)
            for key, value in payload.get("terminal_parameters", {}).items()
        },
        requirements={
            target: tuple(
                Requirement(item["permission"], tuple(item["bindings"]))
                for item in items
            )
            for target, items in payload.get("requirements", {}).items()
        },
        authorizers=tuple(
            Authorizer(
                item["target"],
                tuple(item["bindings"]),
                permission=item.get("permission", "tool_call"),
            )
            for item in payload["authorizers"]
        ),
        operations=tuple(
            Operation(
                item["target"],
                tuple(item["bindings"]),
                permission=item.get("permission", "tool_call"),
            )
            for item in payload["operations"]
        ),
        **{
            key: payload[key]
            for key in ("max_steps", "max_paths", "max_depth")
            if key in payload
        },
    )


def _loaded_source_closure(
    sources: dict[str, str],
    packages: set[str],
    modules: Mapping[str, ModuleType],
) -> None:
    """Collect loaded framework dependencies without executing further imports.

    The root distributions come from the original source inventory. Imports
    outside those distributions and unloaded imports remain unresolved if the
    analyzer needs them; finding an import never creates a trusted-call summary.
    Reading module dictionaries avoids running lazy export hooks. Source-based
    alias resolution remains the analyzer's responsibility.
    """
    roots = {name.split(".", 1)[0] for name in sources}
    pending = list(sorted(sources))
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen or name.split(".", 1)[0] not in roots:
            continue
        seen.add(name)
        loaded = modules.get(name)
        if loaded is not None:
            namespace = vars(loaded)
            if "__path__" in namespace:
                packages.add(name)
            if name not in sources:
                try:
                    source_file = inspect.getsourcefile(loaded)
                    if source_file is None:
                        raise OSError("module has no Python source file")
                    sources[name] = Path(source_file).read_text(encoding="utf-8")
                except (OSError, TypeError):
                    # A namespace package has no executable facade to analyze.
                    if namespace.get("__file__") is not None:
                        raise ValueError(f"source module unavailable: {name}") from None
        parts = name.split(".")
        pending.extend(".".join(parts[:index]) for index in range(1, len(parts)))
        if name not in sources:
            continue
        try:
            tree = ast.parse(sources[name])
        except SyntaxError:
            # The source analyzer reports the parse error and cannot certify it.
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                pending.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                try:
                    parent = _import_parent(name, node, packages)
                except ValueError:
                    continue
                pending.append(parent)
                pending.extend(
                    f"{parent}.{alias.name}"
                    for alias in node.names
                    if alias.name != "*"
                )
                parent_module = modules.get(parent)
                if parent_module is not None:
                    for alias in node.names:
                        exported = vars(parent_module).get(alias.name)
                        if inspect.isfunction(exported) or inspect.isclass(exported):
                            pending.append(exported.__module__)
    # Namespace packages have no source and need no package-source declaration.
    packages.intersection_update(sources)


def installed_spec() -> VerificationSpec:
    """Discover installed tool/base-class sources for a strict repository audit.

    This adapter uses already imported framework types; verify() itself never
    executes supplied source. Missing dynamic dispatch/type models stay errors.
    """
    from langchain_core.tools import BaseTool, StructuredTool, Tool

    from langgraph.prebuilt.security.guarded import _GuardedExecutor
    from langgraph.prebuilt.tool_node import ToolNode

    sources: dict[str, str] = {}
    packages: set[str] = set()
    for cls in (BaseTool, StructuredTool, Tool, ToolNode, _GuardedExecutor):
        for base in cls.__mro__:
            if base.__module__ in {"builtins", "typing", "abc"}:
                continue
            module = inspect.getmodule(base)
            if module is None:
                raise ValueError(f"source module unavailable: {base.__qualname__}")
            sources[module.__name__] = inspect.getsource(module)
    # Scan the prebuilt package independently so a new tool subclass/file is
    # included without editing a hand-maintained entry-point catalog.
    root = Path(__file__).parents[1]
    for file in sorted(root.rglob("*.py")):
        parts = list(file.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
            packages.add(".".join(["langgraph.prebuilt", *parts]))
        sources[".".join(["langgraph.prebuilt", *parts])] = file.read_text(
            encoding="utf-8"
        )
    _loaded_source_closure(sources, packages, dict(sys.modules))
    guarded = "langgraph.prebuilt.security.guarded._GuardedExecutor"
    node = "langgraph.prebuilt.tool_node.ToolNode"
    policy_paths = (f"{guarded}.stack", f"{node}._security_stack")
    host_paths = (
        f"{guarded}.security.host_executor",
        f"{node}._security_host_executor",
    )
    authorizers = tuple(
        Authorizer(f"{path}.{name}", ("arg:0", "arg:1", "result:constraints"))
        for path in policy_paths
        for name in ("permission", "apermission")
    )
    operations = tuple(
        Operation(f"{path}.{name}", ("arg:0", "arg:1", "arg:2"))
        for path in host_paths
        for name in ("invoke", "ainvoke")
    )
    return VerificationSpec(
        sources=sources,
        package_modules=tuple(sorted(packages)),
        async_terminals=tuple(
            [f"{path}.apermission" for path in policy_paths]
            + [f"{path}.ainvoke" for path in host_paths]
        ),
        terminal_parameters={
            **{item.target: ("principal", "call", "approval") for item in authorizers},
            **{
                item.target: ("principal", "call", "constraints") for item in operations
            },
        },
        surfaces=("langchain_core.tools.base.BaseTool", node, guarded),
        authorizers=authorizers,
        operations=operations,
    )


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path, nargs="?")
    parser.add_argument(
        "--installed",
        action="store_true",
        help="Audit installed framework sources with no opaque helper exemptions",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if (args.spec is not None) == args.installed:
            raise ValueError("provide exactly one of a spec path or --installed")
        if args.installed:
            from langgraph.prebuilt.security.tool_api_verifier import verify_tool_apis

            source_report = verify(installed_spec())
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                api_report = asyncio.run(verify_tool_apis())
            report = {
                "schema_version": 1,
                "complete": source_report["complete"] and api_report["complete"],
                "property": source_report["property"],
                "source_proof": source_report,
                "api_conformance": api_report,
                "summary": {
                    "source": source_report["summary"],
                    "api": api_report["summary"],
                },
            }
        else:
            report = verify(load_spec(args.spec))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = {
            "complete": False,
            "issues": [{"reason": f"invalid verification input: {exc}"}],
        }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
