"""Source-derived host output correspondence under explicit entry premises.

This component proves the OutputRequest path through ObjectManagerHost. It does
not authorize that request, admit its payload, certify runtime bindings, or
establish placement/host isolation. Candidate source is parsed, never executed.
"""

from __future__ import annotations

import ast
import hashlib
import symtable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

_OBJECTS = "langgraph.prebuilt.security.objects"
_HOST = "langgraph.prebuilt.security.object_manager"
_INPUT_VALIDATOR = "langgraph.prebuilt.security.output_data.validate_output_request"
_REQUESTS = frozenset(
    {
        "DispatchRequest",
        "ToolRegistryRequest",
        "StateRequest",
        "ModelInvocationRequest",
        "OutputRequest",
    }
)
_CONTENT = ("request", "content")
_CONFIDENTIALITY = ("request", "labels", "confidentiality")
_CLEARANCE = ("request", "clearance")
_SUBSET = ("subset",)
_DISPATCH = ("bound_dispatch",)
_Value = tuple[str, ...]


class _Unsupported(Exception):
    def __init__(
        self, node: ast.AST, reason: str, *, obligation: dict[str, Any] | None = None
    ):
        self.line = getattr(node, "lineno", 0)
        self.reason = reason
        self.obligation = obligation
        super().__init__(reason)


@dataclass
class _State:
    env: dict[str, _Value]
    clearance: bool | None = None
    lock_depth: int = 0
    exit: str = ""
    result: _Value = ()
    trace: list[dict[str, Any]] = field(default_factory=list)

    def clone(self) -> _State:
        return replace(self, env=dict(self.env), trace=list(self.trace))


def _module_bindings(tree: ast.Module) -> dict[str, str]:
    """Resolve only direct source imports; duplicate relevant names are rejected."""
    bindings: dict[str, str] = {}
    for node in tree.body:
        declared: dict[str, str] = {}
        if isinstance(node, ast.ImportFrom) and not node.level and node.module:
            declared = {
                alias.asname or alias.name: node.module + "." + alias.name
                for alias in node.names
            }
        elif isinstance(node, ast.Import):
            # `import a.b.c` binds `a` to the top-level module; only an alias
            # binds the full dotted path, so a bare import can never select a
            # module attribute such as the validator.
            declared = {
                alias.asname or alias.name.split(".")[0]: alias.name
                if alias.asname
                else alias.name.split(".")[0]
                for alias in node.names
            }
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            declared = {node.name: "source:" + node.name}
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(not isinstance(target, ast.Name) for target in targets):
                raise _Unsupported(
                    node, "module heap mutation requires an initialization proof"
                )
            declared = {
                part.id: "assigned:" + part.id
                for target in targets
                for part in ast.walk(target)
                if isinstance(part, ast.Name)
            }
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        else:
            raise _Unsupported(
                node, "module binding effects require a separate initialization proof"
            )
        for name, target in declared.items():
            if name in bindings:
                raise _Unsupported(node, f"rebound module name: {name}")
            bindings[name] = target
    return bindings


def _slot_annotation(node: ast.expr, bindings: dict[str, str]) -> None:
    """Admit a bounded annotation grammar without dataclass pseudo-fields.

    Postponed annotations are required below. The resolver deliberately does
    not expand arbitrary aliases or evaluate annotation expressions.
    """
    allowed = {
        "builtins.str",
        "builtins.bool",
        "builtins.frozenset",
        "builtins.tuple",
        "typing.Any",
        "collections.abc.Mapping",
        "langgraph.prebuilt.security.types.Principal",
        "langgraph.prebuilt.security.types.Tool",
        "source:DispatchKind",
        "source:StateOperation",
        "source:SecurityLabels",
        "source:LabeledValue",
    }
    if isinstance(node, ast.Name):
        resolved = bindings.get(node.id, "builtins." + node.id)
        if resolved in allowed:
            return
    elif isinstance(node, ast.Subscript):
        _slot_annotation(node.value, bindings)
        _slot_annotation(node.slice, bindings)
        return
    elif isinstance(node, ast.Tuple):
        for item in node.elts:
            _slot_annotation(item, bindings)
        return
    elif isinstance(node, ast.Constant) and node.value is Ellipsis:
        return
    raise _Unsupported(node, "field annotation is not a modeled native slot annotation")


def _slot_default(node: ast.expr | None, bindings: dict[str, str]) -> None:
    """Exclude descriptor defaults and unknown default evaluation protocols.

    Accepted constructors still require the separate initialization and runtime
    binding premises. Their results have no descriptor protocol in this model.
    """
    if node is None or (
        isinstance(node, ast.Constant) and type(node.value) in {str, bool, type(None)}
    ):
        return
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        resolved = bindings.get(node.func.id, "builtins." + node.func.id)
        if (
            resolved in {"builtins.frozenset", "source:SecurityLabels"}
            and not node.args
            and not node.keywords
        ):
            return
        if resolved == "dataclasses.field" and not node.args:
            seen: set[str] = set()
            for keyword in node.keywords:
                name = keyword.arg
                if name is None or name in seen:
                    break
                seen.add(name)
                if name in {"compare", "repr"}:
                    if (
                        not isinstance(keyword.value, ast.Constant)
                        or type(keyword.value.value) is not bool
                    ):
                        break
                elif name == "default":
                    # Recursive field(...) descriptors/defaults are not data.
                    if not isinstance(keyword.value, ast.Constant) or type(
                        keyword.value.value
                    ) not in {str, bool, type(None)}:
                        break
                elif name == "default_factory":
                    factory = keyword.value
                    if (
                        not isinstance(factory, ast.Name)
                        or bindings.get(factory.id, "builtins." + factory.id)
                        != "builtins.dict"
                    ):
                        break
                else:
                    break
            else:
                if not {"default", "default_factory"} <= seen:
                    return
    raise _Unsupported(
        node, "field default may invoke an unknown or descriptor protocol"
    )


def _native_records(
    tree: ast.Module, bindings: dict[str, str], extra: tuple[str, ...] = ()
) -> dict[str, list[str]]:
    if bindings.get("annotations") != "__future__.annotations":
        raise _Unsupported(
            tree, "record annotation evaluation requires an initialization proof"
        )
    records = {}
    for name in (*sorted(_REQUESTS), "SecurityLabels", *extra):
        candidates = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == name
        ]
        if len(candidates) != 1:
            raise _Unsupported(tree, f"missing or duplicate native record: {name}")
        node = candidates[0]
        if node.bases or node.keywords or len(node.decorator_list) != 1:
            raise _Unsupported(node, f"native record layout is unresolved: {name}")
        decorator = node.decorator_list[0]
        if (
            not isinstance(decorator, ast.Call)
            or not isinstance(decorator.func, ast.Name)
            or bindings.get(decorator.func.id) != "dataclasses.dataclass"
            or decorator.args
            or len(decorator.keywords) != 2
            or {item.arg for item in decorator.keywords} != {"frozen", "slots"}
            or any(
                not isinstance(item.value, ast.Constant) or item.value.value is not True
                for item in decorator.keywords
            )
        ):
            raise _Unsupported(
                node, f"native frozen slot decorator is unresolved: {name}"
            )
        fields = []
        members: set[str] = set()
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                member_name = member.name
            elif isinstance(member, ast.AnnAssign) and isinstance(
                member.target, ast.Name
            ):
                member_name = member.target.id
            else:
                member_name = None
            if member_name is not None:
                if member_name in members:
                    raise _Unsupported(
                        member, f"rebound record member: {name}.{member_name}"
                    )
                members.add(member_name)
            if isinstance(member, ast.AnnAssign) and isinstance(
                member.target, ast.Name
            ):
                if member.simple != 1:
                    raise _Unsupported(
                        member,
                        "parenthesized annotation does not declare a dataclass slot",
                    )
                _slot_annotation(member.annotation, bindings)
                _slot_default(member.value, bindings)
                fields.append(member.target.id)
            elif isinstance(member, ast.Expr) and isinstance(
                member.value, ast.Constant
            ):
                continue
            elif (
                isinstance(member, ast.FunctionDef)
                and not member.decorator_list
                and (
                    member.name == "__post_init__"
                    or (
                        name not in {"OutputRequest", "SecurityLabels"}
                        and not member.name.startswith("__")
                    )
                )
            ):
                # Construction is an entry premise, not part of this derivation.
                continue
            else:
                raise _Unsupported(
                    member, f"custom record access/layout requires a model: {name}"
                )
        if len(fields) != len(set(fields)) or any(
            field.startswith("__") for field in fields
        ):
            raise _Unsupported(node, f"ambiguous native fields: {name}")
        records[name] = fields
    if not {"content", "labels", "clearance"} <= set(records["OutputRequest"]):
        raise _Unsupported(tree, "OutputRequest lacks required projection fields")
    if "confidentiality" not in records["SecurityLabels"]:
        raise _Unsupported(tree, "SecurityLabels lacks confidentiality")
    return records


class _Derivation:
    def __init__(
        self,
        tree: ast.Module,
        bindings: dict[str, str],
        scopes: symtable.SymbolTable,
        max_steps: int,
        validator: dict[str, Any] | None = None,
    ):
        self.bindings = bindings
        self.validator = validator
        self.validator_used = False
        self.remaining = max_steps
        self.forwardings: list[dict[str, Any]] = []
        hosts = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ObjectManagerHost"
        ]
        if (
            len(hosts) != 1
            or hosts[0].bases
            or hosts[0].keywords
            or hosts[0].decorator_list
        ):
            raise _Unsupported(tree, "host class lookup/layout requires a model")
        host = hosts[0]
        host_scope = next(
            scope
            for scope in scopes.get_children()
            if scope.get_name() == "ObjectManagerHost"
        )
        self.local_names = {
            scope.get_name(): {
                symbol.get_name() for symbol in scope.get_symbols() if symbol.is_local()
            }
            for scope in host_scope.get_children()
        }
        self.methods = {}
        self.host_slots: tuple[str, ...] | None = None
        for member in host.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (
                    member.decorator_list
                    or member.name in self.methods
                    or member.name
                    in {"__getattribute__", "__getattr__", "__setattr__", "__delattr__"}
                ):
                    raise _Unsupported(
                        member, "host method lookup can be changed by a source protocol"
                    )
                self.methods[member.name] = member
            elif (
                isinstance(member, ast.Assign)
                and len(member.targets) == 1
                and isinstance(member.targets[0], ast.Name)
                and member.targets[0].id == "__slots__"
            ):
                if (
                    self.host_slots is not None
                    or not isinstance(member.value, ast.Tuple)
                    or not member.value.elts
                    or any(
                        not isinstance(value, ast.Constant)
                        or type(value.value) is not str
                        or not value.value.isidentifier()
                        or value.value.startswith("__")
                        for value in member.value.elts
                    )
                ):
                    raise _Unsupported(
                        member, "host slots require one literal native layout"
                    )
                slots = tuple(value.value for value in member.value.elts)
                if len(set(slots)) != len(slots):
                    raise _Unsupported(member, "host slot names must be unique")
                self.host_slots = slots
            elif not (
                isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
            ):
                raise _Unsupported(member, "host class-body binding requires a model")
        if (
            self.host_slots is None
            or "_lock" not in self.host_slots
            or set(self.host_slots) & self.methods.keys()
        ):
            raise _Unsupported(
                host, "host native slots must include _lock and exclude methods"
            )
        for name, asynchronous in (("dispatch", False), ("adispatch", True)):
            method = self.methods.get(name)
            if (
                method is None
                or isinstance(method, ast.AsyncFunctionDef) != asynchronous
            ):
                raise _Unsupported(host, f"missing or wrong await mode: {name}")
            args = method.args
            if (
                method.decorator_list
                or args.posonlyargs
                or args.kwonlyargs
                or args.defaults
                or args.kw_defaults
                or args.vararg
                or args.kwarg
                or [arg.arg for arg in args.args] != ["self", "principal", "request"]
            ):
                raise _Unsupported(method, f"unsupported entry signature: {name}")
            if any(
                isinstance(node, (ast.Global, ast.Nonlocal))
                for node in ast.walk(method)
            ):
                raise _Unsupported(method, "entry modifies an external lexical scope")
        if {
            "isinstance",
            "type",
            "PermissionError",
            "TypeError",
            "__builtins__",
        } & bindings.keys():
            raise _Unsupported(tree, "native classifier or refusal builtin was rebound")

    def initial(self, name: str) -> dict[str, _Value]:
        return {
            **{local: ("unbound", local) for local in self.local_names[name]},
            **{name: (name,) for name in ("self", "principal", "request")},
        }

    def tick(self, node: ast.AST) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise _Unsupported(node, "derivation budget exhausted")

    def require_validator_derivation(self, node: ast.Call, state: _State) -> None:
        """Diagnose a dependency; recognizing its import grants no semantics."""
        if (
            isinstance(node.func, ast.Name)
            and node.func.id not in state.env
            and self.bindings.get(node.func.id) == _INPUT_VALIDATOR
        ):
            raise _Unsupported(
                node,
                "reachable input validator requires a source-derived admission/effect-safety proof; it is not an opaque helper exemption",
                obligation={
                    "kind": "reachable-input-validation",
                    "target": _INPUT_VALIDATOR,
                    "line": node.lineno,
                    "proved": False,
                    "required": [
                        "Derive the bounded recursive walk over every admitted payload and framework-record shape.",
                        "Bind captured native descriptors, imported record layouts, module globals and helper implementations to their source/runtime meanings.",
                        "Prove no candidate protocols, external effects or request mutation occur; normal completion establishes request/label/clearance shape and inert refusals expose no payload.",
                    ],
                },
            )

    def validated(self, node: ast.Call, state: _State) -> list[_State]:
        """Fork refusal/continuation from a recomputed validator contract.

        Only the exact call on the unchanged effective request is covered. The
        contract changes no request field and runs no candidate protocol.
        """
        if self.validator is None or not self.validator["proved"]:
            self.require_validator_derivation(node, state)
            raise _Unsupported(
                node, "reachable call statement requires an effect derivation"
            )
        if not (
            isinstance(node.func, ast.Name)
            and node.func.id not in state.env
            and self.bindings.get(node.func.id) == _INPUT_VALIDATOR
        ):
            raise _Unsupported(
                node, "reachable call statement requires an effect derivation"
            )
        if (
            len(node.args) != 1
            or node.keywords
            or not isinstance(node.args[0], ast.Name)
            or state.env.get(node.args[0].id) != ("request",)
        ):
            raise _Unsupported(
                node, "validator contract covers only the unchanged effective request"
            )
        self.validator_used = True
        refused = state.clone()
        refused.exit = "raise"
        refused.trace.append(
            {
                "line": node.lineno,
                "rule": "validator-refusal",
                "exception": "OutputDataError or a propagated native exception",
            }
        )
        state.trace.append(
            {
                "line": node.lineno,
                "rule": "source-derived-validator-contract",
                "target": _INPUT_VALIDATOR,
                "source_sha256": self.validator["source_sha256"],
                "effects": "fresh walker state only; no request write or candidate protocol",
            }
        )
        return [refused, state]

    def value(
        self, node: ast.expr, state: _State, *, delegated: bool
    ) -> list[tuple[_State, _Value]]:
        self.tick(node)
        if isinstance(node, ast.Name) and node.id in state.env:
            if state.env[node.id][0] == "unbound":
                raise _Unsupported(
                    node, "compiler-local binding is read before assignment"
                )
            return [(state, state.env[node.id])]
        if isinstance(node, ast.Name) and self.bindings.get(node.id) in {
            _OBJECTS + "." + name for name in _REQUESTS
        }:
            return [(state, ("native-class", self.bindings[node.id]))]
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Is, ast.IsNot))
        ):
            results = []
            for current, left in self.value(node.left, state, delegated=delegated):
                for child, right in self.value(
                    node.comparators[0], current, delegated=delegated
                ):
                    if left[0] != "native-class" or right[0] != "native-class":
                        raise _Unsupported(
                            node,
                            "identity comparison requires modeled native class values",
                        )
                    matched = left == right
                    if isinstance(node.ops[0], ast.IsNot):
                        matched = not matched
                    child.trace.append(
                        {
                            "line": node.lineno,
                            "rule": "native-class-identity",
                            "matched": matched,
                        }
                    )
                    results.append((child, ("literal", repr(matched))))
            return results
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            short_circuit = "False" if isinstance(node.op, ast.And) else "True"
            results = [
                (state, ("literal", "True" if short_circuit == "False" else "False"))
            ]
            for operand in node.values:
                following = []
                for current, prior in results:
                    if prior == ("literal", short_circuit):
                        following.append((current, prior))
                    else:
                        for child, value in self.value(
                            operand, current, delegated=delegated
                        ):
                            if value not in {("literal", "True"), ("literal", "False")}:
                                raise _Unsupported(
                                    node,
                                    "boolean short circuit requires native boolean operands",
                                )
                            following.append((child, value))
                results = following
            return results
        if isinstance(node, ast.Constant) and type(node.value) in {
            str,
            bool,
            type(None),
        }:
            return [(state, ("literal", repr(node.value)))]
        if isinstance(node, ast.Attribute):
            results = []
            for current, base in self.value(node.value, state, delegated=delegated):
                value = (*base, node.attr)
                if value == ("self", "dispatch"):
                    value = _DISPATCH
                if value not in {
                    ("self", "_lock"),
                    _DISPATCH,
                    ("request", "labels"),
                    _CONTENT,
                    _CONFIDENTIALITY,
                    _CLEARANCE,
                }:
                    raise _Unsupported(
                        node,
                        "attribute projection is outside the admitted output data model",
                    )
                results.append((current, value))
            return results
        if isinstance(node, ast.Call):
            self.require_validator_derivation(node, state)
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "type"
                and node.func.id not in state.env
            ):
                if len(node.args) != 1 or node.keywords:
                    raise _Unsupported(node, "native type query requires one argument")
                results = []
                for current, value in self.value(
                    node.args[0], state, delegated=delegated
                ):
                    if value != ("request",):
                        raise _Unsupported(
                            node, "native type query requires the admitted request"
                        )
                    results.append(
                        (current, ("native-class", _OBJECTS + ".OutputRequest"))
                    )
                return results
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "isinstance"
                and node.func.id not in state.env
            ):
                if (
                    len(node.args) != 2
                    or node.keywords
                    or not isinstance(node.args[1], ast.Name)
                    or node.args[1].id in state.env
                ):
                    raise _Unsupported(
                        node, "classifier must use one static native request class"
                    )
                target = self.bindings.get(node.args[1].id, "")
                if target not in {_OBJECTS + "." + name for name in _REQUESTS}:
                    raise _Unsupported(
                        node, "classifier class is not a source-derived disjoint record"
                    )
                results = []
                for current, subject in self.value(
                    node.args[0], state, delegated=delegated
                ):
                    if subject != ("request",):
                        raise _Unsupported(
                            node,
                            "classifier does not test the original effective request",
                        )
                    matched = target == _OBJECTS + ".OutputRequest"
                    current.trace.append(
                        {
                            "line": node.lineno,
                            "rule": "native-classifier",
                            "class": target,
                            "matched": matched,
                        }
                    )
                    results.append((current, ("literal", repr(matched))))
                return results
            if isinstance(node.func, ast.Attribute) and node.func.attr == "issubset":
                if len(node.args) != 1 or node.keywords:
                    raise _Unsupported(
                        node, "clearance comparison has unsupported arguments"
                    )
                results = []
                for current, left in self.value(
                    node.func.value, state, delegated=delegated
                ):
                    for child, right in self.value(
                        node.args[0], current, delegated=delegated
                    ):
                        if (left, right) != (_CONFIDENTIALITY, _CLEARANCE):
                            raise _Unsupported(
                                node, "clearance comparison uses different projections"
                            )
                        child.trace.append(
                            {"line": node.lineno, "rule": "native-frozenset-subset"}
                        )
                        results.append((child, _SUBSET))
                return results
            targets = self.value(node.func, state, delegated=delegated)
            results = []
            for current, target in targets:
                if target != _DISPATCH or delegated:
                    raise _Unsupported(
                        node, "reachable call lacks an output correspondence derivation"
                    )
                if len(node.args) != 2 or node.keywords:
                    raise _Unsupported(
                        node, "dispatch forwarding requires exact positional inputs"
                    )
                for child, principal in self.value(
                    node.args[0], current, delegated=delegated
                ):
                    for bound, request in self.value(
                        node.args[1], child, delegated=delegated
                    ):
                        if (principal, request) != (("principal",), ("request",)):
                            raise _Unsupported(
                                node,
                                "dispatch forwarding changes original identity bindings",
                            )
                        self.forwardings.append(
                            {
                                "line": node.lineno,
                                "principal": "arg:1",
                                "request": "arg:2",
                            }
                        )
                        saved = dict(bound.env)
                        bound.env = self.initial("dispatch")
                        for outcome in self.block(
                            self.methods["dispatch"].body, [bound], delegated=True
                        ):
                            value = outcome.result
                            if outcome.exit == "return":
                                outcome.exit = ""
                            outcome.env = dict(saved)
                            results.append((outcome, value))
            return results
        raise _Unsupported(
            node, f"unsupported reachable expression: {type(node).__name__}"
        )

    def branch(
        self, node: ast.expr, state: _State, truth: bool, *, delegated: bool
    ) -> list[_State]:
        self.tick(node)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.branch(node.operand, state, not truth, delegated=delegated)
        results = []
        for current, value in self.value(node, state, delegated=delegated):
            if current.exit:
                results.append(current)
            elif value in {("literal", "True"), ("literal", "False")}:
                if (value[-1] == "True") == truth:
                    results.append(current)
            elif value == _SUBSET:
                if current.clearance is None or current.clearance == truth:
                    current.clearance = truth
                    results.append(current)
            else:
                raise _Unsupported(
                    node, "predicate requires unmodeled truth/equality protocols"
                )
        return results

    def block(
        self, nodes: list[ast.stmt], states: list[_State], *, delegated: bool
    ) -> list[_State]:
        for node in nodes:
            self.tick(node)
            following = []
            for state in states:
                if state.exit:
                    following.append(state)
                    continue
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    following.append(state)
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    following.extend(self.validated(node.value, state))
                elif isinstance(node, ast.Pass):
                    following.append(state)
                elif (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                ):
                    for current, value in self.value(
                        node.value, state, delegated=delegated
                    ):
                        current.env[node.targets[0].id] = value
                        following.append(current)
                elif isinstance(node, ast.If):
                    for truth, branch in ((True, node.body), (False, node.orelse)):
                        children = self.branch(
                            node.test, state.clone(), truth, delegated=delegated
                        )
                        following.extend(
                            self.block(branch, children, delegated=delegated)
                        )
                elif (
                    isinstance(node, ast.With)
                    and len(node.items) == 1
                    and node.items[0].optional_vars is None
                ):
                    for current, lock in self.value(
                        node.items[0].context_expr, state, delegated=delegated
                    ):
                        if lock != ("self", "_lock"):
                            raise _Unsupported(
                                node,
                                "context manager is not the admitted native host lock",
                            )
                        current.lock_depth += 1
                        current.trace.append(
                            {"line": node.lineno, "rule": "native-host-lock"}
                        )
                        for outcome in self.block(
                            node.body, [current], delegated=delegated
                        ):
                            outcome.lock_depth -= 1
                            following.append(outcome)
                elif isinstance(node, ast.Return) and node.value is not None:
                    for current, value in self.value(
                        node.value, state, delegated=delegated
                    ):
                        if current.exit == "raise":
                            following.append(current)
                            continue
                        if value != _CONTENT or current.clearance is not True:
                            raise _Unsupported(
                                node,
                                "normal return lacks exact effective-content/clearance correspondence",
                            )
                        current.exit, current.result = "return", value
                        current.trace.append(
                            {
                                "line": node.lineno,
                                "rule": "exact-cleared-content-return",
                            }
                        )
                        following.append(current)
                elif isinstance(node, ast.Raise):
                    call = node.exc
                    if (
                        node.cause is not None
                        or not isinstance(call, ast.Call)
                        or not isinstance(call.func, ast.Name)
                        or call.func.id not in {"PermissionError", "TypeError"}
                        or call.func.id in state.env
                        or len(call.args) != 1
                        or call.keywords
                        or not isinstance(call.args[0], ast.Constant)
                        or type(call.args[0].value) is not str
                    ):
                        raise _Unsupported(
                            node,
                            "refusal may expose data or invoke an unknown exception protocol",
                        )
                    state.exit = "raise"
                    state.trace.append(
                        {
                            "line": node.lineno,
                            "rule": "literal-refusal",
                            "exception": call.func.id,
                        }
                    )
                    following.append(state)
                else:
                    raise _Unsupported(
                        node, f"unsupported reachable statement: {type(node).__name__}"
                    )
            states = following
            if len(states) > 64:
                raise _Unsupported(node, "path budget exhausted")
        return states

    def run(self, name: str) -> dict[str, Any]:
        states = self.block(
            self.methods[name].body,
            [_State(self.initial(name))],
            delegated=name == "dispatch",
        )
        if any(not state.exit for state in states):
            raise _Unsupported(
                self.methods[name], "implicit return is not cleared content"
            )
        returned = [state for state in states if state.exit == "return"]
        if not returned:
            raise _Unsupported(
                self.methods[name], "no useful output-return path was derived"
            )
        return {
            "entry": _HOST + ".ObjectManagerHost." + name,
            "proved": True,
            "normal_returns": len(returned),
            "refusals": sum(state.exit == "raise" for state in states),
            "paths": [
                {
                    "exit": state.exit,
                    "clearance": state.clearance,
                    "result": list(state.result),
                    "derivation": state.trace,
                }
                for state in states
            ],
        }


def _validator_dependency(
    output_data_source: str, objects_source: str
) -> dict[str, Any]:
    """Recompute the validator derivation; a saved report is never authority."""
    # Imported here because the output data verifier reuses this module's models.
    from langgraph.prebuilt.security.output_data_verification import (
        verify_output_data_primitives,
    )

    derived = verify_output_data_primitives(output_data_source, objects_source)
    contract = derived["validator_contract"] or {}
    return {
        "kind": "reachable-input-validation",
        "target": _INPUT_VALIDATOR,
        "proved": bool(
            derived["proved"]
            and derived["validator_admission_proved"]
            and derived["effect_safety_proved"]
        ),
        "source_sha256": derived["source_sha256"],
        "checker_sha256": derived["checker_sha256"],
        "entry_premises": contract.get("entry_premises", []),
        "external_layout_premises": contract.get("external_layout_premises", []),
        "issues": derived["issues"],
    }


def verify_output_correspondence(
    host_source: str,
    objects_source: str,
    *,
    max_steps: int = 2_000,
    output_data_source: str | None = None,
) -> dict[str, Any]:
    """Derive exact cleared-content returns for the supplied host source snapshot.

    Entry premises are mandatory composition obligations, not facts inferred
    from annotations. In particular this does not turn any source helper into
    a publication authorizer, and it never executes supplied code. A reachable
    validator call is discharged only by its contract recomputed from the
    supplied output data source; its premises join this report's premises.
    """
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "host-output-correspondence",
        "proved": False,
        "system_complete": False,
        "runtime_binding_proved": False,
        "initialization_proved": False,
        "property": "For the exact admitted OutputRequest path, each normal return from dispatch/adispatch is the identical request.content and confidentiality is a subset of request.clearance. Reachable non-output effects and unknown behavior prevent this derivation.",
        "entry_premises": [
            "The effective request is an exact OutputRequest with an exact SecurityLabels value; confidentiality and clearance are exact native frozensets of inert strings. Annotations and constructors alone do not prove these premises.",
            "Native dataclass/slot/classifier/frozenset semantics apply. Checked source definitions, annotation/type names, imported names, builtins and method bindings match runtime and remain unchanged; instance/class method shadowing is excluded by separate admission. Module/class initialization, assignment RHS evaluation, imports and constructors are not proved by this component and must separately establish these bindings.",
            "The receiver is an exact ObjectManagerHost with native attribute access and no instance method shadowing. Its _lock is a native reentrant lock with no user callbacks and no exception suppression. Request fields and all relevant bindings remain stable across the call.",
        ],
        "remaining_composition": [
            "Authorization of the effective request for its actual principal, destination and call context.",
            "Admission of payload data/capabilities, label provenance, constructors, source/runtime binding and slot-contained policy/host implementations.",
            "Caller publication and pending-approval/continuation handling, every other request kind, complete placement and host isolation/lifetime.",
        ],
        "source_sha256": {
            _HOST: hashlib.sha256(host_source.encode()).hexdigest(),
            _OBJECTS: hashlib.sha256(objects_source.encode()).hexdigest(),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "entries": [],
        "issues": [],
        "dependencies": [],
        "unproved_dependencies": [],
    }
    validator = None
    try:
        if type(max_steps) is not int or max_steps < 1:
            raise ValueError("positive integer derivation budget required")
        host_tree, objects_tree = ast.parse(host_source), ast.parse(objects_source)
        host_scopes = symtable.symtable(host_source, _HOST, "exec")
        symtable.symtable(objects_source, _OBJECTS, "exec")
        report["native_record_models"] = _native_records(
            objects_tree, _module_bindings(objects_tree)
        )
        if output_data_source is not None:
            validator = _validator_dependency(output_data_source, objects_source)
            report["source_sha256"].update(validator["source_sha256"])
        engine = _Derivation(
            host_tree, _module_bindings(host_tree), host_scopes, max_steps, validator
        )
        report["host_layout"] = {
            "class": _HOST + ".ObjectManagerHost",
            "slots": list(engine.host_slots or ()),
            "instance_method_shadowing": False,
            "source_derived": True,
        }
        report["entries"] = [engine.run(name) for name in ("dispatch", "adispatch")]
        report["forwardings"] = engine.forwardings
        report["steps"] = max_steps - engine.remaining
        if engine.validator_used:
            report["dependencies"].append(validator)
        report["proved"] = True
    except _Unsupported as exc:
        report["issues"].append({"line": exc.line, "reason": exc.reason})
        if exc.obligation is not None:
            if validator is not None:
                exc.obligation["derivation_issues"] = validator["issues"]
            report["unproved_dependencies"].append(exc.obligation)
    except (SyntaxError, ValueError) as exc:
        report["issues"].append({"line": getattr(exc, "lineno", 0), "reason": str(exc)})
    return report
