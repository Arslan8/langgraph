"""Source-derived output mediator correspondence under explicit entry premises.

This component proves the publication route through `OutputMediator._emit` and
`_aemit` in `placement.py` and the thin wrappers that forward to them. It does
not authorize any output, certify the rebuilders, prove initialization or bind
loaded code to source. Candidate source is parsed, never executed.
"""

from __future__ import annotations

import ast
import hashlib
import symtable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.output_verification import (
    _module_bindings,
    _native_records,
    _Unsupported,
)

_PLACEMENT = "langgraph.prebuilt.security.placement"
_ROUTER = "langgraph.prebuilt.security.host_router"
_HOST = "langgraph.prebuilt.security.object_manager"
_OBJECTS = "langgraph.prebuilt.security.objects"
_OUTPUT_DATA = "langgraph.prebuilt.security.output_data"
_BINDING = "langgraph.prebuilt.security.binding"
_ENVELOPE = "langgraph.pregel._io._OutputEnvelope"
_CLASS = "OutputMediator"
_WRAPPERS = ("__call__", "acall", "callback", "acallback", "stream", "astream")
_ENTRIES = ("_emit", "_aemit")
_HELPERS = (
    "_output_mediator_fields",
    "_require_output_host",
    "_principal",
    "_operation_id",
    "_identity",
)
_BUILTINS = frozenset(
    {
        "isinstance",
        "type",
        "PermissionError",
        "TypeError",
        "AttributeError",
        "dict",
        "super",
        "__builtins__",
    }
)
# Mediator slot roles bound by name: the class `__slots__` must be exactly
# these names and the slot reader must return them in this role order.
_SLOT_ROLES = ("router", "host", "destination", "clearance")
# Wrapper roles bound by parameter name: positional parameters after the
# receiver, the content role and the rebuilder role each wrapper may forward.
_WRAPPER_SPECS: dict[str, tuple[tuple[str, ...], str, str]] = {
    "__call__": (("value", "config"), "parameter", "identity"),
    "acall": (("value", "config"), "parameter", "identity"),
    "callback": (
        ("value", "config", "deliver"),
        "parameter",
        "callback-deliver-parameter",
    ),
    "acallback": (
        ("value", "config", "deliver"),
        "parameter",
        "callback-deliver-parameter",
    ),
    "stream": (
        ("envelope", "config"),
        "envelope.content",
        "framework-envelope-rebuild",
    ),
    "astream": (
        ("envelope", "config"),
        "envelope.content",
        "framework-envelope-rebuild",
    ),
}
# Builtin calls a module-level assignment may evaluate at import. placement.py
# evaluates none, so the allowlist is empty; every module-level call refuses.
_MODULE_CALLS: frozenset[str] = frozenset()
_CLASS_DECORATORS = frozenset({"dataclasses.dataclass", "typing.runtime_checkable"})
_METHOD_DECORATORS = frozenset({"property", "staticmethod", "classmethod"})
_IMPURE = (
    ast.Call,
    ast.Lambda,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
    ast.NamedExpr,
    ast.Starred,
)
_EFFECTS = ("labels", "operation_id", "request", "route", "rebuild")
_Value = tuple[str, ...]
_SELF: _Value = ("self",)
_CONTENT: _Value = ("content",)
_CONFIG: _Value = ("config",)
_REBUILD: _Value = ("rebuild",)
_CALLBACK: _Value = ("callback_delivery",)
_PRINCIPAL: _Value = ("principal",)
_BOUND: _Value = ("config", "bound")
_LABELS: _Value = ("labels", "host.labels_for_output")
_OPERATION: _Value = ("operation_id", "__graph__", "output")
_REQUEST: _Value = ("request", "OutputRequest")
_ROUTED: _Value = ("routed", "router.output_emit")
_AROUTED: _Value = ("routed", "router.aoutput_emit")
_REBUILT: _Value = ("rebuilt", "routed")
_AWAITED: _Value = ("rebuilt", "routed", "awaited")


@dataclass
class _State:
    env: dict[str, _Value]
    exit: str = ""
    result: _Value = ()
    receiver_exact: bool = False
    router_slot: _Value = ()
    host_slot: _Value = ()
    phase: str = "pre"
    pair_checks: tuple[str, ...] = ()
    result_kind: str = ""
    callback: bool | None = None
    awaitable: bool | None = None
    effects: dict[str, int] = field(default_factory=dict)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def clone(self) -> _State:
        return replace(
            self,
            env=dict(self.env),
            effects=dict(self.effects),
            trace=list(self.trace),
        )

    def consume(self, node: ast.AST, effect: str) -> None:
        """Record one modeled effect; a repeat on the same path is unmodeled."""
        if self.effects.get(effect):
            raise _Unsupported(
                node, f"{effect} occurs more than once on a path: unmodeled effect"
            )
        self.effects[effect] = 1


def _is_name(node: ast.AST | None, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _refusal(node: ast.stmt, shadowed: set[str]) -> str:
    """Admit only `raise PermissionError('literal')` or `TypeError('literal')`."""
    call = node.exc if isinstance(node, ast.Raise) else None
    if (
        not isinstance(node, ast.Raise)
        or node.cause is not None
        or not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.func.id not in {"PermissionError", "TypeError"}
        or call.func.id in shadowed
        or len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.Constant)
        or type(call.args[0].value) is not str
    ):
        raise _Unsupported(
            node, "refusal may expose data or invoke an unknown exception protocol"
        )
    return call.func.id


def _type_call(node: ast.AST, subject: str, shadowed: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and _is_name(node.func, "type")
        and "type" not in shadowed
        and len(node.args) == 1
        and not node.keywords
        and _is_name(node.args[0], subject)
    )


def _type_guard(
    node: ast.stmt,
    subject: str,
    target: str,
    bindings: dict[str, str],
    shadowed: set[str],
) -> dict[str, Any]:
    """Consume `if type(subject) is not Target: raise <literal refusal>`."""
    test = node.test if isinstance(node, ast.If) else None
    if (
        not isinstance(node, ast.If)
        or node.orelse
        or len(node.body) != 1
        or not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.IsNot)
        or not _type_call(test.left, subject, shadowed)
        or not isinstance(test.comparators[0], ast.Name)
        or test.comparators[0].id in shadowed
        or bindings.get(test.comparators[0].id) != target
    ):
        raise _Unsupported(
            node, "admission requires an exact native type identity guard"
        )
    return {
        "line": node.lineno,
        "rule": "exact-type-guard",
        "subject": subject,
        "class": target,
        "refusal": _refusal(node.body[0], shadowed),
    }


def _none_guard(node: ast.stmt, subject: str, shadowed: set[str]) -> dict[str, Any]:
    """Consume `if subject is None: raise <literal refusal>`."""
    test = node.test if isinstance(node, ast.If) else None
    if (
        not isinstance(node, ast.If)
        or node.orelse
        or len(node.body) != 1
        or not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.Is)
        or not _is_name(test.left, subject)
        or not isinstance(test.comparators[0], ast.Constant)
        or test.comparators[0].value is not None
    ):
        raise _Unsupported(node, "guard requires native None identity")
    return {
        "line": node.lineno,
        "rule": "none-identity-guard",
        "subject": subject,
        "refusal": _refusal(node.body[0], shadowed),
    }


def _signature(
    function: ast.FunctionDef | ast.AsyncFunctionDef, positional: int
) -> tuple[list[str], list[str], list[bool]]:
    """Return positional names, keyword-only names and whether each has False."""
    args = function.args
    if (
        function.decorator_list
        or args.posonlyargs
        or args.vararg
        or args.kwarg
        or args.defaults
        or len(args.args) != positional
    ):
        raise _Unsupported(function, f"unsupported entry signature: {function.name}")
    defaults = []
    for default in args.kw_defaults:
        if default is not None and not (
            isinstance(default, ast.Constant) and default.value is False
        ):
            raise _Unsupported(
                function, f"keyword default is not literal False: {function.name}"
            )
        defaults.append(default is not None)
    names = [arg.arg for arg in args.args]
    keywords = [arg.arg for arg in args.kwonlyargs]
    if len(set(names + keywords)) != len(names) + len(keywords):
        raise _Unsupported(function, f"duplicate parameter: {function.name}")
    return names, keywords, defaults


def _slots(member: ast.stmt) -> tuple[str, ...]:
    value = member.value if isinstance(member, ast.Assign) else None
    if (
        not isinstance(value, ast.Tuple)
        or not value.elts
        or any(
            not isinstance(item, ast.Constant)
            or type(item.value) is not str
            or not item.value.isidentifier()
            or item.value.startswith("__")
            for item in value.elts
        )
    ):
        raise _Unsupported(member, "slots require one literal native layout")
    slots = tuple(item.value for item in value.elts)
    if len(set(slots)) != len(slots):
        raise _Unsupported(member, "slot names must be unique")
    return slots


def _pure_annotation(node: ast.AST) -> None:
    """Admit annotation/base expressions that evaluate no call or comprehension."""
    for item in ast.walk(node):
        if isinstance(item, _IMPURE):
            raise _Unsupported(
                item,
                f"module initialization evaluates an unmodeled {type(item).__name__}",
            )


def _pure_module_value(node: ast.expr, bindings: dict[str, str]) -> None:
    """Admit a Constant, Name, Attribute chain, Tuple of those, or allowlisted call."""
    if isinstance(node, (ast.Constant, ast.Name)):
        return
    if isinstance(node, ast.Attribute):
        _pure_module_value(node.value, bindings)
        return
    if isinstance(node, ast.Tuple):
        for item in node.elts:
            _pure_module_value(item, bindings)
        return
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _MODULE_CALLS
        and node.func.id not in bindings
        and not node.keywords
    ):
        for item in node.args:
            _pure_module_value(item, bindings)
        return
    raise _Unsupported(
        node, f"module initialization evaluates an unmodeled {type(node).__name__}"
    )


def _function_effects(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    bindings: dict[str, str],
    *,
    method: bool,
) -> None:
    """Admit a definition whose decorators and defaults run no unmodeled code."""
    for decorator in function.decorator_list:
        if (
            not method
            or not isinstance(decorator, ast.Name)
            or decorator.id not in _METHOD_DECORATORS
            or decorator.id in bindings
        ):
            raise _Unsupported(decorator, "decorator runs unmodeled code at import")
    args = function.args
    for default in (*args.defaults, *args.kw_defaults):
        if default is not None:
            _pure_module_value(default, bindings)
    for arg in (
        *args.posonlyargs,
        *args.args,
        *args.kwonlyargs,
        args.vararg,
        args.kwarg,
    ):
        if arg is not None and arg.annotation is not None:
            _pure_annotation(arg.annotation)
    if function.returns is not None:
        _pure_annotation(function.returns)


def _class_effects(klass: ast.ClassDef, bindings: dict[str, str]) -> None:
    """Admit a class statement whose creation runs no unmodeled code."""
    for decorator in klass.decorator_list:
        callee = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (
            not isinstance(callee, ast.Name)
            or bindings.get(callee.id) not in _CLASS_DECORATORS
            or (
                isinstance(decorator, ast.Call)
                and (
                    decorator.args
                    or any(
                        not isinstance(keyword.value, ast.Constant)
                        for keyword in decorator.keywords
                    )
                )
            )
        ):
            raise _Unsupported(
                decorator, "class decorator runs unmodeled code at import"
            )
    if klass.keywords:
        raise _Unsupported(klass, "class keywords select an unmodeled metaclass")
    for base in klass.bases:
        _pure_annotation(base)
    for member in klass.body:
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _function_effects(member, bindings, method=True)
        elif isinstance(member, ast.Assign):
            if any(not isinstance(target, ast.Name) for target in member.targets):
                raise _Unsupported(member, "class body mutates an unmodeled target")
            _pure_module_value(member.value, bindings)
        elif isinstance(member, ast.AnnAssign):
            if not isinstance(member.target, ast.Name):
                raise _Unsupported(member, "class body mutates an unmodeled target")
            _pure_annotation(member.annotation)
            if member.value is not None:
                _pure_module_value(member.value, bindings)
        elif isinstance(member, ast.ClassDef):
            _class_effects(member, bindings)
        elif not (
            isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
        ):
            raise _Unsupported(member, "class body runs unmodeled code at import")


def _module_effects(tree: ast.Module, bindings: dict[str, str]) -> dict[str, Any]:
    """Refuse module-level statements that run unmodeled code at import.

    Every statement the module executes when imported must be an import without
    a wildcard, a definition whose decorators and defaults are modeled, an
    assignment whose value is a Constant, Name, Attribute chain, Tuple of those
    or an allowlisted builtin call, or a docstring. `_module_bindings` resolves
    the names; this pass refuses the effects behind them.
    """
    assignments = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(alias.name == "*" for alias in node.names):
                raise _Unsupported(node, "wildcard import binds unmodeled module names")
        elif isinstance(node, ast.Assign):
            if any(not isinstance(target, ast.Name) for target in node.targets):
                raise _Unsupported(node, "module statement mutates an unmodeled target")
            _pure_module_value(node.value, bindings)
            assignments += 1
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name):
                raise _Unsupported(node, "module statement mutates an unmodeled target")
            _pure_annotation(node.annotation)
            if node.value is not None:
                _pure_module_value(node.value, bindings)
            assignments += 1
        elif isinstance(node, ast.ClassDef):
            _class_effects(node, bindings)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _function_effects(node, bindings, method=False)
        elif not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)):
            raise _Unsupported(node, "module statement runs unmodeled code at import")
    return {
        "rule": "module-initialization-scan",
        "statements": len(tree.body),
        "assignments": assignments,
        "call_allowlist": sorted(_MODULE_CALLS),
        "class_decorators": sorted(_CLASS_DECORATORS),
    }


class _Derivation:
    def __init__(
        self,
        tree: ast.Module,
        bindings: dict[str, str],
        scopes: symtable.SymbolTable,
        max_steps: int,
        *,
        record_fields: list[str] | None,
        router_slots: tuple[str, ...] | None,
    ):
        self.bindings = bindings
        self.remaining = max_steps
        self.record_fields = record_fields
        self.router_slots = router_slots
        self.asynchronous = False
        self.helpers: dict[str, dict[str, Any]] = {}
        if _BUILTINS & bindings.keys():
            raise _Unsupported(tree, "native classifier or refusal builtin was rebound")
        self.functions: dict[str, ast.FunctionDef] = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in _HELPERS:
                self.functions[node.name] = node
        for name in _HELPERS:
            if name not in self.functions or self.functions[name].decorator_list:
                raise _Unsupported(tree, f"missing or decorated helper: {name}")
        classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == _CLASS
        ]
        if (
            len(classes) != 1
            or classes[0].bases
            or classes[0].keywords
            or classes[0].decorator_list
        ):
            raise _Unsupported(tree, "mediator class lookup/layout requires a model")
        mediator = classes[0]
        self.locals: dict[str, set[str]] = {}
        for scope in scopes.get_children():
            if scope.get_name() == _CLASS:
                for child in scope.get_children():
                    self.locals[child.get_name()] = {
                        symbol.get_name()
                        for symbol in child.get_symbols()
                        if symbol.is_local()
                    }
            elif scope.get_name() in _HELPERS:
                self.locals[scope.get_name()] = {
                    symbol.get_name()
                    for symbol in scope.get_symbols()
                    if symbol.is_local()
                }
        self.methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.slots: tuple[str, ...] | None = None
        for member in mediator.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (
                    member.decorator_list
                    or member.name in self.methods
                    or member.name
                    in {"__getattribute__", "__getattr__", "__setattr__", "__delattr__"}
                ):
                    raise _Unsupported(
                        member, "method lookup can be changed by a source protocol"
                    )
                self.methods[member.name] = member
            elif (
                isinstance(member, ast.Assign)
                and len(member.targets) == 1
                and _is_name(member.targets[0], "__slots__")
            ):
                if self.slots is not None:
                    raise _Unsupported(
                        member, "slots require one literal native layout"
                    )
                self.slots = _slots(member)
            elif not (
                isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
            ):
                raise _Unsupported(member, "class-body binding requires a model")
        if self.slots is None or set(self.slots) & self.methods.keys():
            raise _Unsupported(mediator, "mediator native slots must exclude methods")
        if set(self.slots) != set(_SLOT_ROLES):
            raise _Unsupported(
                mediator, "mediator native slots differ from the four role slots"
            )
        expected = set(_ENTRIES) | set(_WRAPPERS) | {"_approval_required", "__init__"}
        if set(self.methods) != expected:
            raise _Unsupported(
                mediator, "mediator method surface differs from the modeled surface"
            )
        for name, (asynchronous) in (
            ("_emit", False),
            ("_aemit", True),
            ("_approval_required", False),
            *((name, name.startswith("a")) for name in _WRAPPERS),
        ):
            method = self.methods[name]
            if isinstance(method, ast.AsyncFunctionDef) != asynchronous:
                raise _Unsupported(method, f"missing or wrong await mode: {name}")
        for function in (*self.functions.values(), *self.methods.values()):
            if any(
                isinstance(node, (ast.Global, ast.Nonlocal))
                for node in ast.walk(function)
            ):
                raise _Unsupported(function, "entry modifies an external lexical scope")
        self.exception = self.exception_class(tree)
        self.helpers["_output_mediator_fields"] = self.fields_helper()
        self.helpers["_require_output_host"] = self.pair_helper()
        self.helpers["_principal"] = self.principal_helper()
        self.helpers["_operation_id"] = self.operation_helper()
        self.helpers["_identity"] = self.identity_helper()
        self.helpers["_approval_required"] = self.approval_helper()

    def tick(self, node: ast.AST) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise _Unsupported(node, "derivation budget exhausted")

    def shadowed(self, name: str) -> set[str]:
        return self.locals.get(name, set())

    def module_function(self, name: str, positional: int) -> list[str]:
        names, keywords, _ = _signature(self.functions[name], positional)
        if keywords:
            raise _Unsupported(self.functions[name], f"unsupported helper: {name}")
        return names

    def exception_class(self, tree: ast.Module) -> dict[str, Any]:
        """Admit the approval exception as a literal PermissionError subclass."""
        classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "OutputApprovalRequired"
        ]
        if (
            len(classes) != 1
            or len(classes[0].bases) != 1
            or not _is_name(classes[0].bases[0], "PermissionError")
            or classes[0].keywords
            or classes[0].decorator_list
        ):
            raise _Unsupported(tree, "approval exception is not a PermissionError")
        klass = classes[0]
        methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for member in klass.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if member.decorator_list or member.name in methods:
                    raise _Unsupported(member, "approval exception method is unmodeled")
                methods[member.name] = member
            elif not (
                isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
            ):
                raise _Unsupported(member, "approval exception layout is unmodeled")
        if set(methods) != {"__init__", "resume", "aresume"}:
            raise _Unsupported(klass, "approval exception surface is unmodeled")
        init = methods["__init__"]
        names, keywords, _ = _signature(init, 4)
        if keywords or len(init.body) != 4:
            raise _Unsupported(init, "approval exception constructor is unmodeled")
        me, payload, resume, aresume = names
        first = init.body[0]
        call = first.value if isinstance(first, ast.Expr) else None
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != "__init__"
            or not isinstance(call.func.value, ast.Call)
            or not _is_name(call.func.value.func, "super")
            or call.func.value.args
            or call.func.value.keywords
            or len(call.args) != 1
            or call.keywords
            or not isinstance(call.args[0], ast.Constant)
            or type(call.args[0].value) is not str
        ):
            raise _Unsupported(first, "approval exception message is not literal")
        stores: list[str] = []
        for member, source in zip(init.body[1:], (payload, resume, aresume)):
            target = member.targets[0] if isinstance(member, ast.Assign) else None
            if (
                not isinstance(member, ast.Assign)
                or len(member.targets) != 1
                or not isinstance(target, ast.Attribute)
                or not _is_name(target.value, me)
            ):
                raise _Unsupported(member, "approval exception store is unmodeled")
            value = member.value
            if source == payload:
                if not (
                    isinstance(value, ast.Call)
                    and _is_name(value.func, "dict")
                    and len(value.args) == 1
                    and not value.keywords
                    and _is_name(value.args[0], payload)
                ):
                    raise _Unsupported(member, "payload is not a native dict copy")
            elif not _is_name(value, source):
                raise _Unsupported(member, "continuation store is not the argument")
            stores.append(target.attr)
        return {
            "class": _PLACEMENT + ".OutputApprovalRequired",
            "base": "PermissionError",
            "stores": stores,
            "message": "literal",
            "proved": True,
        }

    def fields_helper(self) -> dict[str, Any]:
        """Derive the slot reader: exact receiver, four native slot reads."""
        function = self.functions["_output_mediator_fields"]
        (subject,) = self.module_function("_output_mediator_fields", 1)
        shadowed = self.shadowed("_output_mediator_fields")
        body = function.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
        ):
            body = body[1:]
        if len(body) != 3:
            raise _Unsupported(function, "slot reader has unmodeled statements")
        guard = _type_guard(
            body[0], subject, "source:" + _CLASS, self.bindings, shadowed
        )
        attempt = body[1]
        returned = (
            attempt.body[0] if isinstance(attempt, ast.Try) and attempt.body else None
        )
        value = returned.value if isinstance(returned, ast.Return) else None
        if (
            not isinstance(attempt, ast.Try)
            or len(attempt.body) != 1
            or attempt.orelse
            or attempt.finalbody
            or len(attempt.handlers) != 1
            or not _is_name(attempt.handlers[0].type, "AttributeError")
            or "AttributeError" in shadowed
            or attempt.handlers[0].name is not None
            or len(attempt.handlers[0].body) != 1
            or not isinstance(attempt.handlers[0].body[0], ast.Pass)
            or not isinstance(value, ast.Tuple)
            or len(value.elts) != 4
            or any(
                not isinstance(item, ast.Attribute) or not _is_name(item.value, subject)
                for item in value.elts
            )
        ):
            raise _Unsupported(attempt, "slot reads are not a guarded native tuple")
        read = tuple(
            item.attr for item in value.elts if isinstance(item, ast.Attribute)
        )
        if any(name not in (self.slots or ()) for name in read):
            raise _Unsupported(attempt, "slot reader reads outside the fixed slots")
        if read != _SLOT_ROLES:
            raise _Unsupported(
                attempt, "slot reader order differs from the named slot roles"
            )
        final = _refusal(body[2], shadowed)
        return {
            "helper": _PLACEMENT + "._output_mediator_fields",
            "proved": True,
            "slots": list(read),
            "result": "returns the four native slot values of an exact OutputMediator receiver in order, or a literal refusal; missing slots refuse without publishing the receiver",
            "derivation": [
                guard,
                {"line": attempt.lineno, "rule": "guarded-native-slot-reads"},
                {"line": body[2].lineno, "rule": "literal-refusal", "exception": final},
            ],
        }

    def pair_helper(self) -> dict[str, Any]:
        """Derive the captured router/host pair check."""
        function = self.functions["_require_output_host"]
        router, host = self.module_function("_require_output_host", 2)
        shadowed = self.shadowed("_require_output_host")
        body = function.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
        ):
            body = body[1:]
        if len(body) != 4:
            raise _Unsupported(function, "pair check has unmodeled statements")
        steps = [
            _type_guard(
                body[0], router, _ROUTER + ".HostRouter", self.bindings, shadowed
            ),
            _type_guard(
                body[1], host, _HOST + ".ObjectManagerHost", self.bindings, shadowed
            ),
        ]
        attempt = body[2]
        inner = attempt.body if isinstance(attempt, ast.Try) else []
        read = inner[0].value if inner and isinstance(inner[0], ast.Expr) else None
        test = (
            inner[1].test if len(inner) == 2 and isinstance(inner[1], ast.If) else None
        )
        if (
            not isinstance(attempt, ast.Try)
            or len(inner) != 2
            or attempt.orelse
            or attempt.finalbody
            or len(attempt.handlers) != 1
            or not _is_name(attempt.handlers[0].type, "AttributeError")
            or "AttributeError" in shadowed
            or attempt.handlers[0].name is not None
            or len(attempt.handlers[0].body) != 1
            or not isinstance(attempt.handlers[0].body[0], ast.Pass)
            or not isinstance(read, ast.Attribute)
            or not _is_name(read.value, router)
            or not isinstance(test, ast.Compare)
            or len(test.ops) != 1
            or not isinstance(test.ops[0], ast.Is)
            or not isinstance(test.left, ast.Attribute)
            or not _is_name(test.left.value, router)
            or not _is_name(test.comparators[0], host)
            or not isinstance(inner[1], ast.If)
            or inner[1].orelse
            or len(inner[1].body) != 1
            or not isinstance(inner[1].body[0], ast.Return)
            or inner[1].body[0].value is not None
        ):
            raise _Unsupported(
                attempt, "pair identity check is not a guarded slot read"
            )
        reads = (read.attr, test.left.attr)
        if self.router_slots is not None and any(
            name not in self.router_slots for name in reads
        ):
            raise _Unsupported(attempt, "pair check reads outside the router slots")
        final = _refusal(body[3], shadowed)
        steps.append(
            {
                "line": attempt.lineno,
                "rule": "guarded-router-slot-identity",
                "reads": list(reads),
                "router_slots_source_derived": self.router_slots is not None,
            }
        )
        steps.append(
            {"line": body[3].lineno, "rule": "literal-refusal", "exception": final}
        )
        return {
            "helper": _PLACEMENT + "._require_output_host",
            "proved": True,
            "reads": list(reads),
            "result": "returns None only when the router is an exact HostRouter, the host an exact ObjectManagerHost, the router slot is readable and the router's host slot is the identical host; otherwise a literal PermissionError; no method of either object is invoked",
            "derivation": steps,
        }

    def principal_helper(self) -> dict[str, Any]:
        """Derive the principal reader as a trusted-runtime wrapper."""
        function = self.functions["_principal"]
        (config,) = self.module_function("_principal", 1)
        shadowed = self.shadowed("_principal")
        body = function.body
        if len(body) != 4:
            raise _Unsupported(function, "principal reader has unmodeled statements")
        first = body[0]
        value = first.value if isinstance(first, ast.AnnAssign) else None
        if (
            not isinstance(first, ast.AnnAssign)
            or not isinstance(first.target, ast.Name)
            or not isinstance(value, ast.IfExp)
            or not isinstance(value.test, ast.Compare)
            or len(value.test.ops) != 1
            or not isinstance(value.test.ops[0], ast.Is)
            or not _is_name(value.test.left, config)
            or not isinstance(value.test.comparators[0], ast.Constant)
            or value.test.comparators[0].value is not None
            or not isinstance(value.body, ast.Dict)
            or value.body.keys
            or not _is_name(value.orelse, config)
        ):
            raise _Unsupported(first, "bound config is not the config or a fresh dict")
        bound = first.target.id
        second = body[1]
        call = second.value if isinstance(second, ast.Assign) else None
        if (
            not isinstance(second, ast.Assign)
            or len(second.targets) != 1
            or not isinstance(second.targets[0], ast.Name)
            or not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Name)
            or call.func.id in shadowed
            or self.bindings.get(call.func.id) != _BINDING + ".principal_from"
            or len(call.args) != 1
            or call.keywords
            or not _is_name(call.args[0], bound)
        ):
            raise _Unsupported(second, "principal is not read by the runtime reader")
        principal = second.targets[0].id
        guard = _none_guard(body[2], principal, shadowed)
        returned = body[3]
        result = returned.value if isinstance(returned, ast.Return) else None
        if (
            not isinstance(result, ast.Tuple)
            or len(result.elts) != 2
            or not _is_name(result.elts[0], principal)
            or not _is_name(result.elts[1], bound)
        ):
            raise _Unsupported(returned, "principal reader returns other values")
        return {
            "helper": _PLACEMENT + "._principal",
            "proved": True,
            "premise": "principal_from",
            "result": "returns (principal_from(bound), bound) where bound is the supplied config or a fresh empty dict, or a literal PermissionError when no principal is bound",
            "derivation": [
                {"line": first.lineno, "rule": "bound-config-select"},
                {
                    "line": second.lineno,
                    "rule": "trusted-runtime-principal-reader",
                    "target": _BINDING + ".principal_from",
                },
                guard,
                {"line": returned.lineno, "rule": "principal-pair-return"},
            ],
        }

    def operation_helper(self) -> dict[str, Any]:
        """Derive the operation id as a literal join over the runtime counter."""
        function = self.functions["_operation_id"]
        config, node, operation = self.module_function("_operation_id", 3)
        shadowed = self.shadowed("_operation_id")
        if len(function.body) != 1 or not isinstance(function.body[0], ast.Return):
            raise _Unsupported(function, "operation id has unmodeled statements")
        joined = function.body[0].value
        parts = joined.values if isinstance(joined, ast.JoinedStr) else []
        counter = (
            parts[4].value
            if len(parts) == 5 and isinstance(parts[4], ast.FormattedValue)
            else None
        )
        if (
            len(parts) != 5
            or not isinstance(parts[0], ast.FormattedValue)
            or not _is_name(parts[0].value, node)
            or not isinstance(parts[1], ast.Constant)
            or parts[1].value != ":"
            or not isinstance(parts[2], ast.FormattedValue)
            or not _is_name(parts[2].value, operation)
            or not isinstance(parts[3], ast.Constant)
            or parts[3].value != ":"
            or not isinstance(parts[4], ast.FormattedValue)
            or any(
                item.conversion != -1 or item.format_spec is not None
                for item in parts
                if isinstance(item, ast.FormattedValue)
            )
            or not isinstance(counter, ast.Call)
            or not isinstance(counter.func, ast.Name)
            or counter.func.id in shadowed
            or self.bindings.get(counter.func.id) != _BINDING + ".next_call_index"
            or len(counter.args) != 1
            or counter.keywords
            or not _is_name(counter.args[0], config)
        ):
            raise _Unsupported(function, "operation id is not the literal counter join")
        return {
            "helper": _PLACEMENT + "._operation_id",
            "proved": True,
            "premise": "next_call_index",
            "result": "returns f'{node}:{operation}:{next_call_index(config)}' for literal node/operation strings; the only effect is the runtime counter advance",
            "derivation": [
                {
                    "line": function.body[0].lineno,
                    "rule": "literal-operation-id-join",
                    "target": _BINDING + ".next_call_index",
                }
            ],
        }

    def identity_helper(self) -> dict[str, Any]:
        function = self.functions["_identity"]
        (value,) = self.module_function("_identity", 1)
        body = function.body
        if (
            len(body) != 1
            or not isinstance(body[0], ast.Return)
            or not _is_name(body[0].value, value)
        ):
            raise _Unsupported(function, "identity rebuilder returns another value")
        return {
            "helper": _PLACEMENT + "._identity",
            "proved": True,
            "result": "returns its argument unchanged",
            "derivation": [{"line": body[0].lineno, "rule": "identity-return"}],
        }

    def approval_helper(self) -> dict[str, Any]:
        """Derive the approval exception builder; continuations stay deferred."""
        function = self.methods["_approval_required"]
        names, keywords, defaults = _signature(function, 4)
        shadowed = self.shadowed("_approval_required")
        me, principal, authorization, rebuild = names
        if len(keywords) != 3 or defaults.count(True) != 1:
            raise _Unsupported(function, "approval builder keywords are unmodeled")
        body = function.body
        if len(body) != 7:
            raise _Unsupported(function, "approval builder has unmodeled statements")
        steps = [_type_guard(body[0], me, "source:" + _CLASS, self.bindings, shadowed)]
        check = body[1].value if isinstance(body[1], ast.Expr) else None
        if (
            not isinstance(check, ast.Call)
            or not isinstance(check.func, ast.Name)
            or check.func.id in shadowed
            or self.bindings.get(check.func.id) != "source:_require_output_host"
            or len(check.args) != 2
            or check.keywords
            or any(not isinstance(arg, ast.Name) for arg in check.args)
        ):
            raise _Unsupported(body[1], "approval builder does not recheck the pair")
        router = check.args[0].id if isinstance(check.args[0], ast.Name) else ""
        host = check.args[1].id if isinstance(check.args[1], ast.Name) else ""
        callback = [name for name, has in zip(keywords, defaults) if has]
        if (
            router not in keywords
            or host not in keywords
            or router == host
            or router in callback
            or host in callback
        ):
            raise _Unsupported(body[1], "pair recheck does not use the keyword pair")
        steps.append({"line": body[1].lineno, "rule": "captured-pair-check"})
        third = body[2]
        value = third.value if isinstance(third, ast.Assign) else None
        if (
            not isinstance(third, ast.Assign)
            or len(third.targets) != 1
            or not isinstance(third.targets[0], ast.Name)
            or not isinstance(value, ast.Attribute)
            or value.attr != "escalation"
            or not isinstance(value.value, ast.Attribute)
            or value.value.attr != "decision"
            or not _is_name(value.value.value, authorization)
        ):
            raise _Unsupported(third, "escalation is not the authorization projection")
        escalation = third.targets[0].id
        steps.append(
            {"line": third.lineno, "rule": "authorization-escalation-projection"}
        )
        steps.append(_none_guard(body[3], escalation, shadowed))
        closures = []
        for member, asynchronous in ((body[4], False), (body[5], True)):
            if (
                not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                or isinstance(member, ast.AsyncFunctionDef) != asynchronous
                or member.decorator_list
                or member.args.defaults
                or any(default is not None for default in member.args.kw_defaults)
            ):
                raise _Unsupported(member, "continuation definition has effects")
            closures.append(member.name)
            steps.append(
                {
                    "line": member.lineno,
                    "rule": "deferred-continuation-closure",
                    "name": member.name,
                    "executed_here": False,
                }
            )
        returned = body[6]
        built = returned.value if isinstance(returned, ast.Return) else None
        payload = built.args[0] if isinstance(built, ast.Call) and built.args else None
        if (
            not isinstance(built, ast.Call)
            or not isinstance(built.func, ast.Name)
            or built.func.id in shadowed
            or self.bindings.get(built.func.id) != "source:OutputApprovalRequired"
            or len(built.args) != 3
            or built.keywords
            or not isinstance(payload, ast.Call)
            or not isinstance(payload.func, ast.Attribute)
            or payload.func.attr != "to_payload"
            or not _is_name(payload.func.value, escalation)
            or payload.args
            or payload.keywords
            or not _is_name(built.args[1], closures[0])
            or not _is_name(built.args[2], closures[1])
        ):
            raise _Unsupported(returned, "return is not the bound approval exception")
        steps.append(
            {
                "line": returned.lineno,
                "rule": "approval-exception-construction",
                "class": self.exception["class"],
                "payload": "escalation.to_payload()",
            }
        )
        return {
            "helper": _PLACEMENT + "." + _CLASS + "._approval_required",
            "proved": True,
            "roles": {
                "principal": principal,
                "authorization": authorization,
                "rebuild": rebuild,
                "router": router,
                "host": host,
                "callback_delivery": callback[0],
            },
            "result": "returns a fresh OutputApprovalRequired (a PermissionError) carrying the redacted escalation payload and two unexecuted continuations, or a literal PermissionError; no routing, rebuild or publication occurs",
            "derivation": steps,
        }

    def entry_env(self, name: str) -> dict[str, _Value]:
        method = self.methods[name]
        names, keywords, defaults = _signature(method, 4)
        if len(keywords) != 1 or defaults != [True]:
            raise _Unsupported(method, f"unsupported entry signature: {name}")
        roles = (_SELF, _CONTENT, _CONFIG, _REBUILD)
        return {
            **{local: ("unbound", local) for local in self.shadowed(name)},
            **dict(zip(names, roles)),
            keywords[0]: _CALLBACK,
        }

    def module_target(self, node: ast.Call, state: _State, target: str) -> bool:
        return (
            isinstance(node.func, ast.Name)
            and node.func.id not in state.env
            and self.bindings.get(node.func.id) == target
        )

    def value(self, node: ast.expr, state: _State) -> _Value:
        self.tick(node)
        if isinstance(node, ast.Name) and node.id in state.env:
            if state.env[node.id][0] == "unbound":
                raise _Unsupported(
                    node, "compiler-local binding is read before assignment"
                )
            return state.env[node.id]
        if isinstance(node, ast.Constant) and type(node.value) in {
            str,
            bool,
            type(None),
        }:
            return ("literal", repr(node.value))
        if isinstance(node, ast.Await):
            inner = node.value
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "aoutput_emit"
            ):
                return self.routed(inner, state, asynchronous=True)
            raise _Unsupported(node, "await of an unmodeled awaitable")
        if isinstance(node, ast.Call):
            if self.module_target(node, state, "source:_operation_id"):
                if (
                    len(node.args) != 3
                    or node.keywords
                    or self.value(node.args[0], state) != _BOUND
                    or not isinstance(node.args[1], ast.Constant)
                    or node.args[1].value != "__graph__"
                    or not isinstance(node.args[2], ast.Constant)
                    or node.args[2].value != "output"
                ):
                    raise _Unsupported(
                        node, "operation id is not the literal output id"
                    )
                state.consume(node, "operation_id")
                state.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "trusted-runtime-operation-id",
                        "helper": self.helpers["_operation_id"]["helper"],
                    }
                )
                return _OPERATION
            if self.module_target(node, state, _OBJECTS + ".OutputRequest"):
                if len(node.args) != 5 or node.keywords:
                    raise _Unsupported(node, "request construction is not positional")
                values = [self.value(arg, state) for arg in node.args]
                if values != [
                    ("self", "destination"),
                    _CONTENT,
                    _LABELS,
                    ("self", "clearance"),
                    _OPERATION,
                ]:
                    raise _Unsupported(
                        node, "request fields differ from the captured mediator inputs"
                    )
                if self.record_fields is not None and self.record_fields[:5] != [
                    "destination",
                    "content",
                    "labels",
                    "clearance",
                    "output_id",
                ]:
                    raise _Unsupported(node, "OutputRequest positional layout differs")
                state.consume(node, "request")
                state.phase = "post"
                state.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "output-request-construction",
                        "fields": [
                            "destination",
                            "content",
                            "labels",
                            "clearance",
                            "output_id",
                        ],
                        "layout_source_derived": self.record_fields is not None,
                    }
                )
                return _REQUEST
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "labels_for_output"
            ):
                receiver = self.value(node.func.value, state)
                if (
                    not state.host_slot
                    or receiver != state.host_slot
                    or "pre" not in state.pair_checks
                    or len(node.args) != 2
                    or node.keywords
                    or self.value(node.args[0], state) != _PRINCIPAL
                    or self.value(node.args[1], state) != _CONTENT
                ):
                    raise _Unsupported(
                        node,
                        "label call is not the checked host on the principal and content",
                    )
                state.consume(node, "labels")
                state.trace.append(
                    {"line": node.lineno, "rule": "checked-host-output-labels"}
                )
                return _LABELS
            if isinstance(node.func, ast.Attribute) and node.func.attr == "output_emit":
                return self.routed(node, state, asynchronous=False)
            if (
                isinstance(node.func, ast.Name)
                and state.env.get(node.func.id) == _REBUILD
            ):
                if (
                    len(node.args) != 1
                    or node.keywords
                    or self.value(node.args[0], state) not in {_ROUTED, _AROUTED}
                    or state.result_kind != "dispatch"
                ):
                    raise _Unsupported(
                        node, "rebuild is not applied to the classified routed result"
                    )
                state.consume(node, "rebuild")
                state.trace.append({"line": node.lineno, "rule": "framework-rebuild"})
                return _REBUILT
        raise _Unsupported(
            node, f"unsupported reachable expression: {type(node).__name__}"
        )

    def routed(self, node: ast.Call, state: _State, *, asynchronous: bool) -> _Value:
        receiver = (
            self.value(node.func.value, state)
            if isinstance(node.func, ast.Attribute)
            else ()
        )
        if (
            not state.router_slot
            or receiver != state.router_slot
            or "post" not in state.pair_checks
            or len(node.args) != 2
            or node.keywords
            or self.value(node.args[0], state) != _PRINCIPAL
            or self.value(node.args[1], state) != _REQUEST
        ):
            raise _Unsupported(
                node, "routing is not the rechecked router on the principal and request"
            )
        state.consume(node, "route")
        state.trace.append(
            {
                "line": node.lineno,
                "rule": "router-output-route",
                "target": _ROUTER
                + ".HostRouter."
                + ("aoutput_emit" if asynchronous else "output_emit"),
            }
        )
        return _AROUTED if asynchronous else _ROUTED

    def branch(self, node: ast.expr, state: _State, truth: bool) -> list[_State]:
        self.tick(node)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.branch(node.operand, state, not truth)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            if len(node.values) != 2:
                raise _Unsupported(node, "boolean conjunction arity is unmodeled")
            first, second = node.values
            if truth:
                return [
                    outcome
                    for current in self.branch(first, state, True)
                    for outcome in self.branch(second, current, True)
                ]
            results = self.branch(first, state.clone(), False)
            for current in self.branch(first, state.clone(), True):
                results.extend(self.branch(second, current, False))
            return results
        if isinstance(node, ast.Name) and state.env.get(node.id) == _CALLBACK:
            if state.callback is not None and state.callback != truth:
                return []
            state.callback = truth
            state.trace.append(
                {"line": node.lineno, "rule": "callback-delivery-flag", "value": truth}
            )
            return [state]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if (
                node.func.id == "isinstance"
                and node.func.id not in state.env
                and len(node.args) == 2
                and not node.keywords
                and isinstance(node.args[1], ast.Name)
                and node.args[1].id not in state.env
                and self.bindings.get(node.args[1].id)
                == _OBJECTS + ".ObjectAuthorization"
            ):
                if self.value(node.args[0], state) not in {_ROUTED, _AROUTED}:
                    raise _Unsupported(
                        node, "classifier does not test the routed result"
                    )
                if state.result_kind:
                    raise _Unsupported(node, "routed result is classified twice")
                state.result_kind = "authorization" if truth else "dispatch"
                state.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "native-authorization-classifier",
                        "matched": truth,
                    }
                )
                return [state]
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "isawaitable"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id not in state.env
            and self.bindings.get(node.func.value.id) == "inspect"
            and len(node.args) == 1
            and not node.keywords
        ):
            if self.value(node.args[0], state) != _REBUILT:
                raise _Unsupported(node, "awaitable classifier tests another value")
            if state.awaitable is not None and state.awaitable != truth:
                return []
            state.awaitable = truth
            state.trace.append(
                {
                    "line": node.lineno,
                    "rule": "stdlib-awaitable-classifier",
                    "matched": truth,
                }
            )
            return [state]
        raise _Unsupported(
            node, "predicate requires unmodeled truth/equality protocols"
        )

    def approval_raise(self, node: ast.Raise, state: _State) -> None:
        call = node.exc
        roles = self.helpers["_approval_required"]["roles"]
        if (
            node.cause is not None
            or not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != "_approval_required"
            or self.value(call.func.value, state) != _SELF
            or not state.receiver_exact
            or state.result_kind != "authorization"
            or len(call.args) != 3
            or [self.value(arg, state) for arg in call.args]
            != [_PRINCIPAL, state.env.get("__routed__", ()), _REBUILD]
            or {
                keyword.arg: self.value(keyword.value, state)
                for keyword in call.keywords
            }
            != {
                roles["router"]: state.router_slot,
                roles["host"]: state.host_slot,
                roles["callback_delivery"]: _CALLBACK,
            }
        ):
            raise _Unsupported(
                node, "authorization path must raise the bound approval exception"
            )
        state.exit = "raise"
        state.trace.append(
            {
                "line": node.lineno,
                "rule": "approval-required-raise",
                "exception": "OutputApprovalRequired",
                "helper": self.helpers["_approval_required"]["helper"],
            }
        )

    def block(self, nodes: list[ast.stmt], states: list[_State]) -> list[_State]:
        for node in nodes:
            self.tick(node)
            following: list[_State] = []
            for state in states:
                if state.exit:
                    following.append(state)
                    continue
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    following.append(state)
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    following.extend(self.pair_check(node.value, state))
                elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                    following.extend(self.assign(node, state))
                elif isinstance(node, ast.If):
                    for truth, branch in ((True, node.body), (False, node.orelse)):
                        children = self.branch(node.test, state.clone(), truth)
                        following.extend(self.block(branch, children))
                elif isinstance(node, ast.Return) and node.value is not None:
                    self.returned(node, state)
                    following.append(state)
                elif isinstance(node, ast.Raise):
                    call = node.exc
                    if isinstance(call, ast.Call) and isinstance(
                        call.func, ast.Attribute
                    ):
                        self.approval_raise(node, state)
                    else:
                        exception = _refusal(node, set(state.env))
                        state.exit = "raise"
                        state.trace.append(
                            {
                                "line": node.lineno,
                                "rule": "literal-refusal",
                                "exception": exception,
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

    def pair_check(self, node: ast.Call, state: _State) -> list[_State]:
        if not self.module_target(node, state, "source:_require_output_host"):
            raise _Unsupported(
                node, "reachable call statement requires an effect derivation"
            )
        if len(node.args) != 2 or node.keywords:
            raise _Unsupported(node, "pair check requires the captured router and host")
        router, host = (self.value(arg, state) for arg in node.args)
        if (router, host) != (("self", "router"), ("self", "host")):
            raise _Unsupported(node, "pair check does not test the captured slot pair")
        if state.router_slot and (state.router_slot, state.host_slot) != (router, host):
            raise _Unsupported(node, "pair check changes the captured pair")
        refused = state.clone()
        refused.exit = "raise"
        refused.trace.append(
            {
                "line": node.lineno,
                "rule": "literal-refusal",
                "exception": "PermissionError",
            }
        )
        state.router_slot, state.host_slot = router, host
        state.pair_checks = (*state.pair_checks, state.phase)
        state.trace.append(
            {
                "line": node.lineno,
                "rule": "captured-pair-check",
                "phase": state.phase,
                "helper": self.helpers["_require_output_host"]["helper"],
            }
        )
        return [refused, state]

    def assign(self, node: ast.Assign, state: _State) -> list[_State]:
        target = node.targets[0]
        value = node.value
        if isinstance(target, ast.Tuple) and isinstance(value, ast.Call):
            names = [
                item.id if isinstance(item, ast.Name) else "" for item in target.elts
            ]
            if "" in names or len(set(names)) != len(names):
                raise _Unsupported(node, "tuple target is not distinct local names")
            if self.module_target(value, state, "source:_output_mediator_fields"):
                if (
                    len(value.args) != 1
                    or value.keywords
                    or self.value(value.args[0], state) != _SELF
                    or len(names) != 4
                ):
                    raise _Unsupported(node, "slot read is not on the receiver")
                refused = state.clone()
                refused.exit = "raise"
                refused.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "literal-refusal",
                        "exception": "PermissionError",
                    }
                )
                for name, slot in zip(names, _SLOT_ROLES):
                    state.env[name] = ("self", slot)
                state.receiver_exact = True
                state.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "exact-receiver-slot-reads",
                        "slots": list(_SLOT_ROLES),
                        "helper": self.helpers["_output_mediator_fields"]["helper"],
                    }
                )
                return [refused, state]
            if self.module_target(value, state, "source:_principal"):
                if (
                    len(value.args) != 1
                    or value.keywords
                    or self.value(value.args[0], state) != _CONFIG
                    or len(names) != 2
                ):
                    raise _Unsupported(
                        node, "principal read is not on the native config"
                    )
                refused = state.clone()
                refused.exit = "raise"
                refused.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "literal-refusal",
                        "exception": "PermissionError",
                    }
                )
                state.env[names[0]], state.env[names[1]] = _PRINCIPAL, _BOUND
                state.trace.append(
                    {
                        "line": node.lineno,
                        "rule": "trusted-runtime-principal",
                        "helper": self.helpers["_principal"]["helper"],
                    }
                )
                return [refused, state]
            raise _Unsupported(node, "tuple assignment requires a derived helper")
        if isinstance(target, ast.Name):
            result = self.value(value, state)
            state.env[target.id] = result
            if result in {_ROUTED, _AROUTED}:
                state.env["__routed__"] = result
            return [state]
        raise _Unsupported(node, "assignment target is not a local name")

    def returned(self, node: ast.Return, state: _State) -> None:
        value = node.value
        if isinstance(value, ast.Await):
            if (
                not isinstance(value.value, ast.Name)
                or self.value(value.value, state) != _REBUILT
                or state.result_kind != "dispatch"
                or state.callback is not True
                or state.awaitable is not True
            ):
                raise _Unsupported(node, "awaited return is not the callback rebuild")
            state.exit, state.result = "return", _AWAITED
            state.trace.append(
                {"line": node.lineno, "rule": "awaited-callback-rebuild-return"}
            )
            return
        if value is None:
            raise _Unsupported(node, "bare return is not a rebuilt result")
        result = self.value(value, state)
        if (
            result != _REBUILT
            or state.result_kind != "dispatch"
            or (
                self.asynchronous
                and not (state.callback is False or state.awaitable is False)
            )
        ):
            raise _Unsupported(
                node, "normal return lacks exact rebuilt-result correspondence"
            )
        state.exit, state.result = "return", result
        state.trace.append({"line": node.lineno, "rule": "exact-rebuilt-result-return"})

    def run(self, name: str) -> dict[str, Any]:
        method = self.methods[name]
        self.asynchronous = isinstance(method, ast.AsyncFunctionDef)
        states = self.block(method.body, [_State(self.entry_env(name))])
        if any(not state.exit for state in states):
            raise _Unsupported(method, "implicit return is not a rebuilt result")
        returned = [state for state in states if state.exit == "return"]
        approvals = [
            state
            for state in states
            if any(step["rule"] == "approval-required-raise" for step in state.trace)
        ]
        if not returned or not approvals:
            raise _Unsupported(method, "no return and approval path pair was derived")
        asynchronous = isinstance(method, ast.AsyncFunctionDef)
        route = _AROUTED if asynchronous else _ROUTED
        if any(
            state.env.get("__routed__") != route for state in (*returned, *approvals)
        ):
            raise _Unsupported(method, "route await mode differs from the entry")
        normal = dict.fromkeys(_EFFECTS, 1)
        approval = {effect: 1 for effect in _EFFECTS if effect != "rebuild"}
        for state, expected in (
            *((state, normal) for state in returned),
            *((state, approval) for state in approvals),
        ):
            if state.effects != expected:
                raise _Unsupported(
                    method, "path effect tally differs from the modeled route"
                )
        return {
            "entry": _PLACEMENT + "." + _CLASS + "." + name,
            "proved": True,
            "normal_returns": len(returned),
            "approval_raises": len(approvals),
            "refusals": sum(state.exit == "raise" for state in states) - len(approvals),
            "paths": [
                {
                    "exit": state.exit,
                    "result": list(state.result),
                    "result_kind": state.result_kind,
                    "callback_delivery": state.callback,
                    "awaited": state.awaitable,
                    "effects": dict(state.effects),
                    "derivation": state.trace,
                }
                for state in states
            ],
        }

    def run_wrapper(self, name: str) -> dict[str, Any]:
        """Derive a thin wrapper: optional exact guards, then one forwarding."""
        method = self.methods[name]
        asynchronous = isinstance(method, ast.AsyncFunctionDef)
        names, keywords, _ = _signature(method, len(method.args.args))
        params, content_kind, rebuild_kind = _WRAPPER_SPECS[name]
        if keywords or len(names) < 1 or tuple(names[1:]) != params:
            raise _Unsupported(
                method, f"wrapper signature differs from the modeled roles: {name}"
            )
        me = names[0]
        shadowed = self.shadowed(name)
        steps: list[dict[str, Any]] = []
        envelope: str | None = None
        body = method.body
        if len(body) < 1 or not isinstance(body[-1], ast.Return):
            raise _Unsupported(
                method, "wrapper does not end with the forwarding return"
            )
        for node in body[:-1]:
            self.tick(node)
            test = node.test if isinstance(node, ast.If) else None
            subject = (
                test.left.args[0].id
                if isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Call)
                and test.left.args
                and isinstance(test.left.args[0], ast.Name)
                else ""
            )
            if subject == me:
                steps.append(
                    _type_guard(node, me, "source:" + _CLASS, self.bindings, shadowed)
                )
            elif (
                subject == "envelope"
                and content_kind == "envelope.content"
                and envelope is None
            ):
                steps.append(
                    _type_guard(node, subject, _ENVELOPE, self.bindings, shadowed)
                )
                envelope = subject
            else:
                raise _Unsupported(
                    node, f"unsupported reachable statement: {type(node).__name__}"
                )
        returned = body[-1]
        call = returned.value
        if asynchronous:
            if not isinstance(call, ast.Await):
                raise _Unsupported(returned, "async wrapper does not await the entry")
            call = call.value
        target = "_aemit" if asynchronous else "_emit"
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != target
            or not isinstance(call.func.value, ast.Name)
            or call.func.value.id in shadowed
            or self.bindings.get(call.func.value.id) != "source:" + _CLASS
            or len(call.args) != 4
            or not _is_name(call.args[0], me)
        ):
            raise _Unsupported(returned, "wrapper does not forward to the class entry")
        content, config, rebuild = call.args[1:]
        # Each forwarded argument is bound to its role by name: the content role
        # is the `value` parameter or the checked `envelope.content`, the config
        # role is the `config` parameter and the rebuilder role is exactly
        # `_identity`, the checked `envelope.rebuild` or the `deliver` parameter.
        if content_kind == "envelope.content":
            if (
                envelope is None
                or not isinstance(content, ast.Attribute)
                or content.attr != "content"
                or not _is_name(content.value, envelope)
            ):
                raise _Unsupported(
                    returned, "content role is not the checked envelope content"
                )
        elif not _is_name(content, "value"):
            raise _Unsupported(returned, "content role is not the value parameter")
        if not _is_name(config, "config"):
            raise _Unsupported(returned, "config role is not the config parameter")
        if rebuild_kind == "framework-envelope-rebuild":
            if (
                envelope is None
                or not isinstance(rebuild, ast.Attribute)
                or rebuild.attr != "rebuild"
                or not _is_name(rebuild.value, envelope)
            ):
                raise _Unsupported(
                    returned, "rebuilder role is not the checked envelope rebuild"
                )
        elif rebuild_kind == "identity":
            if (
                not _is_name(rebuild, "_identity")
                or "_identity" in shadowed
                or self.bindings.get("_identity") != "source:_identity"
            ):
                raise _Unsupported(
                    returned, "rebuilder role is not the derived identity rebuilder"
                )
        elif not _is_name(rebuild, "deliver"):
            raise _Unsupported(returned, "rebuilder role is not the deliver parameter")
        flags = {keyword.arg: keyword.value for keyword in call.keywords}
        callback = rebuild_kind == "callback-deliver-parameter"
        if callback != (
            set(flags) == {"callback_delivery"}
            and isinstance(flags.get("callback_delivery"), ast.Constant)
            and flags["callback_delivery"].value is True
        ) or (not callback and flags):
            raise _Unsupported(
                returned, "callback delivery flag does not match the rebuild"
            )
        steps.append(
            {
                "line": returned.lineno,
                "rule": "class-function-forwarding",
                "target": _PLACEMENT + "." + _CLASS + "." + target,
                "content": content_kind,
                "rebuild": rebuild_kind,
                "callback_delivery": callback,
            }
        )
        return {
            "entry": _PLACEMENT + "." + _CLASS + "." + name,
            "proved": True,
            "forwards_to": target,
            "rebuild": rebuild_kind,
            "callback_delivery": callback,
            "derivation": steps,
        }


def _router_dependency(router_source: str) -> dict[str, Any]:
    """Recompute the router source proof; a saved report is never authority."""
    from langgraph.prebuilt.security.boundary_verification import verify_router_source

    tree = ast.parse(router_source)
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "HostRouter"
    ]
    slots: tuple[str, ...] | None = None
    if len(classes) == 1:
        for member in classes[0].body:
            if isinstance(
                member, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and member.name in {"__getattribute__", "__getattr__"}:
                raise _Unsupported(
                    member, "router attribute lookup protocol is unmodeled"
                )
            if (
                isinstance(member, ast.Assign)
                and len(member.targets) == 1
                and _is_name(member.targets[0], "__slots__")
            ):
                slots = _slots(member)
    if slots is None:
        raise _Unsupported(tree, "router native slots are unresolved")
    derived = verify_router_source(router_source)
    wanted = {
        _ROUTER + ".HostRouter.output_emit",
        _ROUTER + ".HostRouter.aoutput_emit",
    }
    coverage = [item for item in derived["coverage"] if item["entry"] in wanted]
    proved = bool(
        derived["complete"]
        and len(coverage) == 2
        and all(
            item["status"] == "verified"
            and item["host_only"]
            and item["entry_protocol_verified"]
            and item["kind"] == "framework"
            for item in coverage
        )
    )
    return {
        "kind": "router-source-proof",
        "target": sorted(wanted),
        "basis": "recomputed-source-proof",
        "proved": proved,
        "claim": derived["claim"],
        "coverage": coverage,
        "slots": slots,
        "issues": derived["issues"],
        "source_sha256": {_ROUTER: hashlib.sha256(router_source.encode()).hexdigest()},
    }


def _labels_dependency(output_data_source: str, objects_source: str) -> dict[str, Any]:
    """Recompute the output data wrapper contract that labels_for_output applies."""
    from langgraph.prebuilt.security.output_data_verification import (
        verify_output_data_primitives,
    )

    derived = verify_output_data_primitives(output_data_source, objects_source)
    target = _OUTPUT_DATA + ".validate_output_data"
    contract = next(
        (item for item in derived["wrapper_contracts"] if item["entry"] == target), None
    )
    return {
        "kind": "output-data-wrapper-contract",
        "target": target,
        "basis": "recomputed-source-proof",
        "proved": bool(
            derived["proved"] and contract is not None and contract["proved"]
        ),
        "result": None if contract is None else contract["result"],
        "entry_premises": [] if contract is None else contract["entry_premises"],
        "issues": derived["issues"],
        "source_sha256": derived["source_sha256"],
    }


def _host_labels_method(object_manager_source: str) -> dict[str, Any]:
    """Locate labels_for_output; its body is reported, not derived, here."""
    tree = ast.parse(object_manager_source)
    hosts = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ObjectManagerHost"
    ]
    methods = [
        member
        for host in hosts
        for member in host.body
        if isinstance(member, ast.FunctionDef) and member.name == "labels_for_output"
    ]
    if len(hosts) != 1 or len(methods) != 1 or methods[0].decorator_list:
        raise _Unsupported(tree, "host labels_for_output method is unresolved")
    method = methods[0]
    calls = [
        node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "validate_output_data"
    ]
    return {
        "method": _HOST + ".ObjectManagerHost.labels_for_output",
        "positional_parameters": [arg.arg for arg in method.args.args],
        "applies_validate_output_data": bool(calls),
        "body_derived": False,
        "source_sha256": {
            _HOST: hashlib.sha256(object_manager_source.encode()).hexdigest()
        },
    }


def verify_output_mediator_correspondence(
    placement_source: str,
    *,
    router_source: str | None = None,
    output_data_source: str | None = None,
    objects_source: str | None = None,
    object_manager_source: str | None = None,
    max_steps: int = 4_000,
) -> dict[str, Any]:
    """Derive exact rebuilt-result returns for the supplied placement snapshot.

    Entry premises are mandatory composition obligations, not facts inferred
    from annotations. Supplied router/output-data/objects sources are
    recomputed into their own proofs and consumed; omitted sources leave an
    explicit premise in `entry_premises`. No supplied code is executed.
    """
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "output-mediator-correspondence",
        "proved": False,
        "system_complete": False,
        "runtime_binding_proved": False,
        "initialization_proved": False,
        "property": "For an exact OutputMediator receiver with the derived fixed slots, each normal return of _emit/_aemit is rebuild(result) where result is exactly the value returned by router.output_emit/aoutput_emit(principal, request) for the OutputRequest constructed in the same call from the captured destination, the content, host.labels_for_output(principal, content), the captured clearance and the literal output operation id; an ObjectAuthorization result raises the bound OutputApprovalRequired (a PermissionError) and nothing is returned; _require_output_host refuses with a literal PermissionError unless the captured router/host pair matches and runs again after the request is built and before routing; in _aemit a callback delivery awaits an awaitable rebuilt value. On every normal-return and approval path host.labels_for_output, _operation_id, OutputRequest and the routing call each occur exactly once, and on every normal-return path rebuild is evaluated exactly once and its value is the returned value; the slot roles are bound by slot name, not reader order. The six public wrappers forward to these entries through the class function with their parameters bound to the content, config and rebuilder roles by name. Module-level initialization evaluates no call, lambda, comprehension or wildcard import.",
        "entry_premises": [
            "The receiver is an exact OutputMediator with the derived fixed __slots__, native slot descriptors and no instance dictionary; the slot values were stored by __init__ in the order the slot reader returns them (router, host, destination, clearance) and stay stable across the call. Initialization is not proved by this component.",
            "rebuild is one of the three framework rebuilders captured by the trusted runtime: _identity (derived), the exact _OutputEnvelope.rebuild, or the callback deliver parameter. It receives exactly the routed result; its body is not certified here.",
            "_principal applies principal_from, the trusted-runtime identity reader over the native config, and _operation_id applies next_call_index, the trusted-runtime call counter; neither runs a candidate protocol or changes any mediator binding, and the counter advance is their only effect.",
            "host.labels_for_output(principal, content) is the exact ObjectManagerHost method bound to the checked router; it returns the SecurityLabels computed by validate_output_data over the host's own channel state without mutating the content or any mediator binding. Its body is not derived by this component.",
            "OutputRequest is the native frozen-slot dataclass whose construction either returns the record with the supplied positional fields (clearance coerced by frozenset) or raises ValueError; ObjectAuthorization.decision.escalation is a native field and Escalation.to_payload is the framework redaction method.",
            "Native semantics of type, isinstance, PermissionError, TypeError, AttributeError, dict, super and inspect.isawaitable apply; checked source bindings, imports and builtins match runtime and remain unchanged; callback_delivery is an exact bool. Every module-level and class-body statement is scanned so that import evaluates only imports without wildcards, definitions, docstrings and assignments of constants, names, attribute chains and tuples of those (no call, lambda or comprehension); the execution of that initialization, the native Enum/dataclass/Protocol class machinery it selects, and loaded-code binding are not proved by this component.",
        ],
        "remaining_composition": [
            "Authorization of the effective request by the router's policy and host for its actual principal, destination and clearance; label provenance.",
            "The approval continuation bodies (resume/aresume), their caller, and consumption of the bound approval; OutputMediator.__init__ and the runtime's capture of rebuilders, envelopes and mediator instances.",
            "MediatedNode, MediatedBranch and every other placement entry; host isolation, lifetime, concurrency and binding of loaded bytecode to the checked sources.",
        ],
        "source_sha256": {
            _PLACEMENT: hashlib.sha256(placement_source.encode()).hexdigest(),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "entries": [],
        "helpers": [],
        "dependencies": [],
        "unproved_dependencies": [],
        "issues": [],
    }
    try:
        if type(max_steps) is not int or max_steps < 1:
            raise ValueError("positive integer derivation budget required")
        tree = ast.parse(placement_source)
        scopes = symtable.symtable(placement_source, _PLACEMENT, "exec")
        bindings = _module_bindings(tree)
        report["module_initialization"] = _module_effects(tree, bindings)
        record_fields = None
        if objects_source is not None:
            objects_tree = ast.parse(objects_source)
            symtable.symtable(objects_source, _OBJECTS, "exec")
            records = _native_records(objects_tree, _module_bindings(objects_tree))
            record_fields = records["OutputRequest"]
            report["source_sha256"][_OBJECTS] = hashlib.sha256(
                objects_source.encode()
            ).hexdigest()
            report["dependencies"].append(
                {
                    "kind": "native-record-layout",
                    "target": _OBJECTS + ".OutputRequest",
                    "basis": "recomputed-source-proof",
                    "proved": True,
                    "fields": list(record_fields),
                }
            )
        else:
            report["entry_premises"].append(
                "OutputRequest positional fields are (destination, content, labels, clearance, output_id, ...); no objects source was supplied to derive this layout."
            )
        router_slots = None
        if router_source is not None:
            router = _router_dependency(router_source)
            report["source_sha256"].update(router["source_sha256"])
            if not router["proved"]:
                raise _Unsupported(
                    tree,
                    "router output route requires the recomputed router source proof",
                    obligation={k: v for k, v in router.items() if k != "coverage"},
                )
            router_slots = router["slots"]
            report["dependencies"].append(router)
        else:
            report["entry_premises"].append(
                "router.output_emit/aoutput_emit are the exact HostRouter framework routes whose source proof claims that each normal return is the authorized dispatch result for the identical effective request, or an unchanged ESCALATE authorization; HostRouter has native slots policy and host. No router source was supplied to recompute that proof."
            )
            report["dependencies"].append(
                {
                    "kind": "router-source-proof",
                    "target": [
                        _ROUTER + ".HostRouter.output_emit",
                        _ROUTER + ".HostRouter.aoutput_emit",
                    ],
                    "basis": "entry-premise",
                }
            )
        if output_data_source is not None and objects_source is not None:
            labels = _labels_dependency(output_data_source, objects_source)
            report["source_sha256"].update(labels["source_sha256"])
            if not labels["proved"]:
                raise _Unsupported(
                    tree,
                    "host output labels require the recomputed validate_output_data contract",
                    obligation=labels,
                )
            report["dependencies"].append(labels)
        else:
            report["entry_premises"].append(
                "validate_output_data returns a fresh exact SecurityLabels for the content without candidate protocols; no output data source was supplied to recompute its wrapper contract."
            )
            report["dependencies"].append(
                {
                    "kind": "output-data-wrapper-contract",
                    "target": _OUTPUT_DATA + ".validate_output_data",
                    "basis": "entry-premise",
                }
            )
        if object_manager_source is not None:
            host = _host_labels_method(object_manager_source)
            report["source_sha256"].update(host["source_sha256"])
            report["dependencies"].append(
                {"kind": "host-labels-method-shape", "basis": "source-shape", **host}
            )
        engine = _Derivation(
            tree,
            bindings,
            scopes,
            max_steps,
            record_fields=record_fields,
            router_slots=router_slots,
        )
        report["mediator_layout"] = {
            "class": _PLACEMENT + "." + _CLASS,
            "slots": list(engine.slots or ()),
            "instance_method_shadowing": False,
            "source_derived": True,
        }
        report["approval_exception"] = engine.exception
        report["helpers"] = list(engine.helpers.values())
        report["entries"] = [engine.run(name) for name in _ENTRIES]
        report["entries"].extend(engine.run_wrapper(name) for name in _WRAPPERS)
        report["steps"] = max_steps - engine.remaining
        report["proved"] = True
    except _Unsupported as exc:
        report["issues"].append({"line": exc.line, "reason": exc.reason})
        if exc.obligation is not None:
            report["unproved_dependencies"].append(exc.obligation)
    except (SyntaxError, ValueError) as exc:
        report["issues"].append({"line": getattr(exc, "lineno", 0), "reason": str(exc)})
    return report
