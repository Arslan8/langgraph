"""Source-derived evidence for the closed admission surface.

This component parses `admission.py`, `config.py`, `placement.py` and `mac.py`
with `ast` and `symtable` and derives four obligations about the opt-in closed
admission gate (`SecurityConfig(closed_admission=True)`). Candidate source is
never imported or executed. Every statement of each analyzed function must be
consumed by an accepted statement form; an unknown construct, an unknown call
target, a forbidden protocol spelling (`isinstance`, `getattr`, `__module__`,
`get_name`, `.invoke`) or a missing required step leaves that obligation
unproved. Obligation (b) also derives that reducer, cache, retry and trace
callbacks are refused against pinned framework imports, and obligation (d)
that the runtime MAC re-binds the compiled Pregel nodes (`bound` and branch
writers) to the captured wrappers by identity on every check. `MODEL_CALL`
nodes are covered by all four: identity-only allowlist selection (a), `MODEL`
placement on the closed compile path (b), the model hook before the pinned
class-level call (c) and MAC binding (d). Declared `TRUSTED_APPLICATION`
nodes (advisor decision D11) are covered by all four as well: selection only by
exact membership in the deployer's exact frozenset, after the model allowlist
and with a declared `ToolNode` refused (a), refusal of undeclared bodies and
of declarations naming no node on the closed compile path (b), dispatch of
only the function captured at admission after recheck (c) and MAC binding (d).
Their bodies are trusted, not contained; admission binds identity only.
Declared `TRUSTED_APPLICATION_BRANCH` edges are covered the same way: exact
membership of the inventory name in `trusted_application_branches` (a), every
declaration bound to an admitted trusted branch (b), the captured function
after recheck (c) and binding through the compiled branch writers (d).
Initialization,
runtime binding, imports, async adapter lifecycles and the correctness of
`recheck` itself remain premises. The report never claims system completeness
or closure of SGV901.
"""

from __future__ import annotations

import ast
import hashlib
import symtable
from pathlib import Path
from typing import Any

_ADMISSION = "langgraph.prebuilt.security.admission"
_CONFIG = "langgraph.prebuilt.security.config"
_PLACEMENT = "langgraph.prebuilt.security.placement"
_MAC = "langgraph.prebuilt.security.mac"

_CODES = frozenset(
    {
        "UNSUPPORTED_NODE_BODY",
        "UNSUPPORTED_BRANCH",
        "DESCRIPTOR_CHANGED",
        "UNSUPPORTED_ASYNC",
        "CLOSED_ADMISSION_REQUIRED",
        "UNSUPPORTED_CALLBACK",
    }
)
# Spellings that read a candidate protocol or re-dispatch through candidate
# controlled references. They are refused in every analyzed function.
_PROTOCOL_NAMES = frozenset(
    {
        "isinstance",
        "issubclass",
        "hasattr",
        "setattr",
        "delattr",
        "callable",
        "eval",
        "exec",
        "compile",
        "__import__",
        "vars",
        "dir",
        "inspect",
    }
)
_PROTOCOL_ATTRIBUTES = frozenset(
    {
        "__module__",
        "__name__",
        "__qualname__",
        "__class__",
        "__getattribute__",
        "__getattr__",
        "get_name",
        "invoke",
        "ainvoke",
        "batch",
        "abatch",
        "stream",
        "astream",
        "transform",
        "atransform",
        "bound",
        "steps",
        "first",
        "middle",
        "last",
        "signature",
        "get_type_hints",
        "promoted",
        "promotion_reason",
        "startswith",
        "endswith",
    }
)
_NATIVE_METHODS = frozenset({"items", "values", "get", "append", "pop", "close"})


class _Unsupported(Exception):
    def __init__(self, node: Any, reason: str) -> None:
        self.line = getattr(node, "lineno", 0)
        self.reason = reason
        super().__init__(reason)


class _Rules:
    """Per-scope admission rules for expressions and statements."""

    __slots__ = (
        "calls",
        "attributes",
        "names",
        "awaits",
        "methods",
        "handlers",
        "withs",
        "exempt",
        "pinned",
    )

    def __init__(
        self,
        calls: frozenset[str],
        *,
        attributes: frozenset[str] = frozenset(),
        names: frozenset[str] = frozenset(),
        awaits: bool = False,
        methods: frozenset[str] = _NATIVE_METHODS,
        handlers: frozenset[str] = frozenset({"AttributeError", "PermissionError"}),
        withs: frozenset[str] = frozenset(),
        exempt: frozenset[str] = frozenset(),
        pinned: frozenset[str] = frozenset(),
    ) -> None:
        self.calls = calls
        self.attributes = attributes
        self.names = names
        self.awaits = awaits
        self.methods = methods
        self.handlers = handlers
        self.withs = withs
        # Protocol attributes a scope may read because binding them by identity
        # is the obligation itself (`bound` in the compiled-graph binder).
        self.exempt = exempt
        # Names compared by identity that must resolve to module globals.
        self.pinned = pinned


def _definitions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Index top-level functions and class methods; duplicates are refused."""
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def record(name: str, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if name in found:
            raise _Unsupported(node, f"duplicate definition: {name}")
        found[name] = node

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            record(node.name, node)
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    record(node.name + "." + member.name, member)
    return found


def _require(
    found: dict[str, Any], name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    node = found.get(name)
    if node is None:
        raise _Unsupported(ast.Module(body=[], type_ignores=[]), f"missing: {name}")
    if node.decorator_list:
        raise _Unsupported(node, f"decorated definition is not modeled: {name}")
    return node


def _scope_table(table: symtable.SymbolTable, path: tuple[str, ...]) -> Any:
    current = table
    for part in path:
        children = [
            child for child in current.get_children() if child.get_name() == part
        ]
        if len(children) != 1:
            raise _Unsupported(
                ast.Module(body=[], type_ignores=[]), "scope is not unique: " + part
            )
        current = children[0]
    return current


def _require_global_calls(
    table: symtable.SymbolTable, name: str, rules: _Rules
) -> None:
    """Every accepted call target must resolve to a module global, never a local."""
    scope = _scope_table(table, tuple(name.split(".")))
    for symbol in scope.get_symbols():
        if symbol.is_global() and symbol.is_assigned():
            raise _Unsupported(
                ast.Module(body=[], type_ignores=[]),
                f"{name} rebinds module global {symbol.get_name()}",
            )
        if symbol.is_nonlocal():
            raise _Unsupported(
                ast.Module(body=[], type_ignores=[]), f"{name} uses nonlocal"
            )
        if (
            symbol.get_name() in rules.calls or symbol.get_name() in rules.pinned
        ) and symbol.get_name() not in {"function", "afunction"}:
            if not symbol.is_global() and not symbol.is_local():
                raise _Unsupported(
                    ast.Module(body=[], type_ignores=[]),
                    f"{name}: unresolved call target {symbol.get_name()}",
                )
            if symbol.is_local():
                raise _Unsupported(
                    ast.Module(body=[], type_ignores=[]),
                    f"{name}: local shadows call target {symbol.get_name()}",
                )


def _admit_expression(node: ast.AST, rules: _Rules) -> None:
    for part in ast.walk(node):
        if isinstance(part, ast.Call):
            function = part.func
            if isinstance(function, ast.Name):
                if function.id not in rules.calls:
                    raise _Unsupported(part, f"unknown call target: {function.id}")
            elif isinstance(function, ast.Attribute):
                spelled = ast.unparse(function)
                if spelled in rules.calls:
                    continue
                if function.attr not in rules.methods or not isinstance(
                    function.value, (ast.Name, ast.Attribute)
                ):
                    raise _Unsupported(part, f"unknown call target: {spelled}")
            else:
                raise _Unsupported(part, "dynamic call target")
            if any(keyword.arg is None for keyword in part.keywords) or any(
                isinstance(argument, ast.Starred) for argument in part.args
            ):
                raise _Unsupported(part, "unpacked call arguments")
        elif isinstance(part, ast.Attribute):
            if (
                part.attr in _PROTOCOL_ATTRIBUTES and part.attr not in rules.exempt
            ) or part.attr in rules.attributes:
                raise _Unsupported(part, f"protocol attribute: {part.attr}")
        elif isinstance(part, ast.Name):
            if part.id in _PROTOCOL_NAMES or part.id in rules.names:
                raise _Unsupported(part, f"protocol name: {part.id}")
        elif isinstance(part, ast.Await):
            if not rules.awaits:
                raise _Unsupported(part, "await outside an admitted async route")
        elif isinstance(
            part,
            (
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.Yield,
                ast.YieldFrom,
                ast.NamedExpr,
                ast.Starred,
            ),
        ):
            raise _Unsupported(part, "unmodeled expression form")


def _raise_code(node: ast.stmt) -> str | None:
    """Match `raise <Exception>(<CODE or literal>)` optionally `from None`."""
    if not isinstance(node, ast.Raise) or node.exc is None:
        return None
    if node.cause is not None and not (
        isinstance(node.cause, ast.Constant) and node.cause.value is None
    ):
        return None
    exc = node.exc
    if (
        not isinstance(exc, ast.Call)
        or not isinstance(exc.func, ast.Name)
        or exc.func.id not in {"PermissionError", "SecurityConfigurationError"}
        or len(exc.args) != 1
        or exc.keywords
    ):
        return None
    argument = exc.args[0]
    # `code` is the parameter of the `_require_*` helpers; every caller passes a
    # registered constant, which the expression admission of the caller checks.
    if isinstance(argument, ast.Name) and (
        argument.id in _CODES or argument.id == "code"
    ):
        return argument.id
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    return None


def _is_refusal_block(body: list[ast.stmt], rules: _Rules) -> str:
    """A guard body is either `raise CODE` or `placement_stack.close(); raise`."""
    if not body or _raise_code(body[-1]) is None:
        raise _Unsupported(body[0] if body else ast.Pass(), "guard does not refuse")
    for statement in body[:-1]:
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and ast.unparse(statement.value.func) == "placement_stack.close"
            and not statement.value.args
        ):
            raise _Unsupported(statement, "guard body has effects before refusal")
    return _raise_code(body[-1]) or ""


def _admit_statements(body: list[ast.stmt], rules: _Rules) -> int:
    """Consume every statement with an accepted form; return the count consumed."""
    consumed = 0
    for statement in body:
        consumed += 1
        if isinstance(statement, ast.Expr):
            if isinstance(statement.value, ast.Constant):
                continue
            if isinstance(statement.value, ast.Await):
                if not rules.awaits:
                    raise _Unsupported(statement, "await outside an admitted route")
                _admit_expression(statement.value.value, rules)
                continue
            if not isinstance(statement.value, ast.Call):
                raise _Unsupported(statement, "expression statement is not a call")
            _admit_expression(statement.value, rules)
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if isinstance(target, ast.Tuple):
                    if any(not isinstance(item, ast.Name) for item in target.elts):
                        raise _Unsupported(statement, "nested unpacking target")
                elif isinstance(target, ast.Subscript):
                    if not isinstance(target.value, ast.Name):
                        raise _Unsupported(statement, "indirect subscript target")
                    _admit_expression(target.slice, rules)
                elif isinstance(target, ast.Attribute):
                    if not isinstance(target.value, ast.Name):
                        raise _Unsupported(statement, "indirect attribute target")
                    if target.attr in _PROTOCOL_ATTRIBUTES:
                        raise _Unsupported(statement, "protocol attribute target")
                elif not isinstance(target, ast.Name):
                    raise _Unsupported(statement, "unmodeled assignment target")
            if statement.value is not None:
                _admit_expression(statement.value, rules)
        elif isinstance(statement, ast.If):
            _admit_expression(statement.test, rules)
            consumed += _admit_statements(statement.body, rules)
            consumed += _admit_statements(statement.orelse, rules)
        elif isinstance(statement, ast.Raise):
            if _raise_code(statement) is None and statement.exc is not None:
                raise _Unsupported(statement, "raise is not a registered refusal")
        elif isinstance(statement, ast.Return):
            if statement.value is not None:
                _admit_expression(statement.value, rules)
        elif isinstance(statement, ast.Try):
            if statement.orelse or statement.finalbody:
                raise _Unsupported(statement, "try else/finally is not modeled")
            for handler in statement.handlers:
                if (
                    not isinstance(handler.type, ast.Name)
                    or handler.type.id not in rules.handlers
                ):
                    raise _Unsupported(handler, "unmodeled exception handler")
                consumed += _admit_statements(handler.body, rules)
            consumed += _admit_statements(statement.body, rules)
        elif isinstance(statement, ast.For):
            if statement.orelse:
                raise _Unsupported(statement, "unmodeled loop form")
            target = statement.target
            names = target.elts if isinstance(target, ast.Tuple) else [target]
            if any(not isinstance(item, ast.Name) for item in names):
                raise _Unsupported(statement, "unmodeled loop target")
            _admit_expression(statement.iter, rules)
            consumed += _admit_statements(statement.body, rules)
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            if isinstance(statement, ast.ImportFrom) and statement.level:
                raise _Unsupported(statement, "relative import")
        elif isinstance(statement, ast.With):
            # Only a named native lock may be entered; its body is admitted.
            if len(statement.items) != 1 or statement.items[0].optional_vars:
                raise _Unsupported(statement, "unmodeled context manager")
            context = statement.items[0].context_expr
            if not isinstance(context, ast.Name) or context.id not in rules.withs:
                raise _Unsupported(statement, "unmodeled context manager")
            consumed += _admit_statements(statement.body, rules)
        elif isinstance(statement, (ast.Continue, ast.Pass)):
            continue
        else:
            raise _Unsupported(statement, "unmodeled statement form")
    return consumed


def _mentions(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(part, ast.Name) and part.id == name for part in ast.walk(node)
    )


def _exact_guard(statement: ast.stmt, subject: str) -> tuple[str, str] | None:
    """Match `if type(<subject>) is not <Class>: raise <Error>(<CODE>)`."""
    if not isinstance(statement, ast.If) or statement.orelse:
        return None
    test = statement.test
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.IsNot)
        or not isinstance(test.left, ast.Call)
        or not isinstance(test.left.func, ast.Name)
        or test.left.func.id != "type"
        or len(test.left.args) != 1
        or test.left.keywords
        or not isinstance(test.left.args[0], ast.Name)
        or test.left.args[0].id != subject
        or not isinstance(test.comparators[0], ast.Name)
    ):
        return None
    if len(statement.body) != 1:
        return None
    code = _raise_code(statement.body[0])
    if code is None:
        return None
    return test.comparators[0].id, code


def _call_target(statement: ast.stmt) -> str | None:
    value = None
    if isinstance(statement, ast.Expr):
        value = statement.value
    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
        value = statement.value
    elif isinstance(statement, ast.Return):
        value = statement.value
    if isinstance(value, ast.Await):
        value = value.value
    if isinstance(value, ast.Call):
        return ast.unparse(value.func)
    return None


def _calls_in(statement: ast.stmt) -> list[str]:
    return [
        ast.unparse(part.func)
        for part in ast.walk(statement)
        if isinstance(part, ast.Call)
    ]


def _uses_of(statement: ast.stmt, name: str) -> list[str]:
    """Spell every call whose arguments mention `name` and every attribute read."""
    uses = []
    for part in ast.walk(statement):
        if isinstance(part, ast.Call) and any(
            _mentions(argument, name) for argument in [*part.args, *part.keywords]
        ):
            uses.append("call:" + ast.unparse(part.func))
        if (
            isinstance(part, ast.Attribute)
            and isinstance(part.value, ast.Name)
            and part.value.id == name
        ):
            uses.append("attr:" + part.attr)
    return uses


def _candidate_reads_guarded(
    function: ast.FunctionDef | ast.AsyncFunctionDef, candidate: str
) -> list[str]:
    """Require every `candidate.<attr>` read to be inside `try/except AttributeError`.

    The reads are plain assignments `name = candidate.attr` whose only effect is
    the native attribute lookup on an exact framework type. Outside such a block
    the candidate may only be passed to accepted helpers or constructors.
    """
    reads: list[str] = []

    def walk(body: list[ast.stmt], guarded: bool) -> None:
        for statement in body:
            if isinstance(statement, ast.Try):
                handled = {
                    handler.type.id
                    for handler in statement.handlers
                    if isinstance(handler.type, ast.Name)
                }
                walk(statement.body, guarded or "AttributeError" in handled)
                for handler in statement.handlers:
                    walk(handler.body, guarded)
                continue
            if isinstance(statement, (ast.If, ast.For)):
                walk(statement.body, guarded)
                walk(getattr(statement, "orelse", []), guarded)
                if _mentions(
                    statement.test if isinstance(statement, ast.If) else statement.iter,
                    candidate,
                ):
                    test = (
                        statement.test
                        if isinstance(statement, ast.If)
                        else statement.iter
                    )
                    for part in ast.walk(test):
                        if (
                            isinstance(part, ast.Attribute)
                            and isinstance(part.value, ast.Name)
                            and part.value.id == candidate
                        ):
                            raise _Unsupported(
                                statement, f"unguarded read of {candidate}.{part.attr}"
                            )
                continue
            for part in ast.walk(statement):
                if (
                    isinstance(part, ast.Attribute)
                    and isinstance(part.value, ast.Name)
                    and part.value.id == candidate
                ):
                    if not guarded or not (
                        isinstance(statement, ast.Assign)
                        and isinstance(statement.value, ast.Attribute)
                        and statement.value is part
                    ):
                        raise _Unsupported(
                            statement, f"unguarded read of {candidate}.{part.attr}"
                        )
                    reads.append(part.attr)

    walk(function.body, False)
    return reads


# ---------------------------------------------------------------------------
# Obligation (a): admit_node/admit_branch select by exact type identity.
# ---------------------------------------------------------------------------

_ADMISSION_RULES = _Rules(
    frozenset(
        {
            "type",
            "len",
            "tuple",
            "PermissionError",
            "_require_name",
            "_require_config",
            "_capture_tool_node",
            "_capture_branch",
            "_tool_node_state",
            "_branch_state",
            "_language_admission",
            "_is_bound_method",
            "_pinned_branch_id",
            "AdmittedDescriptor",
            "_CapturedToolNode",
            "_CapturedBranch",
            "ToolNode.__dict__.get",
            "_allowlisted_model",
            "_admit_model_call",
            "_model_allowlist",
            "_capture_model",
            "_model_endpoint",
            "_model_state",
            "_class_function",
            "_CapturedModel",
            "importlib.import_module",
            "_declared_trusted",
            "_declared_application_nodes",
            "_admit_trusted_application",
            "_capture_application",
            "_application_state",
            "_application_code",
            "_is_coroutine",
            "_is_executor_shim",
            "_CapturedApplication",
            "_declared_trusted_branch",
            "_declared_application_branches",
            "_bind_declared_branches",
            "_admit_trusted_branch",
            "_capture_trusted_branch",
            "_trusted_branch_state",
            "_CapturedTrustedBranch",
        }
    ),
    attributes=frozenset({"metadata"}),
    methods=_NATIVE_METHODS | frozenset({"setdefault"}),
    handlers=frozenset({"AttributeError", "PermissionError", "ImportError"}),
)
# The model allowlist is matched by identity only: exact registry entries,
# resolved by import into a pinned dictionary, compared with `is`. A declared
# trusted application node is selected afterwards, so a declared model keeps
# `MODEL_CALL`, and only by exact membership in the deployer's frozenset.
_MODEL_SELECTION = (
    "registry_id = _allowlisted_model(type(runnable))",
    "if registry_id is not None:\n    return _admit_model_call(name, runnable, registry_id)",
    "if _declared_trusted(name, config):\n    return _admit_trusted_application(name, runnable)",
)
_DECLARED_NODES = [
    "config = _require_config(config, UNSUPPORTED_NODE_BODY)",
    "declared = config.trusted_application_nodes",
    "if type(declared) is not frozenset:\n    raise PermissionError(UNSUPPORTED_NODE_BODY)",
    "for item in declared:\n    if type(item) is not str:\n        raise PermissionError(UNSUPPORTED_NODE_BODY)",
    "return declared",
]
_DECLARED_MEMBERSHIP = [
    "declared = _declared_application_nodes(config)",
    "return name in declared",
]
_BRANCH_SELECTION = (
    "if _declared_trusted_branch(name, config):\n    return _admit_trusted_branch(name, branch)",
)
_DECLARED_BRANCHES = [
    item.replace("UNSUPPORTED_NODE_BODY", "UNSUPPORTED_BRANCH").replace(
        "trusted_application_nodes", "trusted_application_branches"
    )
    for item in _DECLARED_NODES
]
_DECLARED_BRANCH_MEMBERSHIP = [
    "declared = _declared_application_branches(config)",
    "return name in declared",
]
_BOUND_BRANCHES = [
    "declared = _declared_application_branches(config)",
    "for name in declared:\n    descriptor = inventory.get(name)\n    if type(descriptor) is not AdmittedDescriptor:\n        raise PermissionError(UNSUPPORTED_BRANCH)\n    if descriptor.kind is not AdmittedKind.TRUSTED_APPLICATION_BRANCH:\n        raise PermissionError(UNSUPPORTED_BRANCH)",
]
_ALLOWLIST_LOOP = [
    "for registry_id, allowed in _model_allowlist():\n    if allowed is not None and kind is allowed:\n        return registry_id",
    "return None",
]


def _entry_guard_precedes_use(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    candidate: str,
    expected_class: str,
    expected_code: str,
    helper: str,
    selections: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Prove: no statement reads `candidate` before its exact-type guard, and
    afterwards the candidate flows only into `helper` and the result record.

    `selections` are the exact statements allowed to mention the candidate
    before the guard (the identity-only model allowlist selection); each must
    appear once, in order.
    """
    guard_line = None
    seen: list[str] = []
    for index, statement in enumerate(function.body):
        guard = _exact_guard(statement, candidate)
        if guard is not None:
            if guard != (expected_class, expected_code):
                raise _Unsupported(statement, "exact-type guard differs")
            guard_line = statement.lineno
            remaining = function.body[index + 1 :]
            break
        if _mentions(statement, candidate):
            spelled = ast.unparse(statement)
            if spelled not in selections or spelled in seen:
                raise _Unsupported(
                    statement, f"{candidate} used before exact-type guard"
                )
            seen.append(spelled)
    else:
        raise _Unsupported(function, f"no exact-type guard on {candidate}")
    if tuple(seen) != selections:
        raise _Unsupported(function, "model selection differs")
    helper_calls = 0
    for statement in remaining:
        for use in _uses_of(statement, candidate):
            if use != "call:" + helper:
                raise _Unsupported(statement, f"candidate flows to {use}")
            helper_calls += 1
    if helper_calls != 1:
        raise _Unsupported(function, f"{candidate} must flow once into {helper}")
    return {"guard_line": guard_line, "class": expected_class, "code": expected_code}


def _prove_exact_type_selection(
    tree: ast.Module, table: symtable.SymbolTable
) -> dict[str, Any]:
    found = _definitions(tree)
    entries = []
    scoped = (
        "admit_node",
        "admit_branch",
        "_admit_model_call",
        "_model_allowlist",
        "_allowlisted_model",
        "_capture_model",
        "_model_endpoint",
        "_class_function",
        "_capture_tool_node",
        "_capture_branch",
        "_language_admission",
        "_is_bound_method",
        "_require_name",
        "_require_config",
        "_declared_application_nodes",
        "_declared_trusted",
        "_admit_trusted_application",
        "_capture_application",
        "_is_executor_shim",
        "_declared_application_branches",
        "_declared_trusted_branch",
        "_bind_declared_branches",
        "_admit_trusted_branch",
        "_capture_trusted_branch",
    )
    for name in scoped:
        function = _require(found, name)
        if isinstance(function, ast.AsyncFunctionDef):
            raise _Unsupported(function, "admission must be synchronous")
        consumed = _admit_statements(function.body, _ADMISSION_RULES)
        _require_global_calls(table, name, _ADMISSION_RULES)
        entries.append({"function": name, "statements": consumed})
    node = _entry_guard_precedes_use(
        _require(found, "admit_node"),
        "runnable",
        "ToolNode",
        "UNSUPPORTED_NODE_BODY",
        "_capture_tool_node",
        _MODEL_SELECTION,
    )
    model = _prove_model_selection(found)
    application = _prove_application_selection(found)
    branch = _entry_guard_precedes_use(
        _require(found, "admit_branch"),
        "branch",
        "BranchSpec",
        "UNSUPPORTED_BRANCH",
        "_capture_branch",
        _BRANCH_SELECTION,
    )
    trusted_branch = _prove_trusted_branch_selection(found)
    # The captured candidates are read only through native attribute lookups
    # guarded by `AttributeError`; the remaining uses are identity checks.
    node_reads = _candidate_reads_guarded(_require(found, "_capture_tool_node"), "node")
    for required in ("func", "afunc", "_wrap_tool_call", "_awrap_tool_call"):
        if required not in node_reads:
            raise _Unsupported(found["_capture_tool_node"], f"missing read: {required}")
    capture_branch = _require(found, "_capture_branch")
    path_guard = None
    for statement in capture_branch.body:
        guard = _exact_guard(statement, "path")
        if guard is not None:
            if guard != ("RunnableCallable", "UNSUPPORTED_BRANCH"):
                raise _Unsupported(statement, "branch path guard differs")
            path_guard = statement.lineno
            break
        if _mentions(statement, "path") and not (
            isinstance(statement, ast.Assign)
            and ast.unparse(statement.value) == "branch.path"
        ):
            raise _Unsupported(statement, "path used before exact-type guard")
    if path_guard is None:
        raise _Unsupported(capture_branch, "no exact-type guard on path")
    path_reads = _candidate_reads_guarded(capture_branch, "path")
    if "func" not in path_reads:
        raise _Unsupported(capture_branch, "branch function is not read natively")
    return {
        "proved": True,
        "property": "admit_node refuses with admission:unsupported_node_body unless type(runnable) is ToolNode, and admit_branch refuses with admission:unsupported_branch unless type(branch) is BranchSpec, before any other read of the candidate; afterwards the candidate flows only into the capture helper, whose reads are native attribute lookups guarded by AttributeError and identity checks. A chat model is selected only when _allowlisted_model finds type(runnable) identical (`is`) to a class pinned from the exact _MODEL_CLASSES registry; the candidate then flows once into _capture_model, which re-guards type(model) is the pinned class, reads only model.__dict__ under AttributeError and resolves invoke/ainvoke on the class. A trusted application node is selected only after the model allowlist, only when _declared_trusted finds the exact str name in the exact frozenset SecurityConfig.trusted_application_nodes (every member re-guarded as exact str; no heuristic, metadata or module test), and the candidate then flows once into _capture_application, whose first step refuses with admission:unsupported_node_body unless type(node) is RunnableCallable, so a declared ToolNode (a distinct exact type) is refused rather than downgraded and a declared model keeps MODEL_CALL; its reads are native attribute lookups guarded by AttributeError. A trusted application branch is selected, before the BranchSpec guard, only when _declared_trusted_branch finds the exact inventory name <source>:branch:<branch_name> in the exact frozenset SecurityConfig.trusted_application_branches; the candidate flows once into _capture_trusted_branch, which guards type(branch) is BranchSpec and type(path) is RunnableCallable first, reads the path only under AttributeError, and refuses a pinned framework branch so it is never downgraded; _bind_declared_branches refuses any declaration not admitted as TRUSTED_APPLICATION_BRANCH. No isinstance, getattr, __module__, __name__, get_name, signature or invoke protocol is spelled in the admission entry functions.",
        "entries": entries,
        "admit_node": node,
        "model_selection": model,
        "application_selection": application,
        "trusted_branch_selection": trusted_branch,
        "admit_branch": branch,
        "capture_branch_path_guard_line": path_guard,
        "issues": [],
    }


def _prove_model_selection(found: dict[str, Any]) -> dict[str, Any]:
    """Prove the model allowlist is an identity match and capture re-guards it."""
    allowlisted = _require(found, "_allowlisted_model")
    if _body_text(allowlisted) != _ALLOWLIST_LOOP:
        raise _Unsupported(allowlisted, "model selection is not the identity loop")
    allowlist = _require(found, "_model_allowlist")
    _require_text(
        allowlist,
        (
            "for module_name, attribute in _MODEL_CLASSES:",
            "module = importlib.import_module(module_name)\n            resolved = module.__dict__.get(attribute)",
            "_pinned_models.setdefault(registry_id, resolved)",
            "return tuple(_pinned_models.items())",
        ),
    )
    admit = _require(found, "_admit_model_call")
    uses = [use for statement in admit.body for use in _uses_of(statement, "model")]
    if uses != ["call:_capture_model"]:
        raise _Unsupported(admit, "model flows outside _capture_model")
    capture = _require(found, "_capture_model")
    guard_line = None
    for statement in capture.body:
        guard = _exact_guard(statement, "model")
        if guard is not None:
            if guard != ("model_class", "UNSUPPORTED_NODE_BODY"):
                raise _Unsupported(statement, "model guard differs")
            guard_line = statement.lineno
            break
        if _mentions(statement, "model"):
            raise _Unsupported(statement, "model used before exact-type guard")
    if guard_line is None:
        raise _Unsupported(capture, "no exact-type guard on model")
    if "model_class = _pinned_models.get(registry_id)" not in _body_text(capture):
        raise _Unsupported(capture, "model class is not the pinned registry entry")
    if _candidate_reads_guarded(capture, "model") != ["__dict__"]:
        raise _Unsupported(capture, "model reads differ from its native dict")
    _require_text(
        capture,
        (
            "call = _class_function(model_class, 'invoke')",
            "acall = _class_function(model_class, 'ainvoke')",
        ),
    )
    return {"guard_line": guard_line, "class": "model_class"}


def _prove_application_selection(found: dict[str, Any]) -> dict[str, Any]:
    """Prove trusted application selection is exact frozenset membership only.

    The declared set is the exact frozenset read from the exact config with
    every member re-guarded as an exact `str`; membership is the only test.
    The candidate flows once into `_capture_application`, whose first use of
    the candidate is the exact `RunnableCallable` guard, so a declared
    `ToolNode` refuses and is never admitted under a weaker kind.
    """
    declared = _require(found, "_declared_application_nodes")
    if _body_text(declared) != _DECLARED_NODES:
        raise _Unsupported(declared, "declared set is not the exact frozenset")
    membership = _require(found, "_declared_trusted")
    if _body_text(membership) != _DECLARED_MEMBERSHIP:
        raise _Unsupported(membership, "selection is not exact set membership")
    admit = _require(found, "_admit_trusted_application")
    uses = [use for statement in admit.body for use in _uses_of(statement, "runnable")]
    if uses != ["call:_capture_application"]:
        raise _Unsupported(admit, "candidate flows outside _capture_application")
    if (
        "return AdmittedDescriptor(AdmittedKind.TRUSTED_APPLICATION, name, identity, captured, source)"
        not in _body_text(admit)
    ):
        raise _Unsupported(admit, "trusted application descriptor differs")
    capture = _require(found, "_capture_application")
    guard_line = None
    for statement in capture.body:
        guard = _exact_guard(statement, "node")
        if guard is not None:
            if guard != ("RunnableCallable", "UNSUPPORTED_NODE_BODY"):
                raise _Unsupported(statement, "application guard differs")
            guard_line = statement.lineno
            break
        if _mentions(statement, "node"):
            raise _Unsupported(statement, "node used before exact-type guard")
    if guard_line is None:
        raise _Unsupported(capture, "no exact-type guard on the application node")
    if not any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "langgraph._internal._runnable"
        and [alias.name for alias in statement.names] == ["RunnableCallable"]
        and statement.names[0].asname is None
        for statement in capture.body
    ):
        raise _Unsupported(capture, "RunnableCallable is not the framework class")
    reads = _candidate_reads_guarded(capture, "node")
    for required in ("func", "afunc", "kwargs", "explode_args", "func_accepts"):
        if required not in reads:
            raise _Unsupported(capture, f"missing read: {required}")
    return {"guard_line": guard_line, "class": "RunnableCallable"}


def _prove_trusted_branch_selection(found: dict[str, Any]) -> dict[str, Any]:
    """Prove trusted branch selection is exact frozenset membership only."""
    declared = _require(found, "_declared_application_branches")
    if _body_text(declared) != _DECLARED_BRANCHES:
        raise _Unsupported(declared, "declared branches are not the exact frozenset")
    membership = _require(found, "_declared_trusted_branch")
    if _body_text(membership) != _DECLARED_BRANCH_MEMBERSHIP:
        raise _Unsupported(membership, "branch selection is not set membership")
    bound = _require(found, "_bind_declared_branches")
    if _body_text(bound) != _BOUND_BRANCHES:
        raise _Unsupported(bound, "declared branches are not bound to admissions")
    admit = _require(found, "_admit_trusted_branch")
    uses = [use for statement in admit.body for use in _uses_of(statement, "branch")]
    if uses != ["call:_capture_trusted_branch"]:
        raise _Unsupported(admit, "candidate flows outside _capture_trusted_branch")
    if (
        "return AdmittedDescriptor(AdmittedKind.TRUSTED_APPLICATION_BRANCH, name, identity, captured, source)"
        not in _body_text(admit)
    ):
        raise _Unsupported(admit, "trusted branch descriptor differs")
    capture = _require(found, "_capture_trusted_branch")
    statements = [
        item
        for item in capture.body
        if not _is_docstring(item)
        and not isinstance(item, (ast.Import, ast.ImportFrom))
    ]
    guard = _exact_guard(statements[0], "branch") if statements else None
    if guard != ("BranchSpec", "UNSUPPORTED_BRANCH"):
        raise _Unsupported(capture, "no leading exact-type guard on the branch")
    if len(statements) < 3 or ast.unparse(statements[1]) != "path = branch.path":
        raise _Unsupported(capture, "path is not read after the branch guard")
    if _exact_guard(statements[2], "path") != (
        "RunnableCallable",
        "UNSUPPORTED_BRANCH",
    ):
        raise _Unsupported(capture, "no exact-type guard on the branch path")
    imports = {
        (statement.module, alias.name)
        for statement in capture.body
        if isinstance(statement, ast.ImportFrom)
        for alias in statement.names
        if alias.asname is None
    }
    if (
        not {
            ("langgraph._internal._runnable", "RunnableCallable"),
            ("langgraph.graph._branch", "BranchSpec"),
        }
        <= imports
    ):
        raise _Unsupported(capture, "guard classes are not the framework classes")
    reads = _candidate_reads_guarded(capture, "path")
    for required in ("func", "afunc", "kwargs", "explode_args", "func_accepts"):
        if required not in reads:
            raise _Unsupported(capture, f"missing read: {required}")
    _require_text(
        capture,
        (
            "if _pinned_branch_id(func) is not None:\n        raise PermissionError(UNSUPPORTED_BRANCH)",
        ),
    )
    return {"guard_line": statements[0].lineno, "class": "BranchSpec"}


# ---------------------------------------------------------------------------
# Obligation (b): closed_admission compile path refuses before protocols.
# ---------------------------------------------------------------------------

_CLOSED_RULES = _Rules(
    frozenset(
        {
            "type",
            "tuple",
            "PermissionError",
            "MediatedNode",
            "MediatedBranch",
            "PlacementSpec",
            "admit_node",
            "admit_branch",
            "_closed_admission_inventory",
            "_admitted_node_kind",
            "branch._replace",
        }
    ),
    attributes=frozenset({"metadata"}),
    names=frozenset({"resolve_placement", "_find_tool_nodes", "getattr"}),
    methods=frozenset({"items", "close"}),
)
_INVENTORY_RULES = _Rules(
    frozenset(
        {
            "type",
            "PermissionError",
            "admit_node",
            "admit_branch",
            "_admit_channels",
            "_admit_node_policies",
            "_declared_application_nodes",
            "frozenset",
            "_bind_declared_branches",
        }
    ),
    names=frozenset({"resolve_placement", "_find_tool_nodes", "getattr"}),
    methods=frozenset({"items"}),
)
# Framework objects the callback refusal compares by identity, each pinned to
# the module that defines it; a local or top-level rebinding leaves (b)
# unproved. `BinaryOperatorAggregate` is also pinned so the reducer read is
# taken from the exact framework channel class.
_PINNED_IMPORTS: dict[str, str] = {
    "add": "operator",
    "add_messages": "langgraph.graph.message",
    "default_cache_key": "langgraph._internal._cache",
    "default_retry_on": "langgraph._internal._retry",
    "AnyValue": "langgraph.channels",
    "BinaryOperatorAggregate": "langgraph.channels",
    "EphemeralValue": "langgraph.channels",
    "LastValue": "langgraph.channels",
    "LastValueAfterFinish": "langgraph.channels",
    "Topic": "langgraph.channels",
    "UntrackedValue": "langgraph.channels",
    "CachePolicy": "langgraph.types",
    "RetryPolicy": "langgraph.types",
}
_PINNED_TUPLES: dict[str, str] = {
    "_FRAMEWORK_REDUCERS": "(add, add_messages)",
    "_FRAMEWORK_CHANNELS": (
        "(AnyValue, BinaryOperatorAggregate, EphemeralValue, LastValue, "
        "LastValueAfterFinish, Topic, UntrackedValue)"
    ),
}
_CALLBACK_RULES = _Rules(
    frozenset({"type", "tuple", "PermissionError", "_pinned"}),
    methods=frozenset({"items"}),
    pinned=frozenset(_PINNED_IMPORTS) | frozenset(_PINNED_TUPLES),
)


def _refusal_guards(function: ast.AST) -> list[tuple[str, str]]:
    """Spell every `if <test>: raise <Error>(<CODE>)` guard as `(test, code)`."""
    guards = []
    for part in ast.walk(function):
        if isinstance(part, ast.If) and len(part.body) == 1:
            code = _raise_code(part.body[0])
            if code is not None:
                guards.append((ast.unparse(part.test), code))
    return guards


def _body_text(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Unparse every non-docstring, non-import statement of a function body."""
    return [
        ast.unparse(statement)
        for statement in function.body
        if not _is_docstring(statement)
        and not isinstance(statement, (ast.Import, ast.ImportFrom))
    ]


def _prove_pinned_module_bindings(tree: ast.Module) -> None:
    """Prove the identity targets are bound once, by the expected imports."""
    bound: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.asname is not None:
                    raise _Unsupported(statement, "aliased import of a pinned name")
                if alias.name in bound:
                    raise _Unsupported(statement, f"rebound import: {alias.name}")
                bound[alias.name] = statement.module or ""
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                bound[alias.asname or alias.name] = "import"
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if not isinstance(target, ast.Name):
                    raise _Unsupported(statement, "unmodeled module assignment")
                if target.id in bound:
                    raise _Unsupported(statement, f"rebound module name: {target.id}")
                expected = _PINNED_TUPLES.get(target.id)
                if expected is not None and (
                    statement.value is None or ast.unparse(statement.value) != expected
                ):
                    raise _Unsupported(statement, f"pinned tuple differs: {target.id}")
                bound[target.id] = "assign"
        elif isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if statement.name in bound:
                raise _Unsupported(statement, f"rebound module name: {statement.name}")
            bound[statement.name] = "def"
    for name, module in _PINNED_IMPORTS.items():
        if bound.get(name) != module:
            raise _Unsupported(tree, f"{name} is not imported from {module}")
    for name in _PINNED_TUPLES:
        if bound.get(name) != "assign":
            raise _Unsupported(tree, f"{name} is not a module tuple")


def _prove_callback_refusal(
    found: dict[str, Any], tree: ast.Module, table: symtable.SymbolTable
) -> dict[str, Any]:
    """Prove reducer, cache, retry and trace callbacks refuse before admission."""
    _prove_pinned_module_bindings(tree)
    pinned = _require(found, "_pinned")
    if [argument.arg for argument in pinned.args.args] != ["value", "pins"] or (
        _body_text(pinned)
        != [
            "for pin in pins:\n    if value is pin:\n        return True",
            "return False",
        ]
    ):
        raise _Unsupported(pinned, "_pinned is not the identity membership loop")
    channels = _require(found, "_admit_channels")
    policies = _require(found, "_admit_node_policies")
    consumed = 0
    for name, function in (
        ("_pinned", pinned),
        ("_admit_channels", channels),
        ("_admit_node_policies", policies),
    ):
        consumed += _admit_statements(function.body, _CALLBACK_RULES)
        _require_global_calls(table, name, _CALLBACK_RULES)
    channel_guards = _refusal_guards(channels)
    for required in (
        ("type(channels) is not dict", "UNSUPPORTED_NODE_BODY"),
        ("not _pinned(reducer, _FRAMEWORK_REDUCERS)", "UNSUPPORTED_CALLBACK"),
        ("not _pinned(kind, _FRAMEWORK_CHANNELS)", "UNSUPPORTED_CALLBACK"),
    ):
        if required not in channel_guards:
            raise _Unsupported(channels, f"channel guard lacks: {required[0]}")
    channel_text = ast.unparse(channels)
    for required in (
        "kind = type(channel)",
        "if kind is BinaryOperatorAggregate:\n            reducer = channel.operator\n            if not _pinned(reducer, _FRAMEWORK_REDUCERS):\n                raise PermissionError(UNSUPPORTED_CALLBACK)\n        elif not _pinned(kind, _FRAMEWORK_CHANNELS):\n            raise PermissionError(UNSUPPORTED_CALLBACK)",
    ):
        if required not in channel_text:
            raise _Unsupported(channels, f"channel admission lacks: {required[:24]}")
    policy_guards = _refusal_guards(policies)
    for required in (
        ("trace is not None", "UNSUPPORTED_CALLBACK"),
        (
            "type(cache) is not CachePolicy or cache.key_func is not default_cache_key",
            "UNSUPPORTED_CALLBACK",
        ),
        (
            "type(policy) is not RetryPolicy or policy.retry_on is not default_retry_on",
            "UNSUPPORTED_CALLBACK",
        ),
    ):
        if required not in policy_guards:
            raise _Unsupported(policies, f"policy guard lacks: {required[0]}")
    policy_text = ast.unparse(policies)
    for required in (
        "retry = spec.retry_policy",
        "cache = spec.cache_policy",
        "trace = spec.trace_policy",
        "if cache is not None:\n        if type(cache) is not CachePolicy or cache.key_func is not default_cache_key:\n            raise PermissionError(UNSUPPORTED_CALLBACK)",
        "if type(retry) is RetryPolicy:\n        policies = (retry,)\n    elif type(retry) is tuple or type(retry) is list:\n        policies = tuple(retry)\n    else:\n        raise PermissionError(UNSUPPORTED_CALLBACK)\n    for policy in policies:\n        if type(policy) is not RetryPolicy or policy.retry_on is not default_retry_on:\n            raise PermissionError(UNSUPPORTED_CALLBACK)",
    ):
        if required not in policy_text:
            raise _Unsupported(policies, f"policy admission lacks: {required[:24]}")
    return {"statements": consumed, "guards": channel_guards + policy_guards}


def _closed_branch(statement: ast.stmt) -> list[ast.stmt] | None:
    if (
        isinstance(statement, ast.If)
        and ast.unparse(statement.test) == "self.closed_admission"
        and not statement.orelse
    ):
        return statement.body
    return None


def _membership_guard(statement: ast.stmt, key: str, container: str) -> str:
    """Match `if <key> not in <container>: [placement_stack.close()]; raise`."""
    test = statement.test if isinstance(statement, ast.If) else None
    if (
        test is None
        or statement.orelse
        or not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.NotIn)
        or ast.unparse(test.left) != key
        or ast.unparse(test.comparators[0]) != container
    ):
        raise _Unsupported(statement, f"missing membership guard on {key}")
    return _is_refusal_block(statement.body, _CLOSED_RULES)


def _wrapper_construction(
    statement: ast.stmt, target: str, wrapper: str, inner: str, key: str
) -> None:
    """Match the wrapper assignment carrying `descriptor=admitted[<key>]`."""
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        raise _Unsupported(statement, "wrapper assignment differs")
    if ast.unparse(statement.targets[0]) != target:
        raise _Unsupported(statement, "wrapper target differs")
    call = statement.value
    if wrapper == "MediatedBranch":
        if (
            not isinstance(call, ast.Call)
            or ast.unparse(call.func) != "branch._replace"
            or call.args
            or len(call.keywords) != 1
            or call.keywords[0].arg != "path"
        ):
            raise _Unsupported(statement, "branch replacement differs")
        call = call.keywords[0].value
    if (
        not isinstance(call, ast.Call)
        or ast.unparse(call.func) != wrapper
        or not call.args
        or ast.unparse(call.args[0]) != inner
    ):
        raise _Unsupported(statement, "wrapper does not wrap the admitted body")
    keywords = {keyword.arg: ast.unparse(keyword.value) for keyword in call.keywords}
    if keywords.get("descriptor") != f"admitted[{key}]":
        raise _Unsupported(statement, "wrapper is not bound to its descriptor")
    if wrapper == "MediatedNode":
        if len(call.args) != 3 or ast.unparse(call.args[1]) != (
            f"PlacementSpec({key}, NodeTrust.TRUSTED, _admitted_node_kind(admitted[{key}]))"
        ):
            raise _Unsupported(statement, "placement is not the admitted placement")
    elif keywords.get("trust") != "NodeTrust.TRUSTED":
        raise _Unsupported(statement, "branch trust is not the admitted placement")


def _closed_loop_body(
    body: list[ast.stmt], key: str, target: str, wrapper: str, inner: str
) -> str:
    if len(body) != 3 or not isinstance(body[2], ast.Continue):
        raise _Unsupported(body[0], "closed admission body has extra statements")
    code = _membership_guard(body[0], key, "admitted")
    _wrapper_construction(body[1], target, wrapper, inner, key)
    _admit_statements(body, _CLOSED_RULES)
    return code


def _prove_closed_compile_refusal(
    tree: ast.Module, table: symtable.SymbolTable
) -> dict[str, Any]:
    found = _definitions(tree)
    configure = _require(found, "SecurityConfig.configure_graph")
    inventory_line = None
    for statement in configure.body:
        closed = _closed_branch(statement)
        if closed is not None:
            if len(closed) != 1 or ast.unparse(closed[0]) != (
                "admitted = _closed_admission_inventory(self, graph)"
            ):
                raise _Unsupported(statement, "inventory statement differs")
            inventory_line = statement.lineno
            break
        if _mentions(statement, "graph"):
            raise _Unsupported(statement, "graph read before closed inventory")
    if inventory_line is None:
        raise _Unsupported(configure, "closed inventory is not built")
    node_loop = branch_loop = verify = None
    for statement in configure.body:
        if isinstance(statement, ast.For):
            iterated = ast.unparse(statement.iter)
            if iterated == "graph.nodes.items()":
                node_loop = statement
            elif iterated == "graph.branches.items()":
                branch_loop = statement
        closed = _closed_branch(statement)
        if closed is not None and any(
            "_verify_admitted_graph(admitted, graph)" == ast.unparse(part)
            for part in ast.walk(statement)
            if isinstance(part, ast.Call)
        ):
            verify = statement
    if node_loop is None or branch_loop is None:
        raise _Unsupported(configure, "node or branch placement loop missing")
    if ast.unparse(node_loop.target) != "(name, node_spec)":
        raise _Unsupported(node_loop, "node loop target differs")
    node_closed = _closed_branch(node_loop.body[0])
    if node_closed is None:
        raise _Unsupported(node_loop, "closed admission is not the first node step")
    node_code = _closed_loop_body(
        node_closed, "name", "node_spec.runnable", "MediatedNode", "node_spec.runnable"
    )
    inner = branch_loop.body
    if (
        len(inner) != 1
        or not isinstance(inner[0], ast.For)
        or ast.unparse(inner[0].target) != "(branch_name, branch)"
        or ast.unparse(inner[0].iter) != "tuple(branches.items())"
        or len(inner[0].body) < 2
        or ast.unparse(inner[0].body[0])
        != "placement_name = f'{source}:branch:{branch_name}'"
    ):
        raise _Unsupported(branch_loop, "branch loop shape differs")
    branch_closed = _closed_branch(inner[0].body[1])
    if branch_closed is None:
        raise _Unsupported(inner[0], "closed admission is not the first branch step")
    branch_code = _closed_loop_body(
        branch_closed,
        "placement_name",
        "branches[branch_name]",
        "MediatedBranch",
        "branch.path",
    )
    if verify is None:
        raise _Unsupported(configure, "admitted graph is not verified after wrapping")
    model_kind = _require(found, "_admitted_node_kind")
    if _body_text(model_kind) != [
        "if descriptor.kind is AdmittedKind.MODEL_CALL:\n    return NodeKind.MODEL",
        "return NodeKind.STANDARD",
    ]:
        raise _Unsupported(model_kind, "model descriptors are not placed as MODEL")
    _require_text(
        _require(found, "_verify_admitted_graph"),
        (
            "elif type(implementation) is _CapturedModel:\n            if type(wrapper) is not MediatedNode or wrapper.runnable is not implementation.node or wrapper.spec.kind is not NodeKind.MODEL:\n                raise PermissionError(DESCRIPTOR_CHANGED)",
            "elif type(implementation) is _CapturedBranch or type(implementation) is _CapturedTrustedBranch:\n            if type(wrapper) is not MediatedBranch or wrapper.runnable is not implementation.path:\n                raise PermissionError(DESCRIPTOR_CHANGED)",
            "elif type(implementation) is _CapturedApplication:\n            if type(wrapper) is not MediatedNode or wrapper.runnable is not implementation.node or wrapper.spec.kind is not NodeKind.STANDARD:\n                raise PermissionError(DESCRIPTOR_CHANGED)",
            "recheck(descriptor)",
        ),
    )
    inventory = _require(found, "_closed_admission_inventory")
    consumed = _admit_statements(inventory.body, _INVENTORY_RULES)
    _require_global_calls(table, "_closed_admission_inventory", _INVENTORY_RULES)
    graph_guard = None
    for statement in inventory.body:
        guard = _exact_guard(statement, "graph")
        if guard is not None:
            if guard != ("StateGraph", "UNSUPPORTED_NODE_BODY"):
                raise _Unsupported(statement, "builder guard differs")
            graph_guard = statement.lineno
            break
        if _mentions(statement, "graph"):
            raise _Unsupported(statement, "graph read before exact-type guard")
    if graph_guard is None:
        raise _Unsupported(inventory, "no exact-type guard on the builder")
    admitted_calls = {"admit_node": 0, "admit_branch": 0}
    loops = [
        statement for statement in inventory.body if isinstance(statement, ast.For)
    ]
    if len(loops) != 2:
        raise _Unsupported(inventory, "inventory loops differ")
    # Channels are admitted after the builder guard and before any node body.
    spelled = [ast.unparse(statement) for statement in inventory.body]
    if "_admit_channels(graph.channels)" not in spelled:
        raise _Unsupported(inventory, "state channels are not admitted")
    channels_index = spelled.index("_admit_channels(graph.channels)")
    if inventory.body[channels_index].lineno < graph_guard or channels_index > (
        inventory.body.index(loops[0])
    ):
        raise _Unsupported(inventory, "channel admission is out of order")
    # Every declared trusted application name must be a node of this builder,
    # checked before any node body is admitted.
    declared_steps = [
        "declared = _declared_application_nodes(config)",
        "if not declared <= frozenset(nodes):\n    raise PermissionError(UNSUPPORTED_NODE_BODY)",
    ]
    if declared_steps[0] not in spelled or declared_steps[1] not in spelled:
        raise _Unsupported(inventory, "declared names are not bound to the nodes")
    declared_index = spelled.index(declared_steps[0])
    if (
        spelled.index(declared_steps[1]) != declared_index + 1
        or declared_index > inventory.body.index(loops[0])
        or inventory.body[declared_index].lineno < graph_guard
    ):
        raise _Unsupported(inventory, "declared-name check is out of order")
    # Every declared trusted branch must have been admitted as one; checked
    # after both admission loops and before the inventory is returned.
    if spelled[-2:] != [
        "_bind_declared_branches(config, inventory)",
        "return inventory",
    ]:
        raise _Unsupported(inventory, "declared branches are not bound")
    for loop in loops:
        innermost = loop
        while isinstance(innermost.body[-1], ast.For):
            innermost = innermost.body[-1]
        last = innermost.body[-1]
        target = _call_target(last)
        if target not in admitted_calls or not isinstance(last, ast.Assign):
            raise _Unsupported(last, "loop does not end by admitting the body")
        if ast.unparse(last.targets[0]).split("[")[0] != "inventory":
            raise _Unsupported(last, "admission result is not recorded")
        if target == "admit_node" and (
            len(innermost.body) < 2
            or ast.unparse(innermost.body[-2]) != "_admit_node_policies(spec)"
        ):
            raise _Unsupported(last, "node policies are not admitted before the body")
        admitted_calls[target] += 1
        for statement in innermost.body[:-1]:
            for spelled in _calls_in(statement):
                if spelled in admitted_calls:
                    raise _Unsupported(statement, "admission precedes shape checks")
        for part in ast.walk(loop):
            if isinstance(part, ast.Attribute) and part.attr == "metadata":
                parent_ok = False
                for statement in ast.walk(loop):
                    if isinstance(statement, ast.Assign) and statement.value is part:
                        parent_ok = True
                if not parent_ok:
                    raise _Unsupported(loop, "metadata is consulted for admission")
    if admitted_calls != {"admit_node": 1, "admit_branch": 1}:
        raise _Unsupported(inventory, "node and branch admission calls differ")
    metadata_uses = [
        ast.unparse(statement)
        for statement in ast.walk(inventory)
        if isinstance(statement, ast.If) and _mentions(statement.test, "metadata")
    ]
    if metadata_uses != [
        "if metadata is not None and type(metadata) is not dict:\n    raise PermissionError(UNSUPPORTED_NODE_BODY)"
    ]:
        raise _Unsupported(inventory, "metadata use is not the exact-dict check")
    callbacks = _prove_callback_refusal(found, tree, table)
    return {
        "proved": True,
        "property": "Under closed_admission, configure_graph builds the inventory through _closed_admission_inventory before any other read of the builder; that function guards type(graph) is StateGraph, refuses with admission:unsupported_callback any state channel that is not an exact framework channel class or whose BinaryOperatorAggregate reducer is not operator.add or langgraph.graph.message.add_messages by identity (pinned module imports), refuses every node whose cache_policy.key_func, retry_policy.retry_on or trace_policy is not the framework default before that node is admitted, refuses with admission:unsupported_node_body a trusted_application_nodes declaration naming no node of the builder before any body is admitted, refuses with admission:unsupported_branch (after both admission loops) any trusted_application_branches declaration not admitted as a trusted branch, admits every node body with admit_node (which refuses every undeclared plain body) and every branch with admit_branch after exact container checks only, and consults metadata solely for an exact-dict check. In the placement loops the closed branch refuses admission:descriptor_changed for any entry without a descriptor and otherwise constructs MediatedNode/MediatedBranch around the admitted body with its descriptor and the fixed TRUSTED placement (kind MODEL exactly for a MODEL_CALL descriptor, so the model hook runs, STANDARD otherwise, including TRUSTED_APPLICATION, whose wrapper must hold exactly the captured RunnableCallable), reaching neither resolve_placement, _find_tool_nodes, metadata promotion nor any other statement; the wrapped graph is verified against the inventory afterwards.",
        "inventory_line": inventory_line,
        "builder_guard_line": graph_guard,
        "node_refusal": node_code,
        "branch_refusal": branch_code,
        "inventory_statements": consumed,
        "callback_refusal": callbacks,
        "issues": [],
    }


# ---------------------------------------------------------------------------
# Obligation (c): descriptor-bound dispatch without self.runnable fallback.
# ---------------------------------------------------------------------------

_DISPATCH_RULES = _Rules(
    frozenset(
        {
            "type",
            "PermissionError",
            "_admitted_node",
            "_admitted_branch",
            "_bounded_input",
            "_model_messages",
            "_model_update",
            "self._invoke_model_call",
            "self._ainvoke_model_call",
            "self._invoke_application",
            "self._ainvoke_application",
            "self._invoke_trusted_branch",
            "self._ainvoke_trusted_branch",
            "_application_kwargs",
            "_run_application",
            "_run_application_in_executor",
            "self._model_input",
            "self._amodel_input",
            "_principal",
            "_framework_runtime",
            "_narrowed_config",
            "_pinned_tool_node_functions",
            "_require_async_route",
            "_route_sends",
            "_aroute_sends",
            "function",
            "afunction",
            "captured.function",
            "self._dispatch",
            "self._adispatch",
            "self._state_writes",
            "self._astate_writes",
        }
    ),
    attributes=frozenset({"runnable", "spec", "untrusted_host", "descriptor"}),
    names=frozenset({"getattr"}),
    awaits=True,
    methods=frozenset(),
)
_HELPER_RULES = _Rules(
    frozenset(
        {
            "type",
            "PermissionError",
            "_bind_node_descriptor",
            "_bind_branch_descriptor",
            "recheck",
            "_require_no_shadowed_methods",
        }
    ),
    methods=frozenset(),
)


def _prove_dispatch(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    helper: str,
    primitive: str,
    *,
    is_async: bool,
) -> dict[str, Any]:
    body = function.body
    statements = [statement for statement in body if not _is_docstring(statement)]
    if isinstance(function, ast.AsyncFunctionDef) is not is_async:
        raise _Unsupported(function, "dispatch form differs from its route")
    if (
        not statements
        or ast.unparse(statements[0]) != f"captured = {helper}(self, kwargs)"
    ):
        raise _Unsupported(function, f"first step is not {helper}")
    _admit_statements(body, _DISPATCH_RULES)
    if helper == "_admitted_node":
        route = (
            "await self._ainvoke_model_call" if is_async else "self._invoke_model_call"
        )
        if len(statements) < 2 or ast.unparse(statements[1]) != (
            f"if type(captured) is _CapturedModel:\n    return {route}(captured, input, config)"
        ):
            raise _Unsupported(function, "model route is not the second step")
        application = (
            "await self._ainvoke_application"
            if is_async
            else "self._invoke_application"
        )
        if len(statements) < 3 or ast.unparse(statements[2]) != (
            f"if type(captured) is _CapturedApplication:\n    return {application}(captured, input, config)"
        ):
            raise _Unsupported(function, "application route is not the third step")
        statements = [statements[0], *statements[3:]]
    else:
        route = (
            "await self._ainvoke_trusted_branch"
            if is_async
            else "self._invoke_trusted_branch"
        )
        if len(statements) < 2 or ast.unparse(statements[1]) != (
            f"if type(captured) is _CapturedTrustedBranch:\n    return {route}(captured, input, config)"
        ):
            raise _Unsupported(function, "trusted branch route is not the second step")
        statements = [statements[0], *statements[2:]]
    primitive_index = None
    router_index = None
    for index, statement in enumerate(statements):
        spelled = ast.unparse(statement)
        if spelled.startswith("result = "):
            value = statement.value if isinstance(statement, ast.Assign) else None
            if isinstance(value, ast.Await):
                value = value.value
            if (
                not isinstance(value, ast.Call)
                or ast.unparse(value.func) != primitive
                or value.keywords
            ):
                raise _Unsupported(statement, "result is not the pinned primitive")
            if primitive in {"function", "afunction"} and (
                ast.unparse(value.args[0]) != "captured.node"
                or [ast.unparse(item) for item in value.args[1:]]
                != ["data", "narrowed", "runtime"]
            ):
                raise _Unsupported(statement, "primitive receiver or data differ")
            if primitive == "captured.function" and [
                ast.unparse(item) for item in value.args
            ] != ["data"]:
                raise _Unsupported(statement, "branch function receives extra data")
            primitive_index = index
        elif _call_target(statement) in {"self._dispatch", "self._adispatch"}:
            router_index = index
        for use in _uses_of(statement, "input"):
            if use != "call:_bounded_input":
                raise _Unsupported(statement, "input bypasses the bounded copy")
        for use in _uses_of(statement, "config"):
            if use != "call:_principal":
                raise _Unsupported(statement, "config bypasses the native principal")
        for use in _uses_of(statement, "kwargs"):
            if use != "call:" + helper:
                raise _Unsupported(statement, "kwargs reach a call")
    if primitive_index is None:
        raise _Unsupported(function, "no pinned primitive call")
    if primitive in {"function", "afunction"} and (
        router_index is None or router_index > primitive_index
    ):
        raise _Unsupported(function, "router mediation does not precede the call")
    if is_async and primitive == "afunction":
        if "_require_async_route(captured)" not in [
            ast.unparse(statement) for statement in statements[:primitive_index]
        ]:
            raise _Unsupported(function, "async route is not required before start")
    return {"function": function.name, "primitive": primitive, "steps": len(statements)}


def _prove_model_dispatch(
    function: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
) -> dict[str, Any]:
    """Prove the model route runs the hook before the pinned class-level call."""
    if isinstance(function, ast.AsyncFunctionDef) is not is_async:
        raise _Unsupported(function, "model dispatch form differs from its route")
    if [argument.arg for argument in function.args.args] != [
        "self",
        "captured",
        "input",
        "config",
    ]:
        raise _Unsupported(function, "model dispatch parameters differ")
    _admit_statements(function.body, _DISPATCH_RULES)
    prefix = "await " if is_async else ""
    pinned = "afunction" if is_async else "function"
    expected = [
        "data = _bounded_input(input)",
        "principal, bound_config = _principal(config)",
        "narrowed = _narrowed_config(bound_config)",
        f"{pinned} = captured.{'acall' if is_async else 'call'}",
        f"{prefix}self.{'_adispatch' if is_async else '_dispatch'}(principal, bound_config)",
        f"effective = {prefix}self.{'_amodel_input' if is_async else '_model_input'}(principal, data, bound_config)",
        "messages = _model_messages(effective)",
        f"result = {prefix}{pinned}(captured.node, messages, narrowed)",
        f"return {prefix}self.{'_astate_writes' if is_async else '_state_writes'}(principal, _model_update(result))",
    ]
    if _body_text(function) != expected:
        raise _Unsupported(function, "model route steps differ from hook-then-call")
    return {"function": function.name, "primitive": pinned, "steps": len(expected)}


def _prove_application_dispatch(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    found: dict[str, Any],
    *,
    is_async: bool,
) -> dict[str, Any]:
    """Prove a trusted application route runs only the captured function.

    The route is reached only after `_admitted_node` (descriptor binding and
    recheck). It reads the principal from the native config, runs the
    existing router dispatch, then calls `captured.function` (pinned at
    admission) through `_run_application`, whose body is exactly the call with
    the graph input and the injected framework keywords, or the framework
    `run_in_executor` for a synchronous body on the async route. The input and
    config are deliberately not narrowed: the body is trusted per D11.
    """
    if isinstance(function, ast.AsyncFunctionDef) is not is_async:
        raise _Unsupported(function, "application dispatch form differs")
    if [argument.arg for argument in function.args.args] != [
        "self",
        "captured",
        "input",
        "config",
    ]:
        raise _Unsupported(function, "application dispatch parameters differ")
    _admit_statements(function.body, _DISPATCH_RULES)
    if is_async:
        expected = [
            "principal, bound_config = _principal(config)",
            "injected = _application_kwargs(captured, bound_config)",
            "function = captured.function",
            "await self._adispatch(principal, bound_config)",
            "if captured.is_async:\n    result = await _run_application(function, input, injected)\nelse:\n    result = await _run_application_in_executor(function, input, injected)",
            "return await self._astate_writes(principal, result)",
        ]
    else:
        expected = [
            "if captured.is_async:\n    raise PermissionError(UNSUPPORTED_ASYNC)",
            "principal, bound_config = _principal(config)",
            "injected = _application_kwargs(captured, bound_config)",
            "function = captured.function",
            "self._dispatch(principal, bound_config)",
            "result = _run_application(function, input, injected)",
            "return self._state_writes(principal, result)",
        ]
    if _body_text(function) != expected:
        raise _Unsupported(function, "application route steps differ")
    run = _require(found, "_run_application")
    if [argument.arg for argument in run.args.args] != [
        "function",
        "value",
        "injected",
    ] or _body_text(run) != ["return function(value, **injected)"]:
        raise _Unsupported(run, "application call is not the captured function")
    executor = _require(found, "_run_application_in_executor")
    if (
        [argument.arg for argument in executor.args.args]
        != ["function", "value", "injected"]
        or _body_text(executor)
        != ["return await run_in_executor(None, function, value, **injected)"]
        or not any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "langgraph._internal._runnable"
            and [alias.name for alias in statement.names] == ["run_in_executor"]
            and statement.names[0].asname is None
            for statement in executor.body
        )
    ):
        raise _Unsupported(executor, "executor route is not the framework shim")
    return {
        "function": function.name,
        "primitive": "captured.function",
        "steps": len(expected),
    }


def _prove_trusted_branch_dispatch(
    function: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
) -> dict[str, Any]:
    """Prove a trusted branch route runs only the captured function.

    Reached only after `_admitted_branch` (binding and recheck); the function
    pinned at admission is called through the proved `_run_application`
    helpers with the branch input and no keywords, then every `Send` in the
    result is authorized through the router as on the framework branch route.
    """
    if isinstance(function, ast.AsyncFunctionDef) is not is_async:
        raise _Unsupported(function, "trusted branch dispatch form differs")
    if [argument.arg for argument in function.args.args] != [
        "self",
        "captured",
        "input",
        "config",
    ]:
        raise _Unsupported(function, "trusted branch parameters differ")
    _admit_statements(function.body, _DISPATCH_RULES)
    if is_async:
        expected = [
            "principal, bound_config = _principal(config)",
            "function = captured.function",
            "result = await _run_application_in_executor(function, input, {})",
            "await _aroute_sends(self.router, principal, result, bound_config, self.name)",
            "return result",
        ]
    else:
        expected = [
            "principal, bound_config = _principal(config)",
            "function = captured.function",
            "result = _run_application(function, input, {})",
            "_route_sends(self.router, principal, result, bound_config, self.name)",
            "return result",
        ]
    if _body_text(function) != expected:
        raise _Unsupported(function, "trusted branch route steps differ")
    return {
        "function": function.name,
        "primitive": "captured.function",
        "steps": len(expected),
    }


def _prove_model_hook(found: dict[str, Any]) -> None:
    """Prove the hook asks the router before returning the effective context."""
    for name, call in (
        ("MediatedNode._model_input", "self.router.model_invoke("),
        ("MediatedNode._amodel_input", "await self.router.amodel_invoke("),
    ):
        hook = _require(found, name)
        statements = _body_text(hook)
        if (
            not statements
            or statements[0]
            != "if self.spec.kind is not NodeKind.MODEL:\n    return value"
            or statements[-1] != "return rebuild(effective)"
            or not statements[-2].startswith(
                "effective = cast(Sequence[LabeledValue], " + call
            )
        ):
            raise _Unsupported(hook, "model hook does not route model_invoke")
    _require_text(
        _require(found, "_bind_node_descriptor"),
        (
            "if type(implementation) is _CapturedToolNode:\n        kind = NodeKind.STANDARD\n    elif type(implementation) is _CapturedModel:\n        kind = NodeKind.MODEL\n    elif type(implementation) is _CapturedApplication:\n        kind = NodeKind.STANDARD\n    else:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "spec.kind is not kind",
        ),
    )


def _is_docstring(statement: ast.stmt) -> bool:
    return isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)


def _prove_helper(
    function: ast.FunctionDef | ast.AsyncFunctionDef, binder: str, extra: str | None
) -> None:
    _admit_statements(function.body, _HELPER_RULES)
    spelled = [ast.unparse(statement) for statement in function.body]
    required = [
        f"{binder}(descriptor, runnable, {'spec' if binder.endswith('node_descriptor') else 'trust'})",
        "recheck(descriptor)",
        "captured = descriptor.implementation",
    ]
    if extra is not None:
        required.append(extra)
    positions = []
    for item in required:
        if item not in spelled:
            raise _Unsupported(function, f"missing step: {item}")
        positions.append(spelled.index(item))
    if positions != sorted(positions) or spelled[-1] != "return captured":
        raise _Unsupported(function, "helper steps are out of order")
    statements = [item for item in function.body if not _is_docstring(item)]
    if ast.unparse(statements[0]) != (
        "if type(kwargs) is not dict or kwargs:\n    raise PermissionError(DESCRIPTOR_CHANGED)"
    ):
        raise _Unsupported(function, "override dictionaries are not refused first")


def _prove_entry_switch(
    function: ast.FunctionDef | ast.AsyncFunctionDef, admitted: str
) -> None:
    first = function.body[0]
    expected = f"return {'await ' if isinstance(function, ast.AsyncFunctionDef) else ''}self.{admitted}(input, config, kwargs)"
    if (
        not isinstance(first, ast.If)
        or ast.unparse(first.test) != "self.descriptor is not None"
        or first.orelse
        or len(first.body) != 1
        or ast.unparse(first.body[0]) != expected
    ):
        raise _Unsupported(first, "descriptor switch is not the first statement")


def _prove_binder(function: ast.FunctionDef | ast.AsyncFunctionDef, link: str) -> None:
    _admit_statements(function.body, _HELPER_RULES)
    spelled = ast.unparse(function)
    for required in (
        "if type(descriptor) is not AdmittedDescriptor:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
        f"implementation.{link} is not runnable",
    ):
        if required not in spelled:
            raise _Unsupported(function, f"binder lacks: {required.splitlines()[0]}")


def _prove_descriptor_dispatch(
    tree: ast.Module, table: symtable.SymbolTable
) -> dict[str, Any]:
    found = _definitions(tree)
    for name, admitted in (
        ("MediatedNode.invoke", "_invoke_admitted"),
        ("MediatedNode.ainvoke", "_ainvoke_admitted"),
        ("MediatedBranch.invoke", "_invoke_admitted"),
        ("MediatedBranch.ainvoke", "_ainvoke_admitted"),
    ):
        _prove_entry_switch(_require(found, name), admitted)
    entries = [
        _prove_dispatch(
            _require(found, "MediatedNode._invoke_admitted"),
            "_admitted_node",
            "function",
            is_async=False,
        ),
        _prove_dispatch(
            _require(found, "MediatedNode._ainvoke_admitted"),
            "_admitted_node",
            "afunction",
            is_async=True,
        ),
        _prove_dispatch(
            _require(found, "MediatedBranch._invoke_admitted"),
            "_admitted_branch",
            "captured.function",
            is_async=False,
        ),
        _prove_dispatch(
            _require(found, "MediatedBranch._ainvoke_admitted"),
            "_admitted_branch",
            "captured.function",
            is_async=True,
        ),
        _prove_model_dispatch(
            _require(found, "MediatedNode._invoke_model_call"), is_async=False
        ),
        _prove_model_dispatch(
            _require(found, "MediatedNode._ainvoke_model_call"), is_async=True
        ),
        _prove_application_dispatch(
            _require(found, "MediatedNode._invoke_application"),
            found,
            is_async=False,
        ),
        _prove_application_dispatch(
            _require(found, "MediatedNode._ainvoke_application"),
            found,
            is_async=True,
        ),
        _prove_trusted_branch_dispatch(
            _require(found, "MediatedBranch._invoke_trusted_branch"), is_async=False
        ),
        _prove_trusted_branch_dispatch(
            _require(found, "MediatedBranch._ainvoke_trusted_branch"), is_async=True
        ),
    ]
    _prove_model_hook(found)
    for name in (
        "MediatedNode._invoke_admitted",
        "MediatedNode._ainvoke_admitted",
        "MediatedBranch._invoke_admitted",
        "MediatedBranch._ainvoke_admitted",
        "MediatedNode._invoke_model_call",
        "MediatedNode._ainvoke_model_call",
        "MediatedNode._invoke_application",
        "MediatedNode._ainvoke_application",
        "MediatedBranch._invoke_trusted_branch",
        "MediatedBranch._ainvoke_trusted_branch",
    ):
        _require_global_calls(table, name, _DISPATCH_RULES)
    _require_text(
        _require(found, "_bind_branch_descriptor"),
        (
            "if type(implementation) is not _CapturedBranch and type(implementation) is not _CapturedTrustedBranch:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "if implementation.path is not runnable or trust is not NodeTrust.TRUSTED:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
        ),
    )
    for name in (
        "_admitted_node",
        "_admitted_branch",
        "_bind_node_descriptor",
        "_bind_branch_descriptor",
    ):
        _require_global_calls(table, name, _HELPER_RULES)
    _prove_helper(
        _require(found, "_admitted_node"),
        "_bind_node_descriptor",
        "_require_no_shadowed_methods(captured.node)",
    )
    _prove_helper(_require(found, "_admitted_branch"), "_bind_branch_descriptor", None)
    _prove_binder(_require(found, "_bind_node_descriptor"), "node")
    _prove_binder(_require(found, "_bind_branch_descriptor"), "path")
    return {
        "proved": True,
        "property": "MediatedNode.invoke/ainvoke and MediatedBranch.invoke/ainvoke switch to the admitted route as their first statement whenever a descriptor is bound. Each admitted route first refuses override kwargs, binds the exact descriptor to the wrapper's runnable and placement, calls recheck, then passes only a bounded copy of the input and a principal from the native config, runs the existing router mediation and calls the pinned framework primitive with the captured node (or the pinned branch function with the bounded data) and nothing else. A MODEL_CALL descriptor (bound only to a TRUSTED/MODEL placement) routes, right after recheck, to _invoke_model_call/_ainvoke_model_call, which run router dispatch, then the model hook _model_input/_amodel_input (whose first step only skips non-MODEL placements and whose result is the router.model_invoke decision), and only then call the class-level invoke/ainvoke captured at admission with the captured model, the hook's effective messages and the narrowed config. A TRUSTED_APPLICATION descriptor (bound only to a TRUSTED/STANDARD placement around the captured RunnableCallable) routes, right after recheck, to _invoke_application/_ainvoke_application, which run router dispatch and then call only the function captured at admission, with the graph input and the normal config and framework keywords it declared (trust per D11, not containment; no Runnable it returns is invoked). A TRUSTED_APPLICATION_BRANCH descriptor (bound only to a TRUSTED MediatedBranch around the captured path) routes, right after recheck, to _invoke_trusted_branch/_ainvoke_trusted_branch, which call only the function captured at admission with the branch input and then authorize every Send in its result through the router. No statement spells self.runnable, .invoke/.ainvoke, mutable func/afunc/bound/steps or unpacked kwargs.",
        "entries": entries,
        "issues": [],
    }


# ---------------------------------------------------------------------------
# Obligation (d): RuntimeMAC requires closed admission for secured graphs.
# ---------------------------------------------------------------------------

_MAC_CALLS = frozenset(
    {
        "type",
        "any",
        "tuple",
        "set",
        "len",
        "PermissionError",
        "SecurityConfigurationError",
        "_closed_boundary",
        "_legacy_boundary",
        "_MacBoundary",
        "_bind_compiled_graph",
        "_channel_write_route",
        "_branch_writer_path",
        "_count",
        "_is_bound_method",
        "recheck",
        "self._check_tool_node",
        "self._check_boundary",
        "getattr",
        "ChannelWrite.__dict__.get",
        "BranchSpec.__dict__.get",
    }
)
_MAC_RULES = _Rules(
    _MAC_CALLS,
    attributes=frozenset(),
    names=frozenset({"isinstance", "admit_node", "admit_branch"}),
    methods=frozenset({"items", "values", "pop", "append"}),
    handlers=frozenset({"AttributeError"}),
    withs=frozenset({"_graph_lock"}),
)
# The compiled-graph binder is the one scope allowed to read `bound`: binding
# it by identity to the captured wrapper is the obligation itself.
_COMPILED_RULES = _Rules(
    _MAC_CALLS,
    attributes=frozenset(),
    names=frozenset({"isinstance", "admit_node", "admit_branch"}),
    methods=frozenset({"items", "values", "pop", "append"}),
    handlers=frozenset({"AttributeError"}),
    exempt=frozenset({"bound"}),
)
_MAC_FUNCTIONS = (
    "register_mac_boundary",
    "_closed_boundary",
    "_legacy_boundary",
    "_bind_compiled_graph",
    "_channel_write_route",
    "_branch_writer_path",
    "_count",
    "RuntimeMAC.check",
    "RuntimeMAC._check_boundary",
)


def _require_text(
    function: ast.FunctionDef | ast.AsyncFunctionDef, required: tuple[str, ...]
) -> str:
    """Require every spelled fragment in the unparsed function; return the text."""
    text = ast.unparse(function)
    for item in required:
        if item not in text:
            raise _Unsupported(
                function, f"{function.name} lacks: {item.splitlines()[0]}"
            )
    return text


def _returns_of(function: ast.AST) -> set[str]:
    return {
        ast.unparse(statement.value)
        for statement in ast.walk(function)
        if isinstance(statement, ast.Return) and statement.value is not None
    }


def _prove_compiled_binding(found: dict[str, Any]) -> dict[str, Any]:
    """Prove the runtime check re-binds the compiled Pregel nodes by identity."""
    bind = _require(found, "_bind_compiled_graph")
    statements = _body_text(bind)
    leading = [
        "compiled = graph.nodes",
        "if type(compiled) is not dict:\n    raise PermissionError(DESCRIPTOR_CHANGED)",
        "expected: dict[str, Any] = {START: DEFAULT_BOUND}",
        "for name, mediated, _ in boundary.nodes:\n    expected[name] = mediated",
        "if set(compiled) != set(expected):\n    raise PermissionError(DESCRIPTOR_CHANGED)",
    ]
    if statements[: len(leading)] != leading:
        raise _Unsupported(bind, "compiled inventory equality is not the first step")
    text = _require_text(
        bind,
        (
            "if type(proc) is not PregelNode or proc.bound is not expected[name]:\n            raise PermissionError(DESCRIPTOR_CHANGED)",
            "writers = proc.writers\n        if type(writers) is not list:\n            raise PermissionError(DESCRIPTOR_CHANGED)",
            "if type(writer) is ChannelWrite:\n                _channel_write_route(writer)\n                continue\n            path = _branch_writer_path(writer)\n            if _count(admitted, path) == 0:\n                raise PermissionError(DESCRIPTOR_CHANGED)\n            found.append(path)",
            "if len(found) != len(admitted):\n            raise PermissionError(DESCRIPTOR_CHANGED)",
            "for mediated in admitted:\n            if _count(found, mediated) != 1:\n                raise PermissionError(DESCRIPTOR_CHANGED)",
            "cache = proc.__dict__\n        cache.pop('node', None)\n        cache.pop('flat_writers', None)",
        ),
    )
    bound_reads = [
        part
        for part in ast.walk(bind)
        if isinstance(part, ast.Attribute) and part.attr == "bound"
    ]
    if len(bound_reads) != 1:
        raise _Unsupported(bind, "bound is read outside the identity check")
    if text.index("proc.bound is not expected[name]") > text.index("cache.pop('node'"):
        raise _Unsupported(bind, "cached plans are dropped before verification")
    branch = _require(found, "_branch_writer_path")
    _require_text(
        branch,
        (
            "if type(writer) is not RunnableCallable:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "if type(func) is not MethodType:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "spec = func.__self__\n    if type(spec) is not BranchSpec:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "if not _is_bound_method(func, spec, BranchSpec.__dict__.get('_route')):\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "if not _is_bound_method(afunc, spec, BranchSpec.__dict__.get('_aroute')):\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "path = spec.path\n    if type(path) is not MediatedBranch:\n        raise PermissionError(DESCRIPTOR_CHANGED)\n    return path",
        ),
    )
    if _returns_of(branch) != {"path"}:
        raise _Unsupported(branch, "branch writer returns an unmodeled value")
    _require_text(
        _require(found, "_channel_write_route"),
        (
            "if type(writer) is not ChannelWrite:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "if not _is_bound_method(func, writer, ChannelWrite.__dict__.get('_write')):\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "if not _is_bound_method(afunc, writer, ChannelWrite.__dict__.get('_awrite')):\n        raise PermissionError(DESCRIPTOR_CHANGED)",
        ),
    )
    count = _require(found, "_count")
    if _body_text(count) != [
        "total = 0",
        "for item in items:\n    if item is value:\n        total = total + 1",
        "return total",
    ]:
        raise _Unsupported(count, "_count is not the identity counting loop")
    return {"binder_line": bind.lineno, "leading_steps": len(leading)}


def _prove_runtime_mac(tree: ast.Module, table: symtable.SymbolTable) -> dict[str, Any]:
    found = _definitions(tree)
    register = _require(found, "register_mac_boundary")
    spelled = ast.unparse(register)
    if (
        "if type(config) is SecurityConfig:\n        if config.closed_admission:\n            boundary = _closed_boundary(builder, graph)\n        else:\n            boundary = _legacy_boundary(builder)"
        not in spelled
    ):
        raise _Unsupported(register, "boundary selection by closed_admission differs")
    for part in ast.walk(register):
        if isinstance(part, ast.Call) and ast.unparse(part.func) == "getattr":
            if (
                len(part.args) != 3
                or ast.unparse(part.args[0]) != "builder"
                or not isinstance(part.args[1], ast.Constant)
                or not (
                    isinstance(part.args[2], ast.Constant)
                    and part.args[2].value is None
                )
            ):
                raise _Unsupported(part, "getattr outside the builder attribute read")
    legacy = _require(found, "_legacy_boundary")
    statements = _body_text(legacy)
    if not statements or statements[0] != (
        "if any(builder.branches.values()):\n    return None"
    ):
        raise _Unsupported(legacy, "branches are not unconfined on the legacy path")
    _require_text(
        legacy,
        (
            "type(mediated) is not MediatedNode",
            "type(mediated.runnable) is not ToolNode",
            "nodes.append(mediated.runnable)",
            "return tuple(nodes)",
        ),
    )
    if _returns_of(legacy) != {"None", "tuple(nodes)"}:
        raise _Unsupported(legacy, "legacy boundary returns an unmodeled value")
    check = _require(found, "RuntimeMAC.check")
    check_steps = (
        "if boundary is None:\n        raise SecurityConfigurationError('mac:unconfined_graph_body')",
        "if type(boundary) is tuple:\n        for node in boundary:\n            self._check_tool_node(node)\n        return",
        "if type(boundary) is not _MacBoundary:\n        raise SecurityConfigurationError('mac:unconfined_graph_body')",
        "self._check_boundary(boundary, target)",
    )
    check_text = _require_text(check, check_steps)
    order = [check_text.index(item) for item in check_steps]
    if order != sorted(order):
        raise _Unsupported(check, "check steps are out of order")
    boundary = _require(found, "RuntimeMAC._check_boundary")
    boundary_steps = _body_text(boundary)
    if (
        not boundary_steps
        or boundary_steps[0] != "_bind_compiled_graph(boundary, graph)"
    ):
        raise _Unsupported(boundary, "compiled graph is not bound before any walk")
    loops = [statement for statement in boundary.body if isinstance(statement, ast.For)]
    if len(loops) != 2:
        raise _Unsupported(boundary, "boundary loops differ")
    for loop, link in zip(loops, ("node", "path")):
        text = ast.unparse(loop)
        if "recheck(descriptor)" not in [
            ast.unparse(statement) for statement in loop.body
        ]:
            raise _Unsupported(loop, "descriptor is not rechecked at check time")
        if f"is not implementation.{link}" not in text:
            raise _Unsupported(
                loop, "wrapper is not bound to the captured implementation"
            )
    closed = _require(found, "_closed_boundary")
    _require_text(
        closed,
        (
            "if type(inventory) is not tuple:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "recheck(descriptor)",
            "if wrappers:\n        raise PermissionError(DESCRIPTOR_CHANGED)",
            "boundary = _MacBoundary(tuple(nodes), tuple(branches))\n    _bind_compiled_graph(boundary, graph)\n    return boundary",
        ),
    )
    _require_text(
        closed,
        (
            "elif type(implementation) is _CapturedBranch or type(implementation) is _CapturedTrustedBranch:\n            if type(wrapper) is not MediatedBranch or wrapper.runnable is not implementation.path:\n                raise PermissionError(DESCRIPTOR_CHANGED)",
            "if type(implementation) is _CapturedToolNode or type(implementation) is _CapturedModel or type(implementation) is _CapturedApplication:\n            if type(wrapper) is not MediatedNode or wrapper.runnable is not implementation.node:\n                raise PermissionError(DESCRIPTOR_CHANGED)",
        ),
    )
    _require_text(
        boundary,
        (
            "if type(implementation) is not _CapturedBranch and type(implementation) is not _CapturedTrustedBranch:\n            raise PermissionError(DESCRIPTOR_CHANGED)\n        if mediated.runnable is not implementation.path:\n            raise PermissionError(DESCRIPTOR_CHANGED)\n        recheck(descriptor)",
            "if type(implementation) is _CapturedModel or type(implementation) is _CapturedApplication:\n            if node is not implementation.node:\n                raise PermissionError(DESCRIPTOR_CHANGED)\n            recheck(descriptor)\n            continue",
        ),
    )
    compiled = _prove_compiled_binding(found)
    consumed = 0
    for name in _MAC_FUNCTIONS:
        function = _require(found, name)
        if isinstance(function, ast.AsyncFunctionDef):
            raise _Unsupported(function, "runtime MAC must be synchronous")
        rules = _COMPILED_RULES if name == "_bind_compiled_graph" else _MAC_RULES
        consumed += _admit_statements(function.body, rules)
        _require_global_calls(table, name, rules)
    return {
        "proved": True,
        "property": "register_mac_boundary records a boundary built by _closed_boundary when SecurityConfig.closed_admission is true and otherwise by _legacy_boundary, which returns None for any graph with branches or any node that is not an exact MediatedNode wrapping an exact ToolNode and the tuple of wrapped ToolNodes only for that exact shape, admitting nothing at compile. RuntimeMAC.check refuses None with mac:unconfined_graph_body, re-examines a legacy tuple through _check_tool_node, and for a closed boundary first re-binds the compiled Pregel graph: the compiled node names must equal the admitted inventory plus START, every graph.nodes[name].bound must be the captured MediatedNode by identity, every writer must be an exact ChannelWrite dispatching its own methods or a BranchSpec._route/_aroute writer whose spec path is a captured MediatedBranch of that node, each captured branch appearing exactly once, with cached plans dropped afterwards; only then is every admitted descriptor bound to its wrapper and rechecked. An admitted MODEL_CALL node is recorded and checked like a tool node: its wrapper must hold exactly the captured model and its descriptor is rechecked; its confinement is the model-invocation hook, not a host executor. A declared TRUSTED_APPLICATION node is recorded and checked the same way: its wrapper must hold exactly the captured RunnableCallable and its descriptor is rechecked, binding its identity; its body is trusted per D11, not confined. A declared TRUSTED_APPLICATION_BRANCH edge is recorded with the framework branches: it must be carried by a compiled BranchSpec writer of its source node whose path is the captured MediatedBranch, and its descriptor is rechecked.",
        "legacy_exception": "an exact MediatedNode wrapping an exact ToolNode with no branches is recorded post hoc as the pre-admission tuple of ToolNodes and re-examined by _check_tool_node; that path admits nothing at compile and cannot show that no compile-time protocol ran before it",
        "compiled_binding": compiled,
        "statements": consumed,
        "issues": [],
    }


# ---------------------------------------------------------------------------


def verify_admission_surface(
    admission_source: str,
    config_source: str,
    placement_source: str,
    mac_source: str,
) -> dict[str, Any]:
    """Derive the four closed-admission obligations from the supplied sources.

    Each obligation is proved only when every statement of its analyzed
    functions is consumed by an accepted form and the required steps appear in
    order; any unknown construct, protocol spelling or missing step leaves it
    unproved with the line recorded in `issues`. The sources are parsed and
    symbol-tabled, never imported.
    """
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "admission-surface",
        "proved": False,
        "system_complete": False,
        "sgv901_closed": False,
        "scope": "Source-derived obligations for the opt-in closed admission gate: exact-type selection in admission.py, the closed compile path in config.py (including the refusal of non-framework reducer, cache, retry and trace callbacks), descriptor-bound dispatch in placement.py and the runtime MAC registry in mac.py with its re-binding of the compiled Pregel nodes. The default SecurityConfig path, graph construction before compile, checkpointers, stream callbacks, output publication, the Pregel scheduler itself and host enforcement are outside this scope.",
        "premises": [
            "Initialization: module and class bodies, imports, refusal code constants, pinned registries and dataclass layouts of the analyzed modules match the loaded runtime; this component does not prove them.",
            "Runtime binding: `type(x) is <Class>` on framework classes reads native storage with no instance or class shadowing; `AdmittedDescriptor`, `_CapturedToolNode` and `_CapturedBranch` are native frozen slot records; the helper functions referenced here are the module globals the symbol table resolves.",
            "Recheck correctness: `admission.recheck` recomputes identity over the captured links; its presence before dispatch is derived here, its correctness is a separate obligation covered by the admission tests.",
            "Async adapters: `_require_async_route` and the exact executor/dispatcher coroutine `ainvoke` routes own their lifecycle and transport; this is a premise, not a derivation.",
            "Framework primitives: `ToolNode._func`/`_afunc`, `tools_condition`, host executors and dispatchers are trusted framework code; the admitted host confines candidate tool bodies.",
            "Model calls: allowlisted chat-model classes (`admission._MODEL_CLASSES`) and their class-level `invoke`/`ainvoke` are trusted provider code. The model-invocation hook decides the capability to call the model before the call; nothing here constrains the content of the prompt or the reply, and the call is performed by the coordinator, not a confined host.",
            "Trusted application nodes: trusted application node bodies are trusted per D11; admission binds their identity only (node name, module, qualname, loaded code and keyword-injection plan), not their globals, closures, defaults or effects. The same holds for declared trusted application branches (branch name, module, qualname, loaded code and routing map). `_application_kwargs` mirrors the framework's `RunnableCallable` keyword injection and is trusted framework-equivalent code.",
            "Graph construction effects before `compile(security=...)` (naming, type hints, signatures, schema inference) and uncovered entry points without an installed RuntimeMAC are outside the proved surface.",
            "Scheduler: the Pregel loop executes `graph.nodes[name].bound` followed by that node's `writers` and nothing else for a node; the compiled-graph binder re-reads exactly those links, and `ChannelWrite` entries (framework closures from compile) are trusted framework code.",
        ],
        "obligations": {},
        "issues": [],
        "source_sha256": {
            _ADMISSION: hashlib.sha256(admission_source.encode()).hexdigest(),
            _CONFIG: hashlib.sha256(config_source.encode()).hexdigest(),
            _PLACEMENT: hashlib.sha256(placement_source.encode()).hexdigest(),
            _MAC: hashlib.sha256(mac_source.encode()).hexdigest(),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    obligations = (
        (
            "exact_type_selection",
            _ADMISSION,
            admission_source,
            _prove_exact_type_selection,
        ),
        (
            "closed_compile_refusal",
            _CONFIG,
            config_source,
            _prove_closed_compile_refusal,
        ),
        (
            "descriptor_dispatch",
            _PLACEMENT,
            placement_source,
            _prove_descriptor_dispatch,
        ),
        ("runtime_mac_closed_admission", _MAC, mac_source, _prove_runtime_mac),
    )
    for key, module, source, prove in obligations:
        try:
            tree = ast.parse(source, filename=module)
            table = symtable.symtable(source, module, "exec")
            report["obligations"][key] = prove(tree, table)
        except _Unsupported as exc:
            report["obligations"][key] = {
                "proved": False,
                "issues": [{"line": exc.line, "reason": exc.reason}],
            }
            report["issues"].append(
                {"obligation": key, "line": exc.line, "reason": exc.reason}
            )
        except (SyntaxError, ValueError) as exc:
            line = getattr(exc, "lineno", 0)
            report["obligations"][key] = {
                "proved": False,
                "issues": [{"line": line, "reason": str(exc)}],
            }
            report["issues"].append(
                {"obligation": key, "line": line, "reason": str(exc)}
            )
    report["proved"] = all(item["proved"] for item in report["obligations"].values())
    return report
