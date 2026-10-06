"""Conservative per-tool Python sink and taint-path analyzer."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

from .schema import (
    Enforcer,
    MediationPoint,
    ResourceClass,
    SinkClass,
    SinkRecord,
    TaintOrigin,
    TaintPath,
    TaintStep,
    ToolSinkReport,
)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Inputs needed to analyze one Python tool function."""

    source: Path
    function: str
    declared_resources: frozenset[ResourceClass] = frozenset()
    argument_origins: tuple[tuple[str, TaintOrigin], ...] = ()

    @property
    def origins(self) -> dict[str, TaintOrigin]:
        """Return configured argument tag origins by parameter name."""
        return dict(self.argument_origins)


@dataclass(frozen=True, slots=True)
class _Trace:
    source: str
    origin: TaintOrigin
    steps: tuple[TaintStep, ...] = ()
    boundary_constrainable: bool = True
    trusted_value_poisoned: bool = False

    def step(
        self,
        node: ast.AST,
        kind: str,
        symbol: str,
        *,
        below_boundary: bool = False,
    ) -> _Trace:
        return replace(
            self,
            steps=(
                *self.steps,
                TaintStep(
                    kind=kind,
                    symbol=symbol,
                    line=getattr(node, "lineno", 0),
                    column=getattr(node, "col_offset", 0),
                ),
            ),
            boundary_constrainable=self.boundary_constrainable and not below_boundary,
            trusted_value_poisoned=(
                self.trusted_value_poisoned
                or (below_boundary and self.origin is TaintOrigin.TRUSTED_TAG)
            ),
        )


_FILESYSTEM_FUNCTIONS = {
    "builtins.open",
    "os.chmod",
    "os.chown",
    "os.link",
    "os.makedirs",
    "os.mkdir",
    "os.remove",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.symlink",
    "os.truncate",
    "os.unlink",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "shutil.rmtree",
}
_FILESYSTEM_METHODS = {
    "chmod",
    "mkdir",
    "open",
    "read_bytes",
    "read_text",
    "rmdir",
    "symlink_to",
    "touch",
    "truncate",
    "unlink",
    "write_bytes",
    "write_text",
}
_PROCESS_PREFIXES = (
    "asyncio.create_subprocess_",
    "multiprocessing.",
    "os.exec",
    "os.fork",
    "os.popen",
    "os.posix_spawn",
    "os.spawn",
    "os.system",
    "subprocess.",
)
_NETWORK_PREFIXES = (
    "aiohttp.",
    "asyncio.open_connection",
    "ftplib.",
    "grpc.",
    "http.client.",
    "httpx.",
    "paramiko.",
    "requests.",
    "socket.",
    "urllib.",
    "urllib3.",
    "websockets.",
)
_DATABASE_PREFIXES = (
    "aiosqlite.",
    "asyncpg.",
    "mysql.",
    "psycopg.",
    "pymongo.",
    "redis.",
    "sqlite3.",
    "sqlalchemy.",
)
_DATABASE_METHODS = {"execute", "executemany", "executescript"}
_NETWORK_METHODS = {"connect", "delete", "get", "head", "patch", "post", "put", "request", "send"}
_NATIVE_PREFIXES = ("cffi.", "ctypes.")
_DYNAMIC_SYMBOLS = {
    "builtins.__import__",
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "importlib.import_module",
    "runpy.run_module",
    "runpy.run_path",
}
_DELEGATION_NAMES = {"delegate_to_subagent", "spawn_agent", "spawn_child"}
_POST_BOUNDARY_TRANSFORMS = {
    "os.path.join",
    "pathlib.Path.joinpath",
    "shlex.quote",
    "urllib.parse.urljoin",
}


def analyze_tool(spec: ToolSpec) -> ToolSinkReport:
    """Analyze one named function and emit a machine-readable sink report."""
    source_path = spec.source.resolve()
    try:
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        return ToolSinkReport(
            tool=spec.function,
            source=str(source_path),
            sinks=(),
            parse_errors=(str(exc),),
        )
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    function = functions.get(spec.function)
    if function is None:
        return ToolSinkReport(
            tool=spec.function,
            source=str(source_path),
            sinks=(),
            parse_errors=(f"function {spec.function!r} not found",),
        )
    imports = _imports(tree)
    analyzer = _ToolAnalyzer(spec, source_path, function, imports)
    analyzer.run()
    return ToolSinkReport(
        tool=spec.function,
        source=str(source_path),
        sinks=tuple(sorted(analyzer.sinks, key=lambda sink: (sink.line, sink.column, sink.symbol))),
    )


class _ToolAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        spec: ToolSpec,
        source: Path,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        imports: dict[str, str],
    ) -> None:
        self.spec = spec
        self.source = source
        self.function = function
        self.imports = imports
        origins = spec.origins
        self.values: dict[str, tuple[_Trace, ...]] = {
            argument.arg: (
                _Trace(
                    source=argument.arg,
                    origin=origins.get(argument.arg, TaintOrigin.TOOL_ARGUMENT),
                ),
            )
            for argument in _arguments(function.args)
        }
        self.control: tuple[_Trace, ...] = ()
        self.sinks: list[SinkRecord] = []

    def run(self) -> None:
        for statement in self.function.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        traces = self._traces(node.value)
        for target in node.targets:
            self._assign(target, traces)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._assign(node.target, self._traces(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        traces = _merge_traces(self._traces(node.target), self._traces(node.value))
        traces = self._transform(traces, node, "concatenation", node.op.__class__.__name__)
        self._assign(node.target, traces)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        previous = self.control
        self.control = _merge_traces(previous, self._traces(node.test))
        for statement in (*node.body, *node.orelse):
            self.visit(statement)
        self.control = previous

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        traces = self._traces(node.iter)
        self._assign(node.target, traces)
        previous = self.control
        self.control = _merge_traces(previous, traces)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)
        self.control = previous

    visit_AsyncFor = visit_For

    def visit_Call(self, node: ast.Call) -> None:
        qualified = self._qualified_name(node.func)
        receiver_traces = (
            self._traces(node.func.value) if isinstance(node.func, ast.Attribute) else ()
        )
        traces = _merge_traces(
            receiver_traces,
            *(self._traces(argument) for argument in node.args),
            *(self._traces(keyword.value) for keyword in node.keywords),
            self.control,
        )
        classification = _classify_sink(qualified, node.func)
        if classification is not None:
            sink_class, resource_class, enforcer, operation = classification
            sink_traces = tuple(_to_path(trace) for trace in traces)
            resource_after_boundary = resource_class in {
                ResourceClass.FILESYSTEM,
                ResourceClass.NETWORK,
                ResourceClass.EXEC,
                ResourceClass.SQL,
                ResourceClass.MAIL,
                ResourceClass.CHAT,
            }
            points = {MediationPoint.ARGUMENT_BOUNDARY}
            for trace in traces:
                if not trace.boundary_constrainable:
                    points.add(MediationPoint.POST_VALIDATION_TRANSFORM)
            if resource_after_boundary:
                points.add(MediationPoint.RESOURCE_RESOLUTION)
            if sink_class is SinkClass.NATIVE:
                points.add(MediationPoint.NATIVE_CALL)
            if sink_class is SinkClass.DYNAMIC:
                points.add(MediationPoint.DYNAMIC_DISPATCH)
            if enforcer is Enforcer.KERNEL:
                points.add(MediationPoint.KERNEL_RESOURCE)
            elif enforcer is Enforcer.BROKER:
                points.add(MediationPoint.BROKER_REQUEST)
            self.sinks.append(
                SinkRecord(
                    sink_id=_sink_id(self.source, self.function.name, node, qualified),
                    sink_class=sink_class,
                    resource_class=resource_class,
                    alternate_resource_classes=(
                        (ResourceClass.FILESYSTEM,) if qualified == "urllib.request.urlopen" else ()
                    ),
                    required_enforcer=enforcer,
                    path=str(self.source),
                    function=self.function.name,
                    line=node.lineno,
                    column=node.col_offset,
                    symbol=qualified,
                    operation=operation,
                    taint_paths=sink_traces,
                    mediation_points=tuple(sorted(points, key=lambda item: item.value)),
                    resource_identity_after_boundary=resource_after_boundary,
                    grant_declared=resource_class in self.spec.declared_resources,
                )
            )
        elif self._is_dynamic_callable(node.func):
            self.sinks.append(
                SinkRecord(
                    sink_id=_sink_id(self.source, self.function.name, node, qualified),
                    sink_class=SinkClass.DYNAMIC,
                    resource_class=ResourceClass.UNKNOWN,
                    alternate_resource_classes=(),
                    required_enforcer=Enforcer.UNKNOWN,
                    path=str(self.source),
                    function=self.function.name,
                    line=node.lineno,
                    column=node.col_offset,
                    symbol=qualified,
                    operation="dispatch",
                    taint_paths=tuple(_to_path(trace) for trace in traces),
                    mediation_points=(
                        MediationPoint.ARGUMENT_BOUNDARY,
                        MediationPoint.DYNAMIC_DISPATCH,
                    ),
                    resource_identity_after_boundary=True,
                    grant_declared=False,
                )
            )
        self.generic_visit(node)

    def _traces(self, node: ast.AST) -> tuple[_Trace, ...]:
        if isinstance(node, ast.Name):
            return self.values.get(node.id, ())
        if isinstance(node, ast.Constant):
            return ()
        if isinstance(node, ast.Attribute):
            return self._traces(node.value)
        if isinstance(node, ast.Subscript):
            return _merge_traces(self._traces(node.value), self._traces(node.slice))
        if isinstance(node, ast.List | ast.Set | ast.Tuple):
            return _merge_traces(*(self._traces(item) for item in node.elts))
        if isinstance(node, ast.Dict):
            values = [*node.keys, *node.values]
            return _merge_traces(*(self._traces(item) for item in values if item is not None))
        if isinstance(node, ast.BinOp):
            traces = _merge_traces(self._traces(node.left), self._traces(node.right))
            return self._transform(traces, node, "concatenation", node.op.__class__.__name__)
        if isinstance(node, ast.JoinedStr):
            traces = _merge_traces(*(self._traces(item) for item in node.values))
            return self._transform(traces, node, "string_format", "f-string")
        if isinstance(node, ast.FormattedValue):
            return self._traces(node.value)
        if isinstance(node, ast.BoolOp):
            return _merge_traces(*(self._traces(item) for item in node.values))
        if isinstance(node, ast.Compare):
            return _merge_traces(
                self._traces(node.left),
                *(self._traces(item) for item in node.comparators),
            )
        if isinstance(node, ast.IfExp):
            return _merge_traces(
                self._traces(node.test),
                self._traces(node.body),
                self._traces(node.orelse),
            )
        if isinstance(node, ast.Call):
            qualified = self._qualified_name(node.func)
            traces = _merge_traces(
                *(self._traces(argument) for argument in node.args),
                *(self._traces(keyword.value) for keyword in node.keywords),
            )
            below_boundary = qualified in _POST_BOUNDARY_TRANSFORMS or _method_name(node.func) in {
                "format",
                "joinpath",
                "replace",
            }
            return self._transform(
                traces,
                node,
                "call_transform",
                qualified,
                below_boundary=below_boundary,
            )
        return _merge_traces(*(self._traces(child) for child in ast.iter_child_nodes(node)))

    def _transform(
        self,
        traces: tuple[_Trace, ...],
        node: ast.AST,
        kind: str,
        symbol: str,
        *,
        below_boundary: bool = True,
    ) -> tuple[_Trace, ...]:
        return tuple(
            trace.step(node, kind, symbol, below_boundary=below_boundary) for trace in traces
        )

    def _assign(self, target: ast.AST, traces: tuple[_Trace, ...]) -> None:
        for item in ast.walk(target):
            if isinstance(item, ast.Name):
                self.values[item.id] = traces

    def _qualified_name(self, expression: ast.expr) -> str:
        raw = _expression_name(expression)
        first, separator, rest = raw.partition(".")
        imported = self.imports.get(first)
        if imported is None:
            if first in {"__import__", "compile", "eval", "exec", "open"}:
                return f"builtins.{raw}"
            return raw
        return imported + (separator + rest if separator else "")

    def _is_dynamic_callable(self, expression: ast.expr) -> bool:
        if isinstance(expression, ast.Name):
            return bool(self.values.get(expression.id))
        if isinstance(expression, ast.Subscript):
            return bool(self._traces(expression))
        return False


def _classify_sink(
    qualified: str,
    expression: ast.expr,
) -> tuple[SinkClass, ResourceClass, Enforcer, str] | None:
    method = _method_name(expression)
    if qualified in _DYNAMIC_SYMBOLS:
        return SinkClass.DYNAMIC, ResourceClass.SYSCALL, Enforcer.KERNEL, "dynamic_code"
    if any(qualified.startswith(prefix) for prefix in _NATIVE_PREFIXES):
        resource = _native_resource(qualified)
        return SinkClass.NATIVE, resource, Enforcer.KERNEL, "native_call"
    if any(qualified.startswith(prefix) for prefix in _PROCESS_PREFIXES):
        return SinkClass.PROCESS, ResourceClass.EXEC, Enforcer.KERNEL, "spawn_or_exec"
    if qualified in _FILESYSTEM_FUNCTIONS or method in _FILESYSTEM_METHODS:
        return SinkClass.FILESYSTEM, ResourceClass.FILESYSTEM, Enforcer.KERNEL, method or "open"
    if (
        any(qualified.startswith(prefix) for prefix in _DATABASE_PREFIXES)
        or method in _DATABASE_METHODS
    ):
        return SinkClass.DATABASE, ResourceClass.SQL, Enforcer.BROKER, method or "query"
    if qualified.startswith("smtplib.") or method == "sendmail":
        return SinkClass.SERVICE, ResourceClass.MAIL, Enforcer.BROKER, "send"
    if (
        "webhook" in qualified.lower()
        or qualified.startswith("slack_sdk.")
        or method in {"chat_postMessage", "post_to_slack"}
    ):
        return SinkClass.SERVICE, ResourceClass.CHAT, Enforcer.BROKER, "post"
    generic_network_method = method in _NETWORK_METHODS and qualified.split(".", 1)[0] in {
        "client",
        "connection",
        "http_client",
        "session",
        "socket",
    }
    if any(qualified.startswith(prefix) for prefix in _NETWORK_PREFIXES) or generic_network_method:
        return SinkClass.NETWORK, ResourceClass.NETWORK, Enforcer.KERNEL, method or "connect"
    if method in _DELEGATION_NAMES or qualified.rsplit(".", 1)[-1] in _DELEGATION_NAMES:
        return (
            SinkClass.DELEGATION,
            ResourceClass.DELEGATION,
            Enforcer.EVALUATOR,
            "delegate",
        )
    return None


def _native_resource(qualified: str) -> ResourceClass:
    lowered = qualified.lower()
    if any(name in lowered for name in ("open", "fopen", "unlink", "rename")):
        return ResourceClass.FILESYSTEM
    if any(name in lowered for name in ("socket", "connect", "bind")):
        return ResourceClass.NETWORK
    if any(name in lowered for name in ("exec", "system", "spawn")):
        return ResourceClass.EXEC
    return ResourceClass.SYSCALL


def _imports(tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
    return imports


def _arguments(arguments: ast.arguments) -> tuple[ast.arg, ...]:
    positional = (*arguments.posonlyargs, *arguments.args)
    vararg = (arguments.vararg,) if arguments.vararg is not None else ()
    kwarg = (arguments.kwarg,) if arguments.kwarg is not None else ()
    return (*positional, *vararg, *arguments.kwonlyargs, *kwarg)


def _merge_traces(*groups: tuple[_Trace, ...]) -> tuple[_Trace, ...]:
    unique: dict[tuple[object, ...], _Trace] = {}
    for trace in (item for group in groups for item in group):
        key = (
            trace.source,
            trace.origin,
            trace.steps,
            trace.boundary_constrainable,
            trace.trusted_value_poisoned,
        )
        unique[key] = trace
    return tuple(unique.values())


def _to_path(trace: _Trace) -> TaintPath:
    return TaintPath(
        source=trace.source,
        origin=trace.origin,
        steps=trace.steps,
        boundary_constrainable=trace.boundary_constrainable,
        trusted_value_poisoned=trace.trusted_value_poisoned,
    )


def _sink_id(source: Path, function: str, node: ast.AST, symbol: str) -> str:
    material = f"{source}:{function}:{node.lineno}:{node.col_offset}:{symbol}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _expression_name(expression: ast.expr) -> str:
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        base = _expression_name(expression.value)
        return f"{base}.{expression.attr}" if base else expression.attr
    if isinstance(expression, ast.Subscript):
        return f"{_expression_name(expression.value)}[...]"
    if isinstance(expression, ast.Call):
        return f"{_expression_name(expression.func)}(...)"
    return expression.__class__.__name__


def _method_name(expression: ast.expr) -> str | None:
    return expression.attr if isinstance(expression, ast.Attribute) else None
