"""Manifest admission and grant-bound APIs for in-process Cedar tools.

This is restricted source checking, not confinement of arbitrary Python. The
coordinator, tool construction, and stable runtime bindings remain trusted.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import textwrap
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path
from types import CodeType, FunctionType

from langchain_core.tools import BaseTool, StructuredTool

from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    check_manifest_consistency,
    format_manifest_diagnostics,
)
from langgraph.prebuilt.security.mediators.contracts import client_binding
from langgraph.prebuilt.security.object_policy import ObjectGrant, SecurityManifest

_active_grant: ContextVar[ObjectGrant | None] = ContextVar(
    "inprocess_object_grant", default=None
)


def read_text(path: str) -> str:
    """Read UTF-8 text only when the current invocation grants this exact file."""
    if type(path) is not str:
        raise HostExecutionDenied("inprocess:resource_must_be_string")
    grant = _active_grant.get()
    canonical = str(Path(path).resolve(strict=True))
    if grant is None or not any(
        line.class_name == "fs"
        and line.operation == "read"
        and line.selector == canonical
        for line in grant.lines
    ):
        raise HostExecutionDenied("inprocess:resource_not_granted")
    return Path(canonical).read_text(encoding="utf-8")


class ManifestAdmission:
    """Check actual tool bodies and reject changes to admitted callables/APIs."""

    def __init__(self, tool: BaseTool, manifest: SecurityManifest) -> None:
        # Subclasses can override invocation and execute an unchecked body.
        if type(tool) is not StructuredTool:
            raise SecurityConfigurationError(
                "manifest_consistency: requires a standard StructuredTool"
            )
        self.tool = tool
        self.bindings = []
        self.reports = []
        self.defaults = []
        self.clients = []
        for attribute in ("func", "coroutine"):
            function = getattr(tool, attribute)
            if function is None:
                continue
            if not isinstance(function, FunctionType) or hasattr(
                function, "__wrapped__"
            ):
                raise SecurityConfigurationError(
                    "manifest_consistency: wrapped or non-function body is unsupported"
                )
            if function.__closure__:
                raise SecurityConfigurationError(
                    "manifest_consistency: captured closure state is unsupported"
                )
            try:
                # Passing the code object avoids inspect's automatic unwrapping.
                source = textwrap.dedent(inspect.getsource(function.__code__))
            except (OSError, TypeError) as exc:
                raise SecurityConfigurationError(
                    "manifest_consistency: source unavailable"
                ) from exc
            # Source may have changed on disk since import. A report about that
            # new text must not admit the previously loaded executable body.
            tree = ast.parse(source)
            # Python can choose different method-call bytecode based on the
            # complete compilation unit. Recompile that unit without executing
            # it, and bind the extracted body to the same source location.
            try:
                module_tree = ast.parse(Path(function.__code__.co_filename).read_text())
                compiled = compile(
                    module_tree,
                    function.__code__.co_filename,
                    "exec",
                    dont_inherit=True,
                )
            except (OSError, SyntaxError) as exc:
                raise SecurityConfigurationError(
                    "manifest_consistency: source unavailable"
                ) from exc
            entries = [
                node
                for node in ast.walk(module_tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function.__name__
                and min([node.lineno, *(item.lineno for item in node.decorator_list)])
                == function.__code__.co_firstlineno
            ]
            candidates = []
            pending = [compiled]
            while pending:
                code = pending.pop()
                if (
                    code.co_name == function.__name__
                    and code.co_firstlineno == function.__code__.co_firstlineno
                ):
                    candidates.append(code)
                pending.extend(
                    value for value in code.co_consts if isinstance(value, CodeType)
                )
            if (
                len(entries) != 1
                or len(tree.body) != 1
                or ast.dump(entries[0]) != ast.dump(tree.body[0])
                or len(candidates) != 1
            ) or any(
                getattr(candidates[0], key) != getattr(function.__code__, key)
                for key in ("co_code", "co_consts", "co_names", "co_varnames")
            ):
                raise SecurityConfigurationError(
                    "manifest_consistency: source does not match loaded code"
                )
            defaults = (
                *(function.__defaults__ or ()),
                *(function.__kwdefaults__ or {}).values(),
            )
            if any(type(value) is not str for value in defaults):
                raise SecurityConfigurationError(
                    "manifest_consistency: defaults must be inert strings"
                )
            # Only framework resource APIs are terminals, not arbitrary helpers
            # supplied by the tool author. Bind their actual identities as well
            # as their source spelling. Other calls remain unknown.
            terminals = {
                name: value
                for name, value in function.__globals__.items()
                if value is read_text and name in function.__code__.co_names
            }
            operations = tuple(
                ManifestOperation(name, "fs", "read", "path") for name in terminals
            )
            clients = {}
            for name in function.__code__.co_names:
                value = function.__globals__.get(name)
                binding = client_binding(value)
                if binding is not None:
                    binding.validate()
                    clients[name] = value
                    self.clients.append((function, name, binding))
            report = check_manifest_consistency(
                source,
                manifest,
                tool_name=tool.name,
                function=function.__name__,
                operations=operations,
                clients=clients,
            )
            if not report["consistent"]:
                diagnostic = format_manifest_diagnostics(
                    report,
                    source_name=f"{function.__code__.co_filename} ({function.__name__} body)",
                )
                raise SecurityConfigurationError(
                    f"manifest_consistency:{report['status']}:{tool.name}:\n{diagnostic}"
                )
            self.bindings.append((attribute, function, function.__code__, terminals))
            self.defaults.append(
                (function, function.__defaults__, dict(function.__kwdefaults__ or {}))
            )
            self.reports.append(report)
        if not self.bindings:
            raise SecurityConfigurationError("manifest_consistency: missing tool body")
        self.functions = (tool.func, tool.coroutine)

    def validate(self) -> None:
        if (self.tool.func, self.tool.coroutine) != self.functions:
            raise HostExecutionDenied("manifest_consistency:tool_changed")
        for function, name, binding in self.clients:
            if function.__globals__.get(name) is not binding.client:
                raise HostExecutionDenied("manifest_consistency:client_changed")
            try:
                binding.validate()
            except PermissionError as exc:
                raise HostExecutionDenied(
                    "manifest_consistency:client_method_changed"
                ) from exc
        for _, function, code, terminals in self.bindings:
            if function.__code__ is not code or any(
                function.__globals__.get(name) is not value
                for name, value in terminals.items()
            ):
                raise HostExecutionDenied("manifest_consistency:binding_changed")
        for function, positional, keywords in self.defaults:
            current = function.__kwdefaults__ or {}
            if (
                function.__defaults__ is not positional
                or current.keys() != keywords.keys()
                or any(current[name] is not value for name, value in keywords.items())
            ):
                raise HostExecutionDenied("manifest_consistency:defaults_changed")

    def invoke(self, arguments: Mapping[str, object]) -> object:
        """Execute only the admitted body, without arbitrary tool validators/hooks."""
        self.validate()
        function = self.functions[0]
        if function is None:
            raise HostExecutionDenied(
                "manifest_consistency:async_tool_requires_ainvoke"
            )
        self._validate_arguments(arguments)
        return function(**arguments)

    async def ainvoke(self, arguments: Mapping[str, object]) -> object:
        self.validate()
        self._validate_arguments(arguments)
        function = self.functions[1]
        if function is not None:
            return await function(**arguments)
        return await asyncio.to_thread(self.invoke, arguments)

    @staticmethod
    def _validate_arguments(arguments: Mapping[str, object]) -> None:
        if any(type(value) is not str for value in arguments.values()):
            raise HostExecutionDenied("manifest_consistency:arguments_must_be_strings")
