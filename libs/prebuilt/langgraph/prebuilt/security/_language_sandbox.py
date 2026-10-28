"""Execute the admitted data-and-terminal language without executing Python code.

The program is immutable data. There is no eval, exec, import, attribute lookup,
user callable invocation, or library object in the language's value environment.
Framework terminals remain part of the enforcement implementation.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from inspect import Parameter, Signature
from typing import Any

from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.language_verification import (
    TerminalContract,
    _signature_snapshot,
    _terminal_contract_snapshot,
    derive_program,
)
from langgraph.prebuilt.security.types import _decision_arguments, _DecisionArguments


def inert_copy(value: Any, depth: int = 0) -> Any:
    """Accept exact data types without invoking conversion or object protocols."""
    if depth > 32:
        raise HostExecutionDenied("language_sandbox:data_depth")
    kind = type(value)
    if kind is str or kind is int or kind is bool or kind is float or value is None:
        return value
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: inert_copy(child, depth + 1) for key, child in value.items()}
    raise HostExecutionDenied("language_sandbox:non_data_result")


@dataclass(frozen=True, slots=True)
class LanguageProgram:
    body: tuple
    signature: Signature
    terminals: Mapping[str, Callable[..., Any]]
    contracts: Mapping[str, TerminalContract]

    def __post_init__(self):
        try:
            terminals = _decision_arguments(self.terminals)
            contracts = _decision_arguments(self.contracts)
        except TypeError:
            raise SecurityConfigurationError("language_proof:invalid_bindings")
        object.__setattr__(self, "terminals", _DecisionArguments(terminals))
        object.__setattr__(self, "contracts", _DecisionArguments(contracts))

    @classmethod
    def lower(
        cls, entry, terminals, positional_defaults, keyword_defaults, *, contracts
    ):
        """Lower only the admitted syntax; an unknown node always rejects."""
        parameters = []
        positional = [*entry.args.posonlyargs, *entry.args.args]
        first_default = len(positional) - len(positional_defaults)
        for index, arg in enumerate(positional):
            parameters.append(
                Parameter(
                    arg.arg,
                    Parameter.POSITIONAL_ONLY
                    if index < len(entry.args.posonlyargs)
                    else Parameter.POSITIONAL_OR_KEYWORD,
                    default=positional_defaults[index - first_default]
                    if index >= first_default
                    else Parameter.empty,
                )
            )
        for arg in entry.args.kwonlyargs:
            parameters.append(
                Parameter(
                    arg.arg,
                    Parameter.KEYWORD_ONLY,
                    default=keyword_defaults.get(arg.arg, Parameter.empty),
                )
            )
        if entry.args.vararg or entry.args.kwarg:
            raise SecurityConfigurationError("language_sandbox:variadic_parameters")

        def expression(node):
            if isinstance(node, ast.Constant) and any(
                type(node.value) is kind for kind in (str, int, float, bool, type(None))
            ):
                return ("constant", node.value)
            if isinstance(node, ast.Name):
                return ("local", node.id)
            if isinstance(node, ast.JoinedStr):
                return (
                    "join",
                    tuple(
                        expression(part.value)
                        if isinstance(part, ast.FormattedValue)
                        and part.conversion == -1
                        and part.format_spec is None
                        else expression(part)
                        for part in node.values
                    ),
                )
            if isinstance(node, ast.Call):
                target = ast.unparse(node.func)
                if target in terminals and all(
                    kw.arg is not None for kw in node.keywords
                ):
                    return (
                        "call",
                        target,
                        tuple(expression(arg) for arg in node.args),
                        tuple((kw.arg, expression(kw.value)) for kw in node.keywords),
                    )
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
            ):
                return (
                    "compare",
                    isinstance(node.ops[0], ast.Eq),
                    expression(node.left),
                    expression(node.comparators[0]),
                )
            raise SecurityConfigurationError(
                f"language_sandbox:unsupported_expression:{type(node).__name__}"
            )

        def statements(nodes):
            output = []
            for node in nodes:
                if isinstance(node, ast.Return):
                    output.append(
                        (
                            "return",
                            expression(node.value)
                            if node.value is not None
                            else ("constant", None),
                        )
                    )
                elif isinstance(node, ast.Expr):
                    output.append(("expression", expression(node.value)))
                elif isinstance(node, ast.Assign) and all(
                    isinstance(target, ast.Name) for target in node.targets
                ):
                    output.append(
                        (
                            "assign",
                            tuple(target.id for target in node.targets),
                            expression(node.value),
                        )
                    )
                elif isinstance(node, ast.If):
                    output.append(
                        (
                            "if",
                            expression(node.test),
                            statements(node.body),
                            statements(node.orelse),
                        )
                    )
                elif not isinstance(node, ast.Pass):
                    raise SecurityConfigurationError(
                        f"language_sandbox:unsupported_statement:{type(node).__name__}"
                    )
            return tuple(output)

        program = cls(
            statements(entry.body),
            Signature(parameters),
            terminals,
            contracts,
        )
        program.proof()
        return program

    def proof(self) -> dict[str, Any]:
        body, signature, terminals, contracts = self._snapshot()
        return derive_program(body, signature, contracts)

    def _snapshot(self):
        """Capture the exact metadata later used for both proof and execution."""
        body = self.body
        signature = _signature_snapshot(self.signature)
        try:
            terminals = _decision_arguments(self.terminals)
        except TypeError:
            raise SecurityConfigurationError(
                "language_proof:invalid_bindings"
            ) from None
        contracts = _terminal_contract_snapshot(self.contracts)
        if set(terminals) != set(contracts):
            raise SecurityConfigurationError(
                "language_proof:terminal_contract_mismatch"
            )
        return body, signature, terminals, contracts

    def invoke(self, arguments: dict[str, str]) -> Any:
        # No saved certificate or caller-supplied passing flag grants execution.
        body, signature, terminals, contracts = self._snapshot()
        derive_program(body, signature, contracts)
        if type(arguments) is not dict or any(
            type(key) is not str or type(value) is not str
            for key, value in arguments.items()
        ):
            raise HostExecutionDenied("language_proof:arguments_must_be_strings")
        # Binding uses the captured, data-only signature, never a mutable function
        # signature, defaults, globals, descriptors, or a tool schema validator.
        bound = signature.bind(**arguments)
        bound.apply_defaults()
        environment = dict(bound.arguments)

        def expression(node):
            kind = node[0]
            if kind == "constant":
                return node[1]
            if kind == "local":
                if node[1] not in environment:
                    raise HostExecutionDenied("language_sandbox:unbound_local")
                return environment[node[1]]
            if kind == "join":
                parts = [expression(part) for part in node[1]]
                if any(type(part) is not str for part in parts):
                    raise HostExecutionDenied(
                        "language_sandbox:format_requires_strings"
                    )
                return "".join(parts)
            if kind == "compare":
                left, right = expression(node[2]), expression(node[3])
                if type(left) is not str or type(right) is not str:
                    raise HostExecutionDenied(
                        "language_sandbox:comparison_requires_strings"
                    )
                return (left == right) if node[1] else (left != right)
            if kind == "call":
                args = tuple(expression(part) for part in node[2])
                kwargs = {key: expression(part) for key, part in node[3]}
                value = inert_copy(terminals[node[1]](*args, **kwargs))
                if type(value).__name__ not in contracts[node[1]].result:
                    raise HostExecutionDenied("language_proof:terminal_result_type")
                return value
            raise HostExecutionDenied("language_sandbox:invalid_program")

        def statements(body):
            for node in body:
                if node[0] == "return":
                    return True, expression(node[1])
                if node[0] == "expression":
                    expression(node[1])
                elif node[0] == "assign":
                    value = expression(node[2])
                    for name in node[1]:
                        environment[name] = value
                elif node[0] == "if":
                    branch = node[2] if expression(node[1]) else node[3]
                    returned, value = statements(branch)
                    if returned:
                        return True, value
            return False, None

        return inert_copy(statements(body)[1])
