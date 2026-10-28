"""Synthetic language baseline and fixed-operation worker, not a secure Python VM.

The admitted helper intentionally models trusted library code below the language
boundary. Neither condition is attributed to CaMeL or another released sandbox.
"""

import ast
import json
import sys


def admit(source: str) -> None:
    """Admit only literals, arithmetic, and a single prebound helper call."""
    tree = ast.parse(source)
    allowed = (
        ast.Module,
        ast.Assign,
        ast.Name,
        ast.Store,
        ast.Load,
        ast.Constant,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Expr,
        ast.Call,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise PermissionError("language:syntax")
        if isinstance(node, ast.Name) and node.id not in {"result", "helper"}:
            raise PermissionError("language:name")
        if isinstance(node, ast.Call) and (
            not isinstance(node.func, ast.Name)
            or node.func.id != "helper"
            or node.args
            or node.keywords
        ):
            raise PermissionError("language:call")


def run(source: str, p: dict, language: str) -> dict:
    """Execute a frozen probe and return observations, never a security verdict."""
    namespace = {"p": p, "result": None}

    def helper():
        exec(compile(source, "<fixed-probe>", "exec"), namespace)
        return namespace.get("result")

    candidate = "result = helper()" if language == "helper" else source
    if language != "none":
        try:
            admit(candidate)
        except PermissionError as error:
            return {"phase": "admission", "error": str(error)}
    try:
        if language == "none":
            value = helper()
        else:
            scope = {"__builtins__": {}, "helper": helper}
            exec(compile(candidate, "<admitted>", "exec"), scope)
            value = scope.get("result")
        response = {"phase": "executed", "value": value}
        # Optional benchmark telemetry, never used as a security verdict.
        if "_operation_elapsed_ns" in namespace:
            response["operation_elapsed_ns"] = namespace["_operation_elapsed_ns"]
        return response
    except Exception as error:
        return {
            "phase": "operation",
            "error": type(error).__name__,
            "errno": getattr(error, "errno", None),
        }


if __name__ == "__main__":
    print(json.dumps(run(**json.load(sys.stdin))))
