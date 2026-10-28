"""Independent offline fixture producer: literal calls only, no policy synthesis."""

import ast
import json
import sys


def produce(source):
    tree = ast.parse(source)
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Expr):
        raise ValueError("exactly one literal call expression required")
    call = tree.body[0].value
    if not isinstance(call, ast.Call) or call.keywords or not call.args:
        raise ValueError("literal positional call required")
    if any(not isinstance(arg, ast.Constant) for arg in call.args):
        raise ValueError("dynamic inputs unsupported")
    selector = call.args[0].value
    if not isinstance(selector, str):
        raise ValueError("literal resource string required")
    if isinstance(call.func, ast.Name) and call.func.id == "read_text" and len(call.args) == 1:
        class_name, operation = "fs", "read"
    elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        receiver, operation = call.func.value.id, call.func.attr
        if receiver == "records" and operation == "read" and len(call.args) == 1:
            class_name = "db_record"
        elif (receiver == "pump" and operation == "inspect" and len(call.args) == 1) or (
            receiver == "pump"
            and operation == "set_flow"
            and len(call.args) == 2
            and type(call.args[1].value) in {int, float}
        ):
            class_name = "pump"
        else:
            raise ValueError("unsupported literal API")
    else:
        raise ValueError("unknown form")
    return [dict(class_name=class_name, operation=operation, selector=selector, requirement="need")]


if __name__ == "__main__":
    try:
        print(json.dumps({"requirements": produce(sys.stdin.read())}))
    except (SyntaxError, ValueError) as error:
        print(json.dumps({"unsupported": str(error)}))
        sys.exit(2)
