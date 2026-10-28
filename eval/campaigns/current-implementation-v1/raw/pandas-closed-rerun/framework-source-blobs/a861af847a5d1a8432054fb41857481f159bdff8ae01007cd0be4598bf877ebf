"""Source derivations for the closed output validator and its primitives.

The checker accepts a deliberately small statement/expression grammar. Each
accepted operation has a native type/ownership rule; every statement in each
proved helper is consumed. Helper names and source digests are not certificates.
The recursive walker is derived by induction on the remaining depth, then the
public request validator; initialization and runtime binding stay premises.
"""

from __future__ import annotations

import ast
import hashlib
import symtable
from pathlib import Path

from langgraph.prebuilt.security.output_verification import (
    _module_bindings,
    _native_records,
)
from langgraph.prebuilt.security.output_verification import (
    _Unsupported as _RecordUnsupported,
)

_MODULE = "langgraph.prebuilt.security.output_data"
_OBJECTS = "langgraph.prebuilt.security.objects"
# Builtin exceptions whose instances use only the native BaseException layout.
# Classes with extra native fields (OSError, StopIteration, NameError, groups)
# would carry data outside the args/instance-dictionary projection.
_SIMPLE_ERRORS = frozenset(
    {
        "BaseException",
        "Exception",
        "RuntimeError",
        "ValueError",
        "TypeError",
        "AssertionError",
        "LookupError",
        "IndexError",
        "KeyError",
        "ArithmeticError",
        "ZeroDivisionError",
        "OverflowError",
        "NotImplementedError",
    }
)
_VALIDATOR_PREMISES = (
    "CPython semantics for exact type identity, native scalar/container operations, member/getset descriptors, generators and exception handling.",
    "Initialization and runtime binding: every derived module inventory holds the value of its source initializer, imported names select the named classes, and none is rebound afterwards (initialization_proved and runtime_binding_proved remain false).",
    "Field stability: no other thread mutates the request, its labels or any traversed container during validation. Every traversed object therefore stays referenced by the unchanged request, so dropping the walker's references cannot run a candidate finalizer.",
    "Process-global events are outside this model, as for every contract in this report: cyclic garbage collection of unrelated objects (finalizers, weakref callbacks), signal handlers and asynchronous exceptions can run at allocation or bytecode boundaries.",
    "Refusal tracebacks are not sanitized: literal refusal arguments carry no candidate data, but traceback frames reference the candidate (exception_sanitization_proved is false), so callers must not publish them.",
)


class _Unproved(Exception):
    def __init__(self, node, reason):
        self.line = getattr(node, "lineno", 0)
        self.reason = reason
        super().__init__(reason)


def _need(condition, node, reason):
    if not condition:
        raise _Unproved(node, reason)


def _name(node, name):
    return isinstance(node, ast.Name) and node.id == name


def _constant(node, value):
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(value)
        and node.value == value
    )


def _attribute(node, receiver, name):
    return (
        isinstance(node, ast.Attribute)
        and _name(node.value, receiver)
        and node.attr == name
    )


def _body(node):
    return [
        part
        for part in node.body
        if not (
            isinstance(part, ast.Expr)
            and isinstance(part.value, ast.Constant)
            and type(part.value.value) is str
        )
    ]


class _PrimitiveDerivation:
    def __init__(self, source, objects_source):
        self.tree = ast.parse(source)
        self.locals = set()
        scopes = symtable.symtable(source, _MODULE, "exec")
        symtable.symtable(objects_source, _OBJECTS, "exec")
        self.bindings = _module_bindings(self.tree)
        objects = ast.parse(objects_source)
        for tree in (self.tree, objects):
            for node in tree.body:
                _need(
                    not (
                        isinstance(node, ast.ImportFrom)
                        and any(alias.name == "*" for alias in node.names)
                    ),
                    node,
                    "wildcard imports cannot establish exact primitive bindings",
                )
        self.objects = objects
        self.scopes = scopes
        self.records = _native_records(objects, _module_bindings(objects))
        self.inventories = {}
        self.deriving = set()
        self.hypotheses = set()
        _need(
            any(
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                and any(alias.name == "annotations" for alias in node.names)
                for node in self.tree.body
            ),
            self.tree,
            "annotation evaluation is not modeled",
        )
        walkers = [
            node
            for node in self.tree.body
            if isinstance(node, ast.ClassDef) and node.name == "_Walker"
        ]
        _need(len(walkers) == 1, self.tree, "one source walker definition is required")
        walker = walkers[0]
        _need(
            not walker.bases and not walker.keywords and not walker.decorator_list,
            walker,
            "custom walker lookup/construction requires a proof",
        )
        self.methods = {}
        for node in _body(walker):
            _need(
                isinstance(node, ast.FunctionDef)
                and not node.decorator_list
                and node.name not in self.methods,
                node,
                "walker member effects or rebinding are unmodeled",
            )
            _need(
                not node.name.startswith("__") or node.name == "__init__",
                node,
                "custom walker attribute protocol is unmodeled",
            )
            self.methods[node.name] = node
        walker_scope = next(
            scope for scope in scopes.get_children() if scope.get_name() == "_Walker"
        )
        self.compiler_locals = {
            scope.get_name(): {
                symbol.get_name() for symbol in scope.get_symbols() if symbol.is_local()
            }
            for scope in walker_scope.get_children()
        }
        errors = [
            node
            for node in self.tree.body
            if isinstance(node, ast.ClassDef) and node.name == "OutputDataError"
        ]
        _need(len(errors) == 1, self.tree, "one refusal class is required")
        error = errors[0]
        _need(
            len(error.bases) == 1
            and _name(error.bases[0], "PermissionError")
            and not error.keywords
            and not error.decorator_list
            and not _body(error),
            error,
            "refusal class has an unmodeled constructor/protocol",
        )
        self.native("PermissionError", error)
        self.entries = {}
        self.steps = []
        self.locals = set()
        self.descriptor_helper()
        self.locals = set()
        self.slots = self.label_slots()

    def native(self, name, node):
        _need(
            name not in self.bindings and name not in self.locals,
            node,
            "native builtin is rebound: " + name,
        )

    def source_import(self, name, target, node):
        _need(
            name not in self.locals and self.bindings.get(name) == target,
            node,
            "source import does not select " + target,
        )

    def step(self, node, rule, **facts):
        self.steps.append({"line": getattr(node, "lineno", 0), "rule": rule, **facts})

    def function(self, name, positional, keywords=(), defaults=()):
        _need(name in self.methods, self.tree, "missing primitive: " + name)
        function = self.methods[name]
        args = function.args
        _need(
            not args.posonlyargs
            and not args.vararg
            and not args.kwarg
            and len(args.args) == positional
            and len(args.kwonlyargs) == len(keywords),
            function,
            "primitive signature is outside the modeled entry contract",
        )
        names = tuple(arg.arg for arg in args.args)
        all_names = names + tuple(arg.arg for arg in args.kwonlyargs)
        _need(
            len(set(all_names)) == len(all_names)
            and all(
                name
                not in {
                    "type",
                    "len",
                    "tuple",
                    "dict",
                    "str",
                    "set",
                    "frozenset",
                    "sorted",
                    "OutputDataError",
                    "ValueError",
                }
                for name in all_names
            ),
            function,
            "parameter shadows a primitive binding",
        )
        _need(
            len(args.defaults) == len(defaults)
            and all(
                _constant(node, expected)
                for node, expected in zip(args.defaults, defaults)
            ),
            function,
            "default evaluation requires a separate proof",
        )
        for arg, default, expected in zip(args.kwonlyargs, args.kw_defaults, keywords):
            _need(
                _constant(default, expected),
                function,
                "keyword default is not the modeled native boolean",
            )
            _need(arg.arg not in names, function, "keyword parameter rebinding")
        self.steps = []
        self.locals = (
            self.compiler_locals.get(name, set())
            | set(all_names)
            | {
                node.id
                for node in ast.walk(function)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            }
        )
        self.receiver = names[0]
        return (
            function,
            names,
            tuple(arg.arg for arg in args.kwonlyargs),
            _body(function),
        )

    def call(self, node, function, args, *, receiver=None, keywords=()):
        _need(isinstance(node, ast.Call), node, "expected a modeled native call")
        target = (
            _name(node.func, function)
            if receiver is None
            else _attribute(node.func, receiver, function)
        )
        _need(
            target
            and len(node.args) == len(args)
            and len(node.keywords) == len(keywords),
            node,
            "call target/arity is not modeled",
        )
        if receiver is None:
            self.native(function, node)
        for actual, check in zip(node.args, args):
            _need(
                check(actual),
                actual,
                "native call operand does not have the derived type/origin",
            )
        owned_callee = receiver is not None and receiver == getattr(
            self, "receiver", None
        )
        expected_keywords = keywords
        if owned_callee and keywords and function in self.methods:
            parameters = self.methods[function].args.kwonlyargs
            _need(
                len(parameters) == len(keywords),
                node,
                "callee keyword roles do not match the derived primitive contract",
            )
            expected_keywords = tuple(
                (parameter.arg, expected[1])
                for parameter, expected in zip(parameters, keywords)
            )
        for actual, (name, value) in zip(node.keywords, expected_keywords):
            _need(
                actual.arg == name and _constant(actual.value, value),
                actual,
                "keyword input is not a literal native value",
            )
        if owned_callee:
            _need(
                function in self.methods,
                node,
                "receiver method lacks a source definition",
            )
            signature = self.methods[function].args
            _need(
                not signature.posonlyargs
                and not signature.vararg
                and not signature.kwarg
                and signature.args,
                node,
                "source callee binding is outside the finite call grammar",
            )
            positional = [argument.arg for argument in signature.args[1:]]
            keyword_only = [argument.arg for argument in signature.kwonlyargs]
            _need(
                len(node.args) <= len(positional),
                node,
                "source callee cannot bind the supplied positional arguments",
            )
            supplied = set(positional[: len(node.args)])
            for keyword in node.keywords:
                _need(
                    keyword.arg in positional + keyword_only
                    and keyword.arg not in supplied,
                    keyword,
                    "source callee cannot bind the supplied keyword argument",
                )
                supplied.add(keyword.arg)
            required = positional[: len(positional) - len(signature.defaults)]
            required += [
                argument.arg
                for argument, default in zip(
                    signature.kwonlyargs, signature.kw_defaults
                )
                if default is None
            ]
            _need(
                set(required) <= supplied,
                node,
                "source callee has an unsupplied required argument",
            )
            self.step(
                node,
                "source-call-signature-binding",
                callee=function,
                supplied=sorted(supplied),
            )

    def refusal(self, body):
        _need(
            len(body) == 1 and isinstance(body[0], ast.Raise),
            body[0] if body else self.tree,
            "guard must terminate only by a literal refusal",
        )
        node = body[0]
        _need(
            node.cause is None
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id in {"OutputDataError", "ValueError"}
            and len(node.exc.args) == 1
            and not node.exc.keywords
            and isinstance(node.exc.args[0], ast.Constant)
            and type(node.exc.args[0].value) is str,
            node,
            "refusal can invoke a protocol or expose candidate data",
        )
        if node.exc.func.id == "ValueError":
            self.native("ValueError", node)
        else:
            _need(
                "OutputDataError" not in self.locals
                and self.bindings.get("OutputDataError") == "source:OutputDataError",
                node,
                "refusal class is shadowed in the lexical scope",
            )
        self.step(
            node,
            "literal-native-refusal",
            exception=node.exc.func.id,
            exception_sanitization_proved=False,
            scope="native constructor and literal message only; traceback/context publication is not proved",
        )

    def guard(self, node):
        _need(
            isinstance(node, ast.If) and not node.orelse,
            node,
            "guard control flow is unmodeled",
        )
        self.refusal(node.body)
        return node.test

    def exact_guard(self, node, value, expected, *, native=True):
        test = self.guard(node)
        _need(
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.IsNot)
            and _name(test.comparators[0], expected),
            node,
            "guard does not establish exact native identity",
        )
        self.call(test.left, "type", (lambda node: _name(node, value),))
        if native:
            self.native(expected, node)
        self.step(node, "exact-type-after-refusal", value=value, exact_type=expected)

    def bound_guard(self, node, value, receiver):
        test = self.guard(node)
        _need(
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Gt)
            and _attribute(test.comparators[0], receiver, "nodes"),
            test,
            "snapshot allocation lacks the owned node-budget bound",
        )
        self.call(test.left, "len", (lambda node: _name(node, value),))
        self.step(node, "native-length-bounded-before-snapshot", value=value)

    def finish(self, name, function, result, witness, premises=()):
        entry = {
            "entry": _MODULE + "._Walker." + name,
            "proved": True,
            "scope": "primitive contract under the listed typed ownership premises",
            "result": result,
            "useful_path": witness,
            "entry_premises": list(premises),
            "derivation": list(self.steps),
            "source_lines": [function.lineno, function.end_lineno],
            "all_body_statements_consumed": True,
        }
        self.entries[name] = entry
        return entry

    def dependency(self, name, node):
        _need(
            name in self.entries and self.entries[name]["proved"],
            node,
            "callee primitive has no source-derived contract: " + name,
        )
        self.step(node, "source-derived-callee-contract", callee=name)

    def label_slots(self):
        self.source_import("SecurityLabels", _OBJECTS + ".SecurityLabels", self.tree)
        values = [
            node.value
            for node in self.tree.body
            if isinstance(node, ast.Assign)
            and any(_name(target, "_LABEL_SLOTS") for target in node.targets)
        ]
        _need(
            len(values) == 1, self.tree, "native label descriptor inventory is missing"
        )
        call = values[0]
        self.call(call, "tuple", (lambda node: isinstance(node, ast.GeneratorExp),))
        generator = call.args[0]
        _need(
            len(generator.generators) == 1,
            generator,
            "descriptor inventory is not finite",
        )
        loop = generator.generators[0]
        _need(
            isinstance(loop.target, ast.Name)
            and loop.target.id != "SecurityLabels"
            and not loop.ifs
            and not loop.is_async
            and isinstance(loop.iter, ast.Tuple),
            loop,
            "descriptor inventory has unmodeled evaluation or captures its class receiver",
        )
        names = []
        for node in loop.iter.elts:
            _need(
                isinstance(node, ast.Constant)
                and type(node.value) is str
                and node.value in self.records["SecurityLabels"],
                node,
                "descriptor is not a declared native record slot",
            )
            names.append(node.value)
        element = generator.elt
        owner, _ = self.class_storage(element, loop.target.id)
        _need(
            owner == _OBJECTS + ".SecurityLabels",
            element,
            "label descriptor capture changes its class",
        )
        _need(
            names == ["confidentiality", "integrity"],
            generator,
            "label descriptor order does not bind the intended fields",
        )
        return names

    def constructor(self):
        function, names, _, body = self.function("__init__", 4)
        receiver, *budgets = names
        _need(
            len(body) == 8 and isinstance(body[0], ast.For),
            function,
            "owned storage initialization has unmodeled statements",
        )
        loop = body[0]
        _need(
            isinstance(loop.target, ast.Name)
            and loop.target.id not in names
            and isinstance(loop.iter, ast.Tuple)
            and len(loop.iter.elts) == 3
            and all(_name(node, name) for node, name in zip(loop.iter.elts, budgets))
            and not loop.orelse
            and len(loop.body) == 1,
            loop,
            "budget loop must cover exactly the three unchanged constructor inputs",
        )
        test = self.guard(loop.body[0])
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 2,
            test,
            "budget checks are not short-circuit native type/positivity guards",
        )
        exact, positive = test.values
        _need(
            isinstance(exact, ast.Compare)
            and len(exact.ops) == 1
            and isinstance(exact.ops[0], ast.IsNot)
            and _name(exact.comparators[0], "int"),
            exact,
            "budget integer identity is unproved",
        )
        self.native("int", exact)
        self.call(exact.left, "type", (lambda node: _name(node, loop.target.id),))
        _need(
            isinstance(positive, ast.Compare)
            and _name(positive.left, loop.target.id)
            and len(positive.ops) == 1
            and isinstance(positive.ops[0], ast.LtE)
            and _constant(positive.comparators[0], 0),
            positive,
            "budget positivity is unproved",
        )
        self.step(
            loop,
            "finite-tuple-loop",
            cases=3,
            invariant="each constructor budget is an exact positive native integer before storage",
        )
        specifications = (
            ("depth", budgets[0]),
            ("nodes", budgets[1]),
            ("bytes", budgets[2]),
            ("active", "set"),
            ("confidentiality", "set"),
            ("low_integrity", False),
            ("channels", "dict"),
        )
        for node, (attribute, expected) in zip(body[1:], specifications):
            target = (
                node.target
                if isinstance(node, ast.AnnAssign)
                else node.targets[0]
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                else None
            )
            _need(
                _attribute(target, receiver, attribute),
                node,
                "initialization writes outside the derived owned fields",
            )
            value = node.value
            if attribute in {"depth", "nodes", "bytes"}:
                _need(
                    _name(value, expected),
                    value,
                    "budget field has a different input origin",
                )
            elif expected == "set":
                self.call(value, "set", ())
            elif expected == "dict":
                _need(
                    isinstance(value, ast.Dict) and not value.keys,
                    value,
                    "channel storage is not a fresh native dictionary",
                )
            else:
                _need(
                    _constant(value, expected),
                    value,
                    "integrity state is not a native boolean",
                )
            self.step(node, "fresh-owned-field", field=attribute)
        return self.finish(
            "__init__",
            function,
            "owned native integer budgets, empty native sets/dictionary and boolean integrity",
            {"budgets": [64, 100000, 16777216]},
            (
                "fresh exact _Walker receiver; native object attribute storage; source method bindings are stable",
            ),
        )

    def charge(self):
        function, (receiver, amount), _, body = self.function(
            "charge", 2, defaults=(0,)
        )
        self.dependency("__init__", function)
        _need(len(body) == 3, function, "charge contains unmodeled statements")
        for node, attribute, check in (
            (body[0], "nodes", lambda node: _constant(node, 1)),
            (body[1], "bytes", lambda node: _name(node, amount)),
        ):
            _need(
                isinstance(node, ast.AugAssign)
                and isinstance(node.op, ast.Sub)
                and _attribute(node.target, receiver, attribute)
                and check(node.value),
                node,
                "charge must use owned native integer subtraction",
            )
            self.step(node, "owned-native-integer-write", field=attribute)
        test = self.guard(body[2])
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 2,
            test,
            "charge lacks both exhaustion refusals",
        )
        for comparison, attribute in zip(test.values, ("nodes", "bytes")):
            _need(
                isinstance(comparison, ast.Compare)
                and len(comparison.ops) == 1
                and isinstance(comparison.ops[0], ast.Lt)
                and _attribute(comparison.left, receiver, attribute)
                and _constant(comparison.comparators[0], 0),
                comparison,
                "budget exhaustion guard does not match updated owned storage",
            )
        return self.finish(
            "charge",
            function,
            "native owned state preserved; a normal return has nonnegative remaining budgets",
            {"initial_nodes": 2, "initial_bytes": 8, "amount": 4},
            ("constructor-owned state; amount is an exact nonnegative native integer",),
        )

    def string(self):
        function, (receiver, value), (nonempty,), body = self.function(
            "string", 2, (False,)
        )
        _need(
            len(body) == 3, function, "string validator contains unmodeled statements"
        )
        test = self.guard(body[0])
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 2,
            test,
            "string guard must short-circuit before candidate truth conversion",
        )
        exact, empty = test.values
        _need(
            isinstance(exact, ast.Compare)
            and len(exact.ops) == 1
            and isinstance(exact.ops[0], ast.IsNot)
            and _name(exact.comparators[0], "str"),
            exact,
            "string type guard is not exact identity",
        )
        self.native("str", exact)
        self.call(exact.left, "type", (lambda node: _name(node, value),))
        _need(
            isinstance(empty, ast.BoolOp)
            and isinstance(empty.op, ast.And)
            and len(empty.values) == 2
            and _name(empty.values[0], nonempty)
            and isinstance(empty.values[1], ast.UnaryOp)
            and isinstance(empty.values[1].op, ast.Not)
            and _name(empty.values[1].operand, value),
            empty,
            "emptiness check has an unmodeled operand/protocol",
        )
        self.step(
            body[0],
            "short-circuit-exact-string",
            postcondition="candidate truth is evaluated only after exact str identity",
        )
        _need(isinstance(body[1], ast.Expr), body[1], "string budget call is unmodeled")
        call = body[1].value
        self.call(
            call,
            "charge",
            (
                lambda node: (
                    isinstance(node, ast.BinOp)
                    and isinstance(node.op, ast.Mult)
                    and _constant(node.left, 4)
                ),
            ),
            receiver=receiver,
        )
        self.call(call.args[0].right, "len", (lambda node: _name(node, value),))
        self.dependency("charge", call)
        _need(
            isinstance(body[2], ast.Return) and _name(body[2].value, value),
            body[2],
            "string result is not the checked input",
        )
        return self.finish(
            "string",
            function,
            "the identical exact native string; nonempty when requested; no candidate protocol invoked",
            {"value": "x", "nonempty": [False, True]},
            ("constructor-owned state with sufficient budget; nonempty is exact bool",),
        )

    def pairs(self):
        function, (receiver, value), _, body = self.function("pairs", 2)
        self.dependency("__init__", function)
        _need(
            len(body) == 5,
            function,
            "dictionary primitive contains unmodeled statements",
        )
        self.exact_guard(body[0], value, "dict")
        self.bound_guard(body[1], value, receiver)
        assignment = body[2]
        _need(
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Name),
            assignment,
            "snapshot must have one local owner",
        )
        snapshot = assignment.targets[0].id
        _need(
            snapshot not in {receiver, value},
            assignment,
            "snapshot local shadows its receiver/input",
        )
        self.call(assignment.value, "tuple", (lambda node: isinstance(node, ast.Call),))
        self.call(
            assignment.value.args[0],
            "items",
            (lambda node: _name(node, value),),
            receiver="dict",
        )
        self.native("dict", assignment)
        self.step(
            assignment,
            "native-item-snapshot",
            invariant="native tuple of native key/value pairs; no hashing/equality/conversion of candidate keys",
        )
        loop = body[3]
        _need(
            isinstance(loop, ast.For)
            and not loop.orelse
            and _name(loop.iter, snapshot)
            and isinstance(loop.target, ast.Tuple)
            and len(loop.target.elts) == 2
            and all(isinstance(node, ast.Name) for node in loop.target.elts)
            and len(loop.body) == 1,
            loop,
            "snapshot validation loop is not a complete native pair induction",
        )
        loop_names = tuple(node.id for node in loop.target.elts)
        _need(
            len(set(loop_names)) == 2
            and not set(loop_names).intersection({receiver, value, snapshot}),
            loop,
            "pair induction overwrites a live binding or its own key",
        )
        self.exact_guard(loop.body[0], loop.target.elts[0].id, "str")
        self.step(
            loop,
            "all-pairs-induction",
            base="empty snapshot requires no validation",
            step="the unchanged next pair's key must be exact str or execution refuses",
            conclusion="every returned snapshot key is exact str, including a nonempty snapshot",
        )
        _need(
            isinstance(body[4], ast.Return) and _name(body[4].value, snapshot),
            body[4],
            "dictionary primitive returns a different or unvalidated object",
        )
        return self.finish(
            "pairs",
            function,
            "native tuple snapshot of pairs with exact string keys; values remain opaque; original mutable dictionary is not certified stable",
            {"value": {"key": "opaque inert witness"}},
            (
                "constructor-owned native integer budget; native dict.items/tuple semantics",
            ),
        )

    def string_set(self):
        function, (receiver, value), (mutable,), body = self.function(
            "string_set", 2, (False,)
        )
        _need(
            len(body) == 6,
            function,
            "string-set primitive contains unmodeled statements",
        )
        assignment = body[0]
        _need(
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Name)
            and isinstance(assignment.value, ast.IfExp)
            and _name(assignment.value.test, mutable)
            and _name(assignment.value.body, "set")
            and _name(assignment.value.orelse, "frozenset"),
            assignment,
            "container kind is not selected by a native boolean",
        )
        expected = assignment.targets[0].id
        _need(
            expected not in {receiver, value, mutable},
            assignment,
            "container-kind local shadows an entry binding",
        )
        self.native("set", assignment)
        self.native("frozenset", assignment)
        self.exact_guard(body[1], value, expected, native=False)
        self.bound_guard(body[2], value, receiver)
        snapshot_node = body[3]
        _need(
            isinstance(snapshot_node, ast.Assign)
            and len(snapshot_node.targets) == 1
            and isinstance(snapshot_node.targets[0], ast.Name),
            snapshot_node,
            "set snapshot ownership is unmodeled",
        )
        snapshot = snapshot_node.targets[0].id
        _need(
            snapshot not in {receiver, value, mutable, expected},
            snapshot_node,
            "set snapshot shadows a live binding",
        )
        self.call(snapshot_node.value, "tuple", (lambda node: _name(node, value),))
        loop = body[4]
        _need(
            isinstance(loop, ast.For)
            and isinstance(loop.target, ast.Name)
            and _name(loop.iter, snapshot)
            and not loop.orelse
            and len(loop.body) == 1
            and isinstance(loop.body[0], ast.Expr),
            loop,
            "set validation requires a complete finite snapshot induction",
        )
        _need(
            loop.target.id not in {receiver, value, mutable, expected, snapshot},
            loop,
            "element induction overwrites a live binding",
        )
        self.call(
            loop.body[0].value,
            "string",
            (lambda node: _name(node, loop.target.id),),
            receiver=receiver,
            keywords=(("nonempty", True),),
        )
        self.dependency("string", loop)
        self.step(
            loop,
            "all-elements-induction",
            base="empty native snapshot",
            step="each unchanged element passes the exact nonempty string contract",
            conclusion="sorting compares only native strings",
        )
        _need(
            isinstance(body[5], ast.Return), body[5], "string-set result is unmodeled"
        )
        self.call(body[5].value, "sorted", (lambda node: _name(node, snapshot),))
        return self.finish(
            "string_set",
            function,
            "fresh sorted native list of exact nonempty strings, equal to the validated native set snapshot",
            {"value": ["secret"], "mutable": [False, True]},
            (
                "constructor-owned state; mutable is exact bool; native set/frozenset iteration does not hash/compare elements",
            ),
        )

    def labels(self):
        function, (receiver, value), (collect,), body = self.function(
            "labels", 2, (True,)
        )
        self.source_import("SecurityLabels", _OBJECTS + ".SecurityLabels", function)
        _need(
            "_LABEL_SLOTS" not in self.locals,
            function,
            "label descriptor inventory is shadowed in the lexical scope",
        )
        _need(len(body) == 6, function, "label primitive contains unmodeled statements")
        self.exact_guard(body[0], value, "SecurityLabels", native=False)
        assignment = body[1]
        _need(
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Tuple)
            and len(assignment.targets[0].elts) == 2
            and all(isinstance(node, ast.Name) for node in assignment.targets[0].elts)
            and isinstance(assignment.value, ast.GeneratorExp),
            assignment,
            "label slot projection is unmodeled",
        )
        confidentiality, integrity = (node.id for node in assignment.targets[0].elts)
        _need(
            confidentiality != integrity
            and not {confidentiality, integrity}.intersection(
                {receiver, value, collect}
            ),
            assignment,
            "label field locals alias a live binding",
        )
        generator = assignment.value
        _need(
            len(generator.generators) == 1,
            generator,
            "descriptor traversal must use the finite inventory",
        )
        loop = generator.generators[0]
        _need(
            isinstance(loop.target, ast.Name)
            and _name(loop.iter, "_LABEL_SLOTS")
            and not loop.ifs
            and not loop.is_async,
            loop,
            "descriptor traversal does not select the checked inventory",
        )
        _need(
            loop.target.id
            not in {
                receiver,
                value,
                collect,
                confidentiality,
                integrity,
                "SecurityLabels",
                "_LABEL_SLOTS",
            },
            loop,
            "descriptor comprehension captures a live receiver or field binding",
        )
        self.call(
            generator.elt,
            "__get__",
            (lambda node: _name(node, value),),
            receiver=loop.target.id,
        )
        self.step(
            assignment,
            "native-slot-projection",
            fields=self.slots,
            receiver_exact="SecurityLabels",
        )
        compartments_node = body[2]
        _need(
            isinstance(compartments_node, ast.Assign)
            and len(compartments_node.targets) == 1
            and isinstance(compartments_node.targets[0], ast.Name),
            compartments_node,
            "compartment snapshot ownership is unmodeled",
        )
        compartments = compartments_node.targets[0].id
        _need(
            compartments not in {receiver, value, collect, confidentiality, integrity},
            compartments_node,
            "label snapshot overwrites a live binding",
        )
        self.call(
            compartments_node.value,
            "string_set",
            (lambda node: _name(node, confidentiality),),
            receiver=receiver,
        )
        self.dependency("string_set", compartments_node)
        _need(
            isinstance(body[3], ast.Expr), body[3], "integrity validation is unmodeled"
        )
        self.call(
            body[3].value,
            "string",
            (lambda node: _name(node, integrity),),
            receiver=receiver,
            keywords=(("nonempty", True),),
        )
        self.dependency("string", body[3])
        conditional = body[4]
        _need(
            isinstance(conditional, ast.If)
            and _name(conditional.test, collect)
            and not conditional.orelse
            and len(conditional.body) == 2,
            conditional,
            "label collection has unmodeled control flow",
        )
        update, low = conditional.body
        _need(
            isinstance(update, ast.Expr)
            and isinstance(update.value, ast.Call)
            and isinstance(update.value.func, ast.Attribute)
            and _attribute(update.value.func.value, receiver, "confidentiality")
            and update.value.func.attr == "update"
            and len(update.value.args) == 1
            and _name(update.value.args[0], compartments)
            and not update.value.keywords,
            update,
            "collection target is not the owned native confidentiality set",
        )
        _need(
            isinstance(low, ast.AugAssign)
            and isinstance(low.op, ast.BitOr)
            and _attribute(low.target, receiver, "low_integrity")
            and isinstance(low.value, ast.Compare)
            and len(low.value.ops) == 1
            and isinstance(low.value.ops[0], ast.NotEq)
            and _name(low.value.left, integrity)
            and _constant(low.value.comparators[0], "trusted"),
            low,
            "integrity collection is not a native boolean join",
        )
        self.step(
            conditional,
            "owned-label-join",
            inserted="only validated native strings",
            integrity="native bool OR native string comparison",
        )
        result = body[5]
        _need(
            isinstance(result, ast.Return)
            and isinstance(result.value, ast.List)
            and len(result.value.elts) == 3
            and _constant(result.value.elts[0], "SecurityLabels")
            and _name(result.value.elts[1], compartments)
            and _name(result.value.elts[2], integrity),
            result,
            "label result does not correspond to checked field origins",
        )
        return self.finish(
            "labels",
            function,
            "captured confidentiality projection is an exact native frozenset of nonempty strings and captured integrity projection is an exact nonempty str; the returned data and optional owned joins use those validated projections, without certifying later field values",
            {
                "confidentiality": ["secret"],
                "integrity": "trusted",
                "collect": [False, True],
            },
            (
                "constructor-owned state; collect is exact bool; captured descriptors are the source-selected immutable native dataclass slot descriptors",
                "original SecurityLabels fields may remain valid only under a separate field-stability premise; this primitive certifies its captured projections",
            ),
        )

    def channel_labels(self):
        function, (receiver, value), _, body = self.function("channel_labels", 2)
        _need(
            len(body) == 1 and isinstance(body[0], ast.For),
            function,
            "channel table construction contains unmodeled statements",
        )
        loop = body[0]
        _need(
            isinstance(loop.target, ast.Tuple)
            and len(loop.target.elts) == 2
            and all(isinstance(node, ast.Name) for node in loop.target.elts)
            and not loop.orelse
            and len(loop.body) == 3,
            loop,
            "channel table requires a complete native pair induction",
        )
        key, labels = (node.id for node in loop.target.elts)
        _need(
            key != labels and not {key, labels}.intersection({receiver, value}),
            loop,
            "channel pair locals overwrite live entry bindings",
        )
        self.call(
            loop.iter, "pairs", (lambda node: _name(node, value),), receiver=receiver
        )
        self.dependency("pairs", loop)
        validate_key, project, store = loop.body
        _need(
            isinstance(validate_key, ast.Expr),
            validate_key,
            "channel key validation is unmodeled",
        )
        self.call(
            validate_key.value,
            "string",
            (lambda node: _name(node, key),),
            receiver=receiver,
            keywords=(("nonempty", True),),
        )
        self.dependency("string", validate_key)
        _need(
            isinstance(project, ast.Assign)
            and len(project.targets) == 1
            and isinstance(project.targets[0], ast.Tuple)
            and len(project.targets[0].elts) == 3
            and all(isinstance(node, ast.Name) for node in project.targets[0].elts),
            project,
            "channel label projection must unpack the checked native triple",
        )
        tag, compartments, integrity = (node.id for node in project.targets[0].elts)
        _need(
            len({tag, compartments, integrity}) == 3
            and not {tag, compartments, integrity}.intersection(
                {receiver, value, key, labels}
            ),
            project,
            "channel label projection aliases live bindings",
        )
        self.call(
            project.value,
            "labels",
            (lambda node: _name(node, labels),),
            receiver=receiver,
            keywords=(("collect", False),),
        )
        self.dependency("labels", project)
        _need(
            isinstance(store, ast.Assign)
            and len(store.targets) == 1
            and isinstance(store.targets[0], ast.Subscript)
            and _attribute(store.targets[0].value, receiver, "channels")
            and _name(store.targets[0].slice, key)
            and isinstance(store.value, ast.Tuple)
            and len(store.value.elts) == 2
            and _name(store.value.elts[0], compartments)
            and _name(store.value.elts[1], integrity),
            store,
            "channel write does not target owned native storage with validated keys/data",
        )
        self.step(
            loop,
            "owned-channel-map-induction",
            base="empty pair snapshot leaves owned state unchanged",
            step="one native string key stores only the checked string-list/integrity projection",
            conclusion="every inserted key/value is native and no candidate key is hashed before validation",
        )
        return self.finish(
            "channel_labels",
            function,
            "owned channel dictionary contains only exact string keys and checked label projections; no value equality or caller callback is used",
            {
                "value": {
                    "channel": {"confidentiality": ["secret"], "integrity": "trusted"}
                }
            },
            ("constructor-owned state with sufficient budget",),
        )

    def scalar_walk(self):
        """Derive only scalar-return paths; keep the recursive suffix unresolved."""
        function, (receiver, value, depth), _, body = self.function(
            "walk", 3, defaults=(0,)
        )
        # These alter compilation/lookup of earlier statements even when the
        # source occurrence lies after every selected scalar return.
        for node in ast.walk(function):
            _need(
                not isinstance(
                    node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom)
                ),
                node,
                "unproved suffix changes scalar-prefix lexical or generator semantics",
            )
        _need(len(body) >= 9, function, "scalar classification prefix is incomplete")
        self.dependency("__init__", function)
        test = self.guard(body[0])
        _need(
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Gt)
            and _name(test.left, depth)
            and _attribute(test.comparators[0], receiver, "depth"),
            test,
            "scalar depth check does not use the owned native bound",
        )
        self.step(body[0], "native-depth-guard", depth_input="exact nonnegative int")
        classifier = body[1]
        _need(
            isinstance(classifier, ast.Assign)
            and len(classifier.targets) == 1
            and isinstance(classifier.targets[0], ast.Name),
            classifier,
            "scalar classifier is not one local native type query",
        )
        kind = classifier.targets[0].id
        _need(
            kind not in {receiver, value, depth},
            classifier,
            "scalar classifier overwrites a live input",
        )
        self.call(classifier.value, "type", (lambda node: _name(node, value),))
        self.step(classifier, "native-classifier", origin=value, local=kind)
        _need(
            isinstance(body[2], ast.Expr), body[2], "scalar entry charge is unmodeled"
        )
        self.call(body[2].value, "charge", (), receiver=receiver)
        self.dependency("charge", body[2])
        common = list(self.steps)
        cases = []

        def branch(node, expected, statement_count):
            _need(
                isinstance(node, ast.If)
                and not node.orelse
                and len(node.body) == statement_count,
                node,
                "scalar branch has unmodeled control flow or effects",
            )
            predicate = node.test
            _need(
                isinstance(predicate, ast.Compare)
                and len(predicate.ops) == 1
                and isinstance(predicate.ops[0], ast.Is),
                predicate,
                "scalar branch must select by native identity, not equality/protocol",
            )
            if expected is None:
                _need(
                    _name(predicate.left, value)
                    and _constant(predicate.comparators[0], None),
                    predicate,
                    "None branch selects a different input",
                )
            else:
                self.native(expected, predicate)
                _need(
                    _name(predicate.left, kind)
                    and _name(predicate.comparators[0], expected),
                    predicate,
                    "scalar branch is not dominated by the exact input classifier",
                )
            self.step(
                node,
                "exact-scalar-branch",
                input_type="NoneType" if expected is None else expected,
            )

        def result(node, tag, payload=True):
            _need(
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.List)
                and len(node.value.elts) == (2 if payload else 1)
                and _constant(node.value.elts[0], tag),
                node,
                "scalar return is not the corresponding native tagged projection",
            )
            self.step(node, "native-tagged-return", tag=tag)
            return node.value.elts[1] if payload else None

        def finish_case(node, exact_type, witness, extra_premises=()):
            cases.append(
                {
                    "input_type": exact_type,
                    "proved": True,
                    "all_selected_path_statements_consumed": True,
                    "useful_path": witness,
                    "native_premises": list(extra_premises),
                    "source_lines": [node.lineno, node.end_lineno],
                    "derivation": common + self.steps,
                }
            )

        self.steps = []
        branch(body[3], None, 1)
        result(body[3].body[0], "none", payload=False)
        finish_case(body[3], "NoneType", {"value": None, "projection": ["none"]})

        self.steps = []
        branch(body[4], "str", 1)
        payload = result(body[4].body[0], "str")
        self.call(
            payload, "string", (lambda node: _name(node, value),), receiver=receiver
        )
        self.dependency("string", payload)
        finish_case(body[4], "str", {"value": "text", "projection": ["str", "text"]})

        self.steps = []
        branch(body[5], "bool", 1)
        payload = result(body[5].body[0], "bool")
        _need(
            _name(payload, value), payload, "boolean projection changes input identity"
        )
        finish_case(body[5], "bool", {"value": True, "projection": ["bool", True]})

        self.steps = []
        branch(body[6], "int", 2)
        charge, returned = body[6].body
        _need(
            isinstance(charge, ast.Expr),
            charge,
            "integer byte-budget charge is unmodeled",
        )
        self.call(
            charge.value,
            "charge",
            (
                lambda node: (
                    isinstance(node, ast.BinOp)
                    and isinstance(node.op, ast.FloorDiv)
                    and _constant(node.right, 8)
                ),
            ),
            receiver=receiver,
        )
        addition = charge.value.args[0].left
        _need(
            isinstance(addition, ast.BinOp)
            and isinstance(addition.op, ast.Add)
            and _constant(addition.right, 7),
            addition,
            "integer storage bound is not the native byte ceiling",
        )
        self.call(
            addition.left,
            "bit_length",
            (lambda node: _name(node, value),),
            receiver="int",
        )
        self.native("int", addition)
        self.dependency("charge", charge)
        self.step(
            charge,
            "nonnegative-native-storage-charge",
            bound="ceil(int.bit_length(value)/8)",
        )
        payload = result(returned, "int")
        self.call(payload, "hex", (lambda node: _name(node, value),))
        self.step(
            payload,
            "native-integer-encoding",
            exact_receiver="int",
            excludes="candidate __index__ or conversion dispatch",
        )
        finish_case(
            body[6],
            "int",
            {"value": 42, "projection": ["int", "0x2a"]},
            (
                "native int.bit_length returns a nonnegative integer; native hex on exact int returns str",
            ),
        )

        self.steps = []
        branch(body[7], "float", 2)
        finite, returned = body[7].body
        predicate = self.guard(finite)
        _need(
            isinstance(predicate, ast.UnaryOp) and isinstance(predicate.op, ast.Not),
            predicate,
            "non-finite native floats must be refused",
        )
        self.source_import("math", "math", predicate)
        self.call(
            predicate.operand,
            "isfinite",
            (lambda node: _name(node, value),),
            receiver="math",
        )
        self.step(finite, "native-finite-float-guard", input_exact="float")
        payload = result(returned, "float")
        self.call(payload, "hex", (lambda node: _name(node, value),), receiver="float")
        self.native("float", payload)
        finish_case(
            body[7],
            "finite float",
            {"value": 1.25, "projection": ["float", "0x1.4000000000000p+0"]},
            (
                "source-selected native math.isfinite and float.hex on exact float have no candidate conversion protocol",
            ),
        )

        self.steps = []
        branch(body[8], "bytes", 2)
        charge, returned = body[8].body
        _need(isinstance(charge, ast.Expr), charge, "bytes storage charge is unmodeled")
        self.call(
            charge.value,
            "charge",
            (lambda node: isinstance(node, ast.Call),),
            receiver=receiver,
        )
        self.call(charge.value.args[0], "len", (lambda node: _name(node, value),))
        self.dependency("charge", charge)
        payload = result(returned, "bytes")
        self.call(payload, "hex", (lambda node: _name(node, value),), receiver="bytes")
        self.native("bytes", payload)
        finish_case(
            body[8],
            "bytes",
            {"input_hex": "64617461", "projection": ["bytes", "64617461"]},
            (
                "native len and bytes.hex on exact bytes have no candidate conversion protocol",
            ),
        )

        return {
            "entry": _MODULE + "._Walker.walk",
            "scope": "the six exact scalar return cases only",
            "scalar_cases_complete": True,
            "whole_method_proved": False,
            "entry_premises": [
                "constructor-owned native state and source-stable receiver method/builtin/import bindings",
                "depth is an exact nonnegative native integer; useful paths use depth zero and sufficient node/byte budgets",
                "input is one of the six exact native scalar types for the selected case; subclass and other-object paths are not certified",
            ],
            "result": "each selected normal return is the source-selected native tagged projection of its input; only owned budget fields can change and no candidate object protocol is invoked on these paths",
            "cases": cases,
            "unproved_suffix": {
                "source_lines": [body[9].lineno, body[-1].end_lineno]
                if len(body) > 9
                else [],
                "statement_kinds": [type(node).__name__ for node in body[9:]],
                "proved": False,
                "obligation": "all other input types, active-identity lifetime, compound dispatch and recursive field/container traversal remain required",
            },
        }

    # The recursive validator. fields/record/compound are derived under the
    # hypothesis that walk at depth + 1 meets its contract; walk closes the
    # induction with its depth guard and constructor-owned bound.

    def validator(self, scalar):
        """Derive the recursive group by induction, then the public wrappers."""
        # Source-level rebinding of validator globals is excluded, not assumed.
        issues = [
            {
                "component": "module",
                "line": node.lineno,
                "reason": "module code can rebind validator globals",
            }
            for node in ast.walk(self.tree)
            if isinstance(node, (ast.Global, ast.Nonlocal))
        ]
        self.layouts = []
        self.hypotheses = {"walk"}
        for component, derive in (
            ("fields", self.fields),
            ("record", self.record),
            ("compound", self.compound),
            ("walk", lambda: self.walk(scalar)),
            ("_validate_output_request", self.request_validator),
            ("validate_output_request", self.public_validator),
        ):
            try:
                derive()
            except _Unproved as exc:
                issues.append(
                    {"component": component, "line": exc.line, "reason": exc.reason}
                )
            if component == "walk":
                self.hypotheses = set()
                if "walk" not in self.entries:
                    # Contracts derived under an unclosed induction are not proofs.
                    for name in ("record", "compound"):
                        self.entries.pop(name, None)
        return issues

    def contract(self):
        return {
            "entry": _MODULE + ".validate_output_request",
            "proved": True,
            "scope": "admission and effect safety of the actual recursive output validator under the listed premises",
            "admission": "a normal return implies an exact OutputRequest with exact nonempty destination/output_id strings, exact SecurityLabels, an exact frozenset clearance of nonempty strings, content inside the admitted bounded projection, and nested labels within the declared labels",
            "effects": "only the fields of a fresh local walker change; no candidate object protocol, request write, import, I/O or other external effect occurs on any path",
            "refusals": "literal OutputDataError codes or propagated native exceptions; refusal arguments contain no candidate data",
            "components": [
                self.entries[name]["entry"]
                for name in (
                    "fields",
                    "record",
                    "compound",
                    "walk",
                    "_validate_output_request",
                    "validate_output_request",
                )
            ],
            "inventories": {
                name: {
                    "shape": model[0],
                    "size": len(model[1])
                    if model[0] in {"records", "slot-records", "errors", "names"}
                    else len(model[2])
                    if model[0] == "slots"
                    else 1,
                }
                for name, model in sorted(self.inventories.items())
            },
            "entry_premises": list(_VALIDATOR_PREMISES),
            "external_layout_premises": sorted(set(self.layouts)),
            "exception_sanitization_proved": False,
        }

    def inventory(self, name, shape, node):
        _need(
            name not in self.locals,
            node,
            "module inventory is shadowed in the lexical scope: " + name,
        )
        if name not in self.inventories:
            _need(name not in self.deriving, node, "cyclic module inventory: " + name)
            saved = self.locals
            self.locals = set()
            self.deriving.add(name)
            try:
                self.inventories[name] = self.module_inventory(name, node)
            finally:
                self.deriving.discard(name)
                self.locals = saved
        model = self.inventories[name]
        _need(
            model[0] == shape,
            node,
            "module inventory has a different derived shape: " + name,
        )
        self.step(node, "derived-module-inventory", name=name, shape=shape)
        return model

    def module_inventory(self, name, node):
        values = [
            part.value
            for part in self.tree.body
            if isinstance(part, ast.Assign)
            and len(part.targets) == 1
            and _name(part.targets[0], name)
        ]
        _need(
            len(values) == 1 and self.bindings.get(name) == "assigned:" + name,
            node,
            "module inventory is not one source assignment: " + name,
        )
        value = values[0]
        if isinstance(value, ast.Call) and _name(value.func, "_native_descriptor"):
            return ("descriptor", *self.class_storage(value, None))
        if isinstance(value, ast.Call):
            self.call(
                value, "tuple", (lambda part: isinstance(part, ast.GeneratorExp),)
            )
            generator = value.args[0]
            _need(
                len(generator.generators) == 1
                and not generator.generators[0].ifs
                and not generator.generators[0].is_async,
                generator,
                "inventory comprehension is not one finite unfiltered loop",
            )
            loop = generator.generators[0]
            if isinstance(loop.target, ast.Name):
                owner, _ = self.class_storage(generator.elt, loop.target.id)
                return ("slots", owner, self.field_names(loop.iter))
            return ("slot-records", self.slot_records(generator, loop))
        _need(
            isinstance(value, (ast.Tuple, ast.BinOp)),
            value,
            "module inventory has unmodeled evaluation: " + name,
        )
        if isinstance(value, ast.Tuple) and value.elts:
            if all(isinstance(part, ast.Name) for part in value.elts):
                for part in value.elts:
                    _need(
                        part.id in _SIMPLE_ERRORS,
                        part,
                        "exception projection is not a simple native layout",
                    )
                    self.native(part.id, part)
                return ("errors", tuple(part.id for part in value.elts))
            if all(isinstance(part, ast.Tuple) for part in value.elts):
                return ("records", tuple(self.record_row(row) for row in value.elts))
        return ("names", self.field_names(value))

    def class_storage(self, node, field):
        """Return (owner, key) for a call of the source-derived capture helper."""
        _need(
            isinstance(node, ast.Call)
            and _name(node.func, "_native_descriptor")
            and field != "_native_descriptor"
            and "_native_descriptor" not in self.locals
            and self.bindings.get("_native_descriptor") == "source:_native_descriptor"
            and len(node.args) == 2
            and not node.keywords
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id != field
            and (
                _name(node.args[1], field)
                if field is not None
                else isinstance(node.args[1], ast.Constant)
                and type(node.args[1].value) is str
            ),
            node,
            "descriptor capture does not invoke the derived native capture helper",
        )
        self.dependency("_native_descriptor", node)
        owner = node.args[0].id
        binding = self.bindings.get(owner)
        if binding is None:
            _need(
                owner in _SIMPLE_ERRORS,
                node,
                "descriptor owner is not an imported or simple native class",
            )
            self.native(owner, node)
            binding = "builtins." + owner
        _need(
            not binding.startswith(("source:", "assigned:")),
            node,
            "descriptor owner is not an imported or native class",
        )
        return binding, None if field is not None else node.args[1].value

    def record_row(self, row):
        _need(
            isinstance(row, ast.Tuple) and len(row.elts) == 3,
            row,
            "record inventory row is not a literal class/tag/fields triple",
        )
        cls, tag, fields = row.elts
        binding = self.bindings.get(cls.id, "") if isinstance(cls, ast.Name) else ""
        _need(
            binding and not binding.startswith(("source:", "assigned:")),
            cls,
            "record class is not one source-selected import",
        )
        _need(
            isinstance(tag, ast.Constant) and type(tag.value) is str and tag.value,
            tag,
            "record tag is not a nonempty literal string",
        )
        names = self.field_names(fields)
        # A repeated name passes the projection's length check while another
        # field is never traversed, so uniqueness is checked, not assumed.
        _need(
            len(set(names)) == len(names) and all(names),
            fields,
            "record field inventory repeats or omits a field name",
        )
        return (binding, tag.value, names)

    def slot_records(self, generator, loop):
        _need(
            isinstance(loop.target, ast.Tuple)
            and len(loop.target.elts) == 3
            and all(isinstance(part, ast.Name) for part in loop.target.elts),
            loop,
            "slot record inventory does not unpack class/tag/fields rows",
        )
        cls, tag, fields = (part.id for part in loop.target.elts)
        element = generator.elt
        _need(
            len({cls, tag, fields}) == 3
            and isinstance(element, ast.Tuple)
            and len(element.elts) == 4
            and all(
                _name(part, expected)
                for part, expected in zip(element.elts, (cls, tag, fields))
            ),
            element,
            "slot record row does not preserve its class, tag and fields",
        )
        captured = element.elts[3]
        self.call(captured, "tuple", (lambda part: isinstance(part, ast.GeneratorExp),))
        inner = captured.args[0]
        _need(
            len(inner.generators) == 1,
            inner,
            "row descriptor capture is not one finite loop",
        )
        capture = inner.generators[0]
        _need(
            isinstance(capture.target, ast.Name)
            and capture.target.id not in {cls, tag, fields}
            and _name(capture.iter, fields)
            and not capture.ifs
            and not capture.is_async
            and isinstance(inner.elt, ast.Call)
            and _name(inner.elt.func, "_native_descriptor")
            and len(inner.elt.args) == 2
            and not inner.elt.keywords
            and _name(inner.elt.args[0], cls)
            and _name(inner.elt.args[1], capture.target.id),
            inner,
            "row descriptor capture does not select its own class storage by its own fields",
        )
        _need(
            "_native_descriptor" not in self.locals
            and "_native_descriptor" not in {cls, tag, fields, capture.target.id}
            and self.bindings.get("_native_descriptor") == "source:_native_descriptor",
            inner,
            "row descriptor helper binding is shadowed",
        )
        self.dependency("_native_descriptor", inner)
        _need(
            isinstance(loop.iter, ast.Tuple) and loop.iter.elts,
            loop.iter,
            "slot record rows are not a finite literal tuple",
        )
        return tuple(self.record_row(row) for row in loop.iter.elts)

    def field_names(self, node):
        if isinstance(node, ast.Name):
            return self.inventory(node.id, "names", node)[1]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.field_names(node.left) + self.field_names(node.right)
        _need(
            isinstance(node, ast.Tuple)
            and all(
                isinstance(part, ast.Constant) and type(part.value) is str
                for part in node.elts
            ),
            node,
            "field inventory is not a literal string tuple",
        )
        return tuple(part.value for part in node.elts)

    def declared_fields(self, owner, node):
        name = owner.rsplit(".", 1)[1]
        if name not in self.records:
            try:
                self.records.update(
                    _native_records(
                        self.objects, _module_bindings(self.objects), (name,)
                    )
                )
            except _RecordUnsupported as exc:
                raise _Unproved(node, exc.reason) from None
        return self.records[name]

    def owned_local(self, node, live, count=1):
        """Return the fresh locals one assignment binds; never a live binding."""
        _need(
            isinstance(node, ast.Assign) and len(node.targets) == 1,
            node,
            "assignment ownership is unmodeled",
        )
        target = node.targets[0]
        parts = target.elts if count > 1 and isinstance(target, ast.Tuple) else [target]
        _need(
            len(parts) == count and all(isinstance(part, ast.Name) for part in parts),
            node,
            "assignment target is not a fresh local",
        )
        names = tuple(part.id for part in parts)
        _need(
            len(set(names)) == count and not set(names) & set(live),
            node,
            "assignment overwrites a live binding",
        )
        return names[0] if count == 1 else names

    def closed(self, function, entry):
        """Exclude nested scopes, generators and rebinding of entry bindings."""
        for node in ast.walk(function):
            _need(
                node is function
                or not isinstance(
                    node,
                    (
                        ast.Global,
                        ast.Nonlocal,
                        ast.Yield,
                        ast.YieldFrom,
                        ast.Await,
                        ast.Lambda,
                        ast.NamedExpr,
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.ClassDef,
                    ),
                ),
                node,
                "nested scope, generator or lexical rebinding semantics are unmodeled",
            )
            _need(
                not (
                    isinstance(node, ast.Name)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.id in entry
                ),
                node,
                "entry binding is rebound",
            )

    def exact_branch(self, node, kind, expected, size):
        _need(
            isinstance(node, ast.If) and not node.orelse and len(node.body) == size,
            node,
            "classifier branch has unmodeled control flow",
        )
        _need(
            isinstance(node.test, ast.Compare)
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.Is)
            and _name(node.test.left, kind)
            and _name(node.test.comparators[0], expected),
            node.test,
            "branch is not selected by exact classifier identity",
        )
        self.step(node, "exact-classifier-branch", selected_by=expected)
        return node.body

    def returned_list(self, node, count):
        _need(
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.List)
            and len(node.value.elts) == count,
            node,
            "branch result is not the modeled native projection list",
        )
        return node.value.elts

    def tagged(self, node, tag, count):
        values = self.returned_list(node, count + 1)
        _need(
            _constant(values[0], tag),
            node,
            "branch result is not the corresponding tagged projection",
        )
        self.step(node, "native-tagged-return", tag=tag)
        return values[1:]

    def inductive_walk(self, node, receiver, depth, operand):
        _need(
            "walk" in self.hypotheses,
            node,
            "recursive walk is outside the derived induction",
        )
        self.call(
            node,
            "walk",
            (
                operand,
                lambda part: (
                    isinstance(part, ast.BinOp)
                    and isinstance(part.op, ast.Add)
                    and _name(part.left, depth)
                    and _constant(part.right, 1)
                ),
            ),
            receiver=receiver,
        )
        self.step(
            node,
            "inductive-walk-call",
            depth="depth + 1",
            measure="max_depth - depth strictly decreases",
        )
        return True

    def native_method(self, node, owner, method, *operands):
        self.call(
            node,
            method,
            tuple(
                (lambda part, operand=operand: _name(part, operand))
                for operand in operands
            ),
            receiver=owner,
        )
        self.native(owner, node)
        self.step(node, "native-unbound-method", call=owner + "." + method)
        return True

    def instance_dictionary(self, node, value):
        self.call(
            node,
            "__getattribute__",
            (
                lambda part: _name(part, value),
                lambda part: _constant(part, "__dict__"),
            ),
            receiver="object",
        )
        self.native("object", node)
        self.step(node, "native-instance-dictionary", value=value)
        return True

    def slot_projection(self, node, value, owner, fields):
        _need(
            isinstance(node, ast.GeneratorExp) and len(node.generators) == 1,
            node,
            "slot projection is not one finite descriptor traversal",
        )
        loop = node.generators[0]
        _need(
            isinstance(loop.target, ast.Name)
            and isinstance(loop.iter, ast.Name)
            and loop.target.id not in {value, loop.iter.id}
            and not loop.ifs
            and not loop.is_async,
            loop,
            "slot projection does not traverse one derived descriptor inventory",
        )
        _, captured_owner, captured = self.inventory(loop.iter.id, "slots", loop)
        _need(
            captured_owner == owner and captured == fields,
            loop,
            "descriptor inventory does not bind the intended class fields",
        )
        if owner.startswith(_OBJECTS + "."):
            _need(
                set(fields) <= set(self.declared_fields(owner, loop)),
                loop,
                "descriptor is not a declared native record slot",
            )
        self.call(
            node.elt,
            "__get__",
            (lambda part: _name(part, value),),
            receiver=loop.target.id,
        )
        self.step(node, "native-slot-projection", owner=owner, fields=list(fields))
        return True

    def captured_descriptor(self, node, value, owner, field):
        _need(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name),
            node,
            "descriptor read does not use a captured module descriptor",
        )
        _, captured_owner, captured = self.inventory(
            node.func.value.id, "descriptor", node
        )
        _need(
            captured_owner == owner and captured == field,
            node,
            "captured descriptor does not select " + owner + "." + field,
        )
        self.call(
            node,
            "__get__",
            (lambda part: _name(part, value),),
            receiver=node.func.value.id,
        )
        self.step(node, "native-captured-descriptor", owner=owner, field=field)
        return True

    def optional_dictionary(self, test, name):
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.And)
            and len(test.values) == 2
            and isinstance(test.values[0], ast.Compare)
            and len(test.values[0].ops) == 1
            and isinstance(test.values[0].ops[0], ast.IsNot)
            and _name(test.values[0].left, name)
            and _constant(test.values[0].comparators[0], None)
            and isinstance(test.values[1], ast.Compare)
            and len(test.values[1].ops) == 1
            and isinstance(test.values[1].ops[0], ast.IsNot)
            and _name(test.values[1].comparators[0], "dict"),
            test,
            "optional dictionary guard is not native identity",
        )
        self.call(test.values[1].left, "type", (lambda part: _name(part, name),))
        self.native("dict", test)
        self.step(test, "optional-exact-dictionary", value=name)

    def field_query(self, node, names, copied, membership):
        _need(
            isinstance(node, ast.GeneratorExp) and len(node.generators) == 1,
            node,
            "field query is not one finite inventory loop",
        )
        loop = node.generators[0]
        _need(
            isinstance(loop.target, ast.Name)
            and loop.target.id not in {names, copied}
            and _name(loop.iter, names)
            and not loop.ifs
            and not loop.is_async,
            loop,
            "field query does not iterate the derived inventory",
        )
        field = loop.target.id
        element = node.elt
        if membership:
            _need(
                isinstance(element, ast.Compare)
                and len(element.ops) == 1
                and isinstance(element.ops[0], ast.NotIn)
                and _name(element.left, field)
                and _name(element.comparators[0], copied),
                element,
                "field membership query is unmodeled",
            )
        else:
            _need(
                isinstance(element, ast.Subscript)
                and _name(element.value, copied)
                and _name(element.slice, field),
                element,
                "field projection does not select the checked key",
            )
        return True

    def positive_literal(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return self.positive_literal(node.left) * self.positive_literal(node.right)
        _need(
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and node.value > 0,
            node,
            "walker budget is not a positive integer literal",
        )
        return node.value

    def case(self, inputs, *premises):
        self.layouts.extend(premises)
        return {
            "inputs": [inputs] if isinstance(inputs, str) else list(inputs),
            "layout_premises": list(premises),
            "proved": True,
        }

    def fields(self):
        function, (receiver, value, names), _, body = self.function("fields", 3)
        self.closed(function, {receiver, value, names})
        _need(
            len(body) == 4,
            function,
            "record field projection contains unmodeled statements",
        )
        pairs = self.owned_local(body[0], {receiver, value, names})
        self.call(
            body[0].value,
            "pairs",
            (lambda part: self.instance_dictionary(part, value),),
            receiver=receiver,
        )
        self.dependency("pairs", body[0])
        copied = self.owned_local(body[1], {receiver, value, names, pairs})
        self.call(body[1].value, "dict", (lambda part: _name(part, pairs),))
        self.step(
            body[1],
            "native-dictionary-from-string-pairs",
            keys="exact str from the pairs contract; candidate values are stored, never hashed or compared",
        )
        test = self.guard(body[2])
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 2
            and isinstance(test.values[0], ast.Compare)
            and len(test.values[0].ops) == 1
            and isinstance(test.values[0].ops[0], ast.NotEq),
            test,
            "record shape guard is unmodeled",
        )
        size, membership = test.values
        self.call(size.left, "len", (lambda part: _name(part, copied),))
        self.call(size.comparators[0], "len", (lambda part: _name(part, names),))
        self.call(
            membership,
            "any",
            (lambda part: self.field_query(part, names, copied, True),),
        )
        self.step(
            body[2],
            "exact-record-field-inventory",
            conclusion="the instance dictionary has exactly the inventory's string keys",
        )
        _need(
            isinstance(body[3], ast.Return),
            body[3],
            "record field result is unmodeled",
        )
        self.call(
            body[3].value,
            "tuple",
            (lambda part: self.field_query(part, names, copied, False),),
        )
        return self.finish(
            "fields",
            function,
            "native tuple of the inventory-selected instance-dictionary values, in inventory order; the values remain opaque",
            {"names": ["content"], "instance_dictionary": {"content": "opaque"}},
            (
                "the exact admitted record class resolves __dict__ to its native instance dictionary; names is a derived literal string inventory",
            ),
        )

    def record(self):
        function, (receiver, tag, names, values, depth), _, body = self.function(
            "record", 5
        )
        entry_names = {receiver, tag, names, values, depth}
        self.closed(function, entry_names)
        _need(
            len(body) == 1 and isinstance(body[0], ast.Return),
            function,
            "record projection contains unmodeled statements",
        )
        result = body[0].value
        _need(
            isinstance(result, ast.List)
            and len(result.elts) == 2
            and _name(result.elts[0], tag)
            and isinstance(result.elts[1], ast.ListComp)
            and len(result.elts[1].generators) == 1,
            result,
            "record projection is not the tagged field list",
        )
        listing = result.elts[1]
        loop = listing.generators[0]
        _need(
            isinstance(loop.target, ast.Tuple)
            and len(loop.target.elts) == 2
            and all(isinstance(part, ast.Name) for part in loop.target.elts)
            and not loop.ifs
            and not loop.is_async,
            loop,
            "record fields are not one finite paired traversal",
        )
        field, item = (part.id for part in loop.target.elts)
        _need(
            field != item and not {field, item} & entry_names,
            loop,
            "record traversal aliases a live binding",
        )
        self.call(
            loop.iter,
            "zip",
            (lambda part: _name(part, names), lambda part: _name(part, values)),
        )
        _need(
            isinstance(listing.elt, ast.List)
            and len(listing.elt.elts) == 2
            and _name(listing.elt.elts[0], field),
            listing.elt,
            "record field projection does not preserve its inventory name",
        )
        self.inductive_walk(
            listing.elt.elts[1], receiver, depth, lambda part: _name(part, item)
        )
        self.step(
            body[0],
            "finite-record-traversal",
            names="derived literal inventory",
            values="native tuple built by the caller",
        )
        entry = self.finish(
            "record",
            function,
            "tagged list pairing each inventory name with the walk projection of its value at depth + 1",
            {"tag": "Interrupt", "names": ["value"], "values": ["text"]},
            (
                "names is a derived literal string inventory and values a native tuple; walk at depth + 1 meets its contract (induction hypothesis)",
            ),
        )
        entry["inductive_hypothesis"] = "walk at depth + 1"
        return entry

    def compound(self):
        function, frame, _, body = self.function("compound", 4)
        self.closed(function, set(frame))
        self.dispatched = set()
        _need(
            len(body) == 13,
            function,
            "compound dispatch contains unmodeled statements",
        )
        cases = [
            derive(node, frame)
            for node, derive in zip(
                body,
                (
                    self.text_case,
                    self.dictionary_case,
                    self.sequence_case,
                    self.labels_case,
                    self.labeled_value_case,
                    self.interrupt_case,
                    self.uuid_case,
                    self.slot_record_case,
                    self.tuple_record_case,
                    self.event_case,
                    self.model_case,
                    self.error_case,
                ),
            )
        ]
        self.refusal(body[12:])
        entry = self.finish(
            "compound",
            function,
            "for each admitted exact type, the tagged projection derived for its branch; every other type is refused; only owned walker state changes and no candidate protocol runs",
            {"value": {"key": "text"}, "kind": "dict"},
            (
                "kind is type(value), and the walk prefix has already returned for None and the exact scalar types",
                "every recursive walk call at depth + 1 meets the walk contract (induction hypothesis, closed by walk)",
            ),
        )
        entry["cases"] = cases
        entry["inductive_hypothesis"] = "walk at depth + 1"
        return entry

    def text_case(self, node, frame):
        receiver, value, kind, _ = frame
        (result,) = self.exact_branch(node, kind, "TextAccessor", 1)
        self.source_import(
            "TextAccessor", "langchain_core.messages.base.TextAccessor", node
        )
        (payload,) = self.tagged(result, "TextAccessor", 1)
        self.call(
            payload,
            "string",
            (lambda part: self.native_method(part, "str", "__str__", value),),
            receiver=receiver,
        )
        self.dependency("string", payload)
        return self.case(
            "langchain_core.messages.base.TextAccessor",
            "langchain_core.messages.base.TextAccessor is a str subclass without instance storage; str.__str__ returns an exact native str without subclass dispatch",
        )

    def dictionary_case(self, node, frame):
        receiver, value, kind, depth = frame
        self.native("dict", node)
        snapshot, loop, result = self.exact_branch(node, kind, "dict", 3)
        live = set(frame)
        pairs = self.owned_local(snapshot, live)
        self.call(
            snapshot.value,
            "pairs",
            (lambda part: _name(part, value),),
            receiver=receiver,
        )
        self.dependency("pairs", snapshot)
        live.add(pairs)
        _need(
            isinstance(loop, ast.For)
            and not loop.orelse
            and _name(loop.iter, pairs)
            and isinstance(loop.target, ast.Tuple)
            and len(loop.target.elts) == 2
            and all(isinstance(part, ast.Name) for part in loop.target.elts)
            and len(loop.body) == 2,
            loop,
            "channel inheritance is not one complete pair induction",
        )
        key, ignored = (part.id for part in loop.target.elts)
        _need(
            key != ignored and not {key, ignored} & live,
            loop,
            "pair induction overwrites a live binding",
        )
        lookup, conditional = loop.body
        inherited = self.owned_local(lookup, live | {key, ignored})
        call = lookup.value
        _need(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "get"
            and _attribute(call.func.value, receiver, "channels")
            and len(call.args) == 1
            and _name(call.args[0], key)
            and not call.keywords,
            call,
            "channel lookup is not owned native dictionary access by a checked key",
        )
        _need(
            isinstance(conditional, ast.If)
            and not conditional.orelse
            and isinstance(conditional.test, ast.Compare)
            and len(conditional.test.ops) == 1
            and isinstance(conditional.test.ops[0], ast.IsNot)
            and _name(conditional.test.left, inherited)
            and _constant(conditional.test.comparators[0], None)
            and len(conditional.body) == 2,
            conditional,
            "channel inheritance has unmodeled control flow",
        )
        update, low = conditional.body

        def item(part, index):
            return (
                isinstance(part, ast.Subscript)
                and _name(part.value, inherited)
                and _constant(part.slice, index)
            )

        _need(
            isinstance(update, ast.Expr)
            and isinstance(update.value, ast.Call)
            and isinstance(update.value.func, ast.Attribute)
            and update.value.func.attr == "update"
            and _attribute(update.value.func.value, receiver, "confidentiality")
            and len(update.value.args) == 1
            and item(update.value.args[0], 0)
            and not update.value.keywords,
            update,
            "inherited compartments are not joined into owned native storage",
        )
        _need(
            isinstance(low, ast.AugAssign)
            and isinstance(low.op, ast.BitOr)
            and _attribute(low.target, receiver, "low_integrity")
            and isinstance(low.value, ast.Compare)
            and len(low.value.ops) == 1
            and isinstance(low.value.ops[0], ast.NotEq)
            and item(low.value.left, 1)
            and _constant(low.value.comparators[0], "trusted"),
            low,
            "inherited integrity is not a native boolean join",
        )
        self.dependency("channel_labels", loop)
        self.step(
            loop,
            "owned-channel-label-inheritance",
            keys="exact str from the pairs contract",
            stored="checked string list and integrity string from the channel_labels contract",
        )
        (listing,) = self.tagged(result, "dict", 1)
        _need(
            isinstance(listing, ast.ListComp) and len(listing.generators) == 1,
            listing,
            "dictionary projection is not one finite pair traversal",
        )
        traversal = listing.generators[0]
        _need(
            isinstance(traversal.target, ast.Tuple)
            and len(traversal.target.elts) == 2
            and all(isinstance(part, ast.Name) for part in traversal.target.elts)
            and _name(traversal.iter, pairs)
            and not traversal.ifs
            and not traversal.is_async,
            traversal,
            "dictionary projection does not traverse the checked snapshot",
        )
        name, child = (part.id for part in traversal.target.elts)
        _need(
            name != child and not {name, child} & live,
            traversal,
            "dictionary projection aliases a live binding",
        )
        _need(
            isinstance(listing.elt, ast.List) and len(listing.elt.elts) == 2,
            listing.elt,
            "dictionary entry projection is unmodeled",
        )
        self.call(
            listing.elt.elts[0],
            "string",
            (lambda part: _name(part, name),),
            receiver=receiver,
        )
        self.dependency("string", listing.elt)
        self.inductive_walk(
            listing.elt.elts[1], receiver, depth, lambda part: _name(part, child)
        )
        return self.case("dict")

    def sequence_case(self, node, frame):
        receiver, value, kind, depth = frame
        _need(
            isinstance(node, ast.If) and not node.orelse and len(node.body) == 3,
            node,
            "sequence branch has unmodeled control flow",
        )
        test = node.test
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 2
            and all(
                isinstance(part, ast.Compare)
                and len(part.ops) == 1
                and isinstance(part.ops[0], ast.Is)
                and _name(part.left, kind)
                and _name(part.comparators[0], expected)
                for part, expected in zip(test.values, ("tuple", "list"))
            ),
            test,
            "sequence branch is not selected by exact tuple/list identity",
        )
        self.native("tuple", test)
        self.native("list", test)
        bound, snapshot_node, result = node.body
        self.bound_guard(bound, value, receiver)
        snapshot = self.owned_local(snapshot_node, set(frame))
        self.call(snapshot_node.value, "tuple", (lambda part: _name(part, value),))
        self.step(
            snapshot_node,
            "native-sequence-snapshot",
            invariant="bounded native tuple of the exact tuple/list items",
        )
        label, listing = self.returned_list(result, 2)
        _need(
            isinstance(label, ast.IfExp)
            and isinstance(label.test, ast.Compare)
            and len(label.test.ops) == 1
            and isinstance(label.test.ops[0], ast.Is)
            and _name(label.test.left, kind)
            and _name(label.test.comparators[0], "tuple")
            and _constant(label.body, "tuple")
            and _constant(label.orelse, "list"),
            label,
            "sequence tag is not selected by the exact classifier",
        )
        _need(
            isinstance(listing, ast.ListComp) and len(listing.generators) == 1,
            listing,
            "sequence projection is not one finite traversal",
        )
        loop = listing.generators[0]
        _need(
            isinstance(loop.target, ast.Name)
            and loop.target.id not in set(frame) | {snapshot}
            and _name(loop.iter, snapshot)
            and not loop.ifs
            and not loop.is_async,
            loop,
            "sequence projection does not traverse the checked snapshot",
        )
        self.inductive_walk(
            listing.elt, receiver, depth, lambda part: _name(part, loop.target.id)
        )
        return self.case(["tuple", "list"])

    def labels_case(self, node, frame):
        receiver, value, kind, _ = frame
        (result,) = self.exact_branch(node, kind, "SecurityLabels", 1)
        self.source_import("SecurityLabels", _OBJECTS + ".SecurityLabels", node)
        _need(isinstance(result, ast.Return), result, "label result is unmodeled")
        self.call(
            result.value,
            "labels",
            (lambda part: _name(part, value),),
            receiver=receiver,
        )
        self.dependency("labels", result)
        return self.case(_OBJECTS + ".SecurityLabels")

    def labeled_value_case(self, node, frame):
        receiver, value, kind, depth = frame
        projection, check, labels_node, result = self.exact_branch(
            node, kind, "LabeledValue", 4
        )
        self.source_import("LabeledValue", _OBJECTS + ".LabeledValue", node)
        name, content, labels = self.owned_local(projection, set(frame), 3)
        self.slot_projection(
            projection.value,
            value,
            _OBJECTS + ".LabeledValue",
            ("name", "value", "labels"),
        )
        live = set(frame) | {name, content, labels}
        _need(isinstance(check, ast.Expr), check, "value name check is unmodeled")
        self.call(
            check.value,
            "string",
            (lambda part: _name(part, name),),
            receiver=receiver,
            keywords=(("nonempty", True),),
        )
        self.dependency("string", check)
        label_data = self.owned_local(labels_node, live)
        self.call(
            labels_node.value,
            "labels",
            (lambda part: _name(part, labels),),
            receiver=receiver,
        )
        self.dependency("labels", labels_node)
        projected, walked, data = self.tagged(result, "LabeledValue", 3)
        _need(
            _name(projected, name) and _name(data, label_data),
            result,
            "labeled value projection does not use its checked fields",
        )
        self.inductive_walk(walked, receiver, depth, lambda part: _name(part, content))
        return self.case(_OBJECTS + ".LabeledValue")

    def interrupt_case(self, node, frame):
        receiver, value, kind, depth = frame
        projection, check, schema_guard, result = self.exact_branch(
            node, kind, "Interrupt", 4
        )
        self.source_import("Interrupt", "langgraph.types.Interrupt", node)
        fields = ("value", "id", "response_schema")
        content, identifier, schema = self.owned_local(projection, set(frame), 3)
        self.slot_projection(
            projection.value, value, "langgraph.types.Interrupt", fields
        )
        _need(isinstance(check, ast.Expr), check, "interrupt id check is unmodeled")
        self.call(
            check.value,
            "string",
            (lambda part: _name(part, identifier),),
            receiver=receiver,
            keywords=(("nonempty", True),),
        )
        self.dependency("string", check)
        self.optional_dictionary(self.guard(schema_guard), schema)
        _need(isinstance(result, ast.Return), result, "interrupt result is unmodeled")
        self.call(
            result.value,
            "record",
            (
                lambda part: _constant(part, "Interrupt"),
                lambda part: (
                    isinstance(part, ast.Tuple)
                    and len(part.elts) == 3
                    and all(
                        _constant(item, field) for item, field in zip(part.elts, fields)
                    )
                ),
                lambda part: (
                    isinstance(part, ast.Tuple)
                    and len(part.elts) == 3
                    and all(
                        _name(item, local)
                        for item, local in zip(part.elts, (content, identifier, schema))
                    )
                ),
                lambda part: _name(part, depth),
            ),
            receiver=receiver,
        )
        self.dependency("record", result)
        return self.case(
            "langgraph.types.Interrupt",
            "langgraph.types.Interrupt stores value, id and response_schema in native member descriptors and has no other instance state",
        )

    def uuid_case(self, node, frame):
        receiver, value, kind, _ = frame
        number_node, safe_node, guard, selection, result = self.exact_branch(
            node, kind, "UUID", 5
        )
        self.source_import("UUID", "uuid.UUID", node)
        live = set(frame)
        number = self.owned_local(number_node, live)
        safe = self.owned_local(safe_node, live | {number})
        for part, field in ((number_node, "int"), (safe_node, "is_safe")):
            self.call(
                part.value,
                "__getattribute__",
                (
                    lambda item: _name(item, value),
                    lambda item, field=field: _constant(item, field),
                ),
                receiver="object",
            )
        self.native("object", node)
        test = self.guard(guard)
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 2,
            test,
            "UUID integer guard is unmodeled",
        )
        exact, bounded = test.values
        _need(
            isinstance(exact, ast.Compare)
            and len(exact.ops) == 1
            and isinstance(exact.ops[0], ast.IsNot)
            and _name(exact.comparators[0], "int"),
            exact,
            "UUID integer identity is unmodeled",
        )
        self.call(exact.left, "type", (lambda part: _name(part, number),))
        self.native("int", exact)
        comparison = bounded.operand if isinstance(bounded, ast.UnaryOp) else None
        _need(
            isinstance(bounded.op, ast.Not)
            and isinstance(comparison, ast.Compare)
            and _constant(comparison.left, 0)
            and [type(op) for op in comparison.ops] == [ast.LtE, ast.Lt]
            and _name(comparison.comparators[0], number)
            and isinstance(comparison.comparators[1], ast.BinOp)
            and isinstance(comparison.comparators[1].op, ast.LShift)
            and _constant(comparison.comparators[1].left, 1)
            and _constant(comparison.comparators[1].right, 128),
            bounded,
            "UUID integer range is not the native 128-bit bound",
        )
        self.step(guard, "short-circuit-exact-integer-range", value=number)
        tag = self.uuid_tag(selection, live | {number, safe}, safe)
        payload, label = self.tagged(result, "UUID", 2)
        self.call(payload, "hex", (lambda part: _name(part, number),))
        _need(_name(label, tag), label, "UUID safety tag is not the derived literal")
        return self.case(
            "uuid.UUID",
            "uuid.UUID stores int and is_safe in native slots; uuid.SafeUUID members are plain enum class attributes",
        )

    def uuid_tag(self, node, live, safe):
        self.source_import("SafeUUID", "uuid.SafeUUID", node)
        tag = None
        for member in ("safe", "unsafe", "unknown"):
            _need(
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Is)
                and _name(node.test.left, safe)
                and _attribute(node.test.comparators[0], "SafeUUID", member)
                and len(node.body) == 1
                and len(node.orelse) == 1,
                node,
                "UUID safety selection is not native enum identity",
            )
            assigned = self.owned_local(node.body[0], live)
            _need(
                tag in {None, assigned} and _constant(node.body[0].value, member),
                node.body[0],
                "UUID safety tag is not one literal local",
            )
            tag = assigned
            node = node.orelse[0]
        self.refusal([node])
        self.step(node, "native-enum-identity-selection", members=3)
        return tag

    def inventory_loop(self, node, frame, shape, arity, size):
        _need(
            isinstance(node, ast.For)
            and not node.orelse
            and isinstance(node.iter, ast.Name)
            and len(node.body) == 1,
            node,
            "record dispatch is not one finite inventory loop",
        )
        targets = (
            node.target.elts if isinstance(node.target, ast.Tuple) else [node.target]
        )
        _need(
            len(targets) == arity
            and all(isinstance(part, ast.Name) for part in targets),
            node,
            "inventory loop target does not unpack the derived rows",
        )
        names = tuple(part.id for part in targets)
        _need(
            len(set(names)) == arity and not set(names) & set(frame),
            node,
            "inventory loop overwrites a live binding",
        )
        rows = self.inventory(node.iter.id, shape, node)[1]
        # A class listed twice is dispatched by its first row, so a shorter
        # shadowing row would silently drop fields; each class has one row.
        classes = [row if shape == "errors" else row[0] for row in rows]
        _need(
            not set(classes) & self.dispatched and len(set(classes)) == len(classes),
            node,
            "record class appears in more than one dispatch row",
        )
        self.dispatched.update(classes)
        body = self.exact_branch(node.body[0], frame[2], names[0], size)
        self.step(
            node, "finite-inventory-dispatch", inventory=node.iter.id, rows=len(rows)
        )
        return rows, names, body

    def slot_record_case(self, node, frame):
        receiver, value, kind, depth = frame
        rows, (_, tag, names, slots), (shape, result) = self.inventory_loop(
            node, frame, "slot-records", 4, 2
        )
        test = self.guard(shape)
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.And)
            and len(test.values) == 2
            and isinstance(test.values[0], ast.Compare)
            and len(test.values[0].ops) == 1
            and isinstance(test.values[0].ops[0], ast.Is)
            and _name(test.values[0].left, kind)
            and _name(test.values[0].comparators[0], "Command"),
            test,
            "command shape guard does not select the exact Command class",
        )
        self.source_import("Command", "langgraph.types.Command", test)
        self.call(
            test.values[1],
            "pairs",
            (lambda part: self.instance_dictionary(part, value),),
            receiver=receiver,
        )
        self.dependency("pairs", test.values[1])
        self.step(shape, "empty-command-instance-dictionary")

        def captured(part):
            self.call(
                part,
                "tuple",
                (
                    lambda item: (
                        isinstance(item, ast.GeneratorExp) and len(item.generators) == 1
                    ),
                ),
            )
            generator = part.args[0]
            loop = generator.generators[0]
            _need(
                isinstance(loop.target, ast.Name)
                and loop.target.id not in set(frame) | {slots}
                and _name(loop.iter, slots)
                and not loop.ifs
                and not loop.is_async,
                loop,
                "row descriptor projection does not traverse its captured descriptors",
            )
            self.call(
                generator.elt,
                "__get__",
                (lambda item: _name(item, value),),
                receiver=loop.target.id,
            )
            self.step(part, "native-row-descriptor-projection")
            return True

        _need(isinstance(result, ast.Return), result, "slot record result is unmodeled")
        self.call(
            result.value,
            "record",
            (
                lambda part: _name(part, tag),
                lambda part: _name(part, names),
                captured,
                lambda part: _name(part, depth),
            ),
            receiver=receiver,
        )
        self.dependency("record", result)
        return self.case(
            [row[0] for row in rows],
            *(
                f"{row[0]} stores {', '.join(row[2])} in native member descriptors and has no other instance state"
                for row in rows
            ),
            "langgraph.types.Command resolves __dict__ to its native instance dictionary",
        )

    def tuple_record_case(self, node, frame):
        receiver, value, kind, depth = frame
        rows, (_, tag, names), (shape, result) = self.inventory_loop(
            node, frame, "records", 3, 2
        )
        test = self.guard(shape)
        _need(
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotEq),
            test,
            "tuple record length guard is unmodeled",
        )
        self.native_method(test.left, "tuple", "__len__", value)
        self.call(test.comparators[0], "len", (lambda part: _name(part, names),))

        def items(part):
            self.call(
                part,
                "tuple",
                (
                    lambda item: (
                        isinstance(item, ast.GeneratorExp) and len(item.generators) == 1
                    ),
                ),
            )
            generator = part.args[0]
            loop = generator.generators[0]
            _need(
                isinstance(loop.target, ast.Name)
                and loop.target.id not in set(frame) | {tag, names}
                and not loop.ifs
                and not loop.is_async,
                loop,
                "tuple record items are not one finite index traversal",
            )
            self.call(loop.iter, "range", (lambda item: isinstance(item, ast.Call),))
            self.call(loop.iter.args[0], "len", (lambda item: _name(item, names),))
            self.native_method(
                generator.elt, "tuple", "__getitem__", value, loop.target.id
            )
            return True

        _need(
            isinstance(result, ast.Return), result, "tuple record result is unmodeled"
        )
        self.call(
            result.value,
            "record",
            (
                lambda part: _name(part, tag),
                lambda part: _name(part, names),
                items,
                lambda part: _name(part, depth),
            ),
            receiver=receiver,
        )
        self.dependency("record", result)
        return self.case(
            [row[0] for row in rows],
            *(
                f"{row[0]} is a tuple subclass; tuple.__len__ and tuple.__getitem__ bypass subclass protocols"
                for row in rows
            ),
        )

    def event_case(self, node, frame):
        receiver, value, kind, depth = frame
        rows, (_, tag, names), (selection, result) = self.inventory_loop(
            node, frame, "records", 3, 2
        )
        fields = self.owned_local(selection, set(frame) | {tag, names})
        self.call(
            selection.value,
            "fields",
            (lambda part: _name(part, value), lambda part: _name(part, names)),
            receiver=receiver,
        )
        self.dependency("fields", selection)
        _need(isinstance(result, ast.Return), result, "event result is unmodeled")
        self.call(
            result.value,
            "record",
            (
                lambda part: _name(part, tag),
                lambda part: _name(part, names),
                lambda part: _name(part, fields),
                lambda part: _name(part, depth),
            ),
            receiver=receiver,
        )
        self.dependency("record", result)
        return self.case(
            [row[0] for row in rows],
            *(
                f"{row[0]} resolves __dict__ to its native instance dictionary and keeps all instance state there"
                for row in rows
            ),
        )

    def model_case(self, node, frame):
        receiver, value, kind, depth = frame
        rows, (_, tag, names), body = self.inventory_loop(node, frame, "records", 3, 7)
        selection, extra_node, private_node, set_node, extra_guard, private_guard = (
            body[:6]
        )
        live = set(frame) | {tag, names}
        fields = self.owned_local(selection, live)
        self.call(
            selection.value,
            "fields",
            (lambda part: _name(part, value), lambda part: _name(part, names)),
            receiver=receiver,
        )
        self.dependency("fields", selection)
        live.add(fields)
        extra = self.owned_local(extra_node, live)
        self.captured_descriptor(
            extra_node.value, value, "pydantic.BaseModel", "__pydantic_extra__"
        )
        live.add(extra)
        private = self.owned_local(private_node, live)
        self.captured_descriptor(
            private_node.value, value, "pydantic.BaseModel", "__pydantic_private__"
        )
        live.add(private)
        field_set = self.owned_local(set_node, live)
        self.call(
            set_node.value,
            "string_set",
            (
                lambda part: self.captured_descriptor(
                    part, value, "pydantic.BaseModel", "__pydantic_fields_set__"
                ),
            ),
            receiver=receiver,
            keywords=(("mutable", True),),
        )
        self.dependency("string_set", set_node)
        self.optional_dictionary(self.guard(extra_guard), extra)
        self.optional_dictionary(self.guard(private_guard), private)
        record, extra_part, private_part, set_part = self.returned_list(body[6], 4)
        self.call(
            record,
            "record",
            (
                lambda part: _name(part, tag),
                lambda part: _name(part, names),
                lambda part: _name(part, fields),
                lambda part: _name(part, depth),
            ),
            receiver=receiver,
        )
        self.dependency("record", body[6])
        for part, label, operand in (
            (extra_part, "extra", extra),
            (private_part, "private", private),
        ):
            _need(
                isinstance(part, ast.List)
                and len(part.elts) == 2
                and _constant(part.elts[0], label),
                part,
                "model storage projection is unmodeled",
            )
            self.inductive_walk(
                part.elts[1],
                receiver,
                depth,
                lambda item, operand=operand: _name(item, operand),
            )
        _need(
            isinstance(set_part, ast.List)
            and len(set_part.elts) == 2
            and _constant(set_part.elts[0], "fields_set")
            and _name(set_part.elts[1], field_set),
            set_part,
            "model field-set projection is unmodeled",
        )
        return self.case(
            [row[0] for row in rows],
            *(
                f"{row[0]} is a pydantic BaseModel whose declared fields live in its native instance dictionary and other state in the extra/private/fields-set member descriptors"
                for row in rows
            ),
        )

    def error_case(self, node, frame):
        receiver, value, kind, depth = frame
        rows, (expected,), (live_guard, result) = self.inventory_loop(
            node, frame, "errors", 1, 2
        )
        test = self.guard(live_guard)
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.Or)
            and len(test.values) == 4,
            test,
            "live exception guard is unmodeled",
        )
        for part, field in zip(
            test.values[:3], ("__traceback__", "__cause__", "__context__")
        ):
            _need(
                isinstance(part, ast.Compare)
                and len(part.ops) == 1
                and isinstance(part.ops[0], ast.IsNot)
                and _constant(part.comparators[0], None),
                part,
                "exception link check is not native identity",
            )
            self.captured_descriptor(part.left, value, "builtins.BaseException", field)
        self.call(
            test.values[3],
            "pairs",
            (lambda part: self.instance_dictionary(part, value),),
            receiver=receiver,
        )
        self.dependency("pairs", test.values[3])
        self.step(live_guard, "detached-exception-required")
        name, walked = self.tagged(result, "exception", 2)
        _need(
            isinstance(name, ast.Attribute)
            and name.attr == "__name__"
            and _name(name.value, expected),
            name,
            "exception projection name is not the native class name",
        )
        self.inductive_walk(
            walked,
            receiver,
            depth,
            lambda part: self.captured_descriptor(
                part, value, "builtins.BaseException", "args"
            ),
        )
        return self.case(
            ["builtins." + row for row in rows],
            "listed builtin exceptions use the native BaseException layout without extra native fields",
        )

    def walk(self, scalar):
        _need(
            scalar is not None and scalar.get("scalar_cases_complete") is True,
            self.tree,
            "walk prefix lacks its source-derived scalar cases",
        )
        function, (receiver, value, depth), _, body = self.function(
            "walk", 3, defaults=(0,)
        )
        self.closed(function, {receiver, value, depth})
        _need(
            len(body) == 13
            and isinstance(body[1], ast.Assign)
            and isinstance(body[1].targets[0], ast.Name),
            function,
            "walk contains statements outside the derived prefix and identity suffix",
        )
        kind = body[1].targets[0].id
        identity = self.owned_local(body[9], {receiver, value, depth, kind})
        self.call(body[9].value, "id", (lambda part: _name(part, value),))
        stored = {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        }
        _need(
            stored == {kind, identity},
            function,
            "walk rebinds its classifier or identity",
        )
        test = self.guard(body[10])
        _need(
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and _name(test.left, identity)
            and _attribute(test.comparators[0], receiver, "active"),
            test,
            "cycle guard does not test owned active identities",
        )
        self.step(
            body[10],
            "active-identity-cycle-guard",
            invariant="owned native set of the int identities on the current traversal path",
        )

        def active(part, method):
            return (
                isinstance(part, ast.Expr)
                and isinstance(part.value, ast.Call)
                and isinstance(part.value.func, ast.Attribute)
                and part.value.func.attr == method
                and _attribute(part.value.func.value, receiver, "active")
                and len(part.value.args) == 1
                and _name(part.value.args[0], identity)
                and not part.value.keywords
            )

        _need(
            active(body[11], "add"), body[11], "active identity insertion is unmodeled"
        )
        trial = body[12]
        _need(
            isinstance(trial, ast.Try)
            and not trial.handlers
            and not trial.orelse
            and len(trial.body) == 1
            and isinstance(trial.body[0], ast.Return)
            and len(trial.finalbody) == 1
            and active(trial.finalbody[0], "remove"),
            trial,
            "identity lifetime is not one try/finally around the compound dispatch",
        )
        self.call(
            trial.body[0].value,
            "compound",
            (
                lambda part: _name(part, value),
                lambda part: _name(part, kind),
                lambda part: _name(part, depth),
            ),
            receiver=receiver,
        )
        self.dependency("compound", trial.body[0])
        self.step(
            trial,
            "identity-lifetime",
            invariant="the guard admits an identity at most once per path, so its own finally removes an identity that is present",
        )
        for name, method in self.methods.items():
            for node in ast.walk(method):
                _need(
                    name == "__init__"
                    or not (
                        isinstance(node, ast.Attribute)
                        and node.attr == "depth"
                        and isinstance(node.ctx, (ast.Store, ast.Del))
                    ),
                    node,
                    "walker depth bound is written outside its constructor",
                )
        self.step(
            function,
            "walk-induction",
            base="depth > max_depth refuses before any recursive call (scalar prefix guard)",
            step="compound and record call walk only at depth + 1; walk passes depth unchanged to compound",
            measure="max_depth - depth; max_depth is constructor-owned and never written by another method",
            termination="each walk entry charges one node of the finite owned budget",
            closes=["record", "compound"],
        )
        entry = self.finish(
            "walk",
            function,
            "the tagged projection of an admitted value within the owned depth/node/byte budgets, or a refusal; only owned walker state changes and no candidate protocol runs",
            {"value": {"items": [1, "text", None]}},
            ("constructor-owned walker; depth is an exact nonnegative int",),
        )
        entry["scalar_prefix"] = "walk_scalar_cases"
        # Each consumed scalar branch returns a native list with exact str/bool
        # leaves; every consumed compound/record constructor combines only
        # those leaves and recursive results. Closing the same induction also
        # closes this representation lemma, without any equality/injectivity
        # conclusion about the original values.
        entry["projection_domain"] = (
            "finite acyclic exact lists with exact str/bool leaves"
        )
        return entry

    def module_function(self, name, positional, keywords=()):
        functions = [
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        _need(
            len(functions) == 1 and self.bindings.get(name) == "source:" + name,
            self.tree,
            "missing validator definition: " + name,
        )
        function = functions[0]
        args = function.args
        _need(
            not function.decorator_list
            and not args.posonlyargs
            and not args.vararg
            and not args.kwarg
            and len(args.kwonlyargs) == len(keywords)
            and not args.defaults
            and len(args.args) == positional,
            function,
            "validator signature is outside the modeled entry contract",
        )
        names = tuple(arg.arg for arg in (*args.args, *args.kwonlyargs))
        for parameter, default, (expected_name, expected) in zip(
            args.kwonlyargs, args.kw_defaults, keywords
        ):
            _need(
                parameter.arg == expected_name
                and (
                    _constant(default, None)
                    if expected is None
                    else self.positive_literal(default) == expected
                ),
                parameter,
                "wrapper keyword/default does not match the finite public contract",
            )
        scope = next(
            (child for child in self.scopes.get_children() if child.get_name() == name),
            None,
        )
        _need(scope is not None, function, "validator scope is unavailable")
        self.steps = []
        self.receiver = None
        self.locals = (
            {symbol.get_name() for symbol in scope.get_symbols() if symbol.is_local()}
            | set(names)
            | {
                node.id
                for node in ast.walk(function)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            }
        )
        self.closed(function, set(names))
        return function, names, _body(function)

    def finish_module(self, name, function, result, witness, premises=()):
        entry = {
            "entry": _MODULE + "." + name,
            "proved": True,
            "scope": "source-derived validator contract under the listed premises",
            "result": result,
            "useful_path": witness,
            "entry_premises": list(premises),
            "derivation": list(self.steps),
            "source_lines": [function.lineno, function.end_lineno],
            "all_body_statements_consumed": True,
        }
        self.entries[name] = entry
        return entry

    def request_validator(self):
        function, (value,), body = self.module_function("_validate_output_request", 1)
        _need(
            len(body) == 11,
            function,
            "request validator contains unmodeled statements",
        )
        self.source_import("OutputRequest", _OBJECTS + ".OutputRequest", function)
        self.exact_guard(body[0], value, "OutputRequest", native=False)
        fields = self.owned_local(body[1], {value}, 5)
        self.slot_projection(
            body[1].value,
            value,
            _OBJECTS + ".OutputRequest",
            ("destination", "content", "labels", "clearance", "output_id"),
        )
        destination, content, labels, clearance, output_id = fields
        walker = self.owned_local(body[2], {value, *fields})
        constructor = body[2].value
        _need(
            isinstance(constructor, ast.Call)
            and _name(constructor.func, "_Walker")
            and "_Walker" not in self.locals
            and self.bindings.get("_Walker") == "source:_Walker"
            and len(constructor.args) == 3
            and not constructor.keywords,
            constructor,
            "walker construction is not the source constructor with literal budgets",
        )
        budgets = [self.positive_literal(part) for part in constructor.args]
        self.dependency("__init__", constructor)
        self.step(body[2], "fresh-local-walker", budgets=budgets)
        self.receiver = walker
        for node, method, operand, keywords in (
            (body[3], "string", destination, (("nonempty", True),)),
            (body[4], "string", output_id, (("nonempty", True),)),
            (body[5], "labels", labels, ()),
            (body[6], "string_set", clearance, ()),
            (body[7], "walk", content, ()),
        ):
            _need(
                isinstance(node, ast.Expr),
                node,
                "request field validation is unmodeled",
            )
            self.call(
                node.value,
                method,
                (lambda part, operand=operand: _name(part, operand),),
                receiver=walker,
                keywords=keywords,
            )
            self.dependency(method, node)
        confidentiality, integrity = self.owned_local(
            body[8], {value, walker, *fields}, 2
        )
        self.slot_projection(
            body[8].value,
            labels,
            _OBJECTS + ".SecurityLabels",
            ("confidentiality", "integrity"),
        )
        test = self.guard(body[9])
        subset = test.operand if isinstance(test, ast.UnaryOp) else None
        _need(
            isinstance(test.op, ast.Not)
            and isinstance(subset, ast.Call)
            and isinstance(subset.func, ast.Attribute)
            and subset.func.attr == "issubset"
            and _attribute(subset.func.value, walker, "confidentiality")
            and len(subset.args) == 1
            and _name(subset.args[0], confidentiality)
            and not subset.keywords,
            test,
            "payload confidentiality check is not an owned native subset test",
        )
        self.step(
            body[9],
            "nested-confidentiality-subset",
            right="the validated native frozenset (field-stability premise)",
        )
        test = self.guard(body[10])
        _need(
            isinstance(test, ast.BoolOp)
            and isinstance(test.op, ast.And)
            and len(test.values) == 2
            and _attribute(test.values[0], walker, "low_integrity")
            and isinstance(test.values[1], ast.Compare)
            and len(test.values[1].ops) == 1
            and isinstance(test.values[1].ops[0], ast.Eq)
            and _name(test.values[1].left, integrity)
            and _constant(test.values[1].comparators[0], "trusted"),
            test,
            "payload integrity check is not an owned native boolean/string test",
        )
        self.step(body[10], "nested-integrity-consistency")
        return self.finish_module(
            "_validate_output_request",
            function,
            "normal return only for an exact OutputRequest whose destination/output_id are exact nonempty str, labels an exact SecurityLabels, clearance an exact frozenset of nonempty str, content admitted by walk, and nested labels within the declared labels; otherwise a refusal",
            {"destination": "user", "output_id": "out-1", "content": "text"},
            (
                "the request, its labels and traversed containers are stable during validation",
            ),
        )

    def public_validator(self):
        function, (value,), body = self.module_function("validate_output_request", 1)
        _need(
            len(body) == 2, function, "public validator contains unmodeled statements"
        )
        trial, final = body
        _need(
            isinstance(trial, ast.Try)
            and len(trial.body) == 2
            and len(trial.handlers) == 1
            and not trial.orelse
            and not trial.finalbody,
            trial,
            "exception normalization is not one modeled handler",
        )
        call, returned = trial.body
        _need(
            isinstance(call, ast.Expr)
            and isinstance(call.value, ast.Call)
            and _name(call.value.func, "_validate_output_request")
            and "_validate_output_request" not in self.locals
            and self.bindings.get("_validate_output_request")
            == "source:_validate_output_request"
            and len(call.value.args) == 1
            and _name(call.value.args[0], value)
            and not call.value.keywords,
            call,
            "public validator does not delegate the unchanged request",
        )
        self.dependency("_validate_output_request", call)
        _need(
            isinstance(returned, ast.Return) and returned.value is None,
            returned,
            "validated request path returns data",
        )
        handler = trial.handlers[0]
        normalized = ("AttributeError", "RecursionError", "RuntimeError")
        _need(
            handler.name is None
            and isinstance(handler.type, ast.Tuple)
            and tuple(
                part.id if isinstance(part, ast.Name) else None
                for part in handler.type.elts
            )
            == normalized
            and len(handler.body) == 1
            and isinstance(handler.body[0], ast.Pass),
            handler,
            "only native layout, recursion and runtime errors may be normalized",
        )
        for name in normalized:
            self.native(name, handler)
        self.refusal([final])
        self.step(
            trial,
            "fresh-normalized-refusal",
            context="the local normalization handler has ended; CPython restores any enclosing caller exception state, so the new refusal can inherit that caller exception as __context__",
            exception_sanitization_proved=False,
            scope="literal refusal arguments only; inherited caller context and traceback frames may retain candidate data",
        )
        return self.finish_module(
            "validate_output_request",
            function,
            "returns None exactly when the request validator returns; native layout, recursion and runtime errors become a fresh literal refusal; every other refusal propagates unchanged",
            {"destination": "user", "output_id": "out-1", "content": "text"},
        )

    def descriptor_helper(self):
        """Derive finite native namespace selection before any field access."""
        function, (owner, name), body = self.module_function("_native_descriptor", 2)
        _need(len(body) == 10, function, "descriptor capture has unmodeled statements")
        guard = self.guard(body[0])
        _need(
            isinstance(guard, ast.BoolOp)
            and isinstance(guard.op, ast.Or)
            and len(guard.values) == 3,
            guard,
            "descriptor capture does not first admit its class and field name",
        )
        class_test, name_test, empty = guard.values
        _need(
            isinstance(class_test, ast.UnaryOp) and isinstance(class_test.op, ast.Not),
            class_test,
            "descriptor owner lacks a native class guard",
        )
        self.call(
            class_test.operand,
            "issubclass",
            (lambda node: isinstance(node, ast.Call), lambda node: _name(node, "type")),
        )
        self.call(
            class_test.operand.args[0], "type", (lambda node: _name(node, owner),)
        )
        _need(
            isinstance(name_test, ast.Compare)
            and len(name_test.ops) == 1
            and isinstance(name_test.ops[0], ast.IsNot)
            and _name(name_test.comparators[0], "str"),
            name_test,
            "descriptor field name lacks an exact string guard",
        )
        self.call(name_test.left, "type", (lambda node: _name(node, name),))
        self.native("str", name_test)
        _need(
            isinstance(empty, ast.UnaryOp)
            and isinstance(empty.op, ast.Not)
            and _name(empty.operand, name),
            empty,
            "descriptor name emptiness is not a native string check",
        )
        namespace = self.owned_local(body[1], {owner, name})
        get = body[1].value
        _need(
            isinstance(get, ast.Call)
            and isinstance(get.func, ast.Attribute)
            and get.func.attr == "__get__"
            and len(get.args) == 1
            and _name(get.args[0], owner)
            and not get.keywords,
            get,
            "class namespace access can invoke a foreign metaclass",
        )
        descriptor = get.func.value
        _need(
            isinstance(descriptor, ast.Subscript)
            and _attribute(descriptor.value, "type", "__dict__")
            and _constant(descriptor.slice, "__dict__"),
            descriptor,
            "class namespace is not read through the immutable native metaclass descriptor",
        )
        self.native("type", descriptor)
        pairs = self.owned_local(body[2], {owner, name, namespace})
        self.call(body[2].value, "tuple", (lambda node: isinstance(node, ast.Call),))
        self.call(body[2].value.args[0], "items", (), receiver=namespace)
        self.step(
            body[2],
            "native-class-namespace-snapshot",
            shape="exact tuple of exact key/value tuples from the native mappingproxy",
        )
        first = body[3]
        _need(
            isinstance(first, ast.For)
            and isinstance(first.target, ast.Tuple)
            and len(first.target.elts) == 2
            and all(isinstance(node, ast.Name) for node in first.target.elts)
            and _name(first.iter, pairs)
            and len(first.body) == 1
            and not first.orelse,
            first,
            "descriptor namespace keys are not all checked before comparison",
        )
        key, discarded = (node.id for node in first.target.elts)
        _need(
            key != discarded and not {key, discarded} & {owner, name, namespace, pairs},
            first,
            "descriptor namespace scan overwrites live bindings",
        )
        self.exact_guard(first.body[0], key, "str")
        self.step(
            first,
            "all-native-class-keys-induction",
            invariant="every snapshotted key has exact str type before any comparison",
        )
        selected = self.owned_local(
            body[4], {owner, name, namespace, pairs, key, discarded}
        )
        _need(
            _constant(body[4].value, None),
            body[4],
            "missing descriptor is not an inert None sentinel",
        )
        second = body[5]
        _need(
            isinstance(second, ast.For)
            and isinstance(second.target, ast.Tuple)
            and len(second.target.elts) == 2
            and all(isinstance(node, ast.Name) for node in second.target.elts)
            and _name(second.iter, pairs)
            and len(second.body) == 1
            and not second.orelse,
            second,
            "descriptor selection is not a complete finite namespace scan",
        )
        candidate_key, candidate = (node.id for node in second.target.elts)
        _need(
            candidate_key != candidate
            and not {candidate_key, candidate}
            & {owner, name, namespace, pairs, selected},
            second,
            "descriptor selection overwrites live bindings",
        )
        branch = second.body[0]
        _need(
            isinstance(branch, ast.If)
            and not branch.orelse
            and len(branch.body) == 1
            and isinstance(branch.test, ast.Compare)
            and _name(branch.test.left, candidate_key)
            and len(branch.test.ops) == 1
            and isinstance(branch.test.ops[0], ast.Eq)
            and _name(branch.test.comparators[0], name),
            branch,
            "descriptor lookup is not equality of the admitted native strings",
        )
        assignment = branch.body[0]
        _need(
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and _name(assignment.targets[0], selected)
            and _name(assignment.value, candidate),
            assignment,
            "descriptor lookup does not retain only the matching namespace value",
        )
        kinds = self.guard(body[6])
        _need(
            isinstance(kinds, ast.BoolOp)
            and isinstance(kinds.op, ast.And)
            and len(kinds.values) == 2,
            kinds,
            "descriptor type guard may admit a foreign descriptor protocol",
        )
        for comparison, kind in zip(
            kinds.values, ("MemberDescriptorType", "GetSetDescriptorType")
        ):
            _need(
                isinstance(comparison, ast.Compare)
                and len(comparison.ops) == 1
                and isinstance(comparison.ops[0], ast.IsNot)
                and _name(comparison.comparators[0], kind),
                comparison,
                "descriptor admission is not exact native type identity",
            )
            self.call(comparison.left, "type", (lambda node: _name(node, selected),))
            self.source_import(kind, "types." + kind, comparison)
        descriptor_name = self.owned_local(
            body[7],
            {
                owner,
                name,
                namespace,
                pairs,
                selected,
                candidate_key,
                candidate,
                key,
                discarded,
            },
        )
        _need(
            _attribute(body[7].value, selected, "__name__"),
            body[7],
            "descriptor name is not its admitted native metadata",
        )
        identity = self.guard(body[8])
        _need(
            isinstance(identity, ast.BoolOp)
            and isinstance(identity.op, ast.Or)
            and len(identity.values) == 3,
            identity,
            "descriptor owner/name correspondence is not checked",
        )
        own, exact, equal = identity.values
        _need(
            isinstance(own, ast.Compare)
            and _attribute(own.left, selected, "__objclass__")
            and len(own.ops) == 1
            and isinstance(own.ops[0], ast.IsNot)
            and _name(own.comparators[0], owner),
            own,
            "descriptor owner does not match the supplied exact class identity",
        )
        _need(
            isinstance(exact, ast.Compare)
            and len(exact.ops) == 1
            and isinstance(exact.ops[0], ast.IsNot)
            and _name(exact.comparators[0], "str"),
            exact,
            "descriptor metadata comparison lacks a native string guard",
        )
        self.call(exact.left, "type", (lambda node: _name(node, descriptor_name),))
        _need(
            isinstance(equal, ast.Compare)
            and _name(equal.left, descriptor_name)
            and len(equal.ops) == 1
            and isinstance(equal.ops[0], ast.NotEq)
            and _name(equal.comparators[0], name),
            equal,
            "descriptor metadata does not name the requested field",
        )
        _need(
            isinstance(body[9], ast.Return) and _name(body[9].value, selected),
            body[9],
            "descriptor helper returns something other than the checked descriptor",
        )
        self.step(body[8], "exact-native-descriptor-owner-and-name")
        return self.finish_module(
            "_native_descriptor",
            function,
            "returns the matching exact native member/getset descriptor owned by the supplied class and field name, or a literal refusal; no candidate metaclass, key comparison or descriptor protocol is called",
            {"owner": "SecurityLabels", "name": "confidentiality"},
            (
                "CPython type, issubclass with exact type as second operand, native type.__dict__ descriptor, mappingproxy snapshot and native descriptor metadata semantics",
                "source-selected native builtins/types imports are stable and the class namespace is not concurrently mutated; this proves helper call behavior, not module initialization or subsequent runtime binding",
            ),
        )

    def labels_constructor(self):
        """Derive the actual generated constructor and source post-init.

        Slot layout alone says nothing about post-init effects. This restricted
        derivation applies only to the wrapper's owned frozenset[str] and literal
        integrity inputs; it does not admit arbitrary constructor arguments.
        """
        cls = next(
            node
            for node in self.objects.body
            if isinstance(node, ast.ClassDef) and node.name == "SecurityLabels"
        )
        _need(
            self.records["SecurityLabels"] == ["confidentiality", "integrity"],
            cls,
            "label construction does not have exactly the derived two fields",
        )
        methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)]
        _need(
            len(methods) == 1 and methods[0].name == "__post_init__",
            cls,
            "label constructor requires exactly its source post-init",
        )
        function = methods[0]
        args = function.args
        _need(
            not function.decorator_list
            and len(args.args) == 1
            and not args.posonlyargs
            and not args.kwonlyargs
            and not args.vararg
            and not args.kwarg
            and not args.defaults,
            function,
            "label post-init signature is unmodeled",
        )
        receiver = args.args[0].arg
        body = _body(function)
        self.closed(function, {receiver})
        bindings = _module_bindings(self.objects)
        local_names = {receiver} | {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        }
        for name in ("any", "object", "frozenset", "ValueError"):
            _need(
                name not in bindings and name not in local_names,
                function,
                "label constructor native binding is shadowed: " + name,
            )
        _need(len(body) == 3, function, "label post-init has unmodeled effects")
        self.steps = []
        for node in body[:2]:
            _need(
                isinstance(node, ast.If) and not node.orelse and len(node.body) == 1,
                node,
                "label constructor guard control flow is unmodeled",
            )
            refusal = node.body[0]
            _need(
                isinstance(refusal, ast.Raise)
                and refusal.cause is None
                and isinstance(refusal.exc, ast.Call)
                and _name(refusal.exc.func, "ValueError")
                and len(refusal.exc.args) == 1
                and not refusal.exc.keywords
                and isinstance(refusal.exc.args[0], ast.Constant)
                and type(refusal.exc.args[0].value) is str,
                refusal,
                "label constructor refusal is not native and literal",
            )
        integrity = body[0].test
        _need(
            isinstance(integrity, ast.UnaryOp)
            and isinstance(integrity.op, ast.Not)
            and _attribute(integrity.operand, receiver, "integrity"),
            integrity,
            "label constructor integrity guard is unmodeled",
        )
        labels = body[1].test
        _need(
            isinstance(labels, ast.Call)
            and _name(labels.func, "any")
            and len(labels.args) == 1
            and not labels.keywords
            and isinstance(labels.args[0], ast.GeneratorExp),
            labels,
            "label constructor confidentiality guard is unmodeled",
        )
        generator = labels.args[0]
        _need(len(generator.generators) == 1, generator, "unmodeled label iteration")
        loop = generator.generators[0]
        _need(
            isinstance(loop.target, ast.Name)
            and loop.target.id != receiver
            and _attribute(loop.iter, receiver, "confidentiality")
            and not loop.ifs
            and not loop.is_async
            and isinstance(generator.elt, ast.UnaryOp)
            and isinstance(generator.elt.op, ast.Not)
            and _name(generator.elt.operand, loop.target.id),
            generator,
            "label constructor iteration is not over exact native strings",
        )
        statement = body[2]
        call = statement.value if isinstance(statement, ast.Expr) else None
        _need(
            isinstance(call, ast.Call)
            and _attribute(call.func, "object", "__setattr__")
            and len(call.args) == 3
            and not call.keywords
            and _name(call.args[0], receiver)
            and _constant(call.args[1], "confidentiality"),
            statement,
            "label constructor changes something other than its own native slot",
        )
        frozen = call.args[2]
        _need(
            isinstance(frozen, ast.Call)
            and _name(frozen.func, "frozenset")
            and len(frozen.args) == 1
            and not frozen.keywords
            and _attribute(frozen.args[0], receiver, "confidentiality"),
            frozen,
            "label constructor does not preserve the derived compartments",
        )
        self.step(
            cls,
            "generated-native-dataclass-constructor",
            fields=self.records["SecurityLabels"],
            inputs="owned exact frozenset of nonempty str and literal trusted/low",
        )
        self.step(function, "source-post-init-native-fields-preserved")
        entry = self.finish_module(
            "SecurityLabels.__init__",
            function,
            "constructs an exact SecurityLabels preserving both supplied fields; its complete source post-init uses only native operations on the owned admitted inputs",
            {"confidentiality": ["secret"], "integrity": "low"},
            (
                "standard dataclasses generated constructor/slot semantics and stable source-selected bindings",
            ),
        )
        entry["entry"] = _OBJECTS + ".SecurityLabels.__init__"
        entry["generated_layout_source_lines"] = [cls.lineno, cls.end_lineno]
        return entry

    def wrapper_trial(self, function, body, size):
        """Consume the complete common exception-normalizing wrapper skeleton."""
        _need(len(body) == 2, function, "wrapper has unmodeled outer statements")
        trial, final = body
        _need(
            isinstance(trial, ast.Try)
            and len(trial.body) == size
            and len(trial.handlers) == 1
            and not trial.orelse
            and not trial.finalbody,
            trial,
            "wrapper exception control flow is unmodeled",
        )
        handler = trial.handlers[0]
        normalized = ("AttributeError", "RecursionError", "RuntimeError")
        _need(
            handler.name is None
            and isinstance(handler.type, ast.Tuple)
            and tuple(
                part.id if isinstance(part, ast.Name) else None
                for part in handler.type.elts
            )
            == normalized
            and len(handler.body) == 1
            and isinstance(handler.body[0], ast.Pass),
            handler,
            "wrapper may only normalize native layout/recursion/runtime failures",
        )
        for name in normalized:
            self.native(name, handler)
        self.refusal([final])
        self.step(
            trial,
            "wrapper-native-exception-normalization",
            exception_sanitization_proved=False,
            scope="literal refusal raised after its handler; traceback frames remain outside the publication proof",
        )
        return trial.body

    def fresh_walker(self, node, operands):
        _need(
            isinstance(node, ast.Call)
            and _name(node.func, "_Walker")
            and "_Walker" not in self.locals
            and self.bindings.get("_Walker") == "source:_Walker"
            and len(node.args) == 3
            and not node.keywords,
            node,
            "wrapper does not construct the source walker with three budgets",
        )
        for actual, expected in zip(node.args, operands):
            _need(
                _name(actual, expected)
                if isinstance(expected, str)
                else self.positive_literal(actual) == expected,
                actual,
                "wrapper changes a walker budget",
            )
        self.dependency("__init__", node)
        self.step(node, "fresh-local-walker", budgets=list(operands))

    def walk_wrapper(self):
        function, (value, depth, nodes, size), body = self.module_function("_walk", 4)
        _need(len(body) == 3, function, "walk wrapper has unmodeled statements")
        walker = self.owned_local(body[0], {value, depth, nodes, size})
        self.fresh_walker(body[0].value, (depth, nodes, size))
        projection = self.owned_local(body[1], {value, depth, nodes, size, walker})
        self.receiver = walker
        self.call(
            body[1].value, "walk", (lambda node: _name(node, value),), receiver=walker
        )
        self.dependency("walk", body[1])
        result = body[2]
        _need(
            isinstance(result, ast.Return)
            and isinstance(result.value, ast.Tuple)
            and len(result.value.elts) == 2
            and _name(result.value.elts[0], walker)
            and _name(result.value.elts[1], projection),
            result,
            "walk wrapper does not return the owned walker and its exact projection",
        )
        self.step(result, "owned-walker-and-projection-return")
        return self.finish_wrapper(
            "_walk",
            function,
            "returns the fresh owned walker and the exact tagged projection of the unchanged value, or a refusal; constructor validation rejects unsupported budgets",
            {"value": {"items": [1, "text"]}, "budgets": [64, 100000, 16777216]},
        )

    def labels_wrapper(self):
        function, (value,), body = self.module_function("validate_security_labels", 1)
        validated, returned = self.wrapper_trial(function, body, 2)
        call = validated.value if isinstance(validated, ast.Expr) else None
        _need(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "labels"
            and len(call.args) == 1
            and _name(call.args[0], value)
            and not call.keywords,
            validated,
            "label wrapper does not validate the unchanged input",
        )
        self.fresh_walker(call.func.value, (64, 100000, 16777216))
        self.dependency("labels", validated)
        # The source labels signature must bind this positional input and its
        # proved collect=True default, even for the temporary receiver call.
        signature = self.methods["labels"].args
        _need(
            len(signature.args) == 2
            and not signature.defaults
            and len(signature.kwonlyargs) == 1
            and _constant(signature.kw_defaults[0], True),
            validated,
            "label wrapper source-call binding is unproved",
        )
        _need(
            isinstance(returned, ast.Return) and _name(returned.value, value),
            returned,
            "label wrapper does not return the validated original object",
        )
        self.step(returned, "exact-validated-labels-return")
        return self.finish_wrapper(
            "validate_security_labels",
            function,
            "returns the identical exact SecurityLabels with native nonempty string fields/frozenset compartments, or a refusal; no candidate protocol runs",
            {"confidentiality": ["secret"], "integrity": "low"},
        )

    def data_wrapper(self):
        function, names, body = self.module_function(
            "validate_output_data",
            1,
            (
                ("max_depth", 64),
                ("max_nodes", 100000),
                ("max_bytes", 16777216),
                ("channel_labels", None),
            ),
        )
        value, depth, nodes, size, channels = names
        creation, conditional, walked, returned = self.wrapper_trial(function, body, 4)
        walker = self.owned_local(creation, set(names))
        self.fresh_walker(creation.value, (depth, nodes, size))
        self.receiver = walker
        _need(
            isinstance(conditional, ast.If)
            and isinstance(conditional.test, ast.Compare)
            and _name(conditional.test.left, channels)
            and len(conditional.test.ops) == 1
            and isinstance(conditional.test.ops[0], ast.IsNot)
            and _constant(conditional.test.comparators[0], None)
            and len(conditional.body) == 1
            and isinstance(conditional.body[0], ast.Expr)
            and not conditional.orelse,
            conditional,
            "optional channel labels are not guarded by native None identity",
        )
        self.call(
            conditional.body[0].value,
            "channel_labels",
            (lambda node: _name(node, channels),),
            receiver=walker,
        )
        self.dependency("channel_labels", conditional)
        _need(isinstance(walked, ast.Expr), walked, "wrapper traversal is unmodeled")
        self.call(
            walked.value, "walk", (lambda node: _name(node, value),), receiver=walker
        )
        self.dependency("walk", walked)
        result = returned.value if isinstance(returned, ast.Return) else None
        _need(
            isinstance(result, ast.Call)
            and _name(result.func, "SecurityLabels")
            and len(result.args) == 2
            and not result.keywords,
            returned,
            "label result is not constructed from the collected state",
        )
        self.source_import("SecurityLabels", _OBJECTS + ".SecurityLabels", result)
        self.call(
            result.args[0],
            "frozenset",
            (lambda node: _attribute(node, walker, "confidentiality"),),
        )
        integrity = result.args[1]
        _need(
            isinstance(integrity, ast.IfExp)
            and _attribute(integrity.test, walker, "low_integrity")
            and _constant(integrity.body, "low")
            and _constant(integrity.orelse, "trusted"),
            integrity,
            "result integrity does not preserve the collected low-integrity fact",
        )
        self.dependency("SecurityLabels.__init__", returned)
        self.step(
            returned,
            "collected-label-join-return",
            channels="matching dictionary keys inherit the validated channel label data",
        )
        return self.finish_wrapper(
            "validate_output_data",
            function,
            "returns a fresh exact SecurityLabels containing the walker's collected compartment union and low integrity iff collection found non-trusted integrity, including matching supplied channel labels; it does not authenticate label provenance",
            {
                "value": {"answer": "text"},
                "channel_labels": {
                    "answer": {"confidentiality": ["secret"], "integrity": "low"}
                },
            },
        )

    def digest_wrapper(self):
        function, names, body = self.module_function(
            "output_data_digest",
            1,
            (("max_depth", 64), ("max_nodes", 100000), ("max_bytes", 16777216)),
        )
        value, depth, nodes, size = names
        walked, encoded, returned = self.wrapper_trial(function, body, 3)
        walker, projection = self.owned_local(walked, set(names), 2)
        call = walked.value
        _need(
            isinstance(call, ast.Call)
            and _name(call.func, "_walk")
            and "_walk" not in self.locals
            and self.bindings.get("_walk") == "source:_walk"
            and len(call.args) == 4
            and not call.keywords
            and all(
                _name(actual, expected) for actual, expected in zip(call.args, names)
            ),
            walked,
            "digest does not derive the unchanged input projection and budgets",
        )
        self.dependency("_walk", walked)
        _need(
            self.entries.get("walk", {}).get("projection_domain")
            == "finite acyclic exact lists with exact str/bool leaves",
            walked,
            "native JSON encoding requires the closed structural projection lemma",
        )
        encoding = self.owned_local(encoded, {*names, walker, projection})
        encode = encoded.value
        _need(
            isinstance(encode, ast.Call)
            and isinstance(encode.func, ast.Attribute)
            and encode.func.attr == "encode"
            and len(encode.args) == 1
            and _constant(encode.args[0], "ascii")
            and not encode.keywords,
            encoded,
            "digest encoding is not native ASCII of the JSON string",
        )
        serializer = encode.func.value
        _need(
            isinstance(serializer, ast.Call)
            and _attribute(serializer.func, "json", "dumps")
            and len(serializer.args) == 1
            and _name(serializer.args[0], projection)
            and len(serializer.keywords) == 2,
            serializer,
            "digest JSON input is not the admitted owned projection",
        )
        self.source_import("json", "json", serializer)
        keywords = serializer.keywords
        _need(
            keywords[0].arg == "ensure_ascii"
            and _constant(keywords[0].value, True)
            and keywords[1].arg == "separators"
            and isinstance(keywords[1].value, ast.Tuple)
            and len(keywords[1].value.elts) == 2
            and all(
                _constant(part, expected)
                for part, expected in zip(keywords[1].value.elts, (",", ":"))
            ),
            serializer,
            "digest JSON options may invoke a fallback or change encoding",
        )
        hexdigest = returned.value if isinstance(returned, ast.Return) else None
        _need(
            isinstance(hexdigest, ast.Call)
            and isinstance(hexdigest.func, ast.Attribute)
            and hexdigest.func.attr == "hexdigest"
            and not hexdigest.args
            and not hexdigest.keywords,
            returned,
            "digest return is not the native hash hexadecimal string",
        )
        digest = hexdigest.func.value
        _need(
            isinstance(digest, ast.Call)
            and _attribute(digest.func, "hashlib", "sha256")
            and len(digest.args) == 1
            and not digest.keywords,
            digest,
            "digest algorithm is not source-selected SHA256",
        )
        self.source_import("hashlib", "hashlib", digest)
        payload = digest.args[0]
        _need(
            isinstance(payload, ast.BinOp)
            and isinstance(payload.op, ast.Add)
            and _constant(payload.left, b"slanggraph-output-data-v1\x00")
            and _name(payload.right, encoding),
            payload,
            "digest input does not preserve domain separation and exact encoded projection",
        )
        self.step(
            serializer,
            "native-json-of-owned-projection",
            options={"ensure_ascii": True, "separators": [",", ":"]},
        )
        self.step(
            returned,
            "domain-separated-sha256-expression",
            collision_freedom_proved=False,
            representation_injectivity_proved=False,
            mutation_seal_proved=False,
        )
        return self.finish_wrapper(
            "output_data_digest",
            function,
            "normal return is the hexadecimal SHA256 of b'slanggraph-output-data-v1\\x00' plus ASCII JSON of the exact source-derived tagged projection; this establishes the encoded expression, not equality/injectivity or mutation sealing",
            {"value": {"items": [1, "text", None]}},
            (
                "The source-selected json.dumps, exact str.encode('ascii'), hashlib.sha256 and native hash.hexdigest implement their standard deterministic semantics on the owned exact list/string/bool projection and resulting bytes; their implementations are not proved here.",
            ),
        )

    def finish_wrapper(self, name, function, result, witness, premises=()):
        entry = self.finish_module(name, function, result, witness, premises)
        entry["scope"] = (
            "source-derived output wrapper contract under explicit native/layout/stability premises"
        )
        entry["entry_premises"] = [
            *_VALIDATOR_PREMISES,
            "The wrapper's root value and supplied channel-label values keep all traversed objects referenced and stable for its complete call; the wrapper does not detach or freeze them.",
            *premises,
        ]
        entry["external_layout_premises"] = sorted(set(self.layouts))
        entry["exception_sanitization_proved"] = False
        entry["runtime_binding_proved"] = False
        entry["initialization_proved"] = False
        entry["representation_injectivity_proved"] = False
        entry["collision_freedom_proved"] = False
        entry["mutation_seal_proved"] = False
        return entry


def verify_output_data_primitives(source: str, objects_source: str) -> dict:
    """Derive the primitive helpers, then the recursive validator from source."""
    report = {
        "schema_version": 1,
        "kind": "output-data-primitive-contracts",
        "proved": False,
        "validator_admission_proved": False,
        "effect_safety_proved": False,
        "system_complete": False,
        "runtime_binding_proved": False,
        "initialization_proved": False,
        "primitive_contracts_complete": False,
        "wrapper_contracts_complete": False,
        "source_sha256": {
            _MODULE: hashlib.sha256(source.encode()).hexdigest(),
            _OBJECTS: hashlib.sha256(objects_source.encode()).hexdigest(),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "primitive_contracts": [],
        "walk_scalar_cases": None,
        "validator_components": [],
        "validator_contract": None,
        "constructor_contracts": [],
        "wrapper_contracts": [],
        "descriptor_capture_contract": None,
        "issues": [],
        "remaining_obligations": [
            "Every reachable recursive walk/compound/record/fields path and every public wrapper; loop depth/node budgets, cycles, exception normalization and digest construction.",
            "All other descriptor/record inventories, initialization, runtime import/class/builtin/method binding, and preservation of receiver ownership across unproved methods.",
            "Mutable payload stability, label provenance, request authorization, approval binding, and caller publication.",
        ],
        "native_premises": [
            "CPython exact type identity, native scalar/container operations and immutable native dataclass slot descriptors have their specified semantics.",
            "Source-selected imports/classes/builtins and owned receiver method bindings match the supplied source and remain stable; this checker does not prove imports or initialization.",
        ],
    }
    try:
        engine = _PrimitiveDerivation(source, objects_source)
        report["descriptor_capture_contract"] = engine.entries["_native_descriptor"]
        for method in (
            engine.constructor,
            engine.charge,
            engine.string,
            engine.pairs,
            engine.string_set,
            engine.labels,
            engine.channel_labels,
        ):
            try:
                report["primitive_contracts"].append(method())
            except _Unproved as exc:
                report["issues"].append(
                    {
                        "primitive": method.__name__,
                        "line": exc.line,
                        "reason": exc.reason,
                    }
                )
        report["primitive_contracts_complete"] = (
            not report["issues"] and len(report["primitive_contracts"]) == 7
        )
        try:
            report["walk_scalar_cases"] = engine.scalar_walk()
        except _Unproved as exc:
            report["issues"].append(
                {
                    "component": "walk-scalar-cases",
                    "line": exc.line,
                    "reason": exc.reason,
                }
            )
        report["issues"].extend(engine.validator(report["walk_scalar_cases"]))
        report["validator_components"] = [
            engine.entries[name]
            for name in (
                "fields",
                "record",
                "compound",
                "walk",
                "_validate_output_request",
                "validate_output_request",
            )
            if name in engine.entries
        ]
        report["unproved_source_methods"] = sorted(
            set(engine.methods) - set(engine.entries)
        )
        for component, derive in (
            ("SecurityLabels.__init__", engine.labels_constructor),
            ("_walk", engine.walk_wrapper),
            ("validate_security_labels", engine.labels_wrapper),
            ("validate_output_data", engine.data_wrapper),
            ("output_data_digest", engine.digest_wrapper),
        ):
            try:
                entry = derive()
                report[
                    "constructor_contracts"
                    if component == "SecurityLabels.__init__"
                    else "wrapper_contracts"
                ].append(entry)
            except _Unproved as exc:
                report["issues"].append(
                    {"component": component, "line": exc.line, "reason": exc.reason}
                )
        report["wrapper_contracts_complete"] = (
            len(report["wrapper_contracts"]) == 4
            and len(report["constructor_contracts"]) == 1
            and not report["issues"]
        )
        if (
            not report["issues"]
            and report["primitive_contracts_complete"]
            and len(report["validator_components"]) == 6
            and not report["unproved_source_methods"]
            and report["wrapper_contracts_complete"]
        ):
            report["validator_contract"] = engine.contract()
            report["proved"] = True
            report["validator_admission_proved"] = True
            report["effect_safety_proved"] = True
            report["remaining_obligations"][0] = (
                "Wrapper source expression/flow contracts are derived, including the actual SecurityLabels post-init on admitted inputs. Standard JSON/ASCII/SHA256 behavior remains an explicit primitive premise; representation injectivity, collision freedom, mutation sealing, approval binding and caller publication remain unproved."
            )
    except (SyntaxError, ValueError, _Unproved, _RecordUnsupported) as exc:
        report["issues"].append(
            {
                "line": getattr(exc, "line", getattr(exc, "lineno", 0)),
                "reason": getattr(exc, "reason", str(exc)),
            }
        )
    return report
