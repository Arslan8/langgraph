"""Primitive output admission proofs reject changed behavior, not source hashes."""

import ast
from pathlib import Path

import pytest

from langgraph.prebuilt.security.objects import OutputRequest
from langgraph.prebuilt.security.output_data import (
    OutputDataError,
    validate_output_request,
)
from langgraph.prebuilt.security.output_data_verification import (
    verify_output_data_primitives,
)


def sources():
    base = Path(__file__).parents[2] / "langgraph" / "prebuilt" / "security"
    return (base / "output_data.py").read_text(), (base / "objects.py").read_text()


def changed_method(source, name, edit):
    tree = ast.parse(source)
    walker = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_Walker"
    )
    method = next(
        node
        for node in walker.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    edit(method)
    return ast.unparse(tree)


def replace_in_method(source, name, original, replacement):
    def edit(method):
        text = ast.unparse(method)
        assert original in text
        modified = ast.parse(text.replace(original, replacement)).body[0]
        method.args, method.body = modified.args, modified.body

    return changed_method(source, name, edit)


def assert_unproved(source, objects, primitive=None):
    report = verify_output_data_primitives(source, objects)
    assert not report["primitive_contracts_complete"], report
    assert report["issues"], report
    assert not report["proved"]
    assert not report["validator_admission_proved"]
    assert not report["effect_safety_proved"]
    if primitive is not None:
        assert not any(
            entry["entry"].endswith("." + primitive)
            for entry in report["primitive_contracts"]
        ), report


def test_actual_primitives_and_recursive_validator_have_source_derivations():
    report = verify_output_data_primitives(*sources())
    assert report["primitive_contracts_complete"], report
    assert len(report["primitive_contracts"]) == 7
    assert all(
        entry["proved"]
        and entry["all_body_statements_consumed"]
        and entry["useful_path"]
        for entry in report["primitive_contracts"]
    )
    pairs = next(
        entry
        for entry in report["primitive_contracts"]
        if entry["entry"].endswith(".pairs")
    )
    assert any(step["rule"] == "all-pairs-induction" for step in pairs["derivation"])
    # The recursive group and public wrappers are now derived from source; the
    # system, runtime-binding and initialization obligations stay open.
    assert report["unproved_source_methods"] == []
    assert not report["issues"], report["issues"]
    for flag in ("proved", "validator_admission_proved", "effect_safety_proved"):
        assert report[flag] is True
    for flag in ("system_complete", "runtime_binding_proved", "initialization_proved"):
        assert report[flag] is False
    contract = report["validator_contract"]
    assert contract["exception_sanitization_proved"] is False
    assert any("Field stability" in premise for premise in contract["entry_premises"])
    assert any("garbage collection" in p for p in contract["entry_premises"])
    assert contract["external_layout_premises"]


def test_comment_formatting_and_local_renaming_are_not_digest_exemptions():
    source, objects = sources()
    original = verify_output_data_primitives(source, objects)
    changed = replace_in_method(source, "pairs", "pairs", "items_snapshot")
    # Restore the entrypoint's public method name; only local bindings differ.
    changed = changed.replace("def items_snapshot(", "def pairs(")
    changed += "\n# Different source identity; the body is derived again.\n"
    report = verify_output_data_primitives(changed, objects)
    assert report["primitive_contracts_complete"], report
    assert report["source_sha256"] != original["source_sha256"]


@pytest.mark.parametrize(
    "primitive,original,replacement",
    [
        (
            "__init__",
            "type(limit) is not int or limit <= 0",
            "type(limit) is not int and limit <= 0",
        ),
        ("__init__", "self.nodes = max_nodes", "self.nodes = max_bytes"),
        (
            "__init__",
            "for limit in (max_depth, max_nodes, max_bytes):",
            "for max_depth in (max_depth, max_nodes, max_bytes):",
        ),
        ("charge", "self.nodes -= 1", "self.nodes += 1"),
        ("charge", "self.bytes < 0", "self.bytes > 0"),
        ("string", "type(value) is not str", "not isinstance(value, str)"),
        (
            "string",
            "type(value) is not str or (nonempty and (not value))",
            "(nonempty and not value) or type(value) is not str",
        ),
        ("string", "self.charge(4 * len(value))", "self.charge(4 * value.__len__())"),
        ("string", "return value", "return str(value)"),
        ("pairs", "tuple(dict.items(value))", "tuple(value.items())"),
        ("pairs", "type(key) is not str", "not isinstance(key, str)"),
        ("pairs", "for key, _ in pairs:", "for key, key in pairs:"),
        ("pairs", "for key, _ in pairs:", "for pairs, key in pairs:"),
        (
            "pairs",
            "for key, _ in pairs:\n        if type(key) is not str:",
            "for OutputDataError, _ in pairs:\n        if type(OutputDataError) is not str:",
        ),
        ("pairs", "return pairs", "return value"),
        (
            "pairs",
            "raise OutputDataError('output_data:string_key_required')",
            "raise OutputDataError(key)",
        ),
        (
            "string_set",
            "set if mutable else frozenset",
            "frozenset if mutable else set",
        ),
        ("string_set", "for item in snapshot:", "for snapshot in snapshot:"),
        (
            "string_set",
            "self.string(item, nonempty=True)",
            "self.string(item, nonempty=False)",
        ),
        ("string_set", "return sorted(snapshot)", "return sorted(value)"),
        ("labels", "confidentiality, integrity =", "integrity, integrity ="),
        (
            "labels",
            "slot.__get__(value) for slot in _LABEL_SLOTS",
            "value.__get__(value) for value in _LABEL_SLOTS",
        ),
        (
            "labels",
            "slot.__get__(value) for slot in _LABEL_SLOTS",
            "self.__get__(value) for self in _LABEL_SLOTS",
        ),
        ("labels", "compartments", "_LABEL_SLOTS"),
        ("labels", "confidentiality, integrity =", "SecurityLabels, integrity ="),
        (
            "labels",
            "self.confidentiality.update(compartments)",
            "self.active.update(compartments)",
        ),
        ("labels", "integrity != 'trusted'", "integrity == 'trusted'"),
        (
            "labels",
            "['SecurityLabels', compartments, integrity]",
            "['SecurityLabels', integrity, compartments]",
        ),
        (
            "channel_labels",
            "self.channels[key] = (compartments, integrity)",
            "self.channels[labels] = (compartments, integrity)",
        ),
        (
            "channel_labels",
            "self.labels(labels, collect=False)",
            "self.labels(labels, collect=True)",
        ),
        (
            "channel_labels",
            "_, compartments, integrity =",
            "key, compartments, integrity =",
        ),
    ],
)
def test_mutated_primitive_effects_and_correspondence_are_unproved(
    primitive, original, replacement
):
    source, objects = sources()
    assert_unproved(
        replace_in_method(source, primitive, original, replacement), objects, primitive
    )


@pytest.mark.parametrize(
    "primitive",
    ["__init__", "charge", "string", "pairs", "string_set", "labels", "channel_labels"],
)
def test_deny_all_replacements_do_not_supply_useful_primitive_proofs(primitive):
    source, objects = sources()
    changed = changed_method(
        source,
        primitive,
        lambda method: setattr(
            method, "body", ast.parse("raise OutputDataError('denied')").body
        ),
    )
    assert_unproved(changed, objects, primitive)


@pytest.mark.parametrize("primitive", ["string", "pairs", "string_set", "labels"])
def test_candidate_protocol_before_guard_is_not_ignored(primitive):
    source, objects = sources()

    def edit(method):
        method.body.insert(0, ast.parse("value.model_dump()").body[0])

    assert_unproved(changed_method(source, primitive, edit), objects, primitive)


@pytest.mark.parametrize(
    "binding",
    [
        "type",
        "len",
        "tuple",
        "dict",
        "str",
        "set",
        "frozenset",
        "sorted",
        "PermissionError",
    ],
)
def test_rebound_native_module_operations_are_not_certified(binding):
    source, objects = sources()
    assert_unproved(source + "\n" + binding + " = unknown\n", objects)


def test_local_binding_semantics_prevent_a_false_useful_path():
    source, objects = sources()
    # Even the earlier guard's type() refers to this local under Python's rules.
    changed = replace_in_method(
        source,
        "pairs",
        "pairs = tuple(dict.items(value))",
        "type = tuple(dict.items(value))",
    )
    changed = replace_in_method(
        changed, "pairs", "for key, _ in pairs:", "for key, _ in type:"
    )
    changed = replace_in_method(changed, "pairs", "return pairs", "return type")
    assert_unproved(changed, objects, "pairs")


def test_descriptor_inventory_is_derived_from_actual_record_fields():
    source, objects = sources()
    changed = source.replace(
        'for name in ("confidentiality", "integrity")',
        'for name in ("integrity", "confidentiality")',
        1,
    )
    assert changed != source
    assert_unproved(changed, objects)
    changed = objects.replace(
        "class SecurityLabels:",
        "class SecurityLabels:\n    def __getattribute__(self, name):\n        return unknown(name)",
    )
    assert_unproved(source, changed)
    formatted = ast.unparse(ast.parse(source))
    changed = formatted.replace(
        "_native_descriptor(SecurityLabels, name) for name in",
        "_native_descriptor(SecurityLabels, SecurityLabels) for SecurityLabels in",
    )
    assert changed != formatted
    assert_unproved(changed, objects)


def test_refusal_constructor_and_module_effects_remain_obligations():
    source, objects = sources()
    changed = source.replace(
        "class OutputDataError(PermissionError):",
        "class OutputDataError(PermissionError):\n    def __new__(cls, message):\n        return unknown(message)",
    )
    assert_unproved(changed, objects)
    assert_unproved(source + "\nunknown()\n", objects)
    assert_unproved(source + "\nfrom unknown import *\n", objects)
    assert_unproved(source, objects + "\nfrom unknown import *\n")


def test_unknown_recursive_behavior_cannot_turn_partial_contracts_into_a_gate():
    source, objects = sources()
    changed = changed_method(
        source,
        "compound",
        lambda method: setattr(
            method, "body", ast.parse("return value.privileged_operation()").body
        ),
    )
    report = verify_output_data_primitives(changed, objects)
    assert report["primitive_contracts_complete"]
    assert "compound" in report["unproved_source_methods"]
    assert not report["proved"]
    assert not report["validator_admission_proved"]
    assert not report["effect_safety_proved"]


def assert_scalar_unproved(source, objects):
    report = verify_output_data_primitives(source, objects)
    assert report["walk_scalar_cases"] is None, report
    assert report["issues"], report
    assert not report["proved"]
    assert not report["validator_admission_proved"]
    assert not report["effect_safety_proved"]


def test_actual_scalar_walk_paths_have_useful_source_derived_projections():
    report = verify_output_data_primitives(*sources())
    scalar = report["walk_scalar_cases"]
    assert scalar is not None, report
    assert scalar["scalar_cases_complete"]
    assert [case["input_type"] for case in scalar["cases"]] == [
        "NoneType",
        "str",
        "bool",
        "int",
        "finite float",
        "bytes",
    ]
    assert all(
        case["proved"]
        and case["all_selected_path_statements_consumed"]
        and case["useful_path"]
        for case in scalar["cases"]
    )
    assert not scalar["whole_method_proved"]
    assert not scalar["unproved_suffix"]["proved"]
    assert scalar["unproved_suffix"]["source_lines"]
    # The scalar component never certifies the suffix; the separate whole-walk
    # derivation does, by induction on the remaining depth.
    walk = next(
        entry
        for entry in report["validator_components"]
        if entry["entry"].endswith("._Walker.walk")
    )
    assert any(step["rule"] == "walk-induction" for step in walk["derivation"])


@pytest.mark.parametrize(
    "original,replacement",
    [
        ("if depth > self.depth:", "if depth < self.depth:"),
        ("kind = type(value)", "kind = value.__class__"),
        ("kind = type(value)", "value = type(value)"),
        ("self.charge()", "self.charge(-1)"),
        ("if value is None:", "if type(value) is None:"),
        ("if kind is str:", "if isinstance(value, str):"),
        ("if kind is bool:", "if kind == bool:"),
        ("return ['str', self.string(value)]", "return ['str', value]"),
        ("return ['bool', value]", "return ['bool', True]"),
        ("(int.bit_length(value) + 7) // 8", "(value.bit_length() + 7) // 8"),
        ("(int.bit_length(value) + 7) // 8", "(int.bit_length(value) + 7) // 16"),
        ("return ['int', hex(value)]", "return ['int', value.__hex__()]"),
        ("return ['int', hex(value)]", "return ['str', hex(value)]"),
        ("if not math.isfinite(value):", "if math.isfinite(value):"),
        ("math.isfinite(value)", "math.isfinite(depth)"),
        ("return ['float', float.hex(value)]", "return ['float', value.hex()]"),
        ("self.charge(len(value))", "self.charge(value.__len__())"),
        ("return ['bytes', bytes.hex(value)]", "return ['bytes', bytes.hex(depth)]"),
        ("return ['none']", "raise OutputDataError('denied')"),
    ],
)
def test_scalar_protocol_budget_and_projection_mutations_remain_unproved(
    original, replacement
):
    source, objects = sources()
    assert_scalar_unproved(
        replace_in_method(source, "walk", original, replacement), objects
    )


@pytest.mark.parametrize(
    "suffix",
    [
        "del type",
        "import builtins as type",
        "def type(value):\n    return unknown(value)",
        "match None:\n    case type:\n        pass",
        "try:\n    pass\nexcept Exception as type:\n    pass",
        "del hex",
        "import math",
        "def OutputDataError(reason):\n    return unknown(reason)",
        "global unknown",
        "yield value",
        "yield from value",
    ],
)
def test_unproved_suffix_cannot_change_prefix_compilation_or_native_bindings(suffix):
    source, objects = sources()

    def edit(method):
        method.body.extend(ast.parse(suffix).body)

    assert_scalar_unproved(changed_method(source, "walk", edit), objects)


def test_unproved_suffix_remains_required_even_when_scalar_slice_is_unchanged():
    source, objects = sources()

    def edit(method):
        method.body = (
            method.body[:9] + ast.parse("return value.privileged_operation()").body
        )

    report = verify_output_data_primitives(
        changed_method(source, "walk", edit), objects
    )
    assert report["walk_scalar_cases"]["scalar_cases_complete"]
    assert report["walk_scalar_cases"]["unproved_suffix"]["statement_kinds"] == [
        "Return"
    ]
    assert not report["walk_scalar_cases"]["whole_method_proved"]
    assert "walk" in report["unproved_source_methods"]
    assert not report["proved"]


def test_scalar_prefix_never_executes_candidate_source_to_obtain_a_witness():
    source, objects = sources()

    def edit(method):
        method.body.insert(
            0, ast.parse("raise RuntimeError('candidate body must not run')").body[0]
        )

    report = verify_output_data_primitives(
        changed_method(source, "walk", edit), objects
    )
    assert report["walk_scalar_cases"] is None
    assert any(
        "scalar depth" in issue["reason"]
        or "literal refusal" in issue["reason"]
        or "guard control" in issue["reason"]
        for issue in report["issues"]
    )


@pytest.mark.parametrize(
    "primitive,old,new",
    [("string", "nonempty", "required"), ("labels", "collect", "gather")],
)
def test_primitive_call_keywords_bind_against_the_actual_callee_signature(
    primitive, old, new
):
    source, objects = sources()
    changed = replace_in_method(source, primitive, old, new)
    report = verify_output_data_primitives(changed, objects)
    assert not report["primitive_contracts_complete"], report
    assert any("keyword" in issue["reason"] for issue in report["issues"])
    assert not report["proved"]


def test_consistent_keyword_parameter_and_call_renames_are_source_derived():
    source, objects = sources()
    # Every declaration, use and call site changes together; no source digest or
    # original keyword spelling grants the native call binding.
    changed = source.replace("nonempty", "required").replace("collect", "gather")
    report = verify_output_data_primitives(changed, objects)
    assert report["primitive_contracts_complete"], report
    assert report["walk_scalar_cases"]["scalar_cases_complete"]
    assert any(
        step["rule"] == "source-call-signature-binding"
        for entry in report["primitive_contracts"]
        for step in entry["derivation"]
    )


def test_literal_refusal_evidence_does_not_claim_exception_publication_safety():
    report = verify_output_data_primitives(*sources())
    refusals = [
        step
        for entry in report["primitive_contracts"]
        for step in entry["derivation"]
        if step["rule"] == "literal-native-refusal"
    ]
    assert refusals
    assert all(step["exception_sanitization_proved"] is False for step in refusals)


def assert_validator_unproved(source, objects):
    report = verify_output_data_primitives(source, objects)
    assert report["issues"], report
    assert report["validator_contract"] is None
    for flag in ("proved", "validator_admission_proved", "effect_safety_proved"):
        assert report[flag] is False
    return report


def test_recursive_validator_contract_is_source_derived_by_induction():
    report = verify_output_data_primitives(*sources())
    contract = report["validator_contract"]
    assert contract["proved"] and contract["components"]
    entries = {
        entry["entry"].rsplit(".", 1)[1]: entry
        for entry in report["validator_components"]
    }
    assert set(entries) == {
        "fields",
        "record",
        "compound",
        "walk",
        "_validate_output_request",
        "validate_output_request",
    }
    assert all(entry["all_body_statements_consumed"] for entry in entries.values())
    for name in ("record", "compound"):
        assert entries[name]["inductive_hypothesis"] == "walk at depth + 1"
    (induction,) = [
        step
        for step in entries["walk"]["derivation"]
        if step["rule"] == "walk-induction"
    ]
    assert induction["closes"] == ["record", "compound"]
    inputs = [item for case in entries["compound"]["cases"] for item in case["inputs"]]
    assert "dict" in inputs and "uuid.UUID" in inputs
    assert "builtins.KeyError" in inputs
    assert {"_MODELS", "_SLOT_RECORDS", "_PLAIN_ERRORS"} <= set(contract["inventories"])


@pytest.mark.parametrize(
    "original,replacement",
    [
        (
            "[self.string(key), self.walk(child, depth + 1)]",
            "[self.string(key), self.walk(child, depth)]",
        ),
        (
            "[self.walk(child, depth + 1) for child in snapshot]",
            "[self.walk(child, depth + 2) for child in snapshot]",
        ),
        ("if kind is dict:", "if isinstance(value, dict):"),
        ("self.string(str.__str__(value))", "self.string(str(value))"),
        (
            "            snapshot = tuple(value)\n            return [",
            "            snapshot = list(value)\n            return [",
        ),
        ('number = object.__getattribute__(value, "int")', "number = value.int"),
        ("    NotImplementedError,\n)", "    NotImplementedError,\n    OSError,\n)"),
        (
            '        raise OutputDataError("output_data:unsupported_type")',
            '        return ["unknown"]',
        ),
        (
            "copied = dict(fields)",
            'copied = dict(object.__getattribute__(value, "__dict__"))',
        ),
        (
            "return tuple(copied[name] for name in names)",
            "return tuple(getattr(value, name) for name in names)",
        ),
        ("zip(names, values)", "zip(names, values, strict=True)"),
        ("if identity in self.active:", "if value in self.active:"),
        (
            "return self.compound(value, kind, depth)",
            "return self.compound(value, type(value), depth)",
        ),
        ("    walker.walk(content)\n", ""),
        ("    walker.labels(labels)\n", ""),
        ('("name", "value", "labels")', '("name", "labels", "value")'),
        (
            '_MODEL_EXTRA = _native_descriptor(BaseModel, "__pydantic_extra__")',
            '_MODEL_EXTRA = _native_descriptor(BaseModel, "__pydantic_private__")',
        ),
        (
            "_native_descriptor(Interrupt, name) for name in",
            "_native_descriptor(Command, name) for name in",
        ),
        (
            '(BaseMessage, "BaseMessage", _MESSAGE),',
            '(_Walker, "BaseMessage", _MESSAGE),',
        ),
        ("inherited = self.channels.get(key)", "inherited = self.channels.get(_)"),
        ("expected.__name__,", "value.__class__.__name__,"),
        (
            '["extra", self.walk(extra, depth + 1)]',
            '["extra", self.walk(fields, depth + 1)]',
        ),
        ("_GENERATION = (", "tuple = list\n_GENERATION = ("),
        (
            "walker = _Walker(64, 100_000, 16 * 1024 * 1024)",
            "walker = _Walker(64, -1, 16 * 1024 * 1024)",
        ),
        (
            "_MODEL_FIELDS_SET.__get__(value), mutable=True",
            "_MODEL_FIELDS_SET.__get__(value), mutable=False",
        ),
        (
            "    except (AttributeError, RecursionError, RuntimeError):\n        pass\n    # Missing",
            "    except Exception:\n        pass\n    # Missing",
        ),
    ],
)
def test_recursive_validator_mutations_are_unproved(original, replacement):
    source, objects = sources()
    assert source.count(original) == 1
    assert_validator_unproved(source.replace(original, replacement), objects)


@pytest.mark.parametrize(
    "removed",
    [
        "            if len(value) > self.nodes:\n"
        '                raise OutputDataError("output_data:budget")\n',
        "            if schema is not None and type(schema) is not dict:\n"
        '                raise OutputDataError("output_data:interrupt_schema")\n',
        "                if kind is Command and self.pairs(\n"
        '                    object.__getattribute__(value, "__dict__")\n'
        "                ):\n"
        '                    raise OutputDataError("output_data:record_shape")\n',
        '                    or self.pairs(object.__getattribute__(value, "__dict__"))\n',
        "    if not walker.confidentiality.issubset(confidentiality):\n"
        '        raise OutputDataError("output_data:payload_confidentiality")\n',
        "                if tuple.__len__(value) != len(names):\n"
        '                    raise OutputDataError("output_data:record_shape")\n',
        "        try:\n            return self.compound(value, kind, depth)\n"
        "        finally:\n            self.active.remove(identity)\n",
    ],
)
def test_removed_validator_guards_are_unproved(removed):
    source, objects = sources()
    assert source.count(removed) == 1
    assert_validator_unproved(source.replace(removed, ""), objects)


def test_extra_walker_method_or_module_rebinding_blocks_the_contract():
    source, objects = sources()

    def edit(method):
        method.body.append(ast.parse("return None").body[0])

    unused = source.replace(
        "    def fields(self, value: object, names: tuple) -> tuple:",
        "    def reset(self) -> None:\n        self.depth = 1_000_000\n\n"
        "    def fields(self, value: object, names: tuple) -> tuple:",
    )
    report = assert_validator_unproved(unused, objects)
    assert "reset" in report["unproved_source_methods"]
    rebinding = source + "\n\ndef widen():\n    global _MODELS\n    _MODELS = ()\n"
    report = assert_validator_unproved(rebinding, objects)
    assert any(issue.get("component") == "module" for issue in report["issues"])
    cyclic = source.replace("_GENERATION = (", "_GENERATION = _GENERATION + (")
    report = assert_validator_unproved(cyclic, objects)
    assert any("cyclic" in issue["reason"] for issue in report["issues"])
    # A trailing unreachable statement is still unmodeled source.
    assert_validator_unproved(changed_method(source, "compound", edit), objects)


def test_deny_all_or_extra_dispatch_do_not_supply_the_validator_contract():
    source, objects = sources()
    deny_all = changed_method(
        source,
        "compound",
        lambda method: setattr(
            method,
            "body",
            ast.parse('raise OutputDataError("output_data:unsupported_type")').body,
        ),
    )
    assert_validator_unproved(deny_all, objects)
    extra = source.replace(
        "        if kind is dict:",
        "        if kind is set:\n            return ['set', sorted(value)]\n"
        "        if kind is dict:",
    )
    assert_validator_unproved(extra, objects)


def test_unclosed_induction_retracts_conditional_recursive_contracts():
    source, objects = sources()
    changed = source.replace("if identity in self.active:", "if value in self.active:")
    report = assert_validator_unproved(changed, objects)
    assert {"walk", "record", "compound"} <= set(report["unproved_source_methods"])
    assert "fields" not in report["unproved_source_methods"]


@pytest.mark.parametrize(
    "original,replacement",
    [
        (
            '_GENERATION = ("text", "generation_info", "type")',
            '_GENERATION = ("text", "text", "type")',
        ),
        (
            '("run_id", "status", "checkpoint_id"',
            '("run_id", "run_id", "checkpoint_id"',
        ),
        ('("node", "arg", "timeout")', '("node", "node", "timeout")'),
    ],
)
def test_duplicate_inventory_field_names_cannot_hide_a_field(original, replacement):
    # Reviewer-found hole: a repeated name satisfied the length check while a
    # real field (and its nested labels) escaped traversal.
    source, objects = sources()
    assert source.count(original) >= 1
    report = assert_validator_unproved(source.replace(original, replacement), objects)
    assert any("repeats or omits" in issue["reason"] for issue in report["issues"])


def test_a_class_cannot_be_shadowed_by_an_earlier_shorter_row():
    # Re-review finding: a first, shorter row for the same class wins dispatch.
    source, objects = sources()
    original = '        (Send, "Send", ("node", "arg", "timeout")),'
    assert source.count(original) == 1
    shadowed = source.replace(
        original, '        (Send, "Send", ("node", "arg")),\n' + original
    )
    report = assert_validator_unproved(shadowed, objects)
    assert any("more than one dispatch row" in i["reason"] for i in report["issues"])


def changed_function(source, name, edit):
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    edit(function)
    return ast.unparse(tree)


def replace_in_function(source, name, original, replacement):
    def edit(function):
        text = ast.unparse(function)
        assert original in text
        modified = ast.parse(text.replace(original, replacement)).body[0]
        function.args, function.body = modified.args, modified.body

    return changed_function(source, name, edit)


def test_actual_output_wrappers_have_complete_source_flow_contracts():
    report = verify_output_data_primitives(*sources())
    assert report["proved"], report["issues"]
    assert report["wrapper_contracts_complete"]
    assert {
        entry["entry"].rsplit(".", 1)[1] for entry in report["wrapper_contracts"]
    } == {
        "_walk",
        "validate_security_labels",
        "validate_output_data",
        "output_data_digest",
    }
    assert len(report["constructor_contracts"]) == 1
    constructor = report["constructor_contracts"][0]
    assert constructor["entry"].endswith(".SecurityLabels.__init__")
    assert constructor["all_body_statements_consumed"]
    assert {step["rule"] for step in constructor["derivation"]} == {
        "generated-native-dataclass-constructor",
        "source-post-init-native-fields-preserved",
    }
    for entry in report["wrapper_contracts"]:
        assert entry["proved"] and entry["all_body_statements_consumed"]
        assert entry["useful_path"] and entry["derivation"]
        assert entry["entry_premises"] and entry["external_layout_premises"]
        for flag in (
            "exception_sanitization_proved",
            "runtime_binding_proved",
            "initialization_proved",
            "representation_injectivity_proved",
            "collision_freedom_proved",
            "mutation_seal_proved",
        ):
            assert entry[flag] is False
    digest = next(
        entry
        for entry in report["wrapper_contracts"]
        if entry["entry"].endswith(".output_data_digest")
    )
    assert any(
        "json.dumps" in premise and "not proved here" in premise
        for premise in digest["entry_premises"]
    )


@pytest.mark.parametrize(
    "name,original,replacement",
    [
        ("_walk", "walker.walk(value)", "walker.walk(None)"),
        ("_walk", "return (walker, projection)", "return (walker, value)"),
        (
            "_walk",
            "_Walker(max_depth, max_nodes, max_bytes)",
            "_Walker(max_bytes, max_nodes, max_depth)",
        ),
        ("validate_security_labels", ".labels(value)", ".labels(None)"),
        ("validate_security_labels", "return value", "return SecurityLabels()"),
        (
            "validate_security_labels",
            "except (AttributeError, RecursionError, RuntimeError):",
            "except BaseException:",
        ),
        ("validate_output_data", "walker.walk(value)", "walker.walk(None)"),
        (
            "validate_output_data",
            "channel_labels is not None",
            "channel_labels is None",
        ),
        (
            "validate_output_data",
            "walker.channel_labels(channel_labels)",
            "walker.channel_labels({})",
        ),
        ("validate_output_data", "frozenset(walker.confidentiality)", "frozenset()"),
        (
            "validate_output_data",
            "'low' if walker.low_integrity else 'trusted'",
            "'trusted' if walker.low_integrity else 'low'",
        ),
        (
            "validate_output_data",
            "walker.walk(value)",
            "value.emit()\n        walker.walk(value)",
        ),
        (
            "output_data_digest",
            "_walk(value, max_depth, max_nodes, max_bytes)",
            "_walk(None, max_depth, max_nodes, max_bytes)",
        ),
        ("output_data_digest", "json.dumps(projection,", "json.dumps(value,"),
        ("output_data_digest", "ensure_ascii=True", "ensure_ascii=False"),
        (
            "output_data_digest",
            "separators=(',', ':')",
            "separators=(',', ':'), default=repr",
        ),
        ("output_data_digest", ".encode('ascii')", ".encode('utf-8')"),
        ("output_data_digest", "hashlib.sha256", "hashlib.md5"),
        (
            "output_data_digest",
            "b'slanggraph-output-data-v1\\x00' + encoded",
            "encoded",
        ),
        ("output_data_digest", ".hexdigest()", ".digest()"),
        (
            "output_data_digest",
            "return hashlib.sha256",
            "return value or hashlib.sha256",
        ),
    ],
)
def test_output_wrapper_semantic_mutations_have_no_contract(
    name, original, replacement
):
    source, objects = sources()
    changed = replace_in_function(source, name, original, replacement)
    report = verify_output_data_primitives(changed, objects)
    assert not report["proved"] and not report["wrapper_contracts_complete"]
    assert any(issue.get("component") == name for issue in report["issues"]), report[
        "issues"
    ]
    assert not any(
        entry["entry"].endswith("." + name) for entry in report["wrapper_contracts"]
    )


@pytest.mark.parametrize(
    "name",
    ["_walk", "validate_security_labels", "validate_output_data", "output_data_digest"],
)
def test_wrapper_extra_finally_effects_and_unreachable_suffixes_are_not_ignored(name):
    source, objects = sources()

    def extra(function):
        function.body.append(ast.parse("value.emit()").body[0])

    changed = changed_function(source, name, extra)
    report = verify_output_data_primitives(changed, objects)
    assert not report["wrapper_contracts_complete"]
    assert any(issue.get("component") == name for issue in report["issues"])
    if name != "_walk":

        def final(function):
            trial = next(node for node in function.body if isinstance(node, ast.Try))
            trial.finalbody = ast.parse("value.emit()").body

        report = verify_output_data_primitives(
            changed_function(source, name, final), objects
        )
        assert not report["wrapper_contracts_complete"]
        assert any(issue.get("component") == name for issue in report["issues"])


@pytest.mark.parametrize(
    "original,replacement",
    [
        ("if not self.integrity:", "if self.integrity:"),
        (
            "any(not label for label in self.confidentiality)",
            "any(label for label in self.confidentiality)",
        ),
        (
            'object.__setattr__(self, "confidentiality", frozenset(self.confidentiality))',
            'object.__setattr__(self, "confidentiality", frozenset())',
        ),
        (
            'object.__setattr__(self, "confidentiality", frozenset(self.confidentiality))',
            "self.integrity.emit()",
        ),
        (
            'object.__setattr__(self, "confidentiality", frozenset(self.confidentiality))',
            'object.__setattr__(self, "confidentiality", frozenset(self.confidentiality))\n        self.integrity.emit()',
        ),
    ],
)
def test_wrapper_checks_actual_label_post_init_not_just_slot_layout(
    original, replacement
):
    source, objects = sources()
    assert objects.count(original) == 1
    report = verify_output_data_primitives(
        source, objects.replace(original, replacement)
    )
    assert not report["wrapper_contracts_complete"]
    assert report["constructor_contracts"] == []
    assert any(
        issue.get("component") == "SecurityLabels.__init__"
        for issue in report["issues"]
    )
    assert not any(
        entry["entry"].endswith(".validate_output_data")
        for entry in report["wrapper_contracts"]
    )


def test_wrapper_source_renaming_and_keyword_binding_are_rederived():
    source, objects = sources()
    original = verify_output_data_primitives(source, objects)

    class Rename(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in {"walker", "projection", "encoded"}:
                node.id = "derived_" + node.id
            return node

    changed = source
    for name in ("_walk", "validate_output_data", "output_data_digest"):
        changed = changed_function(
            changed, name, lambda function: Rename().visit(function)
        )
    report = verify_output_data_primitives(changed, objects)
    assert report["wrapper_contracts_complete"], report["issues"]
    assert report["source_sha256"] != original["source_sha256"]
    changed = replace_in_function(
        source, "output_data_digest", "max_depth: int=64", "depth: int=64"
    )
    report = verify_output_data_primitives(changed, objects)
    assert not report["wrapper_contracts_complete"]


def test_wrapper_lexical_native_and_module_shadowing_are_not_trusted():
    source, objects = sources()
    for name in ("json", "hashlib", "_walk"):
        changed = replace_in_function(
            source,
            "output_data_digest",
            "_, projection =",
            f"{name} = value\n        _, projection =",
        )
        assert not verify_output_data_primitives(changed, objects)[
            "wrapper_contracts_complete"
        ]
    for binding in ("any", "frozenset", "object", "ValueError"):
        assert not verify_output_data_primitives(
            source, objects + f"\n{binding} = str\n"
        )["wrapper_contracts_complete"]


def test_native_descriptor_capture_has_a_complete_source_derivation():
    report = verify_output_data_primitives(*sources())
    capture = report["descriptor_capture_contract"]
    assert report["proved"], report["issues"]
    assert capture["entry"].endswith("._native_descriptor")
    assert capture["proved"] and capture["all_body_statements_consumed"]
    assert capture["useful_path"]
    assert {step["rule"] for step in capture["derivation"]} >= {
        "native-class-namespace-snapshot",
        "all-native-class-keys-induction",
        "exact-native-descriptor-owner-and-name",
    }
    assert not report["initialization_proved"]
    assert not report["runtime_binding_proved"]


@pytest.mark.parametrize(
    "original,replacement",
    [
        ("not issubclass(type(owner), type)", "not isinstance(owner, type)"),
        ("type(name) is not str", "not isinstance(name, str)"),
        ("or (not name)", "or name"),
        ("type.__dict__['__dict__'].__get__(owner)", "owner.__dict__"),
        ("tuple(namespace.items())", "tuple(owner.items())"),
        ("type(key) is not str", "isinstance(key, str)"),
        ("if key == name:", "if key is name:"),
        ("if key == name:", "if key == owner:"),
        ("descriptor = item", "descriptor = key"),
        (
            "type(descriptor) is not MemberDescriptorType and type(descriptor) is not GetSetDescriptorType",
            "type(descriptor) is not MemberDescriptorType or type(descriptor) is not GetSetDescriptorType",
        ),
        ("descriptor_name = descriptor.__name__", "descriptor_name = name"),
        ("descriptor.__objclass__ is not owner", "descriptor.__objclass__ is owner"),
        ("type(descriptor_name) is not str", "not isinstance(descriptor_name, str)"),
        ("descriptor_name != name", "descriptor_name == name"),
        ("return descriptor", "return getattr(owner, name)"),
        ("return descriptor", "owner.emit()\n    return descriptor"),
        ("for key, _ in pairs:", "for owner, _ in pairs:"),
        ("for key, item in pairs:", "for name, item in pairs:"),
    ],
)
def test_descriptor_helper_semantic_mutations_cannot_certify_captures(
    original, replacement
):
    source, objects = sources()
    changed = replace_in_function(source, "_native_descriptor", original, replacement)
    report = verify_output_data_primitives(changed, objects)
    assert not report["proved"]
    assert report["descriptor_capture_contract"] is None
    assert report["issues"]


def test_descriptor_helper_must_check_all_keys_before_any_lookup():
    source, objects = sources()

    def reorder(function):
        body = function.body
        first = next(
            index for index, node in enumerate(body) if isinstance(node, ast.For)
        )
        check = body.pop(first)
        second = next(
            index for index, node in enumerate(body) if isinstance(node, ast.For)
        )
        body.insert(second + 1, check)

    report = verify_output_data_primitives(
        changed_function(source, "_native_descriptor", reorder), objects
    )
    assert not report["proved"]
    assert report["descriptor_capture_contract"] is None


@pytest.mark.parametrize(
    "original,replacement",
    [
        ("_native_descriptor(SecurityLabels, name)", "SecurityLabels.__dict__[name]"),
        ("_native_descriptor(Interrupt, name)", "Interrupt.__dict__[name]"),
        ("_native_descriptor(cls, name)", "cls.__dict__[name]"),
        (
            '_native_descriptor(BaseModel, "__pydantic_extra__")',
            'BaseModel.__dict__["__pydantic_extra__"]',
        ),
        ('_native_descriptor(BaseException, "args")', 'BaseException.__dict__["args"]'),
    ],
)
def test_each_descriptor_inventory_requires_the_source_derived_helper(
    original, replacement
):
    source, objects = sources()
    assert source.count(original) == 1
    report = verify_output_data_primitives(
        source.replace(original, replacement), objects
    )
    assert not report["proved"], report
    assert report["issues"]


def test_descriptor_capture_generator_cannot_shadow_the_helper_name():
    source, objects = sources()
    formatted = ast.unparse(ast.parse(source))
    original = "_native_descriptor(SecurityLabels, name) for name in"
    replacement = "_native_descriptor(SecurityLabels, _native_descriptor) for _native_descriptor in"
    assert original in formatted
    report = verify_output_data_primitives(
        formatted.replace(original, replacement), objects
    )
    assert not report["proved"]
    assert report["issues"]


@pytest.mark.parametrize(
    "name",
    [
        "_native_descriptor",
        "_walk",
        "validate_security_labels",
        "validate_output_data",
        "output_data_digest",
    ],
)
def test_deny_all_wrappers_do_not_supply_useful_contracts(name):
    source, objects = sources()

    def deny(function):
        function.body = ast.parse(
            'raise OutputDataError("output_data:unsupported_type")'
        ).body

    report = verify_output_data_primitives(
        changed_function(source, name, deny), objects
    )
    assert not report["proved"]
    assert not report["wrapper_contracts_complete"]
    assert not any(
        entry["entry"].endswith("." + name) for entry in report["wrapper_contracts"]
    )


def test_normalized_refusal_preserves_the_unproved_inherited_context_boundary():
    # Ending the local AttributeError handler restores the caller's already
    # active exception. It does not sanitize an exception publication channel.
    outer = ValueError("caller-context-marker")
    try:
        raise outer
    except ValueError:
        with pytest.raises(OutputDataError) as caught:
            validate_output_request(object.__new__(OutputRequest))
    assert caught.value.__context__ is outer
    assert caught.value.__cause__ is None
    assert caught.value.__traceback__ is not None
    assert caught.value.args == ("output_data:invalid_layout",)

    report = verify_output_data_primitives(*sources())
    assert report["proved"], report["issues"]
    assert report["validator_contract"]["exception_sanitization_proved"] is False
    public = next(
        entry
        for entry in report["validator_components"]
        if entry["entry"].endswith(".validate_output_request")
    )
    normalization = next(
        step
        for step in public["derivation"]
        if step["rule"] == "fresh-normalized-refusal"
    )
    assert normalization["exception_sanitization_proved"] is False
    assert "caller exception" in normalization["context"]
    assert "__context__" in normalization["context"]
    assert "traceback" in normalization["scope"]
