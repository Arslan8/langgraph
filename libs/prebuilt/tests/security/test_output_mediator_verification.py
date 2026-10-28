"""Output mediator correspondence derivations; candidate source is never executed."""

import ast
from pathlib import Path

import pytest

from langgraph.prebuilt.security.output_mediator_verification import (
    verify_output_mediator_correspondence,
)

_ROOT = Path(__file__).resolve().parents[2] / "langgraph/prebuilt/security"


def placement_source():
    return (_ROOT / "placement.py").read_text()


def dependency_sources():
    return {
        "router_source": (_ROOT / "host_router.py").read_text(),
        "output_data_source": (_ROOT / "output_data.py").read_text(),
        "objects_source": (_ROOT / "objects.py").read_text(),
        "object_manager_source": (_ROOT / "object_manager.py").read_text(),
    }


def verify(source, **extra):
    return verify_output_mediator_correspondence(source, **extra)


def mediator_method(source, name):
    tree = ast.parse(source)
    mediator = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "OutputMediator"
    )
    return next(
        node
        for node in mediator.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )


def method_text(source, name):
    method = mediator_method(source, name)
    lines = source.splitlines(keepends=True)
    return "".join(lines[method.lineno - 1 : method.end_lineno])


def replace_in_method(source, name, old, new, count=1):
    """Rewrite text inside one OutputMediator method only; `old` must occur."""
    text = method_text(source, name)
    assert old in text, (name, old)
    if count == "last":
        head, _, tail = text.rpartition(old)
        changed = head + new + tail
    else:
        changed = text.replace(old, new, count)
    return source.replace(text, changed, 1)


ENTRY_NAMES = (
    "_emit",
    "_aemit",
    "__call__",
    "acall",
    "callback",
    "acallback",
    "stream",
    "astream",
)


def test_actual_sources_prove_mediator_correspondence_with_recomputed_dependencies():
    report = verify(placement_source(), **dependency_sources())
    assert report["proved"], report["issues"]
    assert report["kind"] == "output-mediator-correspondence"
    assert not report["system_complete"]
    assert not report["runtime_binding_proved"]
    assert not report["initialization_proved"]
    assert not report["issues"] and not report["unproved_dependencies"]
    assert [entry["entry"].rsplit(".", 1)[-1] for entry in report["entries"]] == list(
        ENTRY_NAMES
    )
    assert all(entry["proved"] for entry in report["entries"])
    emit, aemit = report["entries"][:2]
    assert emit["normal_returns"] == 1 and emit["approval_raises"] == 1
    assert aemit["normal_returns"] == 3 and aemit["approval_raises"] == 1
    returned = [path for path in emit["paths"] if path["exit"] == "return"]
    assert returned[0]["result"] == ["rebuilt", "routed"]
    assert returned[0]["result_kind"] == "dispatch"
    rules = [step["rule"] for step in returned[0]["derivation"]]
    assert rules == [
        "exact-receiver-slot-reads",
        "captured-pair-check",
        "trusted-runtime-principal",
        "checked-host-output-labels",
        "trusted-runtime-operation-id",
        "output-request-construction",
        "captured-pair-check",
        "router-output-route",
        "native-authorization-classifier",
        "framework-rebuild",
        "exact-rebuilt-result-return",
    ]
    phases = [
        step["phase"]
        for step in returned[0]["derivation"]
        if step["rule"] == "captured-pair-check"
    ]
    assert phases == ["pre", "post"]
    approval = next(
        path
        for path in emit["paths"]
        if any(step["rule"] == "approval-required-raise" for step in path["derivation"])
    )
    assert approval["exit"] == "raise" and approval["result"] == []
    awaited = [path for path in aemit["paths"] if path["result"][-1:] == ["awaited"]]
    assert len(awaited) == 1
    assert awaited[0]["callback_delivery"] is True and awaited[0]["awaited"] is True
    wrappers = {
        entry["entry"].rsplit(".", 1)[-1]: entry for entry in report["entries"][2:]
    }
    assert wrappers["__call__"]["rebuild"] == "identity"
    assert wrappers["stream"]["rebuild"] == "framework-envelope-rebuild"
    assert wrappers["callback"]["rebuild"] == "callback-deliver-parameter"
    assert wrappers["callback"]["callback_delivery"] is True
    assert wrappers["astream"]["forwards_to"] == "_aemit"
    assert wrappers["__call__"]["forwards_to"] == "_emit"
    assert {helper["helper"].rsplit(".", 1)[-1] for helper in report["helpers"]} == {
        "_output_mediator_fields",
        "_require_output_host",
        "_principal",
        "_operation_id",
        "_identity",
        "_approval_required",
    }
    assert report["mediator_layout"]["slots"] == [
        "router",
        "host",
        "destination",
        "clearance",
    ]
    assert report["approval_exception"]["base"] == "PermissionError"
    kinds = {dependency["kind"]: dependency for dependency in report["dependencies"]}
    assert kinds["router-source-proof"]["proved"]
    assert kinds["router-source-proof"]["basis"] == "recomputed-source-proof"
    assert kinds["output-data-wrapper-contract"]["proved"]
    assert kinds["native-record-layout"]["fields"][:5] == [
        "destination",
        "content",
        "labels",
        "clearance",
        "output_id",
    ]
    assert kinds["host-labels-method-shape"]["applies_validate_output_data"]
    assert not kinds["host-labels-method-shape"]["body_derived"]
    assert set(report["source_sha256"]) == {
        "langgraph.prebuilt.security.placement",
        "langgraph.prebuilt.security.host_router",
        "langgraph.prebuilt.security.output_data",
        "langgraph.prebuilt.security.objects",
        "langgraph.prebuilt.security.object_manager",
    }
    assert report["entry_premises"] and report["remaining_composition"]
    assert len(report["checker_sha256"]) == 64


def test_missing_dependency_sources_become_explicit_premises_not_silent_trust():
    full = verify(placement_source(), **dependency_sources())
    bare = verify(placement_source())
    assert bare["proved"], bare["issues"]
    assert len(bare["entry_premises"]) == len(full["entry_premises"]) + 3
    bases = {
        dependency["kind"]: dependency["basis"] for dependency in bare["dependencies"]
    }
    assert bases == {
        "router-source-proof": "entry-premise",
        "output-data-wrapper-contract": "entry-premise",
    }
    assert set(bare["source_sha256"]) == {"langgraph.prebuilt.security.placement"}


def test_incomplete_router_proof_is_an_unproved_dependency():
    router = dependency_sources()["router_source"]
    broken = router.replace(
        "        return self.route(principal, request)\n",
        "        return request.content\n",
        1,
    )
    assert broken != router
    report = verify(placement_source(), router_source=broken)
    assert not report["proved"]
    assert report["unproved_dependencies"]
    assert report["unproved_dependencies"][0]["kind"] == "router-source-proof"
    assert not report["unproved_dependencies"][0]["proved"]


def test_unproved_output_data_contract_is_an_unproved_dependency():
    sources = dependency_sources()
    data = sources["output_data_source"]
    broken = data.replace("def validate_output_data(", "def validate_output_data_(", 1)
    assert broken != data
    report = verify(
        placement_source(),
        output_data_source=broken,
        objects_source=sources["objects_source"],
    )
    assert not report["proved"]
    assert report["unproved_dependencies"]
    assert report["unproved_dependencies"][0]["kind"] == "output-data-wrapper-contract"


RAW_CONTENT = lambda source: replace_in_method(  # noqa: E731
    source, "_emit", "return rebuild(result)", "return content"
)
RAW_RESULT = lambda source: replace_in_method(  # noqa: E731
    source, "_emit", "return rebuild(result)", "return result"
)
SKIP_SECOND_CHECK = lambda source: replace_in_method(  # noqa: E731
    source, "_emit", "        _require_output_host(router, host)\n", "", "last"
)
SKIP_FIRST_CHECK = lambda source: replace_in_method(  # noqa: E731
    source, "_emit", "        _require_output_host(router, host)\n", ""
)
CANDIDATE_CLEARANCE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "            clearance,\n            _operation_id",
    "            frozenset(),\n            _operation_id",
)
CONTENT_AS_CLEARANCE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "            clearance,\n            _operation_id",
    "            content,\n            _operation_id",
)
SWAPPED_SLOTS = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        request = OutputRequest(\n            destination,",
    "        request = OutputRequest(\n            clearance,",
)
RETURN_AUTHORIZATION = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        if isinstance(result, ObjectAuthorization):\n            raise self._approval_required(",
    "        if isinstance(result, ObjectAuthorization):\n            return rebuild(result)\n            raise self._approval_required(",
)
PRINT_CONTENT = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        return rebuild(result)",
    "        print(content)\n        return rebuild(result)",
)
CALLBACK_ON_NORMAL_PATH = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        return rebuild(result)",
    "        rebuild(content)\n        return rebuild(result)",
)
CALLBACK_BEFORE_ROUTE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        result = router.output_emit(principal, request)",
    "        rebuild(request)\n        result = router.output_emit(principal, request)",
)
UNCLASSIFIED_RESULT = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        if isinstance(result, ObjectAuthorization):",
    "        if isinstance(result, OutputRequest):",
)
LOCAL_REBOUND_REQUEST = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        request = OutputRequest(",
    "        OutputRequest = dict\n        request = OutputRequest(",
)
MODULE_REBOUND_REQUEST = lambda source: source + "\nOutputRequest = dict\n"  # noqa: E731
OTHER_ROUTE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "router.output_emit(principal, request)",
    "router.dispatch(principal, request)",
)
OTHER_PRINCIPAL = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "router.output_emit(principal, request)",
    "router.output_emit(content, request)",
)
UNCHECKED_LABELS_HOST = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "host.labels_for_output(principal, content)",
    "router.labels_for_output(principal, content)",
)
ASYNC_RAW_RETURN = lambda source: replace_in_method(  # noqa: E731
    source, "_aemit", "        return effective\n", "        return result\n"
)
ASYNC_SKIP_AWAIT_GUARD = lambda source: replace_in_method(  # noqa: E731
    source,
    "_aemit",
    "        if callback_delivery and inspect.isawaitable(effective):\n            return await effective\n",
    "",
)
ASYNC_SYNC_ROUTE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_aemit",
    "await router.aoutput_emit(principal, request)",
    "router.output_emit(principal, request)",
)
FIELDS_ISINSTANCE = lambda source: source.replace(  # noqa: E731
    "    if type(mediator) is not OutputMediator:\n",
    "    if not isinstance(mediator, OutputMediator):\n",
    1,
)
STREAM_ISINSTANCE = lambda source: replace_in_method(  # noqa: E731
    source,
    "stream",
    "        if type(self) is not OutputMediator:\n",
    "        if not isinstance(self, OutputMediator):\n",
)
STREAM_UNCHECKED_ENVELOPE = lambda source: replace_in_method(  # noqa: E731
    source,
    "stream",
    '        if type(envelope) is not _OutputEnvelope:\n            raise PermissionError("output:missing_framework_envelope")\n',
    "",
)
PAIR_CHECK_ISINSTANCE = lambda source: source.replace(  # noqa: E731
    "    if type(router) is not HostRouter:\n",
    "    if not isinstance(router, HostRouter):\n",
    1,
)
PAIR_CHECK_NO_IDENTITY = lambda source: source.replace(  # noqa: E731
    "        if router.host is host:\n            return\n",
    "        return\n",
    1,
)
WRAPPER_INSTANCE_LOOKUP = lambda source: replace_in_method(  # noqa: E731
    source,
    "__call__",
    "OutputMediator._emit(self, value, config, _identity)",
    "self._emit(value, config, _identity)",
)
WRAPPER_FOREIGN_REBUILD = lambda source: replace_in_method(  # noqa: E731
    source,
    "__call__",
    "OutputMediator._emit(self, value, config, _identity)",
    "OutputMediator._emit(self, value, config, _rebuild_sequence)",
)
WRAPPER_CALLBACK_WITHOUT_FLAG = lambda source: replace_in_method(  # noqa: E731
    source, "callback", ", callback_delivery=True", ""
)
APPROVAL_RETURNS_CONTENT = lambda source: replace_in_method(  # noqa: E731
    source,
    "_approval_required",
    "        return OutputApprovalRequired(",
    "        return rebuild(authorization.request.content)\n        return OutputApprovalRequired(",
)
NON_LITERAL_REFUSAL = lambda source: replace_in_method(  # noqa: E731
    source,
    "stream",
    'raise PermissionError("output:unsupported_mediator")',
    "raise PermissionError(repr(self))",
)
EXTRA_METHOD = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "    def _emit(",
    "    def emit_raw(self, value):\n        return value\n\n    def _emit(",
)
GETATTR_PROTOCOL = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "    def _emit(",
    "    def __getattr__(self, name):\n        return name\n\n    def _emit(",
)
SHADOWED_TYPE_BUILTIN = lambda source: source.replace(  # noqa: E731
    "\n\ndef _identity(", "\n\ntype = isinstance\n\n\ndef _identity(", 1
)


@pytest.mark.parametrize(
    "mutate",
    [
        RAW_CONTENT,
        RAW_RESULT,
        SKIP_SECOND_CHECK,
        SKIP_FIRST_CHECK,
        CANDIDATE_CLEARANCE,
        CONTENT_AS_CLEARANCE,
        SWAPPED_SLOTS,
        RETURN_AUTHORIZATION,
        PRINT_CONTENT,
        CALLBACK_ON_NORMAL_PATH,
        CALLBACK_BEFORE_ROUTE,
        UNCLASSIFIED_RESULT,
        LOCAL_REBOUND_REQUEST,
        MODULE_REBOUND_REQUEST,
        OTHER_ROUTE,
        OTHER_PRINCIPAL,
        UNCHECKED_LABELS_HOST,
        ASYNC_RAW_RETURN,
        ASYNC_SKIP_AWAIT_GUARD,
        ASYNC_SYNC_ROUTE,
        FIELDS_ISINSTANCE,
        STREAM_ISINSTANCE,
        STREAM_UNCHECKED_ENVELOPE,
        PAIR_CHECK_ISINSTANCE,
        PAIR_CHECK_NO_IDENTITY,
        WRAPPER_INSTANCE_LOOKUP,
        WRAPPER_FOREIGN_REBUILD,
        WRAPPER_CALLBACK_WITHOUT_FLAG,
        APPROVAL_RETURNS_CONTENT,
        NON_LITERAL_REFUSAL,
        EXTRA_METHOD,
        GETATTR_PROTOCOL,
        SHADOWED_TYPE_BUILTIN,
    ],
    ids=lambda mutate: next(
        name for name, value in globals().items() if value is mutate
    ),
)
def test_mutations_flip_the_derivation(mutate):
    source = placement_source()
    changed = mutate(source)
    assert changed != source
    ast.parse(changed)
    report = verify(changed, **dependency_sources())
    assert not report["proved"]
    assert report["issues"], report
    assert (
        all(entry.get("proved") for entry in report["entries"]) or not report["entries"]
    )


def _after_post_check(source, name, inserted):
    """Insert statements after the second pair check of one entry method."""
    route = "router.output_emit" if name == "_emit" else "await router.aoutput_emit"
    old = f"        _require_output_host(router, host)\n        result = {route}"
    new = f"        _require_output_host(router, host)\n{inserted}        result = {route}"
    return replace_in_method(source, name, old, new)


_REQUEST_TEXT = (
    "        request = OutputRequest(\n"
    "            destination,\n"
    "            content,\n"
    "            host.labels_for_output(principal, content),\n"
    "            clearance,\n"
    '            _operation_id(bound_config, "__graph__", "output"),\n'
    "        )\n"
)
SECOND_ROUTE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        return rebuild(result)",
    "        result = router.output_emit(principal, request)\n        return rebuild(result)",
)
ASYNC_SECOND_ROUTE = lambda source: replace_in_method(  # noqa: E731
    source,
    "_aemit",
    "        effective = rebuild(result)",
    "        result = await router.aoutput_emit(principal, request)\n        effective = rebuild(result)",
)
DOUBLE_REBUILD = lambda source: replace_in_method(  # noqa: E731
    source,
    "_emit",
    "        return rebuild(result)",
    "        _first = rebuild(result)\n        return rebuild(result)",
)
ASYNC_DOUBLE_REBUILD = lambda source: replace_in_method(  # noqa: E731
    source,
    "_aemit",
    "        effective = rebuild(result)",
    "        _first = rebuild(result)\n        effective = rebuild(result)",
)
CALLBACK_ROLES_SWAPPED = lambda source: replace_in_method(  # noqa: E731
    source,
    "callback",
    "self, value, config, deliver, callback_delivery=True",
    "self, deliver, config, value, callback_delivery=True",
)
ACALLBACK_ROLES_SWAPPED = lambda source: replace_in_method(  # noqa: E731
    source,
    "acallback",
    "self, value, config, deliver, callback_delivery=True",
    "self, value, deliver, config, callback_delivery=True",
)
CALL_ROLES_SWAPPED = lambda source: replace_in_method(  # noqa: E731
    source,
    "__call__",
    "OutputMediator._emit(self, value, config, _identity)",
    "OutputMediator._emit(self, config, value, _identity)",
)
ACALL_ROLES_SWAPPED = lambda source: replace_in_method(  # noqa: E731
    source,
    "acall",
    "OutputMediator._aemit(self, value, config, _identity)",
    "OutputMediator._aemit(self, config, value, _identity)",
)
STREAM_IDENTITY_REBUILD = lambda source: replace_in_method(  # noqa: E731
    source,
    "stream",
    "envelope.content, config, envelope.rebuild",
    "envelope.content, config, _identity",
)
ASTREAM_IDENTITY_REBUILD = lambda source: replace_in_method(  # noqa: E731
    source,
    "astream",
    "envelope.content, config, envelope.rebuild",
    "envelope.content, config, _identity",
)
STREAM_PARAMS_SWAPPED = lambda source: replace_in_method(  # noqa: E731
    source,
    "stream",
    "def stream(self, envelope: _OutputEnvelope, config: RunnableConfig)",
    "def stream(self, config: _OutputEnvelope, envelope: RunnableConfig)",
)


def _appended(suffix):
    """Return a mutation that appends one module-level statement."""

    def mutate(source):
        return source + suffix

    return mutate


MODULE_SETATTR_MEDIATOR = _appended(
    "\n_patch = setattr(OutputMediator, '__call__', lambda self, value, config: value)\n"
)
MODULE_SETATTR_ROUTER = _appended(
    "\n_patch = setattr(HostRouter, 'output_emit', lambda self, p, r: r.content)\n"
)
MODULE_GLOBALS_SETITEM = _appended(
    "\n_patch = globals().__setitem__('_identity', lambda value: value)\n"
)
MODULE_ANNOTATED_CALL = _appended(
    "\n_patch: object = setattr(OutputMediator, 'stream', _identity)\n"
)
MODULE_LAMBDA = _appended("\n_identity_alias = lambda value: value\n")
MODULE_COMPREHENSION = _appended(
    "\n_patched = [setattr(OutputMediator, name, _identity) for name in ('stream',)]\n"
)
MODULE_WILDCARD_IMPORT = lambda source: source.replace(  # noqa: E731
    "from langgraph.prebuilt.security.binding import next_call_index, principal_from\n",
    "from langgraph.prebuilt.security.binding import next_call_index, principal_from\nfrom os import *\n",
    1,
)
CLASS_BODY_SETATTR = lambda source: source.replace(  # noqa: E731
    "class MediatedBranch(Runnable[Any, Any]):\n",
    "class MediatedBranch(Runnable[Any, Any]):\n    _patch = setattr(OutputMediator, '__call__', _identity)\n",
    1,
)
EXTRA_LABELS_CALL = lambda source: _after_post_check(  # noqa: E731
    source, "_emit", "        _extra = host.labels_for_output(principal, content)\n"
)
EXTRA_OPERATION_ID = lambda source: _after_post_check(  # noqa: E731
    source,
    "_emit",
    '        _extra = _operation_id(bound_config, "__graph__", "output")\n',
)
ASYNC_EXTRA_OPERATION_ID = lambda source: _after_post_check(  # noqa: E731
    source,
    "_aemit",
    '        _extra = _operation_id(bound_config, "__graph__", "output")\n',
)
SECOND_REQUEST = lambda source: _after_post_check(  # noqa: E731
    source, "_emit", _REQUEST_TEXT
)
ASYNC_SECOND_REQUEST = lambda source: _after_post_check(  # noqa: E731
    source, "_aemit", _REQUEST_TEXT
)
SWAPPED_SLOT_READER = lambda source: source.replace(  # noqa: E731
    "return mediator.router, mediator.host, mediator.destination, mediator.clearance",
    "return mediator.router, mediator.host, mediator.clearance, mediator.destination",
    1,
)
SWAPPED_PAIR_READER = lambda source: source.replace(  # noqa: E731
    "return mediator.router, mediator.host, mediator.destination, mediator.clearance",
    "return mediator.host, mediator.router, mediator.destination, mediator.clearance",
    1,
)
RENAMED_SLOT = lambda source: source.replace(  # noqa: E731
    '__slots__ = ("router", "host", "destination", "clearance")',
    '__slots__ = ("router", "host", "destination", "clearance", "extra")',
    1,
)

ADVERSARIAL = [
    (SECOND_ROUTE, "route occurs more than once"),
    (ASYNC_SECOND_ROUTE, "route occurs more than once"),
    (DOUBLE_REBUILD, "rebuild occurs more than once"),
    (ASYNC_DOUBLE_REBUILD, "rebuild occurs more than once"),
    (CALLBACK_ROLES_SWAPPED, "content role is not the value parameter"),
    (ACALLBACK_ROLES_SWAPPED, "config role is not the config parameter"),
    (CALL_ROLES_SWAPPED, "content role is not the value parameter"),
    (ACALL_ROLES_SWAPPED, "content role is not the value parameter"),
    (STREAM_IDENTITY_REBUILD, "rebuilder role is not the checked envelope rebuild"),
    (ASTREAM_IDENTITY_REBUILD, "rebuilder role is not the checked envelope rebuild"),
    (STREAM_PARAMS_SWAPPED, "wrapper signature differs from the modeled roles"),
    (MODULE_SETATTR_MEDIATOR, "module initialization evaluates an unmodeled Call"),
    (MODULE_SETATTR_ROUTER, "module initialization evaluates an unmodeled Call"),
    (MODULE_GLOBALS_SETITEM, "module initialization evaluates an unmodeled Call"),
    (MODULE_ANNOTATED_CALL, "module initialization evaluates an unmodeled Call"),
    (MODULE_LAMBDA, "module initialization evaluates an unmodeled Lambda"),
    (MODULE_COMPREHENSION, "module initialization evaluates an unmodeled ListComp"),
    (MODULE_WILDCARD_IMPORT, "wildcard import binds unmodeled module names"),
    (CLASS_BODY_SETATTR, "module initialization evaluates an unmodeled Call"),
    (EXTRA_LABELS_CALL, "labels occurs more than once"),
    (EXTRA_OPERATION_ID, "operation_id occurs more than once"),
    (ASYNC_EXTRA_OPERATION_ID, "operation_id occurs more than once"),
    (SECOND_REQUEST, "occurs more than once"),
    (ASYNC_SECOND_REQUEST, "occurs more than once"),
    (SWAPPED_SLOT_READER, "slot reader order differs from the named slot roles"),
    (SWAPPED_PAIR_READER, "slot reader order differs from the named slot roles"),
    (RENAMED_SLOT, "mediator native slots differ from the four role slots"),
]


@pytest.mark.parametrize(
    ("mutate", "reason"),
    ADVERSARIAL,
    ids=[
        next(name for name, value in globals().items() if value is mutate)
        for mutate, _ in ADVERSARIAL
    ],
)
def test_adversarial_mutations_are_refused_with_a_specific_reason(mutate, reason):
    source = placement_source()
    changed = mutate(source)
    assert changed != source
    ast.parse(changed)
    report = verify(changed, **dependency_sources())
    assert not report["proved"]
    assert report["issues"], report
    issue = report["issues"][0]
    assert reason in issue["reason"], issue
    assert issue["line"] > 0
    assert not report["unproved_dependencies"]


def test_effect_tallies_are_reported_once_per_modeled_path():
    report = verify(placement_source(), **dependency_sources())
    assert report["proved"], report["issues"]
    for entry in report["entries"][:2]:
        for path in entry["paths"]:
            approval = any(
                step["rule"] == "approval-required-raise" for step in path["derivation"]
            )
            if path["exit"] == "return":
                assert path["effects"] == {
                    "labels": 1,
                    "operation_id": 1,
                    "request": 1,
                    "route": 1,
                    "rebuild": 1,
                }
            elif approval:
                assert path["effects"] == {
                    "labels": 1,
                    "operation_id": 1,
                    "request": 1,
                    "route": 1,
                }
            else:
                assert "rebuild" not in path["effects"]
    scan = report["module_initialization"]
    assert scan["rule"] == "module-initialization-scan"
    assert scan["call_allowlist"] == []
    assert scan["assignments"] >= 1
    assert "exactly once" in report["property"]


def test_blocking_statement_is_reported_with_its_line():
    source = placement_source()
    changed = PRINT_CONTENT(source)
    report = verify(changed)
    assert not report["proved"]
    method = mediator_method(changed, "_emit")
    issue = report["issues"][0]
    assert method.lineno < issue["line"] <= method.end_lineno
    assert (
        "unsupported reachable statement" in issue["reason"]
        or "effect" in issue["reason"]
    )


def test_hashes_bind_sources_and_exhausted_analysis_never_passes():
    source = placement_source()
    first = verify(source)
    second = verify(source + "\n# comment\n")
    assert second["proved"]
    assert (
        first["source_sha256"]["langgraph.prebuilt.security.placement"]
        != second["source_sha256"]["langgraph.prebuilt.security.placement"]
    )
    assert first["checker_sha256"] == second["checker_sha256"]
    exhausted = verify(source, max_steps=5)
    assert not exhausted["proved"]
    assert any("budget" in issue["reason"] for issue in exhausted["issues"])
    assert not verify(source, max_steps=0)["proved"]
    assert not verify("def (:")["proved"]


def test_unknown_candidate_code_is_not_executed(tmp_path):
    marker = tmp_path / "executed"
    source = replace_in_method(
        placement_source(),
        "_emit",
        "        return rebuild(result)",
        f"        open({str(marker)!r}, 'w').close()\n        return rebuild(result)",
    )
    poisoned = source + f"\nopen({str(marker)!r}, 'w').close()\n"
    report = verify(poisoned, **dependency_sources())
    assert not report["proved"]
    assert not marker.exists()
