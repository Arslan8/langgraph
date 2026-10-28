"""Closed admission surface evidence rejects changed behavior, never source hashes."""

from __future__ import annotations

from pathlib import Path

import pytest

from langgraph.prebuilt.security.admission_verification import (
    verify_admission_surface,
)

_BASE = Path(__file__).parents[2] / "langgraph" / "prebuilt" / "security"
_MODULES = ("admission", "config", "placement", "mac")
_OBLIGATIONS = (
    "exact_type_selection",
    "closed_compile_refusal",
    "descriptor_dispatch",
    "runtime_mac_closed_admission",
)


_TRUSTED_PREMISE = (
    "trusted application node bodies are trusted per D11; admission binds "
    "their identity only"
)


@pytest.fixture
def sources() -> dict[str, str]:
    return {name: (_BASE / f"{name}.py").read_text() for name in _MODULES}


def run(sources: dict[str, str]) -> dict:
    return verify_admission_surface(*(sources[name] for name in _MODULES))


def mutate(sources: dict[str, str], module: str, old: str, new: str) -> dict[str, str]:
    assert old in sources[module], (module, old)
    changed = dict(sources)
    changed[module] = sources[module].replace(old, new, 1)
    return changed


def test_actual_sources_prove_every_obligation_without_closing_the_system(sources):
    report = run(sources)
    assert report["proved"], report["issues"]
    assert not report["issues"]
    assert set(report["obligations"]) == set(_OBLIGATIONS)
    assert all(report["obligations"][key]["proved"] for key in _OBLIGATIONS)
    assert report["system_complete"] is False
    assert report["sgv901_closed"] is False
    assert report["scope"]
    assert len(report["premises"]) >= 5
    assert len(report["source_sha256"]) == 4
    assert len(report["checker_sha256"]) == 64
    exact = report["obligations"]["exact_type_selection"]
    assert exact["admit_node"]["class"] == "ToolNode"
    assert exact["admit_node"]["code"] == "UNSUPPORTED_NODE_BODY"
    assert exact["admit_branch"]["class"] == "BranchSpec"
    closed = report["obligations"]["closed_compile_refusal"]
    assert closed["node_refusal"] == "DESCRIPTOR_CHANGED"
    assert closed["branch_refusal"] == "DESCRIPTOR_CHANGED"
    dispatch = report["obligations"]["descriptor_dispatch"]
    assert [entry["primitive"] for entry in dispatch["entries"]] == [
        "function",
        "afunction",
        "captured.function",
        "captured.function",
        "function",
        "afunction",
        "captured.function",
        "captured.function",
        "captured.function",
        "captured.function",
    ]
    assert exact["model_selection"]["class"] == "model_class"
    assert exact["trusted_branch_selection"]["class"] == "BranchSpec"
    assert exact["application_selection"]["class"] == "RunnableCallable"
    assert _TRUSTED_PREMISE in " ".join(report["premises"])
    assert "legacy_exception" in report["obligations"]["runtime_mac_closed_admission"]


@pytest.mark.parametrize(
    "obligation,module,old,new",
    [
        (
            "descriptor_dispatch",
            "placement",
            "result = function(captured.node, data, narrowed, runtime)",
            "result = self.runnable.invoke(data, narrowed)",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "result = await afunction(captured.node, data, narrowed, runtime)",
            "result = await self.runnable.ainvoke(data, narrowed)",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "result = captured.function(data)\n        if type(result) is not str:\n            raise PermissionError(DESCRIPTOR_CHANGED)\n        _route_sends",
            "result = self.runnable.invoke(data, bound_config)\n        if type(result) is not str:\n            raise PermissionError(DESCRIPTOR_CHANGED)\n        _route_sends",
        ),
        (
            "exact_type_selection",
            "admission",
            "if type(runnable) is not ToolNode:",
            "if not isinstance(runnable, ToolNode):",
        ),
        (
            "exact_type_selection",
            "admission",
            "if type(branch) is not BranchSpec:",
            "if not isinstance(branch, BranchSpec):",
        ),
        (
            "exact_type_selection",
            "admission",
            "    _require_name(name, UNSUPPORTED_NODE_BODY)\n",
            '    _require_name(name, UNSUPPORTED_NODE_BODY)\n    if runnable.__module__.startswith("langgraph."):\n        pass\n',
        ),
        (
            "exact_type_selection",
            "admission",
            "    _require_name(name, UNSUPPORTED_NODE_BODY)\n",
            '    _require_name(name, UNSUPPORTED_NODE_BODY)\n    if getattr(runnable, "__module__", "") == "x":\n        pass\n',
        ),
        (
            "exact_type_selection",
            "admission",
            "    _require_name(name, UNSUPPORTED_NODE_BODY)\n",
            "    _require_name(name, UNSUPPORTED_NODE_BODY)\n    runnable.get_name()\n",
        ),
        (
            "closed_compile_refusal",
            "config",
            "if name not in admitted:",
            "if name not in admitted and not (node_spec.metadata or {}).get('security_trust'):",
        ),
        (
            "closed_compile_refusal",
            "config",
            "                    descriptor=admitted[name],\n",
            "",
        ),
        (
            "closed_compile_refusal",
            "config",
            "            inventory[placement_name] = admit_branch(\n                placement_name, branch, config=config\n            )",
            "            pass",
        ),
        (
            "closed_compile_refusal",
            "config",
            "        inventory[name] = admit_node(name, spec.runnable, config=config)",
            "        inventory[name] = admit_node(name, spec.runnable, config=config) if type(metadata) is not dict or not metadata.get('security_trust') else None",
        ),
        (
            "closed_compile_refusal",
            "config",
            "        if self.closed_admission:\n            # Closed admission runs before",
            "        nodes = tuple(_find_tool_nodes(graph))\n        if self.closed_admission:\n            # Closed admission runs before",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "    _bind_node_descriptor(descriptor, runnable, spec)\n    recheck(descriptor)\n",
            "    _bind_node_descriptor(descriptor, runnable, spec)\n",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "    _bind_branch_descriptor(descriptor, runnable, trust)\n    recheck(descriptor)\n",
            "    _bind_branch_descriptor(descriptor, runnable, trust)\n",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "result = function(captured.node, data, narrowed, runtime)",
            "result = function(captured.node, data, narrowed, runtime, **kwargs)",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "result = function(captured.node, data, narrowed, runtime)",
            "result = function(captured.node, input, narrowed, runtime)",
        ),
        (
            "descriptor_dispatch",
            "placement",
            "        if self.descriptor is not None:\n            return self._invoke_admitted(input, config, kwargs)\n        principal, bound_config = _principal(config)\n        self._dispatch",
            "        principal, bound_config = _principal(config)\n        if self.descriptor is not None:\n            return self._invoke_admitted(input, config, kwargs)\n        self._dispatch",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            '        if boundary is None:\n            raise SecurityConfigurationError("mac:unconfined_graph_body")\n',
            "",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "    if any(builder.branches.values()):\n        return None\n",
            "",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "            recheck(descriptor)\n            self._check_tool_node(node)",
            "            self._check_tool_node(node)",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "            boundary = _legacy_boundary(builder)",
            "            boundary = _closed_boundary(builder, graph) if isinstance(builder, object) else None",
        ),
        # Legacy path re-admitting at compile (finding 3).
        (
            "runtime_mac_closed_admission",
            "mac",
            "        nodes.append(mediated.runnable)",
            "        nodes.append(admit_node(name, mediated.runnable, config=config))",
        ),
        # Compiled-node binding (finding 1): bound identity, inventory equality,
        # binder call, branch path binding.
        (
            "runtime_mac_closed_admission",
            "mac",
            "if type(proc) is not PregelNode or proc.bound is not expected[name]:",
            "if type(proc) is not PregelNode:",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "    if set(compiled) != set(expected):\n        raise PermissionError(DESCRIPTOR_CHANGED)\n",
            "",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "        _bind_compiled_graph(boundary, graph)\n        for _, mediated, descriptor in boundary.nodes:",
            "        for _, mediated, descriptor in boundary.nodes:",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "    if type(path) is not MediatedBranch:\n        raise PermissionError(DESCRIPTOR_CHANGED)\n    return path",
            "    return path",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            "            if _count(admitted, path) == 0:\n                raise PermissionError(DESCRIPTOR_CHANGED)\n",
            "",
        ),
        (
            "runtime_mac_closed_admission",
            "mac",
            '        cache = proc.__dict__\n        cache.pop("node", None)\n        cache.pop("flat_writers", None)\n',
            "        pass\n",
        ),
        # Author callback refusal (finding 2): channels, reducers, cache, retry.
        (
            "closed_compile_refusal",
            "config",
            "    _admit_channels(graph.channels)\n",
            "",
        ),
        (
            "closed_compile_refusal",
            "config",
            "            if not _pinned(reducer, _FRAMEWORK_REDUCERS):",
            "            if False:",
        ),
        (
            "closed_compile_refusal",
            "config",
            "        elif not _pinned(kind, _FRAMEWORK_CHANNELS):",
            "        elif False:",
        ),
        (
            "closed_compile_refusal",
            "config",
            "        _admit_node_policies(spec)\n",
            "",
        ),
        (
            "closed_compile_refusal",
            "config",
            "type(cache) is not CachePolicy or cache.key_func is not default_cache_key",
            "type(cache) is not CachePolicy",
        ),
        (
            "closed_compile_refusal",
            "config",
            "type(policy) is not RetryPolicy or policy.retry_on is not default_retry_on",
            "type(policy) is not RetryPolicy",
        ),
        (
            "closed_compile_refusal",
            "config",
            "_FRAMEWORK_REDUCERS = (add, add_messages)",
            "_FRAMEWORK_REDUCERS = (add, add_messages, max)",
        ),
        (
            "closed_compile_refusal",
            "config",
            "from operator import add\n",
            "from operator import add\nadd = max\n",
        ),
        (
            "closed_compile_refusal",
            "config",
            "from langgraph.graph.message import add_messages\n",
            "from langgraph.graph.message import add_messages as _am\n\nadd_messages = _am\n",
        ),
    ],
)
def test_reintroduced_findings_leave_the_obligation_unproved(
    sources, obligation, module, old, new
):
    report = run(mutate(sources, module, old, new))
    assert not report["proved"]
    assert not report["obligations"][obligation]["proved"], report["issues"]
    assert any(issue["obligation"] == obligation for issue in report["issues"])
    assert all(issue["line"] >= 0 for issue in report["issues"])
    assert report["system_complete"] is False
    assert report["sgv901_closed"] is False


_HOOK = "        effective = self._model_input(principal, data, bound_config)\n"
_MESSAGES = "        messages = _model_messages(effective)\n"
_CALL = "        result = function(captured.node, messages, narrowed)\n"


@pytest.mark.parametrize(
    "obligation,module,old,new",
    [
        # Model called before the hook decides the capability.
        (
            "descriptor_dispatch",
            "placement",
            _HOOK + _MESSAGES + _CALL,
            "        messages = _model_messages(data)\n"
            + _CALL
            + "        effective = self._model_input(principal, data, bound_config)\n",
        ),
        # Hook removed from the model route.
        (
            "descriptor_dispatch",
            "placement",
            _HOOK + _MESSAGES,
            "        messages = _model_messages(data)\n",
        ),
        # Hook removed from the async model route.
        (
            "descriptor_dispatch",
            "placement",
            "        effective = await self._amodel_input(principal, data, bound_config)\n",
            "        effective = data\n",
        ),
        # Model reached through the mutable instance attribute.
        (
            "descriptor_dispatch",
            "placement",
            _CALL,
            "        result = captured.node.invoke(messages, narrowed)\n",
        ),
        # The hook no longer routes the model invocation through the router.
        (
            "descriptor_dispatch",
            "placement",
            "            self.router.model_invoke(\n",
            "            _identity(\n",
        ),
        # Model descriptors accepted under a STANDARD placement (hook skipped).
        (
            "descriptor_dispatch",
            "placement",
            "        kind = NodeKind.MODEL\n",
            "        kind = NodeKind.STANDARD\n",
        ),
        # isinstance heuristic in the model allowlist.
        (
            "exact_type_selection",
            "admission",
            "if allowed is not None and kind is allowed:",
            "if allowed is not None and issubclass(kind, allowed):",
        ),
        # Class-name heuristic in model selection.
        (
            "exact_type_selection",
            "admission",
            "    registry_id = _allowlisted_model(type(runnable))\n",
            "    registry_id = _allowlisted_model(type(runnable)) or (\n"
            "        'llm' if 'chatmodel' in type(runnable).__name__.lower() else None\n"
            "    )\n",
        ),
        # Model capture no longer re-guards the exact class.
        (
            "exact_type_selection",
            "admission",
            "    if type(model) is not model_class:\n        raise PermissionError(UNSUPPORTED_NODE_BODY)\n",
            "",
        ),
        # Closed compile path places model descriptors as STANDARD.
        (
            "closed_compile_refusal",
            "config",
            "        return NodeKind.MODEL\n",
            "        return NodeKind.STANDARD\n",
        ),
        # MAC check skips the recheck for model nodes.
        (
            "runtime_mac_closed_admission",
            "mac",
            "                    raise PermissionError(DESCRIPTOR_CHANGED)\n                recheck(descriptor)\n                continue\n",
            "                    raise PermissionError(DESCRIPTOR_CHANGED)\n                continue\n",
        ),
    ],
)
def test_model_call_mutations_leave_the_obligation_unproved(
    sources, obligation, module, old, new
):
    report = run(mutate(sources, module, old, new))
    assert not report["proved"]
    assert not report["obligations"][obligation]["proved"], report["issues"]


def test_unknown_statement_forms_are_not_silently_accepted(sources):
    changed = mutate(
        sources,
        "placement",
        "        captured = _admitted_node(self, kwargs)\n        if type(captured) is _CapturedModel:\n            return self._invoke_model_call(captured, input, config)\n        if type(captured) is _CapturedApplication:\n            return self._invoke_application(captured, input, config)\n        data = _bounded_input(input)\n        principal, bound_config = _principal(config)\n        runtime = _framework_runtime(bound_config)",
        "        captured = _admitted_node(self, kwargs)\n        if type(captured) is _CapturedModel:\n            return self._invoke_model_call(captured, input, config)\n        if type(captured) is _CapturedApplication:\n            return self._invoke_application(captured, input, config)\n        data = _bounded_input(input)\n        with _audit():\n            pass\n        principal, bound_config = _principal(config)\n        runtime = _framework_runtime(bound_config)",
    )
    report = run(changed)
    assert not report["obligations"]["descriptor_dispatch"]["proved"]
    assert any(
        issue["reason"] == "unmodeled context manager" for issue in report["issues"]
    )


def test_local_shadowing_of_a_helper_is_refused(sources):
    changed = mutate(
        sources,
        "placement",
        "    _bind_node_descriptor(descriptor, runnable, spec)\n    recheck(descriptor)\n",
        "    _bind_node_descriptor(descriptor, runnable, spec)\n    recheck = type\n    recheck(descriptor)\n",
    )
    report = run(changed)
    assert not report["obligations"]["descriptor_dispatch"]["proved"]


def test_unparsable_or_empty_sources_prove_nothing(sources):
    report = verify_admission_surface("", "", "", "")
    assert not report["proved"]
    assert all(not item["proved"] for item in report["obligations"].values())
    broken = dict(sources)
    broken["mac"] = "def register_mac_boundary(:\n"
    report = run(broken)
    assert not report["obligations"]["runtime_mac_closed_admission"]["proved"]
    assert report["obligations"]["exact_type_selection"]["proved"]


def test_comment_only_edits_keep_the_proof_but_change_the_binding(sources):
    before = run(sources)
    changed = dict(sources)
    changed["admission"] += "\n# reviewed\n"
    after = run(changed)
    assert after["proved"]
    assert (
        before["source_sha256"]["langgraph.prebuilt.security.admission"]
        != after["source_sha256"]["langgraph.prebuilt.security.admission"]
    )


_SELECT_MODEL = (
    "    registry_id = _allowlisted_model(type(runnable))\n"
    "    if registry_id is not None:\n"
    "        return _admit_model_call(name, runnable, registry_id)\n"
)
_SELECT_TRUSTED = (
    "    if _declared_trusted(name, config):\n"
    "        return _admit_trusted_application(name, runnable)\n"
)
_APP_CALL = "        result = _run_application(function, input, injected)\n"
_APP_DISPATCH = "        self._dispatch(principal, bound_config)\n"


@pytest.mark.parametrize(
    "obligation,module,old,new",
    [
        # (a) Heuristic widening of the exact membership test.
        (
            "exact_type_selection",
            "admission",
            "    return name in declared\n",
            "    return name in declared or name.endswith('_node')\n",
        ),
        # (a) Inferred trust: any plain RunnableCallable is selected.
        (
            "exact_type_selection",
            "admission",
            "    if _declared_trusted(name, config):\n",
            "    if _declared_trusted(name, config) or (\n"
            "        type(runnable).__name__ == 'RunnableCallable'\n"
            "    ):\n",
        ),
        # (a) The declared set is no longer required to be an exact frozenset.
        (
            "exact_type_selection",
            "admission",
            "    if type(declared) is not frozenset:\n"
            "        raise PermissionError(UNSUPPORTED_NODE_BODY)\n",
            "",
        ),
        # (a) Declaration consulted before the model allowlist: a declared
        # model would be downgraded to a trusted application node.
        (
            "exact_type_selection",
            "admission",
            _SELECT_MODEL + _SELECT_TRUSTED,
            _SELECT_TRUSTED + _SELECT_MODEL,
        ),
        # (a) A declared ToolNode (a RunnableCallable subclass) slips through.
        (
            "exact_type_selection",
            "admission",
            "    if type(node) is not RunnableCallable:\n"
            "        raise PermissionError(UNSUPPORTED_NODE_BODY)\n"
            "    missing = False\n"
            "    try:\n"
            "        func = node.func\n"
            "        afunc = node.afunc\n"
            "        bound = node.kwargs",
            "    if not isinstance(node, RunnableCallable):\n"
            "        raise PermissionError(UNSUPPORTED_NODE_BODY)\n"
            "    missing = False\n"
            "    try:\n"
            "        func = node.func\n"
            "        afunc = node.afunc\n"
            "        bound = node.kwargs",
        ),
        # (a) Trusted application admitted under another kind.
        (
            "exact_type_selection",
            "admission",
            "        AdmittedKind.TRUSTED_APPLICATION, name, identity, captured, source",
            "        AdmittedKind.TOOL_NODE, name, identity, captured, source",
        ),
        # (b) Declared names are no longer bound to the builder's nodes.
        (
            "closed_compile_refusal",
            "config",
            "    if not declared <= frozenset(nodes):\n"
            "        raise PermissionError(UNSUPPORTED_NODE_BODY)\n",
            "",
        ),
        # (b) Wrapped graph check accepts a trusted application under MODEL.
        (
            "closed_compile_refusal",
            "config",
            "                or wrapper.spec.kind is not NodeKind.STANDARD\n",
            "                or wrapper.spec.kind is not NodeKind.MODEL\n",
        ),
        # (c) Dispatch through the mutable runnable instead of the capture.
        (
            "descriptor_dispatch",
            "placement",
            _APP_CALL,
            "        result = self.runnable.invoke(input, bound_config)\n",
        ),
        # (c) Function read from the mutable attribute at dispatch time.
        (
            "descriptor_dispatch",
            "placement",
            "        function = captured.function\n"
            "        self._dispatch(principal, bound_config)\n",
            "        function = captured.node.func\n"
            "        self._dispatch(principal, bound_config)\n",
        ),
        # (c) Router dispatch after the trusted body has already run.
        (
            "descriptor_dispatch",
            "placement",
            _APP_DISPATCH + _APP_CALL,
            _APP_CALL + _APP_DISPATCH,
        ),
        # (c) Application route bypassed: falls through to the ToolNode route.
        (
            "descriptor_dispatch",
            "placement",
            "        if type(captured) is _CapturedApplication:\n"
            "            return self._invoke_application(captured, input, config)\n",
            "",
        ),
        # (c) Async route awaits the mutable attribute.
        (
            "descriptor_dispatch",
            "placement",
            "            result = await _run_application(function, input, injected)\n",
            "            result = await captured.node.afunc(input)\n",
        ),
        # (c) The pinned call helper runs something else.
        (
            "descriptor_dispatch",
            "placement",
            "    return function(value, **injected)\n",
            "    return value\n",
        ),
        # (c) Wrapper binding no longer fixes the trusted placement.
        (
            "descriptor_dispatch",
            "placement",
            "    elif type(implementation) is _CapturedApplication:\n"
            "        kind = NodeKind.STANDARD\n",
            "    elif type(implementation) is _CapturedApplication:\n"
            "        kind = spec.kind\n",
        ),
        # (d) MAC check skips the recheck for trusted application nodes.
        (
            "runtime_mac_closed_admission",
            "mac",
            "                or type(implementation) is _CapturedApplication\n"
            "            ):\n"
            "                # A model call",
            "            ):\n                # A model call",
        ),
        # (d) MAC boundary no longer binds trusted application wrappers.
        (
            "runtime_mac_closed_admission",
            "mac",
            "            or type(implementation) is _CapturedApplication\n"
            "        ):\n"
            "            if (\n"
            "                type(wrapper) is not MediatedNode",
            "        ):\n"
            "            if (\n"
            "                type(wrapper) is not MediatedNode",
        ),
    ],
)
def test_trusted_application_mutations_leave_the_obligation_unproved(
    sources, obligation, module, old, new
):
    report = run(mutate(sources, module, old, new))
    assert not report["proved"]
    assert not report["obligations"][obligation]["proved"], report["issues"]


_BRANCH_CALL = "        result = _run_application(function, input, {})\n"
_BRANCH_SENDS = (
    "        _route_sends(self.router, principal, result, bound_config, self.name)\n"
)


@pytest.mark.parametrize(
    "obligation,module,old,new",
    [
        # (a) Heuristic widening of branch membership.
        (
            "exact_type_selection",
            "admission",
            "    declared = _declared_application_branches(config)\n"
            "    return name in declared\n",
            "    declared = _declared_application_branches(config)\n"
            "    return name in declared or name.endswith(':branch:condition')\n",
        ),
        # (a) Inferred trust: every RunnableCallable path is selected.
        (
            "exact_type_selection",
            "admission",
            "    if _declared_trusted_branch(name, config):\n",
            "    if _declared_trusted_branch(name, config) or (\n"
            "        type(branch.path).__name__ == 'RunnableCallable'\n"
            "    ):\n",
        ),
        # (a) The declared branch set is no longer an exact frozenset.
        (
            "exact_type_selection",
            "admission",
            "    declared = config.trusted_application_branches\n"
            "    if type(declared) is not frozenset:\n"
            "        raise PermissionError(UNSUPPORTED_BRANCH)\n",
            "    declared = config.trusted_application_branches\n",
        ),
        # (a) A pinned framework branch may be downgraded to trusted code.
        (
            "exact_type_selection",
            "admission",
            "    if _pinned_branch_id(func) is not None:\n"
            "        raise PermissionError(UNSUPPORTED_BRANCH)\n"
            "    code = _application_code(func, UNSUPPORTED_BRANCH)\n",
            "    code = _application_code(func, UNSUPPORTED_BRANCH)\n",
        ),
        # (a) The path guard is relaxed to a subclass check.
        (
            "exact_type_selection",
            "admission",
            "    path = branch.path\n"
            "    if type(path) is not RunnableCallable:\n"
            "        raise PermissionError(UNSUPPORTED_BRANCH)\n"
            "    missing = False\n"
            "    try:\n"
            "        func = path.func\n"
            "        afunc = path.afunc\n"
            "        bound = path.kwargs\n"
            "        explode = path.explode_args\n"
            "        accepts = path.func_accepts\n"
            "    except AttributeError:\n"
            "        missing = True\n"
            "    if missing:\n"
            "        raise PermissionError(UNSUPPORTED_BRANCH)\n"
            "    if type(func) is not FunctionType or _is_coroutine(func):",
            "    path = branch.path\n"
            "    if not isinstance(path, RunnableCallable):\n"
            "        raise PermissionError(UNSUPPORTED_BRANCH)\n"
            "    missing = False\n"
            "    try:\n"
            "        func = path.func\n"
            "        afunc = path.afunc\n"
            "        bound = path.kwargs\n"
            "        explode = path.explode_args\n"
            "        accepts = path.func_accepts\n"
            "    except AttributeError:\n"
            "        missing = True\n"
            "    if missing:\n"
            "        raise PermissionError(UNSUPPORTED_BRANCH)\n"
            "    if type(func) is not FunctionType or _is_coroutine(func):",
        ),
        # (a) Stale declarations accepted.
        (
            "exact_type_selection",
            "admission",
            "        if descriptor.kind is not AdmittedKind.TRUSTED_APPLICATION_BRANCH:\n"
            "            raise PermissionError(UNSUPPORTED_BRANCH)\n",
            "",
        ),
        # (b) Declarations no longer bound after admission.
        (
            "closed_compile_refusal",
            "config",
            "    _bind_declared_branches(config, inventory)\n",
            "",
        ),
        # (c) Branch dispatched through the mutable path.
        (
            "descriptor_dispatch",
            "placement",
            _BRANCH_CALL,
            "        result = self.runnable.invoke(input, bound_config)\n",
        ),
        # (c) Sends no longer authorized on the trusted branch route.
        (
            "descriptor_dispatch",
            "placement",
            _BRANCH_CALL + _BRANCH_SENDS,
            _BRANCH_CALL,
        ),
        # (c) Trusted branch route bypassed: framework route runs it.
        (
            "descriptor_dispatch",
            "placement",
            "        if type(captured) is _CapturedTrustedBranch:\n"
            "            return self._invoke_trusted_branch(captured, input, config)\n",
            "",
        ),
        # (c) Async route reads the mutable path function.
        (
            "descriptor_dispatch",
            "placement",
            "        result = await _run_application_in_executor(function, input, {})\n",
            "        result = await _run_application_in_executor(\n"
            "            captured.path.func, input, {}\n"
            "        )\n",
        ),
        # (d) MAC check skips the trusted branch recheck.
        (
            "runtime_mac_closed_admission",
            "mac",
            "            if mediated.runnable is not implementation.path:\n"
            "                raise PermissionError(DESCRIPTOR_CHANGED)\n"
            "            recheck(descriptor)\n",
            "            if mediated.runnable is not implementation.path:\n"
            "                raise PermissionError(DESCRIPTOR_CHANGED)\n",
        ),
        # (d) MAC boundary no longer records trusted branches.
        (
            "runtime_mac_closed_admission",
            "mac",
            "        elif (\n"
            "            type(implementation) is _CapturedBranch\n"
            "            or type(implementation) is _CapturedTrustedBranch\n"
            "        ):\n",
            "        elif type(implementation) is _CapturedBranch:\n",
        ),
    ],
)
def test_trusted_branch_mutations_leave_the_obligation_unproved(
    sources, obligation, module, old, new
):
    report = run(mutate(sources, module, old, new))
    assert not report["proved"]
    assert not report["obligations"][obligation]["proved"], report["issues"]
