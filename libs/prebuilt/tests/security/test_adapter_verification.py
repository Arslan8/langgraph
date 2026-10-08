"""Adapter checker regressions; all candidate programs are parsed, never run."""

from __future__ import annotations

from textwrap import dedent

import pytest

from langgraph.prebuilt.security.adapter_verification import check_adapters

BASE = "libs/prebuilt/langgraph/prebuilt/security/"


def check(source, *, module="object_manager", rule="SGV101"):
    report = check_adapters({BASE + module + ".py": dedent(source)})
    return [item for item in report["diagnostics"] if item["rule"] == rule]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "target", ["self.router.state", "self._router.state", "self._authorize"]
)
def test_unused_effective_results_reported_and_returned_results_clear(
    asynchronous, target
):
    prefix, wait = ("async ", "await ") if asynchronous else ("", "")
    source = f"class MediatedStore:\n    {prefix}def batch(self, request):\n        {wait}{target}(request)\n"
    findings = check(source)
    assert len(findings) == 1
    assert findings[0]["symbol"] == "MediatedStore.batch"
    assert findings[0]["owner"] == "implementation"
    assert not check(
        source.replace(f"        {wait}{target}", f"        return {wait}{target}")
    )


def test_nested_function_is_not_mistaken_for_executed_route():
    assert not check("""
        class MediatedStore:
            def batch(self, request):
                def helper():
                    self.router.state(request)
                return helper
    """)


def test_resume_inheritance_is_inspected_and_unknown_helpers_stay_unresolved():
    sources = {
        BASE
        + "object_manager.py": "class ObjectManagerPolicy(StackBoundaryPolicy):\n    pass\n",
        BASE
        + "host_boundary.py": "class StackBoundaryPolicy:\n    def object_resume_permission(self, p, r, a):\n        return self.stack.object_resume_permission(p, r, a)\n",
    }
    report = check_adapters(sources)
    findings = [item for item in report["diagnostics"] if item["rule"] == "SGV102"]
    assert len(findings) == 1
    assert findings[0]["path"].endswith("host_boundary.py")
    assert findings[0]["status"] == "failed"
    sources[BASE + "host_boundary.py"] = sources[BASE + "host_boundary.py"].replace(
        "self.stack.object_resume_permission", "self.unknown_helper"
    )
    findings = [
        item
        for item in check_adapters(sources)["diagnostics"]
        if item["rule"] == "SGV102"
    ]
    assert findings[0]["status"] == "unresolved"
    assert findings[0]["owner"] == "verifier"


def test_resume_local_dac_call_clears_absence_check_without_claiming_proof():
    sources = {
        BASE + "object_manager.py": dedent("""
        class ObjectManagerPolicy:
            def object_resume_permission(self, p, r, a):
                denied = self._dac(r)
                if denied is not None:
                    return denied
                return self.stack.object_resume_permission(p, r, a)
    """)
    }
    report = check_adapters(sources)
    assert not any(item["rule"] == "SGV102" for item in report["diagnostics"])
    assert not report["proof"]


@pytest.mark.parametrize("name", ["_model_input", "_amodel_input"])
def test_nonmapping_model_passthrough_needs_refusal(name):
    source = f"""
        class MediatedNode:
            def {name}(self, principal, value, config):
                if self.spec.kind is not NodeKind.MODEL or not isinstance(value, Mapping):
                    return value
                return normalized(value)
    """
    assert len(check(source, module="placement", rule="SGV103")) == 1
    assert not check(
        source.replace("return value", "raise TypeError('unsupported')"),
        module="placement",
        rule="SGV103",
    )


@pytest.mark.parametrize("name", ["_state_writes", "_astate_writes"])
def test_final_raw_update_passthrough_is_reported(name):
    source = f"class MediatedNode:\n    def {name}(self, principal, result):\n        return result\n"
    assert len(check(source, module="placement", rule="SGV103")) == 1
    assert not check(
        source.replace("return result", "raise TypeError('unsupported')"),
        module="placement",
        rule="SGV103",
    )


def test_non_model_passthrough_is_not_the_nonmapping_model_issue():
    assert not check(
        """
        class MediatedNode:
            def _model_input(self, p, value, config):
                if self.spec.kind is not NodeKind.MODEL:
                    return value
                return self.router.model_invoke(p, value)
    """,
        module="placement",
        rule="SGV103",
    )


def test_raw_callback_publication_is_reported():
    path = "libs/langgraph/langgraph/pregel/main.py"
    source = "class Pregel:\n    def stream(self):\n        manager.on_chain_end(loop.output)\n"
    report = check_adapters({path: source})
    assert any(item["rule"] == "SGV104" for item in report["diagnostics"])
    report = check_adapters({path: source.replace("loop.output", "effective_output")})
    assert not any(item["rule"] == "SGV104" for item in report["diagnostics"])
    assert not report["proof"]


def test_sync_and_async_callback_findings_have_distinct_stable_identities():
    path = "libs/langgraph/langgraph/pregel/main.py"
    source = "class Pregel:\n    def stream(self):\n        manager.on_chain_end(loop.output)\n    async def astream(self):\n        await manager.on_chain_end(loop.output)\n"
    findings = [
        item
        for item in check_adapters({path: source})["diagnostics"]
        if item["rule"] == "SGV104"
    ]
    assert len({item["fingerprint"] for item in findings}) == 2


@pytest.mark.parametrize(
    "effect",
    [
        "self._state[request.resource] = value",
        "return self._state.get(request.resource)",
    ],
)
def test_channel_only_state_keys_are_reported(effect):
    source = f"class ObjectManagerHost:\n    def _state_operation(self, request):\n        {effect}\n"
    assert check(source, rule="SGV105")
    assert not check(
        source.replace(
            "request.resource",
            "(principal.user_id, principal.session_id, request.resource)",
        ),
        rule="SGV105",
    )


def test_new_checkpoint_api_is_discovered_without_fixed_method_list():
    source = """
        class MediatedCheckpointer:
            def new_effect(self, config):
                return self.inner.new_effect(config)
    """
    findings = check(source, module="checkpoint_security", rule="SGV106")
    assert len(findings) == 1
    assert findings[0]["symbol"] == "MediatedCheckpointer.new_effect"


def test_local_checkpoint_route_is_found_but_not_accepted_as_full_proof():
    source = """
        class MediatedCheckpointer:
            def new_effect(self, config):
                return self._helper(config)
            def _helper(self, config):
                return self.router.state(config)
    """
    assert not check(source, module="checkpoint_security", rule="SGV106")


@pytest.mark.parametrize(
    "source", ["", "invalid python (", "class MediatedStore: pass"]
)
def test_missing_or_malformed_inputs_do_not_silently_pass(source):
    report = check_adapters({BASE + "object_manager.py": source})
    assert not report["checks_passed"]
    assert any(item["rule"] == "SGV190" for item in report["diagnostics"])


def test_fingerprint_survives_line_only_edits():
    source = "class MediatedStore:\n    def batch(self, request):\n        self._authorize(request)\n"
    before = check(source)[0]
    after = check("\n# moved\n" + source)[0]
    assert before["line"] != after["line"]
    assert before["fingerprint"] == after["fingerprint"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_raw_backing_store_result_is_reported(asynchronous):
    prefix = "async " if asynchronous else ""
    wait = "await " if asynchronous else ""
    name = "abatch" if asynchronous else "batch"
    source = f"""class MediatedStore:
    {prefix}def {name}(self, ops):
        effective = self.authorize_inputs(ops)
        return {wait}self._store.{name}(effective)
"""
    findings = check(source, rule="SGV107")
    assert len(findings) == 1
    assert findings[0]["symbol"] == f"MediatedStore.{name}"
    mediated = source.replace(
        f"return {wait}self._store.{name}(effective)",
        f"values = {wait}self._store.{name}(effective)\n"
        "        return self.authorize_results(values)",
    )
    assert not check(mediated, rule="SGV107")
    assert not check_adapters({BASE + "object_manager.py": mediated})["proof"]


@pytest.mark.parametrize(
    "body",
    [
        "yield from self.inner.list(config)",
        "for value in self.inner.list(config):\n            yield value",
        "async for value in self.inner.alist(config):\n            yield value",
    ],
)
def test_raw_checkpoint_history_is_reported(body):
    prefix = "async " if body.startswith("async") else ""
    source = f"""class MediatedCheckpointer:
    {prefix}def history(self, config):
        self.router.state(config)
        {body}
"""
    assert len(check(source, module="checkpoint_security", rule="SGV108")) == 1
    mediated = source.replace(
        "yield from self.inner.list(config)",
        "for value in self.inner.list(config):\n"
        "            yield self.verify_history(value)",
    ).replace("yield value", "yield self.verify_history(value)")
    assert not check(mediated, module="checkpoint_security", rule="SGV108")
    assert not check_adapters({BASE + "checkpoint_security.py": mediated})["proof"]
