"""Lazy export bindings are derived from source, never from executed hooks."""

import collections
import collections.abc
from dataclasses import replace
from importlib import import_module
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Operation
from langgraph.prebuilt.security.verification import _Program, installed_spec, verify
from tests.security.test_verification import spec

_LOADER = """
from importlib import import_module

def select(name, module_name, package):
    if module_name == '__module__' or module_name is None:
        try:
            return import_module(f'.{name}', package=package)
        except ModuleNotFoundError:
            raise AttributeError(name)
    else:
        try:
            module = import_module(f'.{module_name}', package=package)
        except ModuleNotFoundError:
            raise ImportError(module_name)
        return getattr(module, name)
"""
_FACADE = """
from loader import select
routes = {'execute': 'impl', 'Base': 'impl'}
__all__ = ('execute', 'Base')

def __getattr__(name):
    module_name = routes.get(name)
    result = select(name, module_name, __spec__.parent)
    globals()[name] = result
    return result
"""
_IMPL = """
from policy import permission, Verdict
from legacy import dispatch

def execute(principal, request):
    decision = permission(principal, request)
    if decision.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
    return dispatch(principal, request)

class Base:
    def invoke(self, principal, request):
        return execute(principal, request)
"""
_ENTRY = """
from app import execute
class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)
"""


def options(*, facade=_FACADE, loader=_LOADER, implementation=_IMPL, entry=_ENTRY):
    return replace(
        spec(),
        sources={
            "app": dedent(facade),
            "app.impl": dedent(implementation),
            "app.entry": dedent(entry),
            "loader": dedent(loader),
        },
        package_modules=("app",),
        surfaces=("app.entry.Tool",),
    )


def test_lazy_export_proof_includes_each_source_helper_and_real_dispatch():
    report = verify(options())
    assert report["complete"], report
    evidence = next(e for e in report["export_resolutions"] if e["name"] == "execute")
    assert evidence["target"] == "app.impl.execute"
    assert evidence["visited_functions"] == ["app.__getattr__", "loader.select"]
    assert report["entries"][0]["dispatches"][0]["call_path"] == [
        "app.entry.Tool.invoke",
        "app.impl.execute",
    ]


def test_imported_module_attribute_uses_the_same_export_analysis():
    report = verify(
        options(
            entry="""
        import app
        class Tool:
            def invoke(self, principal, request):
                return app.execute(principal, request)
    """
        )
    )
    assert report["complete"], report
    assert any(e["name"] == "execute" for e in report["export_resolutions"])


def test_lazy_base_class_preserves_inherited_api_discovery():
    report = verify(
        options(
            entry="""
        from app import Base
        class Tool(Base):
            def run(self, principal, request):
                return self.invoke(principal, request)
    """
        )
    )
    assert report["complete"], report
    assert set(report["surfaces"]["app.entry.Tool"]) == {"invoke", "run"}


def test_changed_export_target_cannot_inherit_other_helpers_authorization():
    current = options()
    current.sources["app"] = current.sources["app"].replace(
        "'execute': 'impl'", "'execute': 'other'"
    )
    current.sources["app.other"] = (
        "from legacy import dispatch\ndef execute(p, r):\n    return dispatch(p, r)\n"
    )
    report = verify(current)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"
    assert report["entries"][0]["dispatches"][0]["call_path"][-1] == "app.other.execute"


@pytest.mark.parametrize("position", ["before", "after"])
def test_effect_inside_export_helper_is_never_accepted(position):
    statement = "dispatch(None, None)\n    "
    loader = _LOADER.replace(
        "from importlib", "from legacy import dispatch\nfrom importlib"
    )
    marker = (
        "if module_name ==" if position == "before" else "return getattr(module, name)"
    )
    loader = loader.replace(marker, statement + marker)
    report = verify(options(loader=loader))
    assert not report["complete"]
    assert any("effect terminal" in i["reason"] for i in report["issues"])


def test_unused_lazy_import_still_requires_analysis_of_its_hook():
    current = options(
        facade="""
        from legacy import dispatch
        def __getattr__(name):
            dispatch(None, None)
            return None
    """,
        entry="""
        from app import unused
        from app.impl import execute
        class Tool:
            def invoke(self, principal, request):
                return execute(principal, request)
    """,
    )
    report = verify(current)
    assert report["entries"][0]["status"] == "verified"
    assert not report["complete"]
    assert any("lazy export unused" in i["reason"] for i in report["issues"])


@pytest.mark.parametrize(
    "cache",
    [
        "globals()['different'] = result",
        "globals()[name] = select('Base', 'impl', __spec__.parent)",
        "routes[name] = 'other'",
    ],
)
def test_export_mutation_must_only_cache_its_own_returned_binding(cache):
    report = verify(options(facade=_FACADE.replace("globals()[name] = result", cache)))
    assert not report["complete"]
    assert any(
        "import mutation" in i["reason"] or "export cache changes" in i["reason"]
        for i in report["issues"]
    )


def test_cache_write_is_optional_and_not_itself_proof_of_the_returned_binding():
    report = verify(
        options(facade=_FACADE.replace("    globals()[name] = result\n", ""))
    )
    assert report["complete"], report


def test_missing_import_source_cannot_be_swallowed_as_an_exception():
    current = options()
    current.sources["app"] = current.sources["app"].replace(
        "'execute': 'impl'", "'execute': 'missing'"
    )
    report = verify(current)
    assert not report["complete"]
    assert any(
        "source unavailable: app.missing" in i["reason"] for i in report["issues"]
    )


def test_finalizer_effect_prevents_a_lazy_export_certificate():
    facade = """
        from app.impl import execute as selected
        from legacy import dispatch
        def __getattr__(name):
            try:
                return selected
            finally:
                dispatch(None, None)
    """
    report = verify(options(facade=facade))
    assert not report["complete"]
    assert any("effect terminal" in i["reason"] for i in report["issues"])


def test_finalizer_return_selects_the_actual_export():
    facade = """
        from app.impl import execute as checked
        from app.other import execute as selected
        def __getattr__(name):
            try:
                return checked
            finally:
                return selected
    """
    current = options(facade=facade)
    current.sources["app.other"] = (
        "from legacy import dispatch\ndef execute(p, r):\n    return dispatch(p, r)\n"
    )
    report = verify(current)
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_recursive_export_cannot_bootstrap_a_binding():
    report = verify(
        options(
            facade="""
        def __getattr__(name):
            return __getattr__(name)
    """
        )
    )
    assert not report["complete"]
    assert any("recursive export" in i["reason"] for i in report["issues"])


def test_unbound_local_does_not_fall_back_to_a_global_import_primitive():
    facade = _FACADE.replace(
        "    return result", "    globals = None\n    return result"
    )
    report = verify(options(facade=facade))
    assert not report["complete"]
    assert any("unbound import local: globals" in i["reason"] for i in report["issues"])


def test_shadowed_import_primitive_uses_its_actual_source_body():
    loader = _LOADER.replace(
        "from importlib import import_module",
        dedent("""
        from legacy import dispatch
        def import_module(name, package=None):
            dispatch(None, None)
            return None
    """),
    )
    report = verify(options(loader=loader))
    assert not report["complete"]
    assert any("effect terminal" in i["reason"] for i in report["issues"])


def test_importlib_source_override_invalidates_the_native_import_model():
    current = options()
    current.sources["importlib"] = (
        "def import_module(name, package=None):\n    return None\n"
    )
    report = verify(current)
    assert not report["complete"]
    assert any(
        "source overrides a standard type-model module" == i["reason"]
        for i in report["issues"]
    )


def test_runtime_module_initialization_is_not_exempted_by_export_resolution():
    current = options()
    current.sources["app.impl"] += "\nunknown_initialization()\n"
    report = verify(current)
    assert any(e["target"] == "app.impl.execute" for e in report["export_resolutions"])
    assert not report["complete"]
    assert any("module initialization" in i["reason"] for i in report["issues"])


def test_hook_decorator_cannot_be_ignored():
    facade = _FACADE.replace("def __getattr__", "@unknown_decorator\ndef __getattr__")
    report = verify(options(facade=facade))
    assert not report["complete"]
    assert any(
        "ordinary source helper unavailable" in i["reason"] for i in report["issues"]
    )


def test_loader_defaults_and_keyword_arguments_follow_python_binding():
    loader = _LOADER.replace(
        "def select(name, module_name, package):",
        "def select(name, module_name=None, *, package=None):",
    )
    facade = _FACADE.replace(
        "select(name, module_name, __spec__.parent)",
        "select(name, module_name, package=__spec__.parent)",
    )
    report = verify(options(facade=facade, loader=loader))
    assert report["complete"], report


def test_export_conflicting_with_a_submodule_remains_unresolved():
    current = options(
        facade="""
        from app.impl import execute as selected
        def __getattr__(name):
            return selected
    """
    )
    current.sources["app.execute"] = "value = None\n"
    report = verify(current)
    assert not report["complete"]
    assert any(
        "conflicts with a source submodule" in i["reason"] for i in report["issues"]
    )


@pytest.mark.parametrize("option", ["max_steps", "max_depth"])
def test_export_resolution_budget_exhaustion_cannot_certify(option):
    report = verify(replace(options(), **{option: 1}))
    assert not report["complete"]
    assert any("budget exhausted" in i["reason"] for i in report["issues"])


def test_installed_ensure_config_export_is_resolved_through_source_helpers():
    program = _Program(installed_spec())
    assert (
        program.qualify("langchain_core.tools.base", "ensure_config")
        == "langchain_core.runnables.config.ensure_config"
    )
    evidence = next(
        e
        for e in program.export_evidence
        if e["module"] == "langchain_core.runnables" and e["name"] == "ensure_config"
    )
    assert evidence["visited_functions"] == [
        "langchain_core._import_utils.import_attr",
        "langchain_core.runnables.__getattr__",
    ]


def test_declared_effect_boundary_cannot_disappear_through_a_lazy_alias():
    current = options()
    report = verify(
        replace(
            current,
            operations=(
                *current.operations,
                Operation("app.execute", ("arg:0", "arg:1")),
            ),
        )
    )
    assert not report["complete"]
    assert any(
        "terminal contract names a rebound import alias" in i["reason"]
        for i in report["issues"]
    )


def test_every_cache_write_must_match_the_final_export():
    facade = _FACADE.replace(
        "globals()[name] = result",
        "globals()[name] = select('Base', 'impl', __spec__.parent)\n    globals()[name] = result",
    )
    report = verify(options(facade=facade))
    assert not report["complete"]
    assert any("export cache changes" in i["reason"] for i in report["issues"])


@pytest.mark.parametrize(
    "replacement",
    ["return None", "dispatch(None, None)\n            raise ImportError(module_name)"],
)
def test_exception_handler_cannot_hide_an_alternate_return_or_effect(replacement):
    loader = _LOADER.replace(
        "from importlib", "from legacy import dispatch\nfrom importlib"
    )
    loader = loader.replace("raise ImportError(module_name)", replacement)
    report = verify(options(loader=loader))
    assert not report["complete"]
    assert any(
        "import handler can return or continue" in i["reason"]
        or "effect terminal" in i["reason"]
        for i in report["issues"]
    )


def test_import_error_diagnostic_is_inert_but_remains_unknown_text():
    loader = _LOADER.replace(
        "except ModuleNotFoundError:\n            raise ImportError(module_name)",
        "except ModuleNotFoundError as error:\n            message = f'{module_name}: {error}'\n            raise ImportError(message) from error",
    )
    report = verify(options(loader=loader))
    assert report["complete"], report
    changed = loader.replace(
        "raise ImportError(message) from error",
        "if message == 'certain':\n                raise ImportError(message)\n            return None",
    )
    report = verify(options(loader=changed))
    assert not report["complete"]
    assert any(
        "comparison requires inert scalar" in i["reason"] for i in report["issues"]
    )


def test_exceptional_prefix_finalizer_cannot_use_only_the_normal_local_value():
    facade = """
        from app.impl import execute as selected
        from legacy import dispatch
        def __getattr__(name):
            flag = True
            try:
                flag = False
                return selected
            finally:
                if flag:
                    dispatch(None, None)
    """
    report = verify(options(facade=facade))
    assert not report["complete"]
    assert any(
        "import predicate requires an inert value" in i["reason"]
        for i in report["issues"]
    )


def test_exceptional_cache_write_must_also_preserve_the_export_binding():
    facade = """
        from importlib import import_module
        from app.impl import execute as selected, Base
        def __getattr__(name):
            try:
                import_module('app.impl')
            except ImportError:
                globals()[name] = Base
                raise
            return selected
    """
    report = verify(options(facade=facade))
    assert not report["complete"]
    assert any("export cache changes" in i["reason"] for i in report["issues"])


def test_native_import_parent_and_lookup_contract():
    assert collections.__spec__.parent == "collections"
    module = import_module(".abc", package=collections.__spec__.parent)
    assert module is collections.abc
    assert getattr(module, "Mapping") is collections.abc.Mapping
