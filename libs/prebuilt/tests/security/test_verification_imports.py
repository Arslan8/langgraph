"""Package spelling and dependency discovery never execute candidate source."""

import json
from dataclasses import replace
from pathlib import Path
from textwrap import dedent
from types import ModuleType

import pytest

from langgraph.prebuilt.security.verification import (
    _loaded_source_closure,
    installed_spec,
    load_spec,
    verify,
)
from tests.security.test_verification import spec

_HELPER = """
from policy import permission, Verdict
from legacy import dispatch

def execute(principal, request):
    decision = permission(principal, request)
    if decision.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
    return dispatch(principal, request)
"""
_TOOL = """
class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)
"""


@pytest.mark.parametrize(
    ("module", "statement", "packages"),
    [
        ("app.tools", "from .helper import execute", ()),
        ("app.tools.entry", "from ..helper import execute", ()),
        ("app.tools", "from ..helper import execute", ("app.tools",)),
        ("app", "from .helper import execute", ("app",)),
    ],
)
def test_relative_import_uses_defining_package(module, statement, packages):
    report = verify(
        replace(
            spec(),
            sources={module: statement + "\n" + _TOOL, "app.helper": _HELPER},
            package_modules=packages,
            surfaces=(f"{module}.Tool",),
        )
    )
    assert report["complete"], report
    assert "app.helper.execute" in report["entries"][0]["visited_functions"]
    assert report["package_modules"] == sorted(packages)


def test_relative_module_import_and_package_reexport_follow_helper_body():
    sources = {
        "app": "from .helper import execute\n",
        "app.helper": _HELPER,
        "app.tools.entry": "from .. import execute\n" + _TOOL,
        "app.other": (
            "from . import helper\n"
            + _TOOL.replace("return execute", "return helper.execute")
        ),
    }
    options = replace(
        spec(),
        sources=sources,
        package_modules=("app",),
        surfaces=("app.tools.entry.Tool", "app.other.Tool"),
    )
    assert verify(options)["complete"]
    sources["app.helper"] = dedent("""
        from legacy import dispatch
        def execute(principal, request):
            return dispatch(principal, request)
    """)
    report = verify(options)
    assert not report["complete"]
    assert all(entry["status"] == "violated" for entry in report["entries"])


@pytest.mark.parametrize(
    ("module", "statement", "reason"),
    [
        ("entry", "from .helper import execute", "no containing package"),
        ("app.entry", "from ..helper import execute", "beyond the containing package"),
        (
            "app.deep.entry",
            "from ...helper import execute",
            "beyond the containing package",
        ),
    ],
)
def test_invalid_relative_import_cannot_certify(module, statement, reason):
    report = verify(
        replace(
            spec(),
            sources={module: statement + "\n" + _TOOL, "helper": _HELPER},
            surfaces=(f"{module}.Tool",),
        )
    )
    assert not report["complete"]
    assert any(reason in issue["reason"] for issue in report["issues"])


@pytest.mark.parametrize("packages", [("missing",), ("example", "example")])
def test_package_manifest_requires_unique_existing_sources(packages):
    with pytest.raises(ValueError, match="package modules"):
        replace(spec(), package_modules=packages)


@pytest.mark.parametrize("source_roots", [False, True])
def test_loading_files_records_package_initializers(tmp_path, source_roots):
    package = tmp_path / "app"
    package.mkdir()
    (package / "__init__.py").write_text("from .helper import execute\n" + _TOOL)
    (package / "helper.py").write_text(_HELPER)
    base = spec()
    payload = {
        "surfaces": ["app.Tool"],
        "authorizers": [vars(item) for item in base.authorizers],
        "operations": [vars(item) for item in base.operations],
    }
    if source_roots:
        payload["source_roots"] = {"app": "app"}
    else:
        payload["sources"] = {"app": "app/__init__.py", "app.helper": "app/helper.py"}
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(payload))
    options = load_spec(path)
    assert options.package_modules == ("app",)
    assert verify(options)["complete"]


def _module(tmp_path, name, source, *, package=False):
    path = tmp_path / (name + (".__init__" if package else "") + ".py")
    path.write_text(source)
    module = ModuleType(name)
    module.__file__ = str(path)
    if package:
        module.__path__ = []
    return module


def test_loaded_closure_follows_transitive_imports_and_empty_facades(tmp_path):
    modules = {
        "app": _module(tmp_path, "app", "", package=True),
        "app.tools": _module(
            tmp_path, "app.tools", "from .helper import execute\n" + _TOOL
        ),
        "app.helper": _module(tmp_path, "app.helper", "from .nested import execute\n"),
        "app.nested": _module(tmp_path, "app.nested", _HELPER),
    }
    sources = {"app.tools": "from .helper import execute\n" + _TOOL}
    packages = set()
    _loaded_source_closure(sources, packages, modules)
    assert set(sources) == set(modules)
    assert packages == {"app"}
    assert verify(
        replace(
            spec(),
            sources=sources,
            surfaces=("app.tools.Tool",),
            package_modules=tuple(packages),
        )
    )["complete"]


def test_discovery_does_not_execute_module_or_lazy_export_hooks(tmp_path):
    source = "raise RuntimeError('candidate source must not execute')\n"
    modules = {
        "app": _module(tmp_path, "app", source, package=True),
        "app.helper": _module(tmp_path, "app.helper", source),
    }

    def lazy(name):
        pytest.fail(f"discovery invoked module __getattr__: {name}")

    modules["app"].__getattr__ = lazy
    sources = {"app.tools": "from . import helper\n"}
    packages = set()
    _loaded_source_closure(sources, packages, modules)
    assert sources["app"] == source
    assert sources["app.helper"] == source


def test_unloaded_dependencies_and_external_distributions_stay_unresolved(tmp_path):
    sources = {
        "app.tools": "from external import execute\nfrom .missing import unused\n"
        + _TOOL
    }
    modules = {"external": _module(tmp_path, "external", _HELPER)}
    packages = set()
    _loaded_source_closure(sources, packages, modules)
    assert set(sources) == {"app.tools"}
    report = verify(replace(spec(), sources=sources, surfaces=("app.tools.Tool",)))
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"


def test_loaded_module_with_missing_source_fails_closed(tmp_path):
    module = _module(tmp_path, "app.helper", _HELPER)
    Path(module.__file__).unlink()
    with pytest.raises(ValueError, match="source module unavailable: app.helper"):
        _loaded_source_closure(
            {"app.tools": "from .helper import execute\n"},
            set(),
            {"app.helper": module},
        )


def test_imported_tool_subclass_enters_the_verified_surface(tmp_path):
    base = "from .helper import execute\nfrom .extra import Extra\n" + _TOOL
    extra = dedent("""
        from .tools import Tool
        class Extra(Tool):
            def inspect(self):
                return None
    """)
    modules = {
        "app": _module(tmp_path, "app", "", package=True),
        "app.helper": _module(tmp_path, "app.helper", _HELPER),
        "app.extra": _module(tmp_path, "app.extra", extra),
    }
    sources = {"app.tools": base}
    packages = set()
    _loaded_source_closure(sources, packages, modules)
    report = verify(
        replace(
            spec(),
            sources=sources,
            surfaces=("app.tools.Tool",),
            package_modules=tuple(packages),
        )
    )
    assert report["complete"], report
    assert set(report["surfaces"]["app.extra.Extra"]) == {"invoke", "inspect"}
    assert report["summary"]["entries"] == 3


def test_package_manifest_changes_resolution_and_certificate():
    sources = {
        "app.entry": "from .helper import execute\n" + _TOOL,
        "app.helper": _HELPER,
        "app.entry.helper": dedent("""
            from legacy import dispatch
            def execute(principal, request):
                return dispatch(principal, request)
        """),
    }
    options = replace(spec(), sources=sources, surfaces=("app.entry.Tool",))
    ordinary = verify(options)
    package = verify(replace(options, package_modules=("app.entry",)))
    assert ordinary["complete"], ordinary
    assert not package["complete"]
    assert ordinary["source_hashes"] == package["source_hashes"]
    assert ordinary["package_modules"] != package["package_modules"]
    assert package["entries"][0]["status"] == "violated"


def test_namespace_parent_has_no_fabricated_initializer(tmp_path):
    namespace = ModuleType("app")
    namespace.__path__ = [str(tmp_path)]
    sources = {"app.tools": "from .helper import execute\n" + _TOOL}
    modules = {
        "app": namespace,
        "app.helper": _module(tmp_path, "app.helper", _HELPER),
    }
    packages = set()
    _loaded_source_closure(sources, packages, modules)
    assert "app" not in sources
    assert not packages
    assert verify(replace(spec(), sources=sources, surfaces=("app.tools.Tool",)))[
        "complete"
    ]


def test_runtime_export_discovers_provider_without_trusting_export_hook(tmp_path):
    facade = _module(
        tmp_path,
        "app.facade",
        "def __getattr__(name):\n    raise RuntimeError('unknown export')\n",
        package=True,
    )

    def placeholder():
        pass

    placeholder.__module__ = "app.provider"
    facade.execute = placeholder
    sources = {"app.tools": "from .facade import execute\n" + _TOOL}
    modules = {
        "app.facade": facade,
        "app.provider": _module(tmp_path, "app.provider", _HELPER),
    }
    packages = set()
    _loaded_source_closure(sources, packages, modules)
    assert "app.provider" in sources
    report = verify(
        replace(
            spec(),
            sources=sources,
            surfaces=("app.tools.Tool",),
            package_modules=tuple(packages),
        )
    )
    assert not report["complete"]
    assert report["entries"][0]["status"] == "unresolved"


def test_installed_discovery_includes_config_helper_source():
    options = installed_spec()
    assert "langchain_core.runnables.config" in options.sources
    assert "def ensure_config(" in options.sources["langchain_core.runnables.config"]
    assert "langchain_core.runnables" in options.package_modules
