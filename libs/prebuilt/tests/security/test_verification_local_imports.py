"""Local source imports and Python lexical scopes preserve proof boundaries."""

from dataclasses import replace
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec

HELPER = """
from policy import permission, Verdict
from legacy import dispatch
def execute(principal, request):
    decision = permission(principal, request)
    if decision.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
    return dispatch(principal, request)
"""


@pytest.mark.parametrize(
    "statement,call",
    [
        ("from helper import execute", "execute"),
        ("from helper import execute as go", "go"),
        ("import helper", "helper.execute"),
        ("import helper as local", "local.execute"),
    ],
)
def test_local_import_analyzes_helper_body(statement, call):
    options = spec(
        f"class Tool:\n    def invoke(self, principal, request):\n        {statement}\n        return {call}(principal, request)\n"
    )
    options = replace(options, sources={**options.sources, "helper": HELPER})
    report = verify(options)
    assert report["complete"], report
    assert "helper.execute" in report["entries"][0]["visited_functions"]
    unsafe = HELPER.replace(
        "return dispatch(principal, request)", "return dispatch(principal, 'different')"
    )
    report = verify(replace(options, sources={**options.sources, "helper": unsafe}))
    assert not report["complete"]
    assert report["entries"][0]["status"] == "violated"


def test_relative_local_import_and_reexport_follow_defining_module():
    options = replace(
        spec(),
        sources={
            "pkg": "from .helper import execute\n",
            "pkg.helper": HELPER,
            "pkg.entry": "class Tool:\n    def invoke(self, principal, request):\n        from . import execute\n        return execute(principal, request)\n",
        },
        surfaces=("pkg.entry.Tool",),
        package_modules=("pkg",),
    )
    assert verify(options)["complete"]


@pytest.mark.parametrize(
    "statement", ["import pkg.helper", "from pkg.helper import execute"]
)
def test_local_submodule_import_requires_parent_initializer(statement):
    options = spec(
        HELPER[HELPER.index("def execute") :]
        + f"\nclass Tool:\n    def invoke(self, principal, request):\n        {statement}\n        return execute(principal, request)\n"
    )
    options = replace(options, sources={**options.sources, "pkg.helper": HELPER})
    report = verify(options)
    assert not report["complete"]
    assert any(
        "parent package source" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "source", ["", "execute = build_callable()", "raise RuntimeError('initializer')"]
)
def test_missing_or_executable_exports_remain_unresolved(source):
    options = spec(
        "class Tool:\n    def invoke(self, principal, request):\n        from helper import execute\n        return execute(principal, request)\n"
    )
    assert not verify(replace(options, sources={**options.sources, "helper": source}))[
        "complete"
    ]


@pytest.mark.parametrize("statement", ["from absent import execute", "import absent"])
def test_unused_unknown_local_import_still_blocks_proof(statement):
    options = spec(
        HELPER[HELPER.index("def execute") :]
        + f"\nclass Tool:\n    def invoke(self, principal, request):\n        {statement}\n        return execute(principal, request)\n"
    )
    report = verify(options)
    assert not report["complete"]
    assert any(
        "module initializer" in i["reason"] for i in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "binding", ["flag = False", "flag: bool", "del flag", "import helper as flag"]
)
def test_read_before_local_binding_cannot_fall_back_to_global(binding):
    options = spec(
        HELPER[HELPER.index("def execute") :]
        + dedent(f"""
        flag = True
        class Tool:
            def invoke(self, principal, request):
                return execute(principal, request)
            def refused(self, principal, request):
                value = flag
                {binding}
                return dispatch(principal, request)
    """)
    )
    report = verify(replace(options, sources={**options.sources, "helper": HELPER}))
    assert report["complete"], report
    refused = next(e for e in report["entries"] if e["entry"].endswith(".refused"))
    assert refused["dispatches"] == []
    assert refused["settled_exceptions"] == 1


def test_deleted_local_does_not_reveal_same_named_global():
    options = spec(
        HELPER[HELPER.index("def execute") :]
        + """
flag = True
class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)
    def refused(self, principal, request):
        flag = False
        del flag
        value = flag
        return dispatch(principal, request)
"""
    )
    assert verify(options)["complete"]


@pytest.mark.parametrize(
    "statement",
    [
        "import pkg.helper",
        "import pkg.helper as local",
        "from pkg.helper import execute",
    ],
)
def test_submodule_import_cannot_reuse_overwritten_package_alias(statement):
    options = replace(
        spec(),
        sources={
            "pkg": "import safe as helper\n",
            "safe": HELPER,
            "pkg.helper": "from legacy import dispatch\ndef execute(p,r): return dispatch(p,r)\n",
            "entry": f"import pkg\nclass Tool:\n    def invoke(self,p,r):\n        {statement}\n        return pkg.helper.execute(p,r)\n",
        },
        surfaces=("entry.Tool",),
        package_modules=("pkg",),
    )
    report = verify(options)
    assert not report["complete"]
    assert any(
        "overwrites" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


def test_same_line_comprehension_does_not_replace_function_scope():
    options = spec(
        HELPER[HELPER.index("def execute") :]
        + """
flag = True
def listcomp(p,r): ignored=flag; flag=False; return [dispatch(p,r) for item in (1,)]
class Tool:
    def invoke(self,principal,request):
        return execute(principal,request)
    def refused(self,principal,request):
        return listcomp(principal,request)
"""
    )
    report = verify(options)
    assert report["complete"], report


def test_exception_target_clear_keeps_the_name_local():
    options = spec(
        HELPER[HELPER.index("def execute") :]
        + """
flag = True
class Tool:
    def invoke(self,principal,request):
        return execute(principal,request)
    def refused(self,principal,request):
        try:
            raise ValueError('refused')
        except ValueError as flag:
            pass
        value = flag
        return dispatch(principal,request)
"""
    )
    report = verify(options)
    assert report["complete"], report


@pytest.mark.parametrize(
    "statement",
    [
        "permission = replacement",
        "del permission",
        "from helper import execute as permission",
    ],
)
def test_unreachable_global_declaration_still_changes_assignment_scope(statement):
    options = spec(f"""
def replacement(principal,request):
    return request["forged_decision"]
class Tool:
    def invoke(self,principal,request):
        if False:
            global permission
        {statement}
        return self.run(principal,request)
    def run(self,principal,request):
        decision = permission(principal,request)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal,request)
""")
    report = verify(replace(options, sources={**options.sources, "helper": HELPER}))
    assert not report["complete"]
    assert any(
        "global or nonlocal" in issue["reason"]
        for entry in report["entries"]
        for issue in entry["issues"]
    )
