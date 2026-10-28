"""Source-only manifest capability coverage and conservative failures."""

import json
import re
import sys
from dataclasses import asdict

import pytest

from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    _main,
    check_manifest_consistency,
    manifest_verification_exit_code,
)
from langgraph.prebuilt.security.object_policy import parse_security_manifest

CLASSES = """
class fs {
  operations read write
  object path
  normalizer identity
  attrs
  enforced_by language_sandbox
}
"""
MODELS = (
    ManifestOperation("storage.read", "fs", "read", "path"),
    ManifestOperation("storage.write", "fs", "write", "path"),
)


def check(source, rules="fs read @{path} need"):
    manifest = parse_security_manifest(CLASSES + "\ntool reader {\n" + rules + "\n}")
    return check_manifest_consistency(
        source, manifest, tool_name="reader", operations=MODELS
    )


def test_alias_and_keyword_resource():
    report = check("""
from storage import read as fetch

def reader(path):
    resource = path
    return fetch(path=resource)
""")
    assert report["consistent"]
    assert report["observed"][0]["rules"] == [0]
    assert not report["unused_rules"]


@pytest.mark.parametrize(
    "body",
    [
        "return storage.write(path)",
        'return storage.read("/different")',
        'return storage.read("@{path}")',
    ],
)
def test_operation_and_resource_mismatches(body):
    assert check(f"def reader(path):\n    {body}")["status"] == "mismatch"


def test_template():
    report = check(
        """
def reader(path):
    return storage.read(f"root/{path}")
""",
        "fs read root/@{path} need",
    )
    assert report["consistent"]


def test_closed_map():
    report = check(
        """
def reader(path, operation):
    if operation == "read":
        return storage.read(path)
    else:
        return storage.write(path)
""",
        "map operation=read fs read @{path} need\nmap operation=write fs write @{path} need",
    )
    assert report["consistent"]
    assert len(report["inferred"]) == 2
    wrong = check(
        """
def reader(path, operation):
    return storage.write(path)
""",
        "map operation=read fs read @{path} need\nmap operation=write fs write @{path} need",
    )
    assert wrong["status"] == "mismatch"


@pytest.mark.parametrize(
    "body",
    [
        "return helper(path)",
        "return storage.read(transform(path))",
        "for item in path:\n        storage.read(item)",
        "if path:\n        storage.read(path)",
        "storage = path\n    return storage.read(path)",
        "return storage.read(**path)",
        "return storage.read(path, path=path)",
        'return storage.read(f"{path!r}")',
    ],
)
def test_unknown_never_passes(body):
    report = check(f"def reader(path):\n    {body}")
    assert report["status"] == "unknown"
    assert not report["consistent"]


def test_missing_manifest_argument():
    assert check("def reader(other):\n    return other")["status"] == "mismatch"


def test_unused_manifest_permissions_are_allowed():
    report = check("def reader(path):\n    return path")
    assert report["status"] == "consistent"
    assert report["inferred_subset_of_manifest"] is True
    assert report["unused_rules"] == [0]


def test_manifest_must_cover_the_inferred_overapproximation():
    report = check("""
def reader(path):
    storage.read(path)
    return storage.write(path)
""")
    assert not report["consistent"]
    assert report["inferred_subset_of_manifest"] is False
    assert [item["operation"] for item in report["inferred"]] == ["read", "write"]
    assert report["outside_manifest"] == [1]
    assert not check("def reader(path): return storage.read(path)", rules="")[
        "consistent"
    ]


@pytest.mark.parametrize(
    "forbidden",
    [
        "getattr(storage, path)(path)",
        "eval(path)",
        "exec(path)",
        "__import__(path)",
        "globals()",
        "locals()",
        "vars(storage)",
        "storage.__dict__",
        "requests.get(path)",
        "socket.socket()",
        "subprocess.run(path)",
        "ctypes.CDLL(path)",
        "helper(path)",
    ],
)
@pytest.mark.parametrize("location", ["before", "after_return", "excluded_branch"])
def test_unmonitored_libraries_and_reflection_always_reject(forbidden, location):
    if location == "before":
        body = f"{forbidden}\n    return storage.read(path)"
    elif location == "after_return":
        body = f"return storage.read(path)\n    {forbidden}"
    else:
        body = f'if operation == "read":\n        return storage.read(path)\n    else:\n        return {forbidden}'
    report = check(
        f"def reader(path, operation):\n    {body}",
        rules="map operation=read fs read @{path} need",
    )
    assert not report["consistent"]
    assert report["status"] == "unknown"
    assert report["inference_complete"] is False
    assert report["inferred_subset_of_manifest"] is None


def test_import_inside_body_rejects_even_after_return():
    report = check(
        "def reader(path):\n    return storage.read(path)\n    import socket"
    )
    assert report["status"] == "unknown"


def test_inference_includes_both_sides_without_manifest_selectors():
    report = check("""
def reader(path, operation):
    if operation == "read":
        return storage.read(path)
    else:
        return storage.write(path)
""")
    assert not report["consistent"]
    assert {effect["operation"] for effect in report["inferred"]} == {"read", "write"}


def test_no_source_execution():
    report = check("""
raise RuntimeError("source must never execute")
def reader(path):
    return storage.read(path)
""")
    assert report["consistent"]
    assert "module initialization" in report["scope"]


@pytest.mark.parametrize(
    "source",
    [
        "bad syntax!",
        "def other(): pass",
        "def reader(path): pass\ndef reader(path): pass",
    ],
)
def test_invalid_entry(source):
    assert check(source)["status"] == "unknown"


def test_invalid_contract():
    manifest = parse_security_manifest(CLASSES + "\ntool reader {}")
    with pytest.raises(ValueError, match="unique"):
        check_manifest_consistency(
            "", manifest, tool_name="reader", operations=MODELS * 2
        )
    with pytest.raises(ValueError, match="unknown modeled"):
        check_manifest_consistency(
            "",
            manifest,
            tool_name="reader",
            operations=(ManifestOperation("storage.remove", "fs", "remove", "path"),),
        )


@pytest.mark.parametrize(
    "body,expected",
    [
        ("return storage.read(path)", 0),
        ("return storage.write(path)", 1),
        ("return helper(path)", 1),
    ],
)
def test_cli(tmp_path, monkeypatch, body, expected):
    source = tmp_path / "tool.py"
    source.write_text(f"def reader(path):\n    {body}")
    manifest = tmp_path / "tool.slp"
    manifest.write_text(CLASSES + "\ntool reader {\nfs read @{path} need\n}")
    models = tmp_path / "models.json"
    models.write_text(json.dumps([asdict(model) for model in MODELS]))
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "checker",
            str(source),
            str(manifest),
            "--tool",
            "reader",
            "--operations",
            str(models),
            "--output",
            str(output),
        ],
    )
    assert _main() == expected
    assert json.loads(output.read_text())["consistent"] == (expected == 0)


@pytest.mark.parametrize(
    "terminal,no_color", [(True, False), (True, True), (False, False)]
)
def test_framework_verifier_diagnostics(monkeypatch, capsys, terminal, no_color):
    monkeypatch.setattr(sys.stderr, "isatty", lambda: terminal)
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        monkeypatch.delenv("NO_COLOR", raising=False)
    bad = check("def reader(path):\n    return storage.write(path)")
    assert manifest_verification_exit_code(bad, source_name="candidate.py") == 1
    output = capsys.readouterr()
    assert output.out == ""
    plain = re.sub(r"\x1b\[[0-9;]*m", "", output.err)
    assert "candidate.py: error: manifest verification failed for reader" in plain
    assert "inferred fs::write on @{path} is not permitted by the manifest" in plain
    assert "Failed subset check: inferred ⊆ manifest." in plain
    assert "candidate.py:2: inferred: fs::write on @{path} from storage.write" in plain
    if terminal and not no_color:
        assert (
            "candidate.py: \x1b[1;31merror:\x1b[0m \x1b[1;33mmanifest verification failed for reader (mismatch)\x1b[0m"
            in output.err
        )
        assert output.err.index("\x1b[1;31m") < output.err.index("\x1b[1;33m")
        for label, message in (
            ("Failed subset check", "inferred ⊆ manifest."),
            ("error", "inferred fs::write"),
            ("inferred", "fs::write on @{path}"),
            ("Static verification", "rejected this tool body."),
        ):
            assert f"\x1b[1;31m{label}:\x1b[0m \x1b[1;33m{message}" in output.err
    else:
        assert output.err == plain
    good = check("def reader(path):\n    return storage.read(path)")
    assert manifest_verification_exit_code(good) == 0
    assert capsys.readouterr() == ("", "")


def test_unknown_diagnostic_identifies_unproved_subset(capsys):
    report = check("def reader(path):\n    storage.read(path)\n    exec(path)")
    assert manifest_verification_exit_code(report) == 1
    diagnostic = capsys.readouterr().err
    assert "Cannot establish subset check: inferred ⊆ allowed operations" in diagnostic
    assert "Subset check not established: inferred ⊆ manifest" in diagnostic
    assert "Failed subset check: inferred ⊆ manifest" not in diagnostic
    assert "unmodeled call: exec" in diagnostic


def test_unproved_subset_uses_red_label_and_yellow_message(monkeypatch, capsys):
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    report = check("def reader(path):\n    exec(path)")
    assert manifest_verification_exit_code(report) == 1
    assert (
        "\x1b[1;31mCannot establish subset check:\x1b[0m \x1b[1;33minferred ⊆ allowed operations"
        in capsys.readouterr().err
    )


def test_unused_write_permission_is_not_an_obligation():
    report = check(
        "def reader(path): return storage.read(path)",
        rules="fs read @{path} need\nfs write @{path} need",
    )
    assert report["consistent"]
    assert report["unused_rules"] == [1]


def test_closed_map_does_not_mix_permissions_between_selector_values():
    report = check(
        "def reader(path, operation): return storage.write(path)",
        rules="map operation=read fs read @{path} need\nmap operation=write fs write @{path} need",
    )
    assert not report["consistent"]
    assert report["outside_manifest"] == [0]
    assert "when operation=read" in report["issues"][0]["reason"]


def test_closed_map_excludes_unmapped_execution_but_audits_all_calls():
    report = check(
        'def reader(path, operation):\n    if operation == "read":\n        return storage.read(path)\n    else:\n        return storage.write(path)',
        rules="map operation=read fs read @{path} need",
    )
    assert report["consistent"]
    assert [effect["operation"] for effect in report["inferred"]] == ["read"]
