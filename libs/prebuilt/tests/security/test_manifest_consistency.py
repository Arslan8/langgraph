"""Source-only manifest capability coverage and conservative failures."""

import json
import sys
from dataclasses import asdict

import pytest

from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    _main,
    check_manifest_consistency,
)
from langgraph.prebuilt.security.object_policy import parse_security_manifest

CLASSES = """
class fs {
  operations read write
  object path
  normalizer identity
  attrs
  enforced_by trusted_tool
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
    assert len(report["observed"]) == 2
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


def test_unused_rules_are_visible():
    report = check("def reader(path):\n    return path")
    assert report["consistent"]
    assert report["unused_rules"] == [0]


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
