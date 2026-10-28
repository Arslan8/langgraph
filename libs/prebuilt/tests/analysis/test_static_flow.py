"""Manifest flow preflight stays conservative and never runs source code."""

import pytest

from langgraph.prebuilt.analysis.static_flow import check_manifest_flow
from langgraph.prebuilt.security.manifest_consistency import ManifestOperation
from langgraph.prebuilt.security.object_policy import parse_security_manifest

CLASSES = """
class fs {
  operations read write delete
  object path
  normalizer identity
  attrs
  enforced_by trusted_tool
}
"""
OPERATIONS = (
    ManifestOperation("api.read", "fs", "read", "path"),
    ManifestOperation("api.write", "fs", "write", "path"),
)
SOURCE = """
def publish():
    value = api.read("/secret")
    api.write("/sink", value)
    return "done"
"""


def check(
    source=SOURCE, rules="fs read /secret need\nfs write /sink need", **overrides
):
    manifest = parse_security_manifest(CLASSES + "\ntool publish {\n" + rules + "\n}")
    options = dict(
        tool_name="publish",
        operations=OPERATIONS,
        read_labels={("fs", "/secret"): {"secret"}},
        write_clearances={("fs", "/sink"): set()},
        input_labels=set(),
        return_clearance={"secret"},
    )
    options.update(overrides)
    return check_manifest_flow(source, manifest, **options)


def test_public_sink_reports_potential_flow_and_cleared_sink_is_compatible():
    report = check()
    assert report["source_check"]["consistent"]
    assert report["status"] == "potential_flow"
    assert report["potential_flows"] == [
        {"destination": "fs:/sink", "missing_clearance": ["secret"]}
    ]
    assert (
        check(write_clearances={("fs", "/sink"): {"secret"}})["status"] == "compatible"
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"read_labels": {}},
        {"write_clearances": {}},
        {"input_labels": None},
        {"return_clearance": None},
    ],
)
def test_missing_classifications_are_unknown(overrides):
    assert check(**overrides)["status"] == "unknown"


@pytest.mark.parametrize(
    "source",
    [
        "def publish():\n    unknown()",
        "def publish():\n    api.read('/undeclared')",
        "not valid python!",
    ],
)
def test_unverified_source_never_passes(source):
    report = check(source)
    assert report["status"] == "unknown"
    assert not report["source_check"]["consistent"]


def test_unused_read_authority_and_order_are_conservative():
    report = check("def publish():\n    api.write('/sink', 'constant')")
    assert report["source_check"]["consistent"]
    assert report["status"] == "potential_flow"
    assert report["source_check"]["unused_rules"] == [0]
    report = check(
        "def publish():\n    api.write('/sink', 'constant')\n    api.read('/secret')"
    )
    assert report["status"] == "potential_flow"


def test_inputs_and_return_destination_are_included():
    report = check(
        "def publish(value):\n    return value",
        rules="",
        input_labels={"secret"},
        return_clearance=set(),
    )
    assert report["status"] == "potential_flow"
    assert report["potential_flows"] == [
        {"destination": "return", "missing_clearance": ["secret"]}
    ]
    assert (
        check(return_clearance=set())["potential_flows"][-1]["destination"] == "return"
    )


@pytest.mark.parametrize(
    "rules",
    [
        "fs read @{path} need",
        "fs read /data/* need",
        "map choice=read fs read /secret need",
        "fs delete /secret need",
    ],
)
def test_unbounded_or_unclassified_authority_is_unknown(rules):
    assert (
        check("def publish():\n    return 'constant'", rules=rules)["status"]
        == "unknown"
    )


def test_analysis_does_not_execute_module_or_function(tmp_path):
    marker = tmp_path / "must-not-exist"
    source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n" + SOURCE
    report = check(source, write_clearances={("fs", "/sink"): {"secret"}})
    assert report["status"] == "compatible"
    assert not marker.exists()
    assert not report["source_check"]["initialization_verified"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"input_labels": "secret"},
        {"return_clearance": ["secret"]},
        {"read_labels": {("fs", "/secret"): "secret"}},
        {"operation_roles": {("fs", "read"): "ignore"}},
    ],
)
def test_invalid_policy_configuration_is_rejected(overrides):
    with pytest.raises(ValueError):
        check(**overrides)
