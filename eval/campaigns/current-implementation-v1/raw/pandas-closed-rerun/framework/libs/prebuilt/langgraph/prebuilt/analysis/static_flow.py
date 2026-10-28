"""Optional conservative information-flow preflight over verified manifests.

This checks an authority bound, not variable-level data dependence. Tool bodies
are parsed, never executed. Runtime authorization and confinement remain separate.
"""

from collections.abc import Mapping, Set
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    check_manifest_consistency,
)
from langgraph.prebuilt.security.object_policy import SecurityManifest

Resource = tuple[str, str]
Operation = tuple[str, str]


def _labels(value):
    if value is None:
        return None
    if not isinstance(value, Set) or any(not isinstance(label, str) for label in value):
        raise ValueError("static_flow:labels_must_be_string_sets")
    return frozenset(value)


def check_manifest_flow(
    source: str,
    manifest: SecurityManifest,
    *,
    tool_name: str,
    operations: tuple[ManifestOperation, ...],
    read_labels: Mapping[Resource, Set[str]],
    write_clearances: Mapping[Resource, Set[str]],
    input_labels: Set[str] | None,
    return_clearance: Set[str] | None,
    operation_roles: Mapping[Operation, Literal["read", "write"]] | None = None,
    function: str | None = None,
    clients: Mapping[str, object] | None = None,
) -> dict:
    """Check whether declared reads/inputs can flow to every write and return.

    Resource classifications, input bounds, return clearance and terminal API
    summaries are trusted policy inputs. Every declared read contributes, even
    if unused; every declared write is checked, regardless of order. Only fixed,
    literal, unconditioned resources are supported. Unknown classifications,
    unsupported source or an incomplete manifest never produce `compatible`.
    """
    roles = (
        {("fs", "read"): "read", ("fs", "write"): "write"}
        if operation_roles is None
        else dict(operation_roles)
    )
    if any(role not in ("read", "write") for role in roles.values()):
        raise ValueError("static_flow:invalid_operation_role")

    read_bound = _labels(input_labels)
    returned_to = _labels(return_clearance)
    inputs = {key: _labels(value) for key, value in read_labels.items()}
    outputs = {key: _labels(value) for key, value in write_clearances.items()}
    source_check = check_manifest_consistency(
        source,
        manifest,
        tool_name=tool_name,
        operations=operations,
        function=function,
        clients=clients,
    )
    issues = []
    if not source_check["consistent"]:
        issues.append("source effects are unknown or not covered by the manifest")
    if read_bound is None:
        issues.append("input confidentiality bound is unknown")
    if returned_to is None:
        issues.append("return destination clearance is unknown")
    bound = set(read_bound or ())
    sinks = []
    for rule in manifest.tools[tool_name].rules:
        resource = (rule.class_name, rule.pattern)
        role = roles.get((rule.class_name, rule.operation))
        if role is None:
            issues.append(
                f"unclassified operation: {rule.class_name}::{rule.operation}"
            )
            continue
        if (
            rule.selector_arg is not None
            or "@{" in rule.pattern
            or any(char in rule.pattern for char in "*?[]")
        ):
            issues.append(f"resource requires a finite literal bound: {resource}")
            continue
        classification = (inputs if role == "read" else outputs).get(resource)
        if classification is None:
            issues.append(f"missing {role} classification: {resource}")
            continue
        if role == "read":
            bound.update(classification)
        else:
            sinks.append((f"{rule.class_name}:{rule.pattern}", classification))
    if returned_to is not None:
        sinks.append(("return", returned_to))
    potential_flows = [
        {"destination": destination, "missing_clearance": sorted(bound - clearance)}
        for destination, clearance in sinks
        if not bound.issubset(clearance)
    ]
    return {
        "status": "unknown"
        if issues
        else "potential_flow"
        if potential_flows
        else "compatible",
        "read_bound": sorted(bound),
        "potential_flows": potential_flows,
        "issues": issues,
        "source_check": source_check,
        "scope": "function_body_and_declared_authority_bound",
    }


@dataclass(frozen=True, kw_only=True)
class StaticFlowPolicy:
    """Opt-in static IFC gate for source-bound in-process manifest admission.

    Classification inputs are copied and frozen. Only a compatible authority
    bound admits the tool; potential flows and unknown evidence reject setup.
    Runtime grant enforcement and admitted-body identity checks remain mandatory.
    """

    read_labels: Mapping[Resource, Set[str]]
    input_labels: Set[str] | None
    return_clearance: Set[str] | None
    write_clearances: Mapping[Resource, Set[str]] = field(default_factory=dict)
    operation_roles: Mapping[Operation, Literal["read", "write"]] | None = None

    def __post_init__(self):
        for name in ("read_labels", "write_clearances"):
            object.__setattr__(
                self,
                name,
                MappingProxyType(
                    {key: _labels(value) for key, value in getattr(self, name).items()}
                ),
            )
        for name in ("input_labels", "return_clearance"):
            object.__setattr__(self, name, _labels(getattr(self, name)))
        if self.operation_roles is not None:
            object.__setattr__(
                self, "operation_roles", MappingProxyType(dict(self.operation_roles))
            )

    def require(
        self,
        source: str,
        manifest: SecurityManifest,
        *,
        tool_name: str,
        operations: tuple[ManifestOperation, ...] = (),
        function: str | None = None,
        clients: Mapping[str, object] | None = None,
    ) -> dict:
        report = check_manifest_flow(
            source,
            manifest,
            tool_name=tool_name,
            operations=operations,
            read_labels=self.read_labels,
            write_clearances=self.write_clearances,
            input_labels=self.input_labels,
            return_clearance=self.return_clearance,
            operation_roles=self.operation_roles,
            function=function,
            clients=clients,
        )
        if report["status"] != "compatible":
            reasons = [
                f"{flow['destination']} lacks {', '.join(flow['missing_clearance'])}"
                for flow in report["potential_flows"]
            ] + report["issues"]
            raise SecurityConfigurationError(
                f"static_flow:{report['status']}:{tool_name}: " + "; ".join(reasons)
            )
        return report
