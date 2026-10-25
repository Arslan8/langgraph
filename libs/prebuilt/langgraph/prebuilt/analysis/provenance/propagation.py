"""Conservative transfer, including context influence and SecurityLabels."""

import json
from collections.abc import Sequence
from dataclasses import replace

from langgraph.prebuilt.analysis.provenance.domains import DomainRegistry
from langgraph.prebuilt.analysis.provenance.records import StoredValue, ValueRecord
from langgraph.prebuilt.analysis.serialization import canonical
from langgraph.prebuilt.security.objects import SecurityLabels


def transfer(
    inputs: Sequence[StoredValue], output: ValueRecord, domains: DomainRegistry
) -> ValueRecord:
    """Copy/summary/model/tool/reducer transfers cannot cleanse their inputs."""
    confidentiality = set(output.labels.confidentiality)
    integrity = {output.labels.integrity}
    origins = set(output.origin_refs)
    for value in inputs:
        confidentiality.update(value.labels.confidentiality)
        integrity.add(value.labels.integrity)
        origins.update(value.origin_refs)
    labels = SecurityLabels(
        frozenset(confidentiality), "trusted" if integrity == {"trusted"} else "low"
    )
    combined = domains.combine(
        [json.loads(value.domains_json) for value in inputs]
        + [json.loads(output.domains_json)]
    )
    return replace(
        output,
        labels=labels,
        domains_json=canonical(combined),
        origin_refs=tuple(sorted(origins)),
    )
