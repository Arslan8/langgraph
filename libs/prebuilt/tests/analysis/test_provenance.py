from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from itertools import product

import pytest

from langgraph.prebuilt.analysis.errors import (
    AnalysisUnavailable,
    MissingValue,
    StorageExhausted,
)
from langgraph.prebuilt.analysis.provenance.checkpoint import CheckpointBinding
from langgraph.prebuilt.analysis.provenance.domains import (
    AllowedReadersDomain,
    DomainRegistry,
)
from langgraph.prebuilt.analysis.provenance.records import DependencyEdge, ValueRecord
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore
from langgraph.prebuilt.security.objects import SecurityLabels
from langgraph.prebuilt.security.types import Principal


def value(content=b"same", tenant="t", **kwargs):
    return ValueRecord(tenant, "s", "r", content, **kwargs)


def test_distinct_identities_and_conservative_transfers(tmp_path):
    path = str(tmp_path / "provenance.db")
    store = SqliteProvenanceStore(path)
    source = store.register(value(labels=SecurityLabels(frozenset({"secret"}), "low")))
    other = store.register(value())
    assert source.value_id != other.value_id
    current = source
    for operation in (
        "copy",
        "summary",
        "format",
        "parse",
        "normalize",
        "reduce",
        "cache",
        "child.return",
        "model.response",
    ):
        current = store.derive((current,), value(b"changed"), operation)
        assert store.get(current).labels.confidentiality == {"secret"}
        assert source in store.ancestors(current)
    store.close()
    reopened = SqliteProvenanceStore(path)
    assert source in reopened.ancestors(current)
    assert reopened.resolve(current) == b"changed"
    with pytest.raises(MissingValue):
        reopened.derive((current,), value(tenant="other"), "copy")
    reopened.close()


def test_domains_algebra():
    domain = AllowedReadersDomain()
    labels = ["public", "unknown", (), ("A", "B"), ("B", "C")]
    assert domain.combine([("A", "B"), ("B", "C")]) == ("B",)
    for a, b, c in product(labels, repeat=3):
        assert domain.combine([a, b]) == domain.combine([b, a])
        assert domain.combine([a, a]) == a
        assert domain.combine([domain.combine([a, b]), c]) == domain.combine(
            [a, domain.combine([b, c])]
        )
        assert domain.is_at_least_as_restrictive(domain.combine([a, b]), a)
    assert domain.can_flow("public", "A")
    assert not domain.can_flow((), "A")
    assert not domain.can_flow("unknown", "A")


def test_concurrent_storage_capacity_and_control():
    store = MemoryProvenanceStore(max_records=30)
    with ThreadPoolExecutor(4) as pool:
        refs = tuple(pool.map(lambda _: store.register(value()), range(20)))
    assert len(set(refs)) == 20
    condition = store.register(
        value(labels=SecurityLabels(frozenset({"secret"}), "low"))
    )
    effect = store.derive(
        (),
        value(),
        "constant-effect",
        edges=(DependencyEdge(parent=condition, kind="control"),),
    )
    assert condition in store.ancestors(effect)
    assert store.get(effect).labels.confidentiality == {"secret"}
    for _ in range(8):
        store.register(value())
    with pytest.raises(StorageExhausted):
        store.register(value())


def test_domain_configuration_bound_on_restart(tmp_path):
    path = str(tmp_path / "domain.db")
    SqliteProvenanceStore(
        path, domains=DomainRegistry((AllowedReadersDomain(),))
    ).close()
    with pytest.raises(ValueError, match="configuration_mismatch"):
        SqliteProvenanceStore(path)


def test_structural_containment_does_not_influence_selected_field():
    store = MemoryProvenanceStore()
    secret = store.register(value(labels=SecurityLabels(frozenset({"secret"}), "low")))
    public = store.register(value())
    container = store.derive(
        (),
        value(),
        "container",
        edges=(
            DependencyEdge(parent=secret, kind="containment", selector="secret"),
            DependencyEdge(parent=public, kind="containment", selector="public"),
        ),
    )
    selected = store.derive((public,), value(), "select")
    assert secret not in store.ancestors(selected)
    assert len(store.get(container).dependencies) == 2


def test_authenticated_checkpoint_restore(tmp_path):
    source = SqliteProvenanceStore(str(tmp_path / "source.db"))
    ref = source.register(value(labels=SecurityLabels(frozenset({"secret"}), "low")))
    principal = Principal("owner", frozenset(), frozenset(), "s")
    sealed = CheckpointBinding(source, b"test-key", "fixed").save(
        principal, (ref,), checkpoint_id="checkpoint"
    )
    target = SqliteProvenanceStore(str(tmp_path / "target.db"))
    binding = CheckpointBinding(target, b"test-key", "fixed")
    assert binding.restore(principal, sealed) == (ref,)
    assert target.get(ref).labels.confidentiality == {"secret"}
    with pytest.raises(AnalysisUnavailable, match="configuration_mismatch"):
        CheckpointBinding(target, b"test-key", "changed").restore(principal, sealed)
    with pytest.raises(PermissionError):
        binding.restore(principal, replace(sealed, payload={}))
    source.close()
    target.close()
