"""Portable negotiation and lifecycle contracts for semantic mediators."""

import time
from dataclasses import replace

import pytest

from langgraph.prebuilt.security import (
    HostExecutionDenied,
    ResourceSupport,
    SupportLevel,
    negotiate_object_grant,
)
from langgraph.prebuilt.security.profile import Requirement
from tests.security.test_enforcement import (
    _Adapter,
    _grant,
    _host,
    _ledger,
    _obligations,
    _Verifier,
)


@pytest.mark.parametrize("platform", ["linux", "windows", "custom-rtos"])
@pytest.mark.parametrize("requirement", [Requirement.NEED, Requirement.WANT])
@pytest.mark.parametrize("available", [False, True])
def test_same_semantic_grant_negotiates_against_actual_host(
    platform, requirement, available
):
    now = time.time()
    host = replace(_host(), platform=platform, issued_at=now - 1, expires_at=now + 60)
    obligations = _obligations()
    supported = {item.obligation_id for item in obligations}
    if not available:
        supported.remove("mail.credential")
    adapters = (_Adapter("host-specific-implementation", supported),)
    if not available and requirement is Requirement.NEED:
        with pytest.raises(HostExecutionDenied, match="required_authority_removed"):
            negotiate_object_grant(
                _grant(requirement),
                _ledger(requirement),
                obligations,
                adapters,
                _Verifier(),
                host,
                expected_nonce=host.nonce,
            )
        return
    record, _ = negotiate_object_grant(
        _grant(requirement),
        _ledger(requirement),
        obligations,
        adapters,
        _Verifier(),
        host,
        expected_nonce=host.nonce,
    )
    assert bool(record.grant.rules) == available
    assert record.plan.removed_wants == (() if available else ("profile:mail",))
    assert record.host.platform == platform


@pytest.mark.parametrize(
    "failure",
    ["untrusted", "missing_complement", "missing_operation", "duplicate", "conflict"],
)
def test_optional_pruning_cannot_hide_invalid_enforcement(failure):
    now = time.time()
    host = replace(_host(), issued_at=now - 1, expires_at=now + 60)
    obligations = _obligations()
    supported = {item.obligation_id for item in obligations} - {"mail.credential"}
    if failure == "missing_complement":
        supported.remove("domain.filesystem.default_deny")
    elif failure == "missing_operation":
        obligations = tuple(
            item for item in obligations if item.obligation_id != "mail.recipient"
        )
    elif failure == "duplicate":
        obligations = (*obligations, obligations[0])
    adapters = [_Adapter("implementation", supported)]
    if failure == "conflict":
        adapters.append(_Adapter("conflicting", supported))
    with pytest.raises(HostExecutionDenied):
        negotiate_object_grant(
            _grant(Requirement.WANT),
            _ledger(Requirement.WANT),
            obligations,
            adapters,
            _Verifier(trusted=failure != "untrusted"),
            host,
            expected_nonce=host.nonce,
        )


def test_supported_semantics_require_explicit_contract_reference():
    with pytest.raises(ValueError, match="conformance witness"):
        ResourceSupport(SupportLevel.EXACT, "callback exists")
    with pytest.raises(ValueError, match="absolute"):
        ResourceSupport(SupportLevel.EXACT, "contract", "review-v1", ("relative",))
