"""Tests for the public descriptor and DAC API."""

import json
from pathlib import Path

from langgraph.prebuilt import security


def test_security_package_exports_descriptor_api() -> None:
    """Keep the descriptor public surface deliberate."""
    snapshot = json.loads((Path(__file__).parent / "api_snapshot.json").read_text())
    assert security.__all__ == tuple(snapshot)
    assert snapshot[:3] == [
        "NORMALIZERS",
        "PRINCIPAL_CONFIG_KEY",
        "ActivationEvidence",
    ]
