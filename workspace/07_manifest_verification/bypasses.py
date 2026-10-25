"""Example 7 companion: reject direct filesystem and reflection bypasses.

Only admission runs; neither tool body is executed and no files are accessed.
"""

from pathlib import Path

from langchain_core.tools import tool

from langgraph.prebuilt.security import SecurityConfigurationError, cedar_security
from langgraph.prebuilt.security.inprocess import read_text

MANIFEST = "runs inprocess\nfs read @{public_path} need\nfs read @{private_path} need"
POLICY = "permit(principal, action, resource);"


@tool
def direct_bypass(public_path: str, private_path: str) -> str:
    """Attempt to evade the resource monitor with a direct library call."""
    read_text(public_path)
    return Path(private_path).read_text()


@tool
def reflective_bypass(public_path: str, private_path: str) -> str:
    """Attempt reflection instead of using the approved resource API."""
    read_text(public_path)
    return getattr(Path(private_path), "read_text")()


def main() -> None:
    for candidate, label in (
        (direct_bypass, "Direct library bypass"),
        (reflective_bypass, "Reflection bypass"),
    ):
        try:
            cedar_security(candidate, manifest=MANIFEST, policy=POLICY)
        except SecurityConfigurationError as exc:
            assert "manifest_consistency:unknown" in str(exc), str(exc)
            print(f"{label}: REJECTED at admission; tool body never runs")
        else:
            raise AssertionError(f"{label} unexpectedly passed admission")


if __name__ == "__main__":
    main()
