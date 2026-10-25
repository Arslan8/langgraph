"""Example 7: a real tool with an incorrect manifest.

Run: python workspace/07_manifest_verification/demo.py
Replace `/tmp/other-report.txt` with `@{path}` below and rerun: admission succeeds.
The function is checked during cedar_security setup; it is never invoked here.
"""

from langchain_core.tools import tool

from langgraph.prebuilt.security import cedar_security
from langgraph.prebuilt.security.inprocess import read_text


@tool
def read_report(path: str) -> str:
    """Read a report through the approved file API."""
    return read_text(path)
    return "nothing"


security = cedar_security(
    read_report,
    # Wrong: the function reads path, but the manifest declares a different file.
    manifest="runs inprocess\nfs read /tmp/other-report.txt need",  # Fix: @{path}.
    policy="permit(principal, action, resource);",
)
