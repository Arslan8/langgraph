"""Demo 14b: static IFC rejects a tool before it can execute."""

from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.analysis.static_flow import StaticFlowPolicy
from langgraph.prebuilt.security import SecurityConfigurationError, cedar_security
from langgraph.prebuilt.security.inprocess import read_text


@tool
def read_report() -> str:
    """Read the confidential report through the approved resource API."""
    return read_text("/private/report.txt")


def main():
    manifest = Path(__file__).with_name("manifest.slp").read_text()
    for destination, clearance, expected in (
        ("public", set(), "REJECTED"),
        ("internal", {"secret"}, "ADMITTED"),
        ("unclassified", None, "REJECTED"),
    ):
        try:
            cedar_security(
                read_report,
                manifest=manifest,
                policy="permit(principal, action, resource);",
                static_flow=StaticFlowPolicy(
                    read_labels={("fs", "/private/report.txt"): {"secret"}},
                    input_labels=set(),  # No caller-supplied data in this tool.
                    return_clearance=clearance,
                ),
            )
        except SecurityConfigurationError as error:
            assert str(error).startswith("static_flow:"), error
            outcome = "REJECTED"
            print(f"{destination}: {outcome} before execution\n  {error}")
        else:
            outcome = "ADMITTED"
            print(f"{destination}: {outcome} by the static IFC gate")
        assert outcome == expected
    print("Tool body never executed; the report file was not read.")


if __name__ == "__main__":
    main()
