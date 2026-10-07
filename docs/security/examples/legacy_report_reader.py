"""Add operator authorization around an unchanged legacy file reader."""

from pathlib import Path
from tempfile import TemporaryDirectory

from langchain_core.tools import StructuredTool
from legacy_tools import read_report

from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityConfig,
    SecurityDeniedError,
    ToolDac,
    effects,
    guarded_tool,
    with_principal,
)


def main() -> None:
    """Allow one report, reject another, and reject a caller lacking scope."""
    with TemporaryDirectory(prefix="legacy-reports-") as directory:
        report = Path(directory, "quarterly.txt")
        private = Path(directory, "payroll.txt")
        report.write_text("Revenue: 42 units", encoding="utf-8")
        private.write_text("Private payroll fixture", encoding="utf-8")

        # Before: trusted application code calls the original function directly.
        print(f"before (direct): {read_report(str(report))}")

        # After: attach metadata to a NEW LangChain tool, not the legacy function.
        adapted = StructuredTool.from_function(read_report)
        effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])(
            adapted
        )
        audit = MemoryAuditSink()
        security = SecurityConfig(
            audit_sink=audit,
            dac_overrides=DacOverrides(
                {
                    "read_report": ToolDac(
                        owner="reporting-service",
                        grants={"analyst": "x", "*": "-"},
                        required_scopes=frozenset({"reports:read"}),
                        arg_grants={"path": {str(report.resolve()): "x", "*": "-"}},
                    )
                }
            ),
        )
        secured = guarded_tool(adapted, security=security)
        alice = Principal(
            "alice", frozenset({"analyst"}), frozenset({"reports:read"}), "reports"
        )
        config = with_principal({}, alice, modules=security.modules)
        result = secured.invoke({"path": str(report)}, config=config)
        assert result == "Revenue: 42 units"
        print(f"allowed: {result}")

        no_scope = Principal("bob", frozenset({"analyst"}), frozenset(), "reports")
        for label, path, caller, expected in (
            ("other report", private, alice, "dac:arg:path"),
            ("missing scope", report, no_scope, "dac:scope"),
        ):
            try:
                secured.invoke(
                    {"path": str(path)},
                    config=with_principal({}, caller, modules=security.modules),
                )
            except SecurityDeniedError as exc:
                assert str(exc) == expected
                print(f"denied ({label}): {exc}")
            else:
                raise AssertionError(f"unexpectedly allowed: {label}")
        assert audit.verify() == (True, None)
        print("audit chain: valid")


if __name__ == "__main__":
    main()
