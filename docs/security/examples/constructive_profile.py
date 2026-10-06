"""Parse a `.slp` profile and construct per-call filesystem authority."""

from langgraph.prebuilt.security import parse_profiles

PROFILE = """
tool read_report {
  owner analyst
  grant analyst: call
  requires fs:read
  syscalls @file-read
  fs read ${path} need, write ${path} want
  net none
  exec none
  service none
}

principal alice {
  roles analyst
  scopes fs:read
  fs read ${home}/**
  net none
  exec none
  service none
}
"""


def main() -> None:
    """Show a dropped want and a required-line denial."""
    profiles = parse_profiles(PROFILE, source="reports.slp")
    bindings = {"alice": {"home": "/srv/alice"}}

    allowed = profiles.evaluate(
        "read_report",
        "alice",
        {"path": "/srv/alice/reports/q4.txt"},
        principal_bindings=bindings,
    )
    assert not allowed.denied
    assert allowed.grant.fs[0].operations == {"read"}
    assert [
        (line.resource_class, line.requirement.value) for line in allowed.removed
    ] == [("fs", "want")]
    print(f"grant: {allowed.grant.fs[0].operations} {allowed.grant.fs[0].path.value}")
    print("removed: write want")

    denied = profiles.evaluate(
        "read_report",
        "alice",
        {"path": "/srv/other/private.txt"},
        principal_bindings=bindings,
    )
    assert denied.denied
    assert denied.reason == "required_line_removed"
    print(f"denied: {denied.reason}")


if __name__ == "__main__":
    main()
