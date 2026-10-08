from __future__ import annotations

from pathlib import Path

import pytest

from langgraph.prebuilt.security.capabilities import LinuxCapabilities
from langgraph.prebuilt.security.check import check_profiles, load_profile_paths, main
from langgraph.prebuilt.security.enforcement import SupportLevel
from langgraph.prebuilt.security.profile import parse_profiles


def _caps(
    *,
    landlock_abi: int = 4,
    cgroup_delegated: bool = True,
    cgroup_kill: bool = True,
    pidfd: bool = True,
) -> LinuxCapabilities:
    return LinuxCapabilities(
        boot_id="boot",
        landlock_abi=landlock_abi,
        cgroup_v2=True,
        cgroup_delegated=cgroup_delegated,
        cgroup_kill=cgroup_kill,
        unprivileged_userns=False,
        bpf_lsm=False,
        landlock_audit=False,
        pidfd=pidfd,
        evidence={},
    )


_PROFILE = """
tool reader {
  owner user
  grant user: call
  runs linux
  syscalls @minimal
  fs read /safe/** need
  net connect 443 need
  exec /usr/bin/helper need
  service github(installation: 1) need
  limits cpu 2s mem 256M pids 2 nofile 32 wall 5s
}
principal alice {
  roles user
}
"""


def test_check_reports_every_rule_as_exact_tightened_or_unsupported() -> None:
    results = check_profiles(
        parse_profiles(_PROFILE),
        _caps(cgroup_delegated=False, cgroup_kill=False),
    )
    by_class = {item.resource_class: item for item in results}

    assert by_class["filesystem"].support is SupportLevel.EXACT
    assert by_class["network"].support is SupportLevel.EXACT
    assert by_class["exec"].support is SupportLevel.EXACT
    assert by_class["limit:cpu_ms"].support is SupportLevel.TIGHTENED
    assert by_class["limit:memory_bytes"].support is SupportLevel.TIGHTENED
    assert by_class["limit:pids"].support is SupportLevel.UNSUPPORTED
    assert by_class["service"].support is SupportLevel.UNSUPPORTED
    assert {item.support.value for item in results} <= {
        "exact",
        "tightened",
        "unsupported",
    }


def test_abi_four_supports_port_rules_but_abi_three_does_not() -> None:
    profile = parse_profiles(_PROFILE)
    abi_four = check_profiles(profile, _caps(landlock_abi=4))
    abi_three = check_profiles(profile, _caps(landlock_abi=3))
    assert (
        next(item for item in abi_four if item.resource_class == "network").support
        is SupportLevel.EXACT
    )
    assert (
        next(item for item in abi_three if item.resource_class == "network").support
        is SupportLevel.UNSUPPORTED
    )


def test_waiver_requires_a_reason_and_stamps_rule_unenforced() -> None:
    result = check_profiles(
        parse_profiles(_PROFILE),
        _caps(),
        waivers={"service": "phase two broker"},
    )
    service = next(item for item in result if item.resource_class == "service")
    assert service.support is SupportLevel.UNSUPPORTED
    assert service.unenforced
    assert service.reason == "waived: phase two broker"


def test_profile_directory_loader_rejects_duplicate_blocks(tmp_path: Path) -> None:
    (tmp_path / "one.slp").write_text(_PROFILE)
    (tmp_path / "two.slp").write_text(_PROFILE)
    with pytest.raises(ValueError, match="duplicate profile blocks"):
        load_profile_paths((tmp_path,))


def test_cli_exits_nonzero_for_unwaived_unsupported_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "profile.slp"
    path.write_text(_PROFILE)
    monkeypatch.setattr(
        "langgraph.prebuilt.security.check.probe_linux_capabilities", _caps
    )
    assert main(("check", "--backend", "linux", str(path))) == 1
    assert (
        main(
            (
                "check",
                "--backend",
                "linux",
                "--waive",
                "service=phase two",
                str(path),
            )
        )
        == 0
    )
