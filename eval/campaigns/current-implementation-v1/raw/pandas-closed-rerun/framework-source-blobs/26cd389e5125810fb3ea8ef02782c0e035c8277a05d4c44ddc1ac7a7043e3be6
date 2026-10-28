"""Compile-time capability gate for `.slp` profiles."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.capabilities import (
    LinuxCapabilities,
    probe_linux_capabilities,
)
from langgraph.prebuilt.security.enforcement import SupportLevel
from langgraph.prebuilt.security.profile import ProfileDocument, parse_profiles


@dataclass(frozen=True, slots=True)
class ProfileSupport:
    """One profile line's conservative backend-lowering verdict."""

    tool: str
    resource_class: str
    selector: str
    support: SupportLevel
    reason: str
    unenforced: bool = False

    def canonical(self) -> Mapping[str, Any]:
        return {
            "reason": self.reason,
            "resource_class": self.resource_class,
            "selector": self.selector,
            "support": self.support.value,
            "tool": self.tool,
            "unenforced": self.unenforced,
        }


def check_profiles(
    profiles: ProfileDocument,
    capabilities: LinuxCapabilities,
    *,
    waivers: Mapping[str, str] | None = None,
) -> tuple[ProfileSupport, ...]:
    """Return a per-rule lowering result for the phase-one Linux contract."""
    waived = dict(waivers or {})
    results: list[ProfileSupport] = []
    for name, profile in sorted(profiles.tools.items()):
        for rule in profile.fs:
            results.append(
                _support(
                    name, "filesystem", _path_text(rule.path), capabilities, waived
                )
            )
        for rule in profile.net:
            results.append(
                _support(name, "network", str(rule.port), capabilities, waived)
            )
        for rule in profile.exec:
            results.append(
                _support(name, "exec", _path_text(rule.path), capabilities, waived)
            )
        for rule in profile.services:
            results.append(_support(name, "service", rule.kind, capabilities, waived))
        for syscall_set in sorted(profile.syscall_sets):
            results.append(
                _support(name, "syscalls", syscall_set, capabilities, waived)
            )
        for limit in ("cpu_ms", "memory_bytes", "pids", "nofile", "wall_ms"):
            if getattr(profile.limits, limit) is not None:
                results.append(
                    _support(name, f"limit:{limit}", limit, capabilities, waived)
                )
    return tuple(results)


def load_profile_paths(paths: Sequence[str | Path]) -> ProfileDocument:
    """Load files or directories, rejecting duplicate blocks across files."""
    files = tuple(_profile_files(paths))
    if not files:
        raise ValueError("no .slp profile files found")
    tools: dict[str, Any] = {}
    principals: dict[str, Any] = {}
    for path in files:
        document = parse_profiles(path.read_text(), source=os.fspath(path))
        duplicate_tools = set(tools).intersection(document.tools)
        duplicate_principals = set(principals).intersection(document.principals)
        if duplicate_tools or duplicate_principals:
            duplicates = sorted(duplicate_tools | duplicate_principals)
            raise ValueError("duplicate profile blocks: " + ", ".join(duplicates))
        tools.update(document.tools)
        principals.update(document.principals)
    return ProfileDocument(tools, principals)


def _support(
    tool: str,
    resource_class: str,
    selector: str,
    capabilities: LinuxCapabilities,
    waivers: Mapping[str, str],
) -> ProfileSupport:
    support = SupportLevel.UNSUPPORTED
    reason = "unsupported rule class"
    if resource_class == "filesystem":
        if capabilities.landlock_abi >= 1:
            support, reason = SupportLevel.EXACT, "Landlock path-beneath rule"
        else:
            reason = "Landlock ABI 1 or later is unavailable"
    elif resource_class == "network":
        if capabilities.landlock_abi >= 4:
            support, reason = SupportLevel.EXACT, "Landlock TCP port rule"
        else:
            reason = "Landlock ABI 4 or later is unavailable"
    elif resource_class == "exec":
        if capabilities.landlock_abi >= 1:
            support, reason = SupportLevel.EXACT, "Landlock EXECUTE rule"
        else:
            reason = "Landlock ABI 1 or later is unavailable"
    elif resource_class == "syscalls" and selector == "minimal":
        support, reason = SupportLevel.EXACT, "seccomp minimal class filter"
    elif resource_class == "limit:nofile":
        support, reason = SupportLevel.EXACT, "RLIMIT_NOFILE"
    elif resource_class == "limit:wall_ms" and capabilities.pidfd:
        support, reason = SupportLevel.EXACT, "supervisor timer and pidfd"
    elif resource_class.startswith("limit:"):
        if capabilities.cgroup_delegated and capabilities.cgroup_kill:
            support, reason = SupportLevel.EXACT, "delegated cgroup v2"
        elif resource_class in {"limit:cpu_ms", "limit:memory_bytes"}:
            support, reason = SupportLevel.TIGHTENED, "rlimit fallback"
        else:
            reason = "delegated cgroup v2 with cgroup.kill is unavailable"
    waiver = waivers.get(resource_class)
    if support is SupportLevel.UNSUPPORTED and waiver:
        return ProfileSupport(
            tool,
            resource_class,
            selector,
            support,
            f"waived: {waiver}",
            unenforced=True,
        )
    return ProfileSupport(tool, resource_class, selector, support, reason)


def _profile_files(paths: Sequence[str | Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw).resolve()
        candidates = sorted(path.rglob("*.slp")) if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.suffix != ".slp" or candidate in seen:
                continue
            seen.add(candidate)
            yield candidate


def _path_text(path: Any) -> str:
    return path.value + ("/**" if path.subtree else "")


def _waivers(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        resource_class, separator, reason = value.partition("=")
        if not separator or not resource_class or not reason:
            raise ValueError("waivers use CLASS=REASON")
        result[resource_class] = reason
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Run `slanggraph check --backend linux profiles/`."""
    parser = argparse.ArgumentParser(prog="slanggraph")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="validate profiles against a backend")
    check.add_argument("paths", nargs="+")
    check.add_argument("--backend", choices=("linux", "landlock"), required=True)
    check.add_argument("--waive", action="append", default=[], metavar="CLASS=REASON")
    check.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        profiles = load_profile_paths(args.paths)
        waivers = _waivers(args.waive)
        capabilities = probe_linux_capabilities()
        results = check_profiles(profiles, capabilities, waivers=waivers)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = {
        "backend": args.backend,
        "boot_id": capabilities.boot_id,
        "capabilities": sorted(capabilities.capabilities),
        "rules": [item.canonical() for item in results],
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        for item in results:
            marker = " unenforced" if item.unenforced else ""
            print(
                f"{item.support.value}{marker}: {item.tool} "
                f"{item.resource_class} {item.selector}: {item.reason}"
            )
    return int(
        any(
            item.support is SupportLevel.UNSUPPORTED and not item.unenforced
            for item in results
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
