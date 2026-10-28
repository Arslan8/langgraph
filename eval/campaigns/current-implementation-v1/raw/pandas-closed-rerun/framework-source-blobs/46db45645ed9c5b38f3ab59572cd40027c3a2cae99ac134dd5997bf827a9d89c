"""Trusted OSTree-backed deployment management for Linux tool bundles."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import urllib.parse
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

_CHECKSUM = re.compile(r"[0-9a-f]{64}")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
_REMOTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_MANIFEST_FIELDS = frozenset(
    {
        "format_version",
        "tool_id",
        "entrypoint",
        "primary_file",
        "import_roots",
        "dependency_lock",
    }
)
_RUNTIME_MANIFEST_FIELDS = frozenset(
    {"format_version", "runtime_id", "interpreter", "import_roots"}
)


class DeploymentError(RuntimeError):
    """A tool deployment could not be safely published or recovered."""


@dataclass(frozen=True, slots=True)
class BundleManifest:
    """Validated manifest committed with one tool bundle."""

    format_version: int
    tool_id: str
    entrypoint: str
    primary_file: str
    import_roots: tuple[str, ...]
    dependency_lock: str | None = None

    @classmethod
    def from_bytes(cls, raw: bytes) -> BundleManifest:
        """Parse a canonical, closed manifest without accepting duplicate keys."""

        def pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise DeploymentError(f"duplicate manifest field:{key}")
                result[key] = value
            return result

        try:
            value = json.loads(raw, object_pairs_hook=pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeploymentError("bundle manifest is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise DeploymentError("bundle manifest must be an object")
        unknown = set(value).difference(_MANIFEST_FIELDS)
        if unknown:
            raise DeploymentError(
                "unknown bundle manifest fields:" + ",".join(sorted(unknown))
            )
        if value.get("format_version") != 1:
            raise DeploymentError("unsupported bundle manifest format")
        tool_id = value.get("tool_id")
        entrypoint = value.get("entrypoint")
        primary_file = value.get("primary_file")
        import_roots = value.get("import_roots")
        dependency_lock = value.get("dependency_lock")
        if not isinstance(tool_id, str) or not tool_id:
            raise DeploymentError("bundle tool_id must be non-empty")
        _validate_entrypoint(entrypoint)
        primary = _relative_path(primary_file, "primary_file", allow_dot=False)
        if (
            not isinstance(import_roots, list)
            or not import_roots
            or any(not isinstance(item, str) for item in import_roots)
        ):
            raise DeploymentError("bundle import_roots must be a non-empty list")
        roots = tuple(
            _relative_path(item, "import root", allow_dot=True) for item in import_roots
        )
        if len(roots) != len(set(roots)):
            raise DeploymentError("bundle import_roots must be unique")
        lock = None
        if dependency_lock is not None:
            lock = _relative_path(dependency_lock, "dependency_lock", allow_dot=False)
        return cls(1, tool_id, entrypoint, primary, roots, lock)

    def canonical(self) -> Mapping[str, Any]:
        """Return stable manifest data for evidence and tests."""
        return MappingProxyType(
            {
                "dependency_lock": self.dependency_lock,
                "entrypoint": self.entrypoint,
                "format_version": self.format_version,
                "import_roots": list(self.import_roots),
                "primary_file": self.primary_file,
                "tool_id": self.tool_id,
            }
        )


@dataclass(frozen=True, slots=True)
class RuntimeManifest:
    """Validated manifest for one independently versioned runtime root."""

    format_version: int
    runtime_id: str
    interpreter: str
    import_roots: tuple[str, ...]

    @classmethod
    def from_bytes(cls, raw: bytes) -> RuntimeManifest:
        """Parse a closed runtime-root manifest without duplicate fields."""
        value = _closed_json_object(raw, "runtime", _RUNTIME_MANIFEST_FIELDS)
        if value.get("format_version") != 1:
            raise DeploymentError("unsupported runtime manifest format")
        runtime_id = value.get("runtime_id")
        interpreter = _relative_path(
            value.get("interpreter"), "runtime interpreter", allow_dot=False
        )
        import_roots = value.get("import_roots")
        if not isinstance(runtime_id, str) or not runtime_id:
            raise DeploymentError("runtime_id must be non-empty")
        if (
            not isinstance(import_roots, list)
            or not import_roots
            or any(not isinstance(item, str) for item in import_roots)
        ):
            raise DeploymentError("runtime import_roots must be a non-empty list")
        roots = tuple(
            _relative_path(item, "runtime import root", allow_dot=False)
            for item in import_roots
        )
        if len(roots) != len(set(roots)):
            raise DeploymentError("runtime import_roots must be unique")
        return cls(1, runtime_id, interpreter, roots)

    def canonical(self) -> Mapping[str, Any]:
        """Return stable runtime manifest data for evidence."""
        return MappingProxyType(
            {
                "format_version": self.format_version,
                "import_roots": list(self.import_roots),
                "interpreter": self.interpreter,
                "runtime_id": self.runtime_id,
            }
        )


@dataclass(frozen=True, slots=True)
class DeploymentBinding:
    """Authority-bearing identity selected before policy preparation."""

    format_version: int
    tool_id: str
    tool_commit: str
    manifest_digest: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if self.format_version != 1 or not self.tool_id:
            raise ValueError("invalid deployment binding")
        for value in (
            self.tool_commit,
            self.manifest_digest,
            self.artifact_digest,
        ):
            if not _CHECKSUM.fullmatch(value):
                raise ValueError("deployment binding digests must be SHA-256 values")

    def canonical(self) -> Mapping[str, str | int]:
        """Return the binding payload included in approvals and grants."""
        return MappingProxyType(
            {
                "artifact_digest": self.artifact_digest,
                "format_version": self.format_version,
                "manifest_digest": self.manifest_digest,
                "tool_commit": self.tool_commit,
                "tool_id": self.tool_id,
            }
        )


@dataclass(frozen=True, slots=True)
class RuntimeBinding:
    """Exact independently published runtime identity."""

    format_version: int
    runtime_id: str
    runtime_commit: str
    manifest_digest: str

    def __post_init__(self) -> None:
        if self.format_version != 1 or not self.runtime_id:
            raise ValueError("invalid runtime binding")
        if not _CHECKSUM.fullmatch(self.runtime_commit) or not _CHECKSUM.fullmatch(
            self.manifest_digest
        ):
            raise ValueError("runtime binding digests must be SHA-256 values")

    def canonical(self) -> Mapping[str, str | int]:
        """Return the runtime payload included in approvals and grants."""
        return MappingProxyType(
            {
                "runtime_commit": self.runtime_commit,
                "runtime_format_version": self.format_version,
                "runtime_id": self.runtime_id,
                "runtime_manifest_digest": self.manifest_digest,
            }
        )


@dataclass(frozen=True, slots=True)
class ToolDeployment:
    """One validated checkout of an exact OSTree tool commit."""

    binding: DeploymentBinding
    manifest: BundleManifest
    checkout_path: Path

    @property
    def artifact_path(self) -> Path:
        """Return the primary source path inside the checkout."""
        return self.checkout_path.joinpath(
            *PurePosixPath(self.manifest.primary_file).parts
        )

    @property
    def import_roots(self) -> tuple[Path, ...]:
        """Return validated Python roots inside the checkout."""
        return tuple(
            self.checkout_path.joinpath(*PurePosixPath(item).parts)
            for item in self.manifest.import_roots
        )


@dataclass(frozen=True, slots=True)
class RuntimeDeployment:
    """One validated checkout of an exact OSTree runtime root."""

    binding: RuntimeBinding
    manifest: RuntimeManifest
    checkout_path: Path

    @property
    def interpreter_path(self) -> Path:
        """Return the host-side interpreter used for digest verification."""
        return self.checkout_path.joinpath(
            *PurePosixPath(self.manifest.interpreter).parts
        )

    @property
    def guest_interpreter_path(self) -> Path:
        """Return the interpreter path after mounting this checkout as `/`."""
        return Path("/").joinpath(*PurePosixPath(self.manifest.interpreter).parts)

    @property
    def guest_import_roots(self) -> tuple[Path, ...]:
        """Return import roots supplied by the mounted runtime."""
        return tuple(
            Path("/").joinpath(*PurePosixPath(item).parts)
            for item in self.manifest.import_roots
        )


@dataclass(frozen=True, slots=True)
class CleanupReport:
    """Result of one reference-aware deployment cleanup pass."""

    retained_commits: tuple[str, ...]
    removed_checkouts: tuple[str, ...]
    removed_runtime_checkouts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TrustedRemote:
    """Operator-approved OSTree publisher configuration."""

    name: str
    url: str
    public_key_digest: str


@dataclass(frozen=True, slots=True)
class DeploymentLease:
    """Durable commits retained for one live or termination-uncertain worker."""

    lease_id: str
    commits: tuple[str, ...]
    principal_id: str
    session_id: str
    call_id: str

    def __post_init__(self) -> None:
        if not all((self.lease_id, self.principal_id, self.session_id, self.call_id)):
            raise ValueError("deployment lease identity must be non-empty")
        commits = tuple(self.commits)
        if (
            not commits
            or commits != tuple(sorted(set(commits)))
            or any(not _CHECKSUM.fullmatch(commit) for commit in commits)
        ):
            raise ValueError("deployment lease commits must be sorted unique checksums")
        object.__setattr__(self, "commits", commits)


class OstreeDeploymentManager:
    """Publish, select, materialize, and retain normalized local bundles."""

    def __init__(
        self,
        root: str | Path,
        *,
        ostree_path: str | Path = "ostree",
        command_timeout_s: float = 30.0,
    ) -> None:
        if command_timeout_s <= 0:
            raise ValueError("command_timeout_s must be positive")
        executable = shutil.which(os.fspath(ostree_path))
        if executable is None:
            raise RuntimeError("ostree is required for tool deployments")
        self.root = Path(root).resolve()
        self.repo = self.root / "repo"
        self.deployments = self.root / "deployments"
        self.runtimes = self.root / "runtimes"
        self.keys = self.root / "keys"
        self._bindings = self.root / "bindings.sqlite3"
        self._lock_path = self.root / ".manager.lock"
        self.ostree_path = executable
        self.command_timeout_s = command_timeout_s
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.deployments.mkdir(mode=0o700, exist_ok=True)
        self.runtimes.mkdir(mode=0o700, exist_ok=True)
        self.keys.mkdir(mode=0o700, exist_ok=True)
        if not self.repo.exists():
            self._run("init", "--mode=bare-user-only")
        self._initialize_bindings()

    def publish_bundle(self, source: str | Path, release_ref: str) -> ToolDeployment:
        """Normalize a source tree and publish one immutable release ref."""
        _validate_ref(release_ref)
        source_path = Path(source).resolve(strict=True)
        if not source_path.is_dir():
            raise DeploymentError("bundle source must be a directory")
        manifest: BundleManifest
        commit: str
        with self._locked():
            if self._try_resolve(release_ref) is not None:
                raise DeploymentError(f"release ref already exists:{release_ref}")
            staging = Path(tempfile.mkdtemp(prefix="publish-", dir=self.root))
            try:
                normalized = staging / "tree"
                normalized.mkdir(mode=0o755)
                _copy_normalized_tree(source_path, normalized)
                _make_tree_read_only(normalized)
                manifest, _, _ = _validate_bundle_tree(normalized)
                output = self._run(
                    "commit",
                    f"--branch={release_ref}",
                    "--parent=none",
                    "--no-xattrs",
                    "--owner-uid=0",
                    "--owner-gid=0",
                    f"--tree=dir={normalized}",
                )
                commit = _checksum_from_output(output)
                if self.resolve_ref(release_ref) != commit:
                    raise DeploymentError("published release ref identity mismatch")
            finally:
                _remove_tree(staging)
        deployment = self.materialize(commit)
        if deployment.manifest != manifest:
            raise DeploymentError("published manifest changed during commit")
        return deployment

    def publish_runtime(
        self, source: str | Path, release_ref: str
    ) -> RuntimeDeployment:
        """Normalize and publish one immutable runtime root."""
        _validate_ref(release_ref)
        source_path = Path(source).resolve(strict=True)
        if not source_path.is_dir():
            raise DeploymentError("runtime source must be a directory")
        manifest: RuntimeManifest
        commit: str
        with self._locked():
            if self._try_resolve(release_ref) is not None:
                raise DeploymentError(f"release ref already exists:{release_ref}")
            staging = Path(tempfile.mkdtemp(prefix="runtime-publish-", dir=self.root))
            try:
                normalized = staging / "tree"
                normalized.mkdir(mode=0o755)
                _copy_normalized_runtime_tree(source_path, normalized)
                _make_runtime_tree_read_only(normalized)
                manifest, _ = _validate_runtime_tree(
                    normalized, require_normalized_modes=True
                )
                output = self._run(
                    "commit",
                    f"--branch={release_ref}",
                    "--parent=none",
                    "--no-xattrs",
                    "--owner-uid=0",
                    "--owner-gid=0",
                    f"--tree=dir={normalized}",
                )
                commit = _checksum_from_output(output)
                if self.resolve_ref(release_ref) != commit:
                    raise DeploymentError("published runtime ref identity mismatch")
            finally:
                _remove_tree(staging)
        deployment = self.materialize_runtime(commit)
        if deployment.manifest != manifest:
            raise DeploymentError("published runtime manifest changed during commit")
        return deployment

    def update_channel(self, channel_ref: str, commit: str) -> None:
        """Move a trusted channel to an already published exact commit."""
        _validate_ref(channel_ref)
        exact = self.resolve_ref(commit)
        if exact != commit:
            raise DeploymentError("channel target must be a full commit checksum")
        self.materialize(exact)
        with self._locked():
            self._run("refs", "--force", f"--create={channel_ref}", exact)

    def update_runtime_channel(self, channel_ref: str, commit: str) -> None:
        """Move a trusted runtime channel to a validated published commit."""
        _validate_ref(channel_ref)
        exact = self.resolve_ref(commit)
        if exact != commit:
            raise DeploymentError("runtime channel target must be a full checksum")
        self.materialize_runtime(exact)
        with self._locked():
            self._run("refs", "--force", f"--create={channel_ref}", exact)

    def configure_remote(
        self,
        name: str,
        url: str,
        *,
        public_key: str | Path,
    ) -> TrustedRemote:
        """Add an immutable remote whose commits require an operator-pinned GPG key."""
        _validate_remote(name)
        _validate_remote_url(url)
        key_source = Path(public_key)
        try:
            key_stat = key_source.lstat()
        except OSError as exc:
            raise DeploymentError("remote public key is unavailable") from exc
        if not stat.S_ISREG(key_stat.st_mode) or key_source.is_symlink():
            raise DeploymentError("remote public key must be a regular file")
        try:
            key_bytes = key_source.read_bytes()
        except OSError as exc:
            raise DeploymentError("remote public key could not be read") from exc
        if not key_bytes:
            raise DeploymentError("remote public key must not be empty")
        key_digest = hashlib.sha256(key_bytes).hexdigest()
        trusted_key = self.keys / f"{key_digest}.gpg"
        remote = TrustedRemote(name, url, key_digest)
        with self._locked(), self._connect() as database:
            row = database.execute(
                "SELECT url, public_key_digest FROM trusted_remotes WHERE name = ?",
                (name,),
            ).fetchone()
            if row is not None:
                if (str(row[0]), str(row[1])) != (url, key_digest):
                    raise DeploymentError("trusted remote configuration is immutable")
                return remote
            key_created = _write_trusted_file(trusted_key, key_bytes)
            try:
                self._run(
                    "remote",
                    "add",
                    "--set=gpg-verify=true",
                    f"--gpg-import={trusted_key}",
                    name,
                    url,
                )
            except DeploymentError:
                if key_created:
                    trusted_key.unlink(missing_ok=True)
                raise
            database.execute(
                "INSERT INTO trusted_remotes (name, url, public_key_digest) VALUES (?, ?, ?)",
                (name, url, key_digest),
            )
        return remote

    def pull_verified_release(
        self,
        remote_name: str,
        remote_ref: str,
        release_ref: str,
    ) -> ToolDeployment:
        """Verify and import a remote commit before creating an immutable release."""
        _validate_remote(remote_name)
        _validate_ref(remote_ref)
        _validate_ref(release_ref)
        with self._connect() as database:
            trusted = database.execute(
                "SELECT 1 FROM trusted_remotes WHERE name = ?", (remote_name,)
            ).fetchone()
        if trusted is None:
            raise DeploymentError("remote publisher is not trusted")
        with self._locked():
            if self._try_resolve(release_ref) is not None:
                raise DeploymentError(f"release ref already exists:{release_ref}")
            self._run("pull", "--bareuseronly-files", remote_name, remote_ref)
            commit = self._try_resolve(f"{remote_name}:{remote_ref}")
            if commit is None:
                raise DeploymentError("verified remote ref is unavailable after pull")
        deployment = self.materialize(commit)
        with self._locked():
            if self._try_resolve(release_ref) is not None:
                raise DeploymentError(f"release ref already exists:{release_ref}")
            self._run("refs", f"--create={release_ref}", commit)
            if self.resolve_ref(release_ref) != commit:
                raise DeploymentError("imported release ref identity mismatch")
        return deployment

    def pull_verified_runtime_release(
        self,
        remote_name: str,
        remote_ref: str,
        release_ref: str,
    ) -> RuntimeDeployment:
        """Verify and import a remote runtime before naming its local release."""
        _validate_remote(remote_name)
        _validate_ref(remote_ref)
        _validate_ref(release_ref)
        with self._connect() as database:
            trusted = database.execute(
                "SELECT 1 FROM trusted_remotes WHERE name = ?", (remote_name,)
            ).fetchone()
        if trusted is None:
            raise DeploymentError("remote publisher is not trusted")
        with self._locked():
            if self._try_resolve(release_ref) is not None:
                raise DeploymentError(f"release ref already exists:{release_ref}")
            self._run("pull", "--bareuseronly-files", remote_name, remote_ref)
            commit = self._try_resolve(f"{remote_name}:{remote_ref}")
            if commit is None:
                raise DeploymentError("verified remote ref is unavailable after pull")
        deployment = self.materialize_runtime(commit)
        with self._locked():
            if self._try_resolve(release_ref) is not None:
                raise DeploymentError(f"release ref already exists:{release_ref}")
            self._run("refs", f"--create={release_ref}", commit)
            if self.resolve_ref(release_ref) != commit:
                raise DeploymentError("imported runtime ref identity mismatch")
        return deployment

    def resolve_ref(self, selection: str) -> str:
        """Resolve a trusted ref or full checksum to one exact local commit."""
        if not isinstance(selection, str) or not selection:
            raise DeploymentError("deployment selection must be non-empty")
        if not _CHECKSUM.fullmatch(selection):
            _validate_ref(selection)
        resolved = self._try_resolve(selection)
        if resolved is None:
            raise DeploymentError(f"deployment selection is unavailable:{selection}")
        return resolved

    def materialize(self, commit: str) -> ToolDeployment:
        """Create or validate a retained checkout of one exact commit."""
        exact = self.resolve_ref(commit)
        if exact != commit:
            raise DeploymentError("materialization requires a full commit checksum")
        destination = self.deployments / exact
        with self._locked():
            self._run("fsck", "--quiet")
            if not destination.exists():
                staging = Path(
                    tempfile.mkdtemp(prefix=f".{exact[:12]}-", dir=self.deployments)
                )
                try:
                    staging.rmdir()
                    self._run(
                        "checkout",
                        "--user-mode",
                        "--force-copy",
                        exact,
                        os.fspath(staging),
                    )
                    self._verify_checkout(exact, staging)
                    _validate_bundle_tree(staging)
                    _make_tree_read_only(staging)
                    os.replace(staging, destination)
                finally:
                    if staging.exists():
                        _remove_tree(staging)
            self._verify_checkout(exact, destination)
            manifest, manifest_digest, artifact_digest = _validate_bundle_tree(
                destination, require_normalized_modes=True
            )
        binding = DeploymentBinding(
            1,
            manifest.tool_id,
            exact,
            manifest_digest,
            artifact_digest,
        )
        return ToolDeployment(binding, manifest, destination)

    def materialize_runtime(self, commit: str) -> RuntimeDeployment:
        """Create or validate a retained checkout of one exact runtime commit."""
        exact = self.resolve_ref(commit)
        if exact != commit:
            raise DeploymentError("runtime materialization requires a full checksum")
        destination = self.runtimes / exact
        with self._locked():
            self._run("fsck", "--quiet")
            if not destination.exists():
                staging = Path(
                    tempfile.mkdtemp(prefix=f".{exact[:12]}-", dir=self.runtimes)
                )
                try:
                    staging.rmdir()
                    self._run(
                        "checkout",
                        "--user-mode",
                        "--force-copy",
                        exact,
                        os.fspath(staging),
                    )
                    self._verify_checkout(exact, staging)
                    _validate_runtime_tree(staging, require_normalized_modes=True)
                    os.replace(staging, destination)
                finally:
                    if staging.exists():
                        _remove_tree(staging)
            self._verify_checkout(exact, destination)
            manifest, manifest_digest = _validate_runtime_tree(
                destination, require_normalized_modes=True
            )
        return RuntimeDeployment(
            RuntimeBinding(1, manifest.runtime_id, exact, manifest_digest),
            manifest,
            destination,
        )

    def bind_invocation(
        self,
        *,
        tool_id: str,
        selection: str,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> ToolDeployment:
        """Persist first selection and reuse it for approval and restart recovery."""
        if not all((tool_id, principal_id, session_id, call_id)):
            raise DeploymentError("deployment binding identity must be non-empty")
        inserted = False
        with self._locked(), self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                """
                SELECT tool_commit FROM invocation_bindings
                WHERE principal_id = ? AND session_id = ? AND tool_id = ? AND call_id = ?
                """,
                (principal_id, session_id, tool_id, call_id),
            ).fetchone()
            if row is None:
                commit = self.resolve_ref(selection)
                database.execute(
                    """
                    INSERT INTO invocation_bindings (
                        principal_id, session_id, tool_id, call_id, tool_commit
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (principal_id, session_id, tool_id, call_id, commit),
                )
                inserted = True
            else:
                commit = str(row[0])
            database.commit()
        try:
            deployment = self.materialize(commit)
            if deployment.manifest.tool_id != tool_id:
                raise DeploymentError("selected deployment tool identity mismatch")
        except DeploymentError:
            if inserted:
                with self._connect() as database:
                    database.execute(
                        """
                        DELETE FROM invocation_bindings
                        WHERE principal_id = ? AND session_id = ?
                          AND tool_id = ? AND call_id = ? AND tool_commit = ?
                        """,
                        (principal_id, session_id, tool_id, call_id, commit),
                    )
            raise
        return deployment

    def recover(self, binding: DeploymentBinding) -> ToolDeployment:
        """Revalidate an authenticated exact selection without resolving a channel."""
        deployment = self.materialize(binding.tool_commit)
        if deployment.binding != binding:
            raise DeploymentError(
                "persisted deployment binding does not match checkout"
            )
        return deployment

    def recover_invocation(
        self,
        binding: DeploymentBinding,
        *,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> ToolDeployment:
        """Require a manager-issued call binding before recovering executable code."""
        with self._connect() as database:
            row = database.execute(
                """
                SELECT tool_commit FROM invocation_bindings
                WHERE principal_id = ? AND session_id = ? AND tool_id = ? AND call_id = ?
                """,
                (principal_id, session_id, binding.tool_id, call_id),
            ).fetchone()
        if row is None or str(row[0]) != binding.tool_commit:
            raise DeploymentError("deployment binding was not issued for invocation")
        return self.recover(binding)

    def bind_runtime_invocation(
        self,
        *,
        runtime: RuntimeDeployment,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> RuntimeDeployment:
        """Persist one exact runtime selection for approval and recovery."""
        selected = self.bind_runtime_selection(
            runtime_id=runtime.manifest.runtime_id,
            selection=runtime.binding.runtime_commit,
            principal_id=principal_id,
            session_id=session_id,
            call_id=call_id,
        )
        if selected.binding != runtime.binding:
            raise DeploymentError("persisted runtime binding does not match executor")
        return selected

    def bind_runtime_selection(
        self,
        *,
        runtime_id: str,
        selection: str,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> RuntimeDeployment:
        """Resolve a runtime channel once and retain its exact commit per call."""
        if not all((runtime_id, principal_id, session_id, call_id)):
            raise DeploymentError("runtime binding identity must be non-empty")
        inserted = False
        with self._locked(), self._connect() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                """
                SELECT runtime_commit FROM runtime_invocation_bindings
                WHERE principal_id = ? AND session_id = ?
                  AND runtime_id = ? AND call_id = ?
                """,
                (
                    principal_id,
                    session_id,
                    runtime_id,
                    call_id,
                ),
            ).fetchone()
            if row is None:
                commit = self.resolve_ref(selection)
                database.execute(
                    """
                    INSERT INTO runtime_invocation_bindings (
                        principal_id, session_id, runtime_id, call_id, runtime_commit
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        principal_id,
                        session_id,
                        runtime_id,
                        call_id,
                        commit,
                    ),
                )
                inserted = True
            else:
                commit = str(row[0])
            database.commit()
        try:
            selected = self.materialize_runtime(commit)
            if selected.manifest.runtime_id != runtime_id:
                raise DeploymentError("selected runtime identity mismatch")
        except DeploymentError:
            if inserted:
                with self._connect() as database:
                    database.execute(
                        """
                        DELETE FROM runtime_invocation_bindings
                        WHERE principal_id = ? AND session_id = ?
                          AND runtime_id = ? AND call_id = ? AND runtime_commit = ?
                        """,
                        (principal_id, session_id, runtime_id, call_id, commit),
                    )
            raise
        return selected

    def recover_runtime_invocation(
        self,
        binding: RuntimeBinding,
        *,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> RuntimeDeployment:
        """Recover a manager-issued exact runtime selection."""
        with self._connect() as database:
            row = database.execute(
                """
                SELECT runtime_commit FROM runtime_invocation_bindings
                WHERE principal_id = ? AND session_id = ?
                  AND runtime_id = ? AND call_id = ?
                """,
                (principal_id, session_id, binding.runtime_id, call_id),
            ).fetchone()
        if row is None or str(row[0]) != binding.runtime_commit:
            raise DeploymentError("runtime binding was not issued for invocation")
        deployment = self.materialize_runtime(binding.runtime_commit)
        if deployment.binding != binding:
            raise DeploymentError("persisted runtime binding does not match checkout")
        return deployment

    def release_invocation(
        self,
        binding: DeploymentBinding,
        *,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> bool:
        """Release a completed invocation's durable deployment reference."""
        with self._locked(), self._connect() as database:
            cursor = database.execute(
                """
                DELETE FROM invocation_bindings
                WHERE principal_id = ? AND session_id = ? AND tool_id = ?
                  AND call_id = ? AND tool_commit = ?
                """,
                (
                    principal_id,
                    session_id,
                    binding.tool_id,
                    call_id,
                    binding.tool_commit,
                ),
            )
        return cursor.rowcount == 1

    def release_runtime_invocation(
        self,
        binding: RuntimeBinding,
        *,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> bool:
        """Release a completed invocation's exact runtime reference."""
        with self._locked(), self._connect() as database:
            cursor = database.execute(
                """
                DELETE FROM runtime_invocation_bindings
                WHERE principal_id = ? AND session_id = ? AND runtime_id = ?
                  AND call_id = ? AND runtime_commit = ?
                """,
                (
                    principal_id,
                    session_id,
                    binding.runtime_id,
                    call_id,
                    binding.runtime_commit,
                ),
            )
        return cursor.rowcount == 1

    def acquire_lease(
        self,
        commits: Sequence[str],
        *,
        principal_id: str,
        session_id: str,
        call_id: str,
    ) -> DeploymentLease:
        """Durably retain exact commits until worker termination is confirmed."""
        retained = tuple(sorted(set(commits)))
        if not retained or not all((principal_id, session_id, call_id)):
            raise DeploymentError("deployment lease identity must be non-empty")
        if any(not _CHECKSUM.fullmatch(commit) for commit in retained):
            raise DeploymentError("deployment lease requires full commit checksums")
        for commit in retained:
            if self.resolve_ref(commit) != commit:
                raise DeploymentError("deployment lease commit is unavailable")
        lease = DeploymentLease(
            secrets.token_hex(16), retained, principal_id, session_id, call_id
        )
        with self._locked(), self._connect() as database:
            database.executemany(
                """
                INSERT INTO active_deployment_leases (
                    lease_id, commit_id, principal_id, session_id, call_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (
                        lease.lease_id,
                        commit,
                        principal_id,
                        session_id,
                        call_id,
                    )
                    for commit in retained
                ),
            )
        return lease

    def release_lease(self, lease: DeploymentLease) -> bool:
        """Release an exact live-worker lease after confirmed termination."""
        with self._locked(), self._connect() as database:
            rows = database.execute(
                """
                SELECT commit_id, principal_id, session_id, call_id
                FROM active_deployment_leases WHERE lease_id = ?
                ORDER BY commit_id
                """,
                (lease.lease_id,),
            ).fetchall()
            expected = [
                (commit, lease.principal_id, lease.session_id, lease.call_id)
                for commit in lease.commits
            ]
            if rows != expected:
                return False
            database.execute(
                "DELETE FROM active_deployment_leases WHERE lease_id = ?",
                (lease.lease_id,),
            )
        return True

    def active_leases(self) -> tuple[DeploymentLease, ...]:
        """Return durable leases for post-restart termination reconciliation."""
        with self._connect() as database:
            rows = database.execute(
                """
                SELECT lease_id, commit_id, principal_id, session_id, call_id
                FROM active_deployment_leases ORDER BY lease_id, commit_id
                """
            ).fetchall()
        grouped: dict[str, tuple[list[str], str, str, str]] = {}
        for lease_id, commit, principal, session, call in rows:
            entry = grouped.setdefault(
                str(lease_id), ([], str(principal), str(session), str(call))
            )
            if entry[1:] != (str(principal), str(session), str(call)):
                raise DeploymentError("deployment lease identity is inconsistent")
            entry[0].append(str(commit))
        return tuple(
            DeploymentLease(lease_id, tuple(values[0]), *values[1:])
            for lease_id, values in grouped.items()
        )

    def retire_release(self, release_ref: str) -> str:
        """Remove an immutable release ref only when no invocation retains it."""
        _validate_ref(release_ref)
        if "/releases/" not in release_ref:
            raise DeploymentError("only explicit release refs may be retired")
        with self._locked(), self._connect() as database:
            commit = self.resolve_ref(release_ref)
            retained = database.execute(
                """
                SELECT 1 FROM invocation_bindings WHERE tool_commit = ?
                UNION ALL
                SELECT 1 FROM runtime_invocation_bindings WHERE runtime_commit = ?
                UNION ALL
                SELECT 1 FROM active_deployment_leases WHERE commit_id = ?
                LIMIT 1
                """,
                (commit, commit, commit),
            ).fetchone()
            if retained is not None:
                raise DeploymentError("release is retained by execution state")
            self._run("refs", "--delete", release_ref)
        return commit

    def cleanup(self) -> CleanupReport:
        """Remove checkouts unreachable from refs and durable invocation bindings."""
        with self._locked(), self._connect() as database:
            retained = {
                str(row[0])
                for row in database.execute(
                    "SELECT DISTINCT tool_commit FROM invocation_bindings"
                )
            }
            retained.update(
                str(row[0])
                for row in database.execute(
                    "SELECT DISTINCT runtime_commit FROM runtime_invocation_bindings"
                )
            )
            retained.update(
                str(row[0])
                for row in database.execute(
                    "SELECT DISTINCT commit_id FROM active_deployment_leases"
                )
            )
            retained.update(_commits_from_ref_listing(self._run("refs", "--revision")))
            removed: list[str] = []
            for candidate in sorted(self.deployments.iterdir()):
                if (
                    candidate.is_dir()
                    and _CHECKSUM.fullmatch(candidate.name)
                    and candidate.name not in retained
                ):
                    _remove_tree(candidate)
                    removed.append(candidate.name)
            removed_runtimes: list[str] = []
            for candidate in sorted(self.runtimes.iterdir()):
                if (
                    candidate.is_dir()
                    and _CHECKSUM.fullmatch(candidate.name)
                    and candidate.name not in retained
                ):
                    _remove_tree(candidate)
                    removed_runtimes.append(candidate.name)
            self._run("prune", "--refs-only", "--depth=0")
        return CleanupReport(
            tuple(sorted(retained)), tuple(removed), tuple(removed_runtimes)
        )

    def _initialize_bindings(self) -> None:
        with self._connect() as database:
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS invocation_bindings (
                    principal_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    tool_commit TEXT NOT NULL,
                    PRIMARY KEY (principal_id, session_id, tool_id, call_id)
                )
                """
            )
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS active_deployment_leases (
                    lease_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    PRIMARY KEY (lease_id, commit_id)
                )
                """
            )
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_invocation_bindings (
                    principal_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    runtime_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    runtime_commit TEXT NOT NULL,
                    PRIMARY KEY (principal_id, session_id, runtime_id, call_id)
                )
                """
            )
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS trusted_remotes (
                    name TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    public_key_digest TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._bindings, timeout=self.command_timeout_s)

    def _try_resolve(self, selection: str) -> str | None:
        try:
            output = self._run("rev-parse", selection)
        except DeploymentError:
            return None
        candidate = output.strip().splitlines()[-1] if output.strip() else ""
        return candidate if _CHECKSUM.fullmatch(candidate) else None

    def _run(self, *arguments: str) -> str:
        command = [self.ostree_path, f"--repo={self.repo}", *arguments]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                env={"LC_ALL": "C", "PATH": os.defpath},
                text=True,
                timeout=self.command_timeout_s,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeploymentError(f"ostree command failed:{arguments[0]}") from exc
        if result.returncode != 0:
            raise DeploymentError(f"ostree command failed:{arguments[0]}")
        return result.stdout

    def _verify_checkout(self, commit: str, checkout: Path) -> None:
        difference = self._run(
            "diff",
            "--no-xattrs",
            "--owner-uid=0",
            "--owner-gid=0",
            commit,
            os.fspath(checkout),
        )
        if difference.strip():
            raise DeploymentError("deployment checkout does not match selected commit")

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _closed_json_object(
    raw: bytes, label: str, allowed_fields: frozenset[str]
) -> dict[str, Any]:
    def pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise DeploymentError(f"duplicate {label} manifest field:{key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"{label} manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentError(f"{label} manifest must be an object")
    unknown = set(value).difference(allowed_fields)
    if unknown:
        raise DeploymentError(
            f"unknown {label} manifest fields:" + ",".join(sorted(unknown))
        )
    return value


def _validate_entrypoint(value: object) -> None:
    if not isinstance(value, str):
        raise DeploymentError("bundle entrypoint must be a string")
    module, separator, attribute = value.partition(":")
    if (
        not separator
        or not module
        or not attribute
        or "<locals>" in attribute
        or any(not part.isidentifier() for part in module.split("."))
        or any(not part.isidentifier() for part in attribute.split("."))
    ):
        raise DeploymentError("bundle entrypoint must be importable module:attribute")


def _relative_path(value: object, label: str, *, allow_dot: bool) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise DeploymentError(f"bundle {label} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise DeploymentError(f"bundle {label} escapes the bundle")
    normalized = path.as_posix()
    if normalized == "." and not allow_dot:
        raise DeploymentError(f"bundle {label} must name a child path")
    if normalized != value:
        raise DeploymentError(f"bundle {label} must be normalized")
    return normalized


def _validate_ref(value: str) -> None:
    if (
        not isinstance(value, str)
        or not _REF.fullmatch(value)
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise DeploymentError("invalid OSTree ref")


def _validate_remote(value: str) -> None:
    if not isinstance(value, str) or not _REMOTE.fullmatch(value):
        raise DeploymentError("invalid OSTree remote name")


def _validate_remote_url(value: str) -> None:
    if not isinstance(value, str) or any(ord(character) < 32 for character in value):
        raise DeploymentError("invalid OSTree remote URL")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"https", "file"}:
        raise DeploymentError("OSTree remote URL must use https or file")
    if parsed.scheme == "https" and not parsed.netloc:
        raise DeploymentError("OSTree HTTPS remote URL must include a host")
    if parsed.scheme == "file" and not parsed.path.startswith("/"):
        raise DeploymentError("OSTree file remote URL must be absolute")


def _write_trusted_file(destination: Path, content: bytes) -> bool:
    if destination.exists():
        if destination.read_bytes() != content:
            raise DeploymentError("trusted key digest collision")
        return False
    descriptor: int | None = None
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        return True
    except OSError as exc:
        raise DeploymentError("trusted public key could not be persisted") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _commits_from_ref_listing(output: str) -> set[str]:
    commits: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        matches = [field for field in fields if _CHECKSUM.fullmatch(field)]
        if len(matches) != 1:
            raise DeploymentError("unexpected OSTree ref listing")
        commits.add(matches[0])
    return commits


def _copy_normalized_tree(source: Path, destination: Path) -> None:
    for root, directories, files in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        relative = root_path.relative_to(source)
        target_root = destination / relative
        before = os.lstat(root_path)
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise DeploymentError("bundle contains an unsupported directory")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise DeploymentError("bundle contains privileged mode bits")
        target_root.mkdir(mode=0o755, exist_ok=True)
        target_root.chmod(0o755)
        for name in (*directories, *files):
            candidate = root_path / name
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode):
                raise DeploymentError("bundle symlinks are unsupported")
            if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                raise DeploymentError("bundle contains privileged mode bits")
        for name in files:
            candidate = root_path / name
            metadata = os.lstat(candidate)
            if not stat.S_ISREG(metadata.st_mode):
                raise DeploymentError("bundle special files are unsupported")
            target = target_root / name
            with candidate.open("rb") as source_file, target.open("xb") as target_file:
                shutil.copyfileobj(source_file, target_file)
                target_file.flush()
                os.fsync(target_file.fileno())
            after = os.lstat(candidate)
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise DeploymentError("bundle source changed during publication")
            target.chmod(0o644)


def _copy_normalized_runtime_tree(source: Path, destination: Path) -> None:
    for root, directories, files in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        relative = root_path.relative_to(source)
        target_root = destination / relative
        before = os.lstat(root_path)
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise DeploymentError("runtime contains an unsupported directory")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise DeploymentError("runtime contains privileged mode bits")
        target_root.mkdir(mode=0o755, exist_ok=True)
        target_root.chmod(0o755)
        for name in (*directories, *files):
            candidate = root_path / name
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode):
                raise DeploymentError("runtime symlinks are unsupported")
            if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                raise DeploymentError("runtime contains privileged mode bits")
        for name in files:
            candidate = root_path / name
            metadata = os.lstat(candidate)
            if not stat.S_ISREG(metadata.st_mode):
                raise DeploymentError("runtime special files are unsupported")
            target = target_root / name
            with candidate.open("rb") as source_file, target.open("xb") as target_file:
                shutil.copyfileobj(source_file, target_file)
                target_file.flush()
                os.fsync(target_file.fileno())
            after = os.lstat(candidate)
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise DeploymentError("runtime source changed during publication")
            target.chmod(0o755 if metadata.st_mode & 0o111 else 0o644)


def _validate_bundle_tree(
    root: Path, *, require_normalized_modes: bool = False
) -> tuple[BundleManifest, str, str]:
    if not root.is_dir() or root.is_symlink():
        raise DeploymentError("deployment checkout is not a directory")
    for directory, directories, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_metadata = os.lstat(directory_path)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise DeploymentError("deployment contains an invalid directory")
        if (
            require_normalized_modes
            and stat.S_IMODE(directory_metadata.st_mode) != 0o555
        ):
            raise DeploymentError("deployment directory mode is not normalized")
        for name in (*directories, *files):
            candidate = directory_path / name
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode):
                raise DeploymentError("deployment symlinks are unsupported")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise DeploymentError("deployment special files are unsupported")
            if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                raise DeploymentError("deployment contains privileged mode bits")
            if (
                require_normalized_modes
                and stat.S_ISREG(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) != 0o444
            ):
                raise DeploymentError("deployment file mode is not normalized")
    manifest_path = root / "bundle.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise DeploymentError("deployment is missing bundle.json") from exc
    manifest = BundleManifest.from_bytes(manifest_bytes)
    primary = root.joinpath(*PurePosixPath(manifest.primary_file).parts)
    if not primary.is_file() or primary.is_symlink():
        raise DeploymentError("deployment primary_file is missing")
    for item in manifest.import_roots:
        import_root = root.joinpath(*PurePosixPath(item).parts)
        if not import_root.is_dir() or import_root.is_symlink():
            raise DeploymentError("deployment import root is missing")
    if manifest.dependency_lock is not None:
        lock = root.joinpath(*PurePosixPath(manifest.dependency_lock).parts)
        if not lock.is_file() or lock.is_symlink():
            raise DeploymentError("deployment dependency lock is missing")
    return (
        manifest,
        hashlib.sha256(manifest_bytes).hexdigest(),
        _file_digest(primary),
    )


def _validate_runtime_tree(
    root: Path, *, require_normalized_modes: bool = False
) -> tuple[RuntimeManifest, str]:
    if not root.is_dir() or root.is_symlink():
        raise DeploymentError("runtime checkout is not a directory")
    for directory, directories, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        metadata = os.lstat(directory_path)
        if not stat.S_ISDIR(metadata.st_mode):
            raise DeploymentError("runtime contains an invalid directory")
        if require_normalized_modes and stat.S_IMODE(metadata.st_mode) != 0o555:
            raise DeploymentError("runtime directory mode is not normalized")
        for name in (*directories, *files):
            candidate = directory_path / name
            item = os.lstat(candidate)
            if stat.S_ISLNK(item.st_mode):
                raise DeploymentError("runtime symlinks are unsupported")
            if not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)):
                raise DeploymentError("runtime special files are unsupported")
            if item.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                raise DeploymentError("runtime contains privileged mode bits")
            if (
                require_normalized_modes
                and stat.S_ISREG(item.st_mode)
                and stat.S_IMODE(item.st_mode) not in {0o444, 0o555}
            ):
                raise DeploymentError("runtime file mode is not normalized")
    manifest_path = root / "runtime.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise DeploymentError("runtime is missing runtime.json") from exc
    manifest = RuntimeManifest.from_bytes(manifest_bytes)
    interpreter = root.joinpath(*PurePosixPath(manifest.interpreter).parts)
    if (
        not interpreter.is_file()
        or interpreter.is_symlink()
        or not interpreter.stat().st_mode & 0o111
    ):
        raise DeploymentError("runtime interpreter is missing or not executable")
    for item in manifest.import_roots:
        import_root = root.joinpath(*PurePosixPath(item).parts)
        if not import_root.is_dir() or import_root.is_symlink():
            raise DeploymentError("runtime import root is missing")
    return manifest, hashlib.sha256(manifest_bytes).hexdigest()


def _make_tree_read_only(root: Path) -> None:
    for directory, directories, files in os.walk(root, topdown=False):
        directory_path = Path(directory)
        for name in files:
            (directory_path / name).chmod(0o444)
        for name in directories:
            (directory_path / name).chmod(0o555)
        directory_path.chmod(0o555)


def _make_runtime_tree_read_only(root: Path) -> None:
    for directory, directories, files in os.walk(root, topdown=False):
        directory_path = Path(directory)
        for name in files:
            path = directory_path / name
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        for name in directories:
            (directory_path / name).chmod(0o555)
        directory_path.chmod(0o555)


def _remove_tree(root: Path) -> None:
    if not root.exists():
        return
    for directory, directories, files in os.walk(root, topdown=False):
        directory_path = Path(directory)
        directory_path.chmod(0o700)
        for name in files:
            (directory_path / name).chmod(0o600)
        for name in directories:
            (directory_path / name).chmod(0o700)
    shutil.rmtree(root)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checksum_from_output(output: str) -> str:
    for line in reversed(output.splitlines()):
        candidate = line.strip()
        if _CHECKSUM.fullmatch(candidate):
            return candidate
    raise DeploymentError("ostree did not return a commit checksum")
