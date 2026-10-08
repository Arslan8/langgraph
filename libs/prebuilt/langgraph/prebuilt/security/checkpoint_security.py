"""Principal-bound, hash-chained verification around any checkpointer."""

from __future__ import annotations

import builtins
import hashlib
import hmac
import json
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
)

from langgraph.prebuilt.security.binding import principal_from
from langgraph.prebuilt.security.host_router import HostRouter
from langgraph.prebuilt.security.object_manager import seal_checkpoint
from langgraph.prebuilt.security.objects import StateOperation, StateRequest
from langgraph.prebuilt.security.types import Principal

_SECURITY_METADATA = "__slanggraph_security__"
_WRITE_WITNESS_CHANNEL = "__slanggraph_write_witness__"
_WRITE_WITNESS_TASK_PREFIX = "__slanggraph_witness__:"


class MediatedCheckpointer(BaseCheckpointSaver):
    """Authenticate checkpoint contents, ancestry, and principal on restore."""

    def __init__(
        self,
        inner: BaseCheckpointSaver,
        router: HostRouter,
        checkpoint_key: bytes,
    ) -> None:
        super().__init__(serde=inner.serde)
        self.inner = inner
        self.router = router
        self.checkpoint_key = bytes(checkpoint_key)

    @property
    def config_specs(self) -> builtins.list[Any]:
        return self.inner.config_specs

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        value = self.inner.get_tuple(config)
        return self._verify(config, value) if value is not None else None

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        value = await self.inner.aget_tuple(config)
        return await self._averify(config, value) if value is not None else None

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        # History inspection is a trusted read, not a restore operation. Each
        # tuple remains authenticated when selected later through get_tuple.
        yield from self.inner.list(config, filter=filter, before=before, limit=limit)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        async for value in self.inner.alist(
            config, filter=filter, before=before, limit=limit
        ):
            yield value

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        principal = _principal(config)
        secured = self._metadata(config, checkpoint, metadata, principal)
        return self.inner.put(config, checkpoint, secured, new_versions)

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        principal = _principal(config)
        secured = await self._ametadata(config, checkpoint, metadata, principal)
        return await self.inner.aput(config, checkpoint, secured, new_versions)

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        principal = _principal(config)
        self.inner.put_writes(config, writes, task_id, task_path)
        witness = self._write_witness(config, writes, task_id, principal)
        witness_task = _WRITE_WITNESS_TASK_PREFIX + witness["digest"]
        self.inner.put_writes(
            config,
            ((_WRITE_WITNESS_CHANNEL, witness),),
            witness_task,
            task_path,
        )

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        principal = _principal(config)
        await self.inner.aput_writes(config, writes, task_id, task_path)
        witness = self._write_witness(config, writes, task_id, principal)
        witness_task = _WRITE_WITNESS_TASK_PREFIX + witness["digest"]
        await self.inner.aput_writes(
            config,
            ((_WRITE_WITNESS_CHANNEL, witness),),
            witness_task,
            task_path,
        )

    def delete_thread(self, thread_id: str) -> None:
        self.inner.delete_thread(thread_id)

    async def adelete_thread(self, thread_id: str) -> None:
        await self.inner.adelete_thread(thread_id)

    def delete_for_runs(self, run_ids: Sequence[str]) -> None:
        self.inner.delete_for_runs(run_ids)

    async def adelete_for_runs(self, run_ids: Sequence[str]) -> None:
        await self.inner.adelete_for_runs(run_ids)

    def copy_thread(self, source_thread_id: str, target_thread_id: str) -> None:
        self.inner.copy_thread(source_thread_id, target_thread_id)

    async def acopy_thread(self, source_thread_id: str, target_thread_id: str) -> None:
        await self.inner.acopy_thread(source_thread_id, target_thread_id)

    def prune(
        self, thread_ids: Sequence[str], *, strategy: str = "keep_latest"
    ) -> None:
        self.inner.prune(thread_ids, strategy=strategy)

    async def aprune(
        self, thread_ids: Sequence[str], *, strategy: str = "keep_latest"
    ) -> None:
        await self.inner.aprune(thread_ids, strategy=strategy)

    def get_next_version(self, current: Any, channel: None) -> Any:
        return self.inner.get_next_version(current, channel)

    def _metadata(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        principal: Principal,
    ) -> CheckpointMetadata:
        predecessor = self.inner.get_tuple(config)
        previous_hash, sequence = _predecessor(predecessor)
        envelope = seal_checkpoint(
            self.checkpoint_key,
            checkpoint_id=checkpoint["id"],
            principal=principal,
            sequence=sequence,
            previous_hash=previous_hash,
            payload=checkpoint,
        )
        secured = dict(metadata)
        secured[_SECURITY_METADATA] = _envelope_metadata(envelope)  # type: ignore[typeddict-unknown-key]
        self.router.state(
            principal,
            StateRequest(
                StateOperation.WRITE,
                f"checkpoint:{checkpoint['id']}",
                principal.user_id,
                value=checkpoint,
            ),
        )
        return secured  # type: ignore[return-value]

    async def _ametadata(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        principal: Principal,
    ) -> CheckpointMetadata:
        predecessor = await self.inner.aget_tuple(config)
        previous_hash, sequence = _predecessor(predecessor)
        envelope = seal_checkpoint(
            self.checkpoint_key,
            checkpoint_id=checkpoint["id"],
            principal=principal,
            sequence=sequence,
            previous_hash=previous_hash,
            payload=checkpoint,
        )
        secured = dict(metadata)
        secured[_SECURITY_METADATA] = _envelope_metadata(envelope)  # type: ignore[typeddict-unknown-key]
        await self.router.astate(
            principal,
            StateRequest(
                StateOperation.WRITE,
                f"checkpoint:{checkpoint['id']}",
                principal.user_id,
                value=checkpoint,
            ),
        )
        return secured  # type: ignore[return-value]

    def _verify(
        self, config: RunnableConfig, value: CheckpointTuple
    ) -> CheckpointTuple:
        principal = _principal(config)
        value = self._verify_pending_writes(value, principal)
        envelope = _envelope(value, principal)
        self.router.state(
            principal,
            StateRequest(
                StateOperation.RESTORE,
                f"checkpoint:{envelope.checkpoint_id}",
                principal.user_id,
                value=envelope,
            ),
        )
        return value

    async def _averify(
        self, config: RunnableConfig, value: CheckpointTuple
    ) -> CheckpointTuple:
        principal = _principal(config)
        value = self._verify_pending_writes(value, principal)
        envelope = _envelope(value, principal)
        await self.router.astate(
            principal,
            StateRequest(
                StateOperation.RESTORE,
                f"checkpoint:{envelope.checkpoint_id}",
                principal.user_id,
                value=envelope,
            ),
        )
        return value

    def _write_witness(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        principal: Principal,
    ) -> dict[str, Any]:
        checkpoint_id = _checkpoint_id(config)
        digest = self._pending_digest(
            checkpoint_id, task_id, writes, principal.user_id, principal.session_id
        )
        return {
            "checkpoint_id": checkpoint_id,
            "task_id": task_id,
            "principal_id": principal.user_id,
            "session_id": principal.session_id,
            "count": len(writes),
            "digest": digest,
        }

    def _pending_digest(
        self,
        checkpoint_id: str,
        task_id: str,
        writes: Sequence[tuple[str, Any]],
        principal_id: str,
        session_id: str,
    ) -> str:
        mac = hmac.new(self.checkpoint_key, digestmod=hashlib.sha256)
        header = json.dumps(
            {
                "checkpoint_id": checkpoint_id,
                "principal_id": principal_id,
                "session_id": session_id,
                "task_id": task_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        mac.update(len(header).to_bytes(8, "big"))
        mac.update(header)
        for channel, item in writes:
            type_name, payload = self.serde.dumps_typed((channel, item))
            encoded_type = type_name.encode()
            mac.update(len(encoded_type).to_bytes(8, "big"))
            mac.update(encoded_type)
            mac.update(len(payload).to_bytes(8, "big"))
            mac.update(payload)
        return mac.hexdigest()

    def _verify_pending_writes(
        self, value: CheckpointTuple, principal: Principal
    ) -> CheckpointTuple:
        pending = value.pending_writes or []
        if not pending:
            return value
        writes_by_task: dict[str, list[tuple[str, Any]]] = {}
        witnesses: dict[str, dict[str, Any]] = {}
        visible = []
        for task_id, channel, item in pending:
            if channel == _WRITE_WITNESS_CHANNEL:
                if not task_id.startswith(_WRITE_WITNESS_TASK_PREFIX):
                    raise PermissionError("checkpoint:malformed_write_witness")
                if not isinstance(item, dict):
                    raise PermissionError("checkpoint:malformed_write_witness")
                witnessed_task = item.get("task_id")
                if not isinstance(witnessed_task, str) or witnessed_task in witnesses:
                    raise PermissionError("checkpoint:malformed_write_witness")
                witnesses[witnessed_task] = item
                continue
            visible.append((task_id, channel, item))
            writes_by_task.setdefault(task_id, []).append((channel, item))
        if set(writes_by_task) != set(witnesses):
            raise PermissionError("checkpoint:unverifiable_pending_writes")
        checkpoint_id = value.checkpoint["id"]
        for task_id, writes in writes_by_task.items():
            witness = witnesses[task_id]
            if (
                witness.get("checkpoint_id") != checkpoint_id
                or witness.get("principal_id") != principal.user_id
                or witness.get("session_id") != principal.session_id
                or witness.get("count") != len(writes)
            ):
                raise PermissionError("checkpoint:invalid_write_witness")
            expected = self._pending_digest(
                checkpoint_id,
                task_id,
                writes,
                principal.user_id,
                principal.session_id,
            )
            digest = witness.get("digest")
            if not isinstance(digest, str) or not hmac.compare_digest(expected, digest):
                raise PermissionError("checkpoint:invalid_write_witness")
        return value._replace(pending_writes=visible)


def _principal(config: RunnableConfig) -> Principal:
    principal = principal_from(config)
    if principal is None:
        raise PermissionError("checkpoint:missing_principal")
    return principal


def _checkpoint_id(config: RunnableConfig) -> str:
    configurable = config.get("configurable")
    checkpoint_id = (
        configurable.get("checkpoint_id") if isinstance(configurable, dict) else None
    )
    if not isinstance(checkpoint_id, str) or not checkpoint_id:
        raise PermissionError("checkpoint:missing_checkpoint_id")
    return checkpoint_id


def _predecessor(value: CheckpointTuple | None) -> tuple[str, int]:
    if value is None:
        return "", 0
    raw = value.metadata.get(_SECURITY_METADATA)
    if not isinstance(raw, dict):
        raise PermissionError("checkpoint:unverifiable_predecessor")
    digest = raw.get("digest")
    sequence = raw.get("sequence")
    if not isinstance(digest, str) or not digest or type(sequence) is not int:
        raise PermissionError("checkpoint:unverifiable_predecessor")
    return digest, sequence + 1


def _envelope(value: CheckpointTuple, principal: Principal):
    from langgraph.prebuilt.security.object_manager import CheckpointEnvelope

    raw = value.metadata.get(_SECURITY_METADATA)
    if not isinstance(raw, dict):
        raise PermissionError("checkpoint:missing_security_metadata")
    try:
        return CheckpointEnvelope(
            str(raw["checkpoint_id"]),
            str(raw["principal_id"]),
            str(raw["session_id"]),
            int(raw["sequence"]),
            str(raw["previous_hash"]),
            value.checkpoint,
            str(raw["digest"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PermissionError("checkpoint:malformed_security_metadata") from exc


def _envelope_metadata(envelope: Any) -> dict[str, Any]:
    return {
        "checkpoint_id": envelope.checkpoint_id,
        "digest": envelope.digest,
        "previous_hash": envelope.previous_hash,
        "principal_id": envelope.principal_id,
        "sequence": envelope.sequence,
        "session_id": envelope.session_id,
    }
