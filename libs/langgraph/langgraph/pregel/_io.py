from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal
from uuid import uuid4

from langchain_core.tracers.log_stream import RunLog, RunLogPatch

from langgraph._internal._constants import (
    ERROR,
    INTERRUPT,
    NULL_TASK_ID,
    RESUME,
    RETURN,
    TASKS,
)
from langgraph._internal._typing import EMPTY_SEQ, MISSING
from langgraph.channels.base import BaseChannel, EmptyChannelError
from langgraph.constants import START, TAG_HIDDEN
from langgraph.errors import InvalidUpdateError
from langgraph.pregel._log import logger
from langgraph.types import Command, PregelExecutableTask, Send, StateSnapshot


@dataclass(frozen=True, slots=True)
class _OutputEnvelope:
    """Framework-created stream framing, distinct from application values."""

    content: Any
    format: str
    namespace: tuple[str, ...]
    mode: str

    def rebuild(self, content: Any) -> Any:
        if self.format == "state-snapshot":
            if type(content) is StateSnapshot:
                return content
            # A replaced snapshot contains only the effective value. In
            # particular, do not copy task results, interrupts or checkpoint
            # metadata from the original snapshot after policy redaction.
            return StateSnapshot(content, (), {}, None, None, None, (), ())
        if self.format in {"legacy-log", "legacy-log-patch"}:
            # Rebuild from the effective state, never the producer's raw patch
            # history. Root replacement stays applicable after any redaction.
            state = deepcopy(content)
            if not (
                isinstance(state, dict)
                and all(
                    key in state
                    for key in (
                        "id",
                        "name",
                        "type",
                        "logs",
                        "streamed_output",
                        "final_output",
                    )
                )
            ):
                state = {
                    "id": str(uuid4()),
                    "name": "security_output",
                    "type": "chain",
                    "logs": {},
                    "streamed_output": [],
                    "final_output": state,
                }
            operation = {"op": "replace", "path": "", "value": state}
            if self.format == "legacy-log-patch":
                return RunLogPatch(operation)
            return RunLog(operation, state=state)
        if self.format == "legacy-event":
            # Validate only the already-authorized result. Never retain fields
            # from the original event when a policy replaced that event.
            if (
                isinstance(content, dict)
                and all(
                    isinstance(content.get(key), str)
                    for key in ("event", "name", "run_id")
                )
                and "data" in content
                and isinstance(content.get("parent_ids"), (list, tuple))
                and all(isinstance(parent, str) for parent in content["parent_ids"])
            ):
                return content
            return {
                "event": "on_custom_event",
                "name": "security_output",
                "run_id": str(uuid4()),
                "parent_ids": [],
                "tags": [],
                "metadata": {},
                "data": content,
            }
        if self.format == "v2-values-interrupts":
            # Both data and interrupt values passed through the same output hook.
            if isinstance(content, dict) and set(content) == {"data", "interrupts"}:
                data, interrupts = content["data"], content["interrupts"]
            else:
                data, interrupts = content, ()
            return {
                "type": self.mode,
                "ns": self.namespace,
                "data": data,
                "interrupts": interrupts,
            }
        if self.format == "v2-values":
            return {
                "type": self.mode,
                "ns": self.namespace,
                "data": content,
                "interrupts": (),
            }
        if self.format == "v2":
            return {"type": self.mode, "ns": self.namespace, "data": content}
        if self.format == "namespace-mode":
            return self.namespace, self.mode, content
        if self.format == "mode":
            return self.mode, content
        if self.format == "namespace":
            return self.namespace, content
        if self.format == "plain":
            return content
        raise ValueError("unknown stream envelope format")


def read_channel(
    channels: Mapping[str, BaseChannel],
    chan: str,
    *,
    catch: bool = True,
) -> Any:
    try:
        return channels[chan].get()
    except EmptyChannelError:
        if catch:
            return None
        else:
            raise


def read_channels(
    channels: Mapping[str, BaseChannel],
    select: Sequence[str] | str,
    *,
    skip_empty: bool = True,
) -> dict[str, Any] | Any:
    if isinstance(select, str):
        return read_channel(channels, select)
    else:
        values: dict[str, Any] = {}
        for k in select:
            try:
                values[k] = read_channel(channels, k, catch=not skip_empty)
            except EmptyChannelError:
                pass
        return values


def map_command(cmd: Command) -> Iterator[tuple[str, str, Any]]:
    """Map input chunk to a sequence of pending writes in the form (channel, value)."""
    if cmd.graph == Command.PARENT:
        raise InvalidUpdateError("There is no parent graph")
    if cmd.goto:
        if isinstance(cmd.goto, (tuple, list)):
            sends = cmd.goto
        else:
            sends = [cmd.goto]
        for send in sends:
            if isinstance(send, Send):
                yield (NULL_TASK_ID, TASKS, send)
            elif isinstance(send, str):
                yield (NULL_TASK_ID, f"branch:to:{send}", START)
            else:
                raise TypeError(
                    f"In Command.goto, expected Send/str, got {type(send).__name__}"
                )
    if cmd.resume is not None:
        yield (NULL_TASK_ID, RESUME, cmd.resume)
    if cmd.update:
        for k, v in cmd._update_as_tuples():
            yield (NULL_TASK_ID, k, v)


def map_input(
    input_channels: str | Sequence[str],
    chunk: dict[str, Any] | Any | None,
) -> Iterator[tuple[str, Any]]:
    """Map input chunk to a sequence of pending writes in the form (channel, value)."""
    if chunk is None:
        return
    elif isinstance(input_channels, str):
        yield (input_channels, chunk)
    else:
        if not isinstance(chunk, dict):
            raise TypeError(f"Expected chunk to be a dict, got {type(chunk).__name__}")
        for k in chunk:
            if k in input_channels:
                yield (k, chunk[k])
            else:
                logger.warning(f"Input channel {k} not found in {input_channels}")


def map_output_values(
    output_channels: str | Sequence[str],
    pending_writes: Literal[True] | Sequence[tuple[str, Any]],
    channels: Mapping[str, BaseChannel],
) -> Iterator[dict[str, Any] | Any]:
    """Map pending writes (a sequence of tuples (channel, value)) to output chunk."""
    if isinstance(output_channels, str):
        if pending_writes is True or any(
            chan == output_channels for chan, _ in pending_writes
        ):
            yield read_channel(channels, output_channels)
    else:
        if pending_writes is True or {
            c for c, _ in pending_writes if c in output_channels
        }:
            yield read_channels(channels, output_channels)


def map_output_updates(
    output_channels: str | Sequence[str],
    tasks: list[tuple[PregelExecutableTask, Sequence[tuple[str, Any]]]],
    cached: bool = False,
) -> Iterator[dict[str, Any | dict[str, Any]]]:
    """Map pending writes (a sequence of tuples (channel, value)) to output chunk."""
    output_tasks = [
        (t, ww)
        for t, ww in tasks
        if (not t.config or TAG_HIDDEN not in t.config.get("tags", EMPTY_SEQ))
        and ww[0][0] != ERROR
        and ww[0][0] != INTERRUPT
    ]
    if not output_tasks:
        return
    updated: list[tuple[str, Any]] = []
    for task, writes in output_tasks:
        rtn = next((value for chan, value in writes if chan == RETURN), MISSING)
        if rtn is not MISSING:
            updated.append((task.name, rtn))
        elif isinstance(output_channels, str):
            updated.extend(
                (task.name, value) for chan, value in writes if chan == output_channels
            )
        elif any(chan in output_channels for chan, _ in writes):
            counts = Counter(chan for chan, _ in writes)
            if any(counts[chan] > 1 for chan in output_channels):
                updated.extend(
                    (
                        task.name,
                        {chan: value},
                    )
                    for chan, value in writes
                    if chan in output_channels
                )
            else:
                updated.append(
                    (
                        task.name,
                        {
                            chan: value
                            for chan, value in writes
                            if chan in output_channels
                        },
                    )
                )
    grouped: dict[str, Any] = {t.name: [] for t, _ in output_tasks}
    for node, value in updated:
        grouped[node].append(value)
    for node, value in grouped.items():
        if len(value) == 0:
            grouped[node] = None
        if len(value) == 1:
            grouped[node] = value[0]
    if cached:
        grouped["__metadata__"] = {"cached": cached}
    yield grouped
