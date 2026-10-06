"""Bind authenticated principals outside graph state and model messages."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from threading import Lock
from typing import Any, cast

from langchain_core.runnables import RunnableConfig

from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.stack import CapModule
from langgraph.prebuilt.security.types import AuditRecord, AuditSink, Principal

PRINCIPAL_CONFIG_KEY = "__principal__"
_CALL_COUNTER_CONFIG_KEY = "__security_call_counter__"
_COUNTER_INIT_LOCK = Lock()


class _CallCounter:
    """Allocate monotonically increasing indexes across one bound session."""

    def __init__(self) -> None:
        self._value = 0
        self._lock = Lock()

    def next(self) -> int:
        with self._lock:
            value = self._value
            self._value += 1
            return value


class SecurityBindingError(RuntimeError):
    """Raised when a module fails while preparing a bound principal."""


def with_principal(
    config: RunnableConfig | None,
    principal: Principal,
    *,
    modules: Sequence[SecurityModule] = (),
) -> RunnableConfig:
    """Return a copied config containing a prepared authenticated principal.

    The reserved `configurable.__principal__` value is framework-owned. The
    principal is never read from graph state or messages. Each module receives
    only its named slot during credential preparation.
    """

    if not isinstance(principal, Principal):
        raise TypeError("principal must be a Principal")
    configured_modules = (CapModule(), *modules)
    names = [module.name for module in configured_modules]
    if len(names) != len(set(names)):
        raise ValueError("security module names must be unique")
    for module in configured_modules:
        slot = principal.security.allocate(module.name)
        try:
            module.cred_prepare(principal, slot)
        except BaseException as exc:
            raise SecurityBindingError(f"cred_prepare failed:{module.name}") from exc

    return _bind_principal(config, principal)


def _bind_principal(
    config: RunnableConfig | None, principal: Principal
) -> RunnableConfig:
    """Bind an already-prepared principal without rerunning credential hooks."""
    copied = dict(config or {})
    raw_configurable = copied.get("configurable")
    if raw_configurable is None:
        configurable: dict[str, Any] = {}
    elif isinstance(raw_configurable, Mapping):
        configurable = dict(raw_configurable)
    else:
        raise TypeError("configurable config must be a mapping")
    configurable[PRINCIPAL_CONFIG_KEY] = principal
    configurable.setdefault(_CALL_COUNTER_CONFIG_KEY, _CallCounter())
    copied["configurable"] = configurable
    _bind_runtime_context(configurable, principal)
    return cast("RunnableConfig", copied)


def next_call_index(config: Mapping[str, Any]) -> int:
    """Return the next framework-owned call index for a bound configuration."""
    configurable = config.get("configurable")
    if not isinstance(configurable, MutableMapping):
        raise SecurityBindingError("security call counter requires configurable config")
    counter = configurable.get(_CALL_COUNTER_CONFIG_KEY)
    if counter is None:
        with _COUNTER_INIT_LOCK:
            counter = configurable.setdefault(_CALL_COUNTER_CONFIG_KEY, _CallCounter())
    if not isinstance(counter, _CallCounter):
        raise SecurityBindingError("security call counter is missing or invalid")
    return counter.next()


def history_for(
    sink: AuditSink | None, principal: Principal
) -> tuple[AuditRecord, ...]:
    """Return prior audit decisions belonging only to this principal session."""
    if sink is None:
        return ()
    return tuple(
        record
        for record in sink.records()
        if record.user_id == principal.user_id
        and record.session_id == principal.session_id
    )


def principal_from(config: Mapping[str, Any] | None) -> Principal | None:
    """Read a bound principal from the reserved config or runtime context."""

    if not config:
        return None
    configurable = config.get("configurable")
    if not isinstance(configurable, Mapping):
        return None
    candidate = configurable.get(PRINCIPAL_CONFIG_KEY)
    if candidate is None:
        runtime = configurable.get("__pregel_runtime")
        context = getattr(runtime, "context", None)
        if isinstance(context, Mapping):
            candidate = context.get(PRINCIPAL_CONFIG_KEY)
        else:
            candidate = getattr(context, PRINCIPAL_CONFIG_KEY, None)
    if candidate is None:
        return None
    if not isinstance(candidate, Principal):
        raise TypeError("reserved principal config contains an invalid value")
    return candidate


def _bind_runtime_context(
    configurable: MutableMapping[str, Any], principal: Principal
) -> None:
    runtime = configurable.get("__pregel_runtime")
    context = getattr(runtime, "context", None)
    if isinstance(context, MutableMapping):
        context[PRINCIPAL_CONFIG_KEY] = principal
