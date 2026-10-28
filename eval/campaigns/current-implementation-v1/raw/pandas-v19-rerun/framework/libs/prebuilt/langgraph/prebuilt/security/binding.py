"""Bind authenticated principals outside graph state and model messages."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from threading import Lock
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.runtime import Runtime

from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.stack import CapModule
from langgraph.prebuilt.security.types import (
    AuditRecord,
    AuditSink,
    Principal,
    _validate_principal,
)

PRINCIPAL_CONFIG_KEY = "__principal__"
_CALL_COUNTER_CONFIG_KEY = "__security_call_counter__"
_COUNTER_INIT_LOCK = Lock()


class _CallCounter:
    """Allocate monotonically increasing indexes across one bound session."""

    __slots__ = ("_value", "_lock")

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

    copied = _configuration_copy(config)
    if type(principal) is not Principal:
        raise TypeError("principal must be a Principal")
    _validate_principal(principal)
    configured_modules = (CapModule(), *modules)
    names = [module.name for module in configured_modules]
    if len(names) != len(set(names)):
        raise ValueError("security module names must be unique")
    for module in configured_modules:
        _validate_principal(principal)
        slot = principal.security.allocate(module.name)
        try:
            module.cred_prepare(principal, slot)
        except BaseException as exc:
            raise SecurityBindingError(f"cred_prepare failed:{module.name}") from exc

    return _bind_principal(copied, principal)


def _plain_dictionary(value: Any) -> dict[str, Any]:
    """Snapshot native dictionaries before key lookup can invoke user equality."""
    if type(value) is not dict:
        raise TypeError("security configuration requires a plain dictionary")
    copied = {}
    for key, item in tuple(value.items()):
        if type(key) is not str:
            raise TypeError("security configuration keys must be plain strings")
        copied[key] = item
    return copied


def _configuration_copy(config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Admit only native dictionary shapes; values are still opaque."""
    copied = {} if config is None else _plain_dictionary(config)
    configurable = copied.get("configurable")
    copied["configurable"] = (
        {} if configurable is None else _plain_dictionary(configurable)
    )
    return copied


def _bind_principal(
    config: RunnableConfig | None, principal: Principal
) -> RunnableConfig:
    """Bind an already-prepared principal without rerunning credential hooks."""
    if type(principal) is not Principal:
        raise TypeError("principal must be a Principal")
    _validate_principal(principal)
    copied = _configuration_copy(config)
    configurable = copied["configurable"]
    configurable[PRINCIPAL_CONFIG_KEY] = principal
    configurable.setdefault(_CALL_COUNTER_CONFIG_KEY, _CallCounter())
    copied["configurable"] = configurable
    _bind_runtime_context(configurable, principal)
    return cast("RunnableConfig", copied)


def next_call_index(config: Mapping[str, Any]) -> int:
    """Return the next framework-owned call index for a bound configuration."""
    copied = _plain_dictionary(config)
    configurable = copied.get("configurable")
    if configurable is None:
        raise SecurityBindingError("security call counter requires configurable config")
    admitted = _plain_dictionary(configurable)
    counter = admitted.get(_CALL_COUNTER_CONFIG_KEY)
    if counter is None:
        with _COUNTER_INIT_LOCK:
            counter = configurable.setdefault(_CALL_COUNTER_CONFIG_KEY, _CallCounter())
    if type(counter) is not _CallCounter:
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


def principal_from(
    config: Mapping[str, Any] | None, *, include_runtime_context: bool = True
) -> Principal | None:
    """Read identity from native config dictionaries or an exact Runtime.

    Attribute-based contexts, custom mappings, subclasses and non-string keys
    cannot establish identity. An unrelated runtime is not consulted when the
    principal is already present in the authoritative configurable dictionary.
    With `include_runtime_context=False`, an absent direct binding returns None
    without consulting a runtime. This supports optional identity on unsecured
    request hooks without interpreting arbitrary application contexts.
    """

    if type(include_runtime_context) is not bool:
        raise TypeError("include_runtime_context must be a boolean")
    copied = _configuration_copy(config)
    configurable = copied["configurable"]
    candidate = configurable.get(PRINCIPAL_CONFIG_KEY)
    if candidate is None:
        if not include_runtime_context:
            return None
        runtime = configurable.get("__pregel_runtime")
        if runtime is None:
            return None
        if type(runtime) is not Runtime:
            raise TypeError("principal context requires an exact Runtime")
        context = _runtime_context(runtime)
        if context is None:
            return None
        candidate = _plain_dictionary(context).get(PRINCIPAL_CONFIG_KEY)
    if candidate is None:
        return None
    if type(candidate) is not Principal:
        raise TypeError("reserved principal config contains an invalid value")
    _validate_principal(candidate)
    return candidate


def _runtime_context(runtime: Runtime) -> Any:
    """Read exact native runtime context without retaining a missing-slot error."""
    if type(runtime) is not Runtime:
        raise TypeError("principal context requires an exact Runtime")
    try:
        return runtime.context
    except AttributeError:
        pass
    raise TypeError("principal context requires an initialized Runtime")


def _bind_runtime_context(
    configurable: MutableMapping[str, Any], principal: Principal
) -> None:
    """Copy a supported native context; opaque runtimes stay untouched.

    The configurable principal is authoritative independently of this optional
    context mirror. No attributes or mapping protocols of opaque values run.
    A child binding never changes the parent's Runtime or shared context. Runtime
    is exact, frozen and slotted; use its source method directly rather than an
    instance-selected method when constructing the replacement.
    """
    runtime = _plain_dictionary(configurable).get("__pregel_runtime")
    if type(runtime) is not Runtime:
        return
    context = _runtime_context(runtime)
    if type(context) is dict:
        copied = _plain_dictionary(context)
        copied[PRINCIPAL_CONFIG_KEY] = principal
        try:
            configurable["__pregel_runtime"] = Runtime.override(runtime, context=copied)
            return
        except AttributeError:
            pass
        raise TypeError("principal context requires an initialized Runtime")
