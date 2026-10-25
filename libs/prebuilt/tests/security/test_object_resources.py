"""Object identities survive binding and never authorize another resource."""

import hashlib
import json
import sys
from abc import ABC, abstractmethod
from dataclasses import replace
from pathlib import Path

import pytest
from langchain_core.tools import tool

from langgraph.prebuilt.security import (
    EnforcementKind,
    HostExecutionDenied,
    HostExecutionError,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ObjectGrantLine,
    Principal,
    Requirement,
    ResourceSupport,
    SecurityConfigurationError,
    SupportLevel,
    cedar_security,
)
from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from langgraph.prebuilt.security.manifest_consistency import check_manifest_consistency
from langgraph.prebuilt.security.mediators.contracts import (
    ResourceContract,
    client_binding,
)
from langgraph.prebuilt.security.mediators.objects import _local, local_resources
from langgraph.prebuilt.security.object_policy import (
    ObjectGrant,
    parse_security_manifest,
)
from langgraph.prebuilt.security.types import ExecutionOutcome, Tool, ToolCall, ToolDac
from tests.security.test_enforcement import _host
from tests.security.test_resource_binding import CONTEXT


class CounterAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def increment(self, amount: int) -> int:
        raise NotImplementedError

    @abstractmethod
    def read(self) -> int:
        raise NotImplementedError


class Counter(CounterAPI):
    def __init__(self):
        self.value = 0

    def increment(self, amount: int) -> int:
        self.value += amount
        return self.value

    def read(self) -> int:
        return self.value


def assessment(line, host):
    return ResourceSupport(SupportLevel.EXACT, "in-memory counter", witness=__file__)


def contract(**kwargs):
    return ResourceContract(
        CounterAPI,
        class_name="counter",
        object_kind="counter",
        lowering="counter.local.v1",
        **kwargs,
    )


FIRST = contract()
SECOND = contract()
first = FIRST.client(export=__name__ + ".first")
second = SECOND.client(export=__name__ + ".second")


@tool
def increment() -> int:
    """Increment the first object."""
    return first.increment(2)


@tool
async def async_increment() -> int:
    """Increment the first object asynchronously."""
    return first.increment(2)


def line(resource, *, trusted=False, operation="increment"):
    return ObjectGrantLine(
        "line",
        "counter",
        operation,
        resource._object_id,
        {},
        Requirement.NEED,
        EnforcementKind.TRUSTED_TOOL if trusted else EnforcementKind.BROKER,
        resource.lowering,
    )


def invocation(resource, name="increment", *, trusted=False):
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool(name, ToolDac("owner", {"*": "x"}), frozenset(), ()), {}, {}, "call", 0
    )
    grant = ObjectGrant(
        "alice", name, "call", "policy", (line(resource, trusted=trusted),)
    )
    return principal, call, grant


@pytest.mark.parametrize("constructor", [False, True])
def test_identity_and_typed_guards(constructor):
    backend = Counter()
    resource = (
        contract(implementation=backend, assess=assessment)
        if constructor
        else FIRST.bind(implementation=backend, assess=assessment)
    )
    client = resource.client(
        export=__name__ + (".constructed" if constructor else ".bound")
    )
    binding = client_binding(client)
    assert binding.contract._adapter is None
    assert binding.contract._object_id == resource._object_id
    assert resource.adapter.invoke(line(resource), {"amount": 2}, CONTEXT) == 2
    with pytest.raises(ValueError, match="payload"):
        resource.adapter.invoke(line(resource), {"amount": True}, CONTEXT)
    with pytest.raises(PermissionError, match="contract"):
        resource.adapter.invoke(line(SECOND), {"amount": 100}, CONTEXT)
    assert (
        resource.adapter.assess(line(SECOND), _host()).support
        is SupportLevel.UNSUPPORTED
    )
    assert backend.value == 2


def test_static_effects_bind_object_and_check_zero_argument_methods():
    resource = FIRST.bind(implementation=Counter(), assess=assessment)
    manifest = parse_security_manifest(
        resource.class_declaration()
        + "\ntool inspect {\n runs linux\n"
        + resource.permission("read")
        + "\n}"
    )

    def check(body):
        return check_manifest_consistency(
            "def inspect():\n    return " + body,
            manifest,
            tool_name="inspect",
            clients={"first": first, "second": second},
        )

    assert check("first.read()")["consistent"]
    assert not check("second.read()")["consistent"]
    assert not check("first.read(2)")["consistent"]
    assert not check("first.increment(2)")["consistent"]


@pytest.mark.parametrize("async_mode", [False, True])
async def test_admitted_inprocess_tool_and_grant_removal(async_mode):
    backend = Counter()
    resource = FIRST.bind(implementation=backend, assess=assessment)
    candidate = async_increment if async_mode else increment
    security = cedar_security(
        candidate,
        resources=(resource,),
        manifest="runs inprocess\n" + resource.permission("increment"),
        policy="permit(principal, action, resource);",
    )
    dispatcher = security.host_executor.dispatcher
    args = invocation(resource, candidate.name, trusted=True)
    result = await dispatcher.ainvoke(*args) if async_mode else dispatcher.invoke(*args)
    assert result.value == 2
    with pytest.raises(HostExecutionDenied, match="not_granted"):
        denied = (*args[:2], replace(args[2], lines=()))
        if async_mode:
            await dispatcher.ainvoke(*denied)
        else:
            dispatcher.invoke(*denied)
    assert backend.value == 2


def test_wrong_object_manifest_rejected_at_admission():
    with pytest.raises(SecurityConfigurationError, match="mismatch"):
        cedar_security(
            increment,
            resources=(SECOND.bind(implementation=Counter(), assess=assessment),),
            manifest="runs inprocess\n" + SECOND.permission("increment"),
            policy="permit(principal, action, resource);",
        )


def test_duplicate_registration_rejected():
    resource = FIRST.bind(implementation=Counter(), assess=assessment)
    with pytest.raises(ValueError, match="distinct object"):
        cedar_security(
            increment,
            resources=(
                resource,
                FIRST.bind(implementation=Counter(), assess=assessment),
            ),
            policy="permit(principal, action, resource);",
        )


def test_os_worker_raw_protocol_cannot_cross_objects(tmp_path):
    if probe_landlock_abi() < 5:
        pytest.skip("Landlock ABI 5 required")
    a, b = Counter(), Counter()
    first_resource = FIRST.bind(implementation=a, assess=assessment)
    second_resource = SECOND.bind(implementation=b, assess=assessment)
    source = tmp_path / "worker.py"
    # Raw framed protocol is language neutral; no typed client or source verifier.
    source.write_text("""import json
import os

def increment(service: str):
    fd = int(os.environ["SLANGGRAPH_BROKER_FD"])
    os.write(fd, (json.dumps({"service": service, "operation": "increment", "payload": {"amount": 2}}) + "\\n").encode())
    return json.loads(os.read(fd, 65536))
""")
    dispatcher = ObjectBrokerDispatcher(
        {
            "increment": LinuxToolSpec(
                "worker:increment",
                source,
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=tuple(
            Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
        ),
        resources=(first_resource, second_resource),
    )
    principal, call, grant = invocation(first_resource)
    for service, status in [
        (first_resource.reference.service, "ok"),
        (second_resource.reference.service, "denied"),
        ("resource:" + __name__ + ".first", "ok"),
        ("resource:" + __name__ + ".second", "denied"),
    ]:
        result = dispatcher.invoke(
            principal, replace(call, args={"service": service}), grant
        )
        assert result.value["status"] == status, json.dumps(result.value)
    assert a.value == 4
    assert b.value == 0


def test_backend_cannot_be_registered_under_two_identities():
    backend = Counter()
    with pytest.raises(ValueError, match="multiple resource identities"):
        cedar_security(
            increment,
            resources=(
                FIRST.bind(implementation=backend, assess=assessment),
                SECOND.bind(implementation=backend, assess=assessment),
            ),
            policy="permit(principal, action, resource);",
        )


@pytest.mark.parametrize(
    "host_requirement", ["capability", "protected_path", "unsupported"]
)
def test_inprocess_cannot_claim_os_protection(host_requirement):
    backend = Counter()

    def unavailable(line, host):
        assert not host.capabilities
        if host_requirement == "unsupported":
            return ResourceSupport(SupportLevel.UNSUPPORTED, "unavailable")
        return ResourceSupport(
            SupportLevel.EXACT,
            "OS protection required",
            witness=__file__,
            required_capabilities=frozenset({"seccomp:minimal"})
            if host_requirement == "capability"
            else frozenset(),
            protected_paths=("/secret",)
            if host_requirement == "protected_path"
            else (),
        )

    resource = FIRST.bind(implementation=backend, assess=unavailable)
    security = cedar_security(
        increment,
        resources=(resource,),
        manifest="runs inprocess\n" + resource.permission("increment"),
        policy="permit(principal, action, resource);",
    )
    with pytest.raises(HostExecutionDenied, match="unsupported_inprocess"):
        security.host_executor.dispatcher.invoke(*invocation(resource, trusted=True))
    assert backend.value == 0


def test_inprocess_lifecycle_and_closed_context():

    events = []

    class Mediator:
        assess = staticmethod(assessment)

        def validate(self, operation, arguments, context):
            events.append(("validate", arguments["amount"]))
            if arguments["amount"] < 0:
                raise ValueError("negative")

    backend = Counter()
    resource = FIRST.bind(
        implementation=backend,
        mediator=Mediator(),
        activate=lambda lines, context: events.append("activate"),
        release=lambda context: events.append("release"),
    )
    with local_resources((resource,), *invocation(resource, trusted=True)):
        saved_dispatch = _local.get()
        assert first.increment(2) == 2
        with pytest.raises(HostExecutionDenied, match="not_granted"):
            second.increment(50)
        with pytest.raises(ValueError, match="negative"):
            first.increment(-1)
    with pytest.raises(HostExecutionDenied, match="closed"):
        saved_dispatch(FIRST._object_id, "increment", {"amount": 2})
    assert backend.value == 2
    assert events == ["activate", ("validate", 2), ("validate", -1), "release"]


@pytest.mark.parametrize("async_mode", [False, True])
async def test_release_failure_reports_indeterminate_effects(async_mode):
    backend = Counter()

    def release(context):
        raise RuntimeError("cleanup failed")

    resource = FIRST.bind(implementation=backend, assess=assessment, release=release)
    candidate = async_increment if async_mode else increment
    security = cedar_security(
        candidate,
        resources=(resource,),
        manifest="runs inprocess\n" + resource.permission("increment"),
        policy="permit(principal, action, resource);",
    )
    dispatcher = security.host_executor.dispatcher
    args = invocation(resource, candidate.name, trusted=True)
    with pytest.raises(HostExecutionError, match="release_failed") as caught:
        if async_mode:
            await dispatcher.ainvoke(*args)
        else:
            dispatcher.invoke(*args)
    assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
    assert backend.value == 2
