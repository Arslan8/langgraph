"""Explicit trusted mediation contracts for test handlers."""

from langgraph.prebuilt.security import EnforcementKind, SupportLevel
from langgraph.prebuilt.security.resource_mediator import (
    ResourceMediatorAdapter,
    ResourceSupport,
)


def exact_mediator(handlers):
    def assess(line, host):
        if (
            line.enforcer is EnforcementKind.BROKER
            and line.lowering is None
            and (line.class_name, line.operation) in handlers
        ):
            return ResourceSupport(
                SupportLevel.EXACT,
                "test handler honors the supplied line",
                "test-exact-object-contract-v1",
            )
        return ResourceSupport(SupportLevel.UNSUPPORTED, "unimplemented test resource")

    def invoke(line, payload, context):
        return handlers[(line.class_name, line.operation)](line, payload)

    return ResourceMediatorAdapter("test-resource-mediator", assess, invoke)
