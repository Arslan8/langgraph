"""Trusted mediated resource evidence, including authoritative grants/receipts."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable


class ResourceAdapter(BoundaryAdapter):
    def access(
        self,
        operation,
        refs,
        *,
        object_identity,
        grant_ref,
        receipt_ref="",
        destination="",
    ):
        if (
            operation not in ("read", "write", "send")
            or not object_identity
            or not grant_ref
        ):
            raise AnalysisUnavailable("analysis:invalid_resource_boundary")
        return self.before(
            f"resource.{operation}",
            refs,
            destination=destination,
            metadata={
                "object_identity": object_identity,
                "grant_ref": grant_ref,
                "receipt_ref": receipt_ref,
            },
        )
