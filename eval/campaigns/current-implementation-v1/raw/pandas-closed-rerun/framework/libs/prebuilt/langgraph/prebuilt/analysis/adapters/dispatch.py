"""Explicit child and branch boundaries, including selection influence."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import BRANCH_MERGE, CHILD_RETURN, CHILD_START


class DispatchAdapter(BoundaryAdapter):
    def child_start(self, refs, *, principal_transfer, scope_transfer):
        return self.before(
            CHILD_START,
            refs,
            metadata={
                "principal_transfer": principal_transfer,
                "scope_transfer": scope_transfer,
            },
        )

    def child_return(self, content, refs):
        ref = self.value(content, refs, CHILD_RETURN)
        self.before(CHILD_RETURN, (ref,))
        return ref

    def merge(self, content, branches, selection_refs=()):
        ref = self.value(content, (*branches, *selection_refs), BRANCH_MERGE)
        self.before(BRANCH_MERGE, (ref,))
        return ref
