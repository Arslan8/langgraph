"""Explicit state/store/checkpoint boundary mediation with preserved dependencies."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import (
    CHECKPOINT_RESTORE,
    CHECKPOINT_SAVE,
    STATE_READ,
    STATE_WRITE,
    STORE_READ,
    STORE_WRITE,
)


class StateAdapter(BoundaryAdapter):
    def read(self, ref, *, store=False):
        self.before(STORE_READ if store else STATE_READ, (ref,))
        return ref

    def write(self, content, parents, *, store=False):
        name = STORE_WRITE if store else STATE_WRITE
        ref = self.value(content, parents, name)
        self.before(name, (ref,))
        return ref

    def save(self, binding, principal, refs, **kwargs):
        self.before(CHECKPOINT_SAVE, refs)
        return binding.save(principal, refs, **kwargs)

    def restore(self, binding, principal, checkpoint):
        refs = binding.restore(principal, checkpoint)
        self.before(CHECKPOINT_RESTORE, refs)
        return refs
