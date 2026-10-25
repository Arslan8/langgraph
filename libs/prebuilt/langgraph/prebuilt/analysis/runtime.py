"""Sequential analysis barriers. Required failures never become clean findings."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic

from langgraph.prebuilt.analysis.config import AnalysisConfig
from langgraph.prebuilt.analysis.contracts import (
    AnalysisContext,
    AnalysisEvent,
    AnalysisResult,
    AnalysisSnapshot,
)
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable, ConfigurationError
from langgraph.prebuilt.analysis.journal import AnalysisJournal
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.analysis.registry import AnalyzerRegistration, Registry
from langgraph.prebuilt.analysis.scope import ScopedValues
from langgraph.prebuilt.analysis.serialization import digest


class AnalysisRuntime:
    """One authenticated run. The root supplies identity and fixed configuration."""

    def __init__(
        self,
        config: AnalysisConfig,
        registry: Registry,
        store: SqliteProvenanceStore,
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        principal_id: str,
        notifications=None,
    ) -> None:
        if not all((tenant_id, session_id, run_id, principal_id)):
            raise ConfigurationError("analysis:missing_run_identity")
        self.config, self.registry, self.store = config, registry, store
        self.tenant_id, self.session_id, self.run_id, self.principal_id = (
            tenant_id,
            session_id,
            run_id,
            principal_id,
        )
        self.journal = AnalysisJournal(store)
        self.notifications = notifications
        self._executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="analysis"
        )

    def _validate(self, event: AnalysisEvent) -> AnalysisEvent:
        if (event.tenant_id, event.session_id, event.run_id) != (
            self.tenant_id,
            self.session_id,
            self.run_id,
        ):
            raise AnalysisUnavailable("analysis:event_identity_mismatch")
        spec = self.registry.events.get(event.event_name)
        if (
            spec is None
            or event.phase != spec.phase
            or event.schema_version != spec.schema_version
        ):
            raise AnalysisUnavailable("analysis:event_schema_mismatch")
        validated = spec.schema.model_validate(event.wire())
        for ref in (*event.input_refs, *event.output_refs):
            value = self.store.get(ref)
            if value.tenant_id != self.tenant_id:
                raise AnalysisUnavailable("analysis:inaccessible_value")
        return validated

    def _context(
        self, event: AnalysisEvent, registration: AnalyzerRegistration
    ) -> AnalysisContext:
        refs = frozenset(
            ref
            for root in (*event.input_refs, *event.output_refs)
            for ref in (root, *self.store.ancestors(root))
        )
        resolver = ScopedValues(self.store, refs, registration.content_access)
        return AnalysisContext(
            event,
            resolver,
            resolver,
            self.journal.relevant_findings(event),
            monotonic() + registration.timeout,
            Event(),
        )

    def _commit(
        self,
        result: AnalysisResult,
        event: AnalysisEvent,
        registration: AnalyzerRegistration,
        context: AnalysisContext,
    ) -> None:
        if not isinstance(result, AnalysisResult):
            raise AnalysisUnavailable("analysis:invalid_result")
        result = AnalysisResult.model_validate_json(result.model_dump_json())
        permitted = context.resolver.refs
        for finding in result.findings:
            if (finding.analyzer_id, finding.analyzer_version) != (
                registration.analyzer_id,
                registration.version,
            ):
                raise AnalysisUnavailable("analysis:analyzer_identity_mismatch")
            if not set((*finding.subject_refs, *finding.evidence_refs)).issubset(
                permitted
            ):
                raise AnalysisUnavailable("analysis:out_of_scope_finding")
        for proposal in result.annotation_proposals:
            if proposal.subject not in permitted:
                raise AnalysisUnavailable("analysis:out_of_scope_annotation")
        for proposal in result.dependency_proposals:
            if proposal.subject not in permitted or proposal.parent not in permitted:
                raise AnalysisUnavailable("analysis:out_of_scope_dependency")
        self.journal.commit_result(event, result)

    def _snapshot(
        self, event: AnalysisEvent, status: str, unavailable: tuple[str, ...] = ()
    ) -> AnalysisSnapshot:
        snapshot = self.journal.snapshot(
            event,
            principal_id=self.principal_id,
            policy_version=self.config.policy_version,
            request_digest=digest(event.wire()),
            status=status,
            unavailable=unavailable,
        )
        if self.notifications is not None:
            self.notifications.publish(snapshot)
        return snapshot

    def process(self, event: AnalysisEvent) -> AnalysisSnapshot:
        event = self._validate(event)
        self._snapshot(event, "pending")
        failed: list[str] = []
        required: list[str] = []
        for registration in self.registry.analyzers:
            if event.event_name not in registration.events:
                continue
            context = self._context(event, registration)
            future = None
            try:
                if set(registration.dependencies).intersection(failed):
                    raise AnalysisUnavailable("analysis:dependency_unavailable")
                future = self._executor.submit(
                    registration.analyzer.analyze, event, context
                )
                result = future.result(timeout=registration.timeout)
                self._commit(result, event, registration, context)
            except Exception:
                failed.append(registration.analyzer_id)
                if registration.mode == "required":
                    required.append(registration.analyzer_id)
            finally:
                context.cancellation.set()
                if future is not None:
                    future.cancel()
        return self._snapshot(
            event,
            "unavailable" if required else "failed" if failed else "complete",
            tuple(required),
        )

    async def aprocess(self, event: AnalysisEvent) -> AnalysisSnapshot:
        event = self._validate(event)
        self._snapshot(event, "pending")
        failed: list[str] = []
        required: list[str] = []
        for registration in self.registry.analyzers:
            if event.event_name not in registration.events:
                continue
            context = self._context(event, registration)
            try:
                if set(registration.dependencies).intersection(failed):
                    raise AnalysisUnavailable("analysis:dependency_unavailable")
                result = await asyncio.wait_for(
                    registration.analyzer.aanalyze(event, context), registration.timeout
                )
                self._commit(result, event, registration, context)
            except asyncio.CancelledError:
                self._snapshot(event, "unavailable", (registration.analyzer_id,))
                raise
            except Exception:
                failed.append(registration.analyzer_id)
                if registration.mode == "required":
                    required.append(registration.analyzer_id)
            finally:
                context.cancellation.set()
        return self._snapshot(
            event,
            "unavailable" if required else "failed" if failed else "complete",
            tuple(required),
        )

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
