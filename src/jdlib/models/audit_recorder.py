from __future__ import annotations

import inspect
import uuid
from collections.abc import Mapping
from dataclasses import replace
from datetime import timedelta

from jdlib.context import Clock, Principal, SystemClock, TenantContext, current_tenant
from jdlib.models.audit import AuditEvent
from jdlib.security.audit import SecurityAuditEvent
from jdlib.security.context import current_security_context_or_none

#: How far a caller-supplied event timestamp may sit from the recorder's clock.
#: The trail's time is evidence, so it is corroborated rather than trusted: an
#: event that predates the write by more than ordinary clock jitter is either
#: backdated or a replay of an old event, and this path refuses to store the
#: claim. The tolerance exists for a producer whose clock differs slightly from
#: the writer's, not for shifting history.
MAX_TIMESTAMP_SKEW = timedelta(minutes=1)


def _ambient_actor(context: TenantContext) -> Principal:
    """Who the caller is acting as, taken from the most specific bound context.

    A request binds a security context — which is also what the envelope's own
    identifiers default from — so that is the authoritative actor; outside a
    request (a background job, a direct call in a test) the tenant context
    carries it. Reading both keeps this check comparing an event against the same
    source the event's actor fields were filled from.
    """
    security = current_security_context_or_none()
    if security is not None:
        return security.principal
    return context.principal


class TenantAuditRecorder:
    def __init__(self, session: object, *, clock: Clock | None = None) -> None:
        self._session = session
        self._clock = clock or SystemClock()

    def record(
        self,
        *,
        action: str,
        target_type: str | None = None,
        target_id: uuid.UUID | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        event = self._row(
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata=metadata,
        )
        self._stage(event)
        return event

    async def arecord(
        self,
        *,
        action: str,
        target_type: str | None = None,
        target_id: uuid.UUID | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Stage an audit event on a session whose ``add`` is awaitable.

        :class:`~jdlib.persistence.session.TenantSession` is such a session: its
        ``add`` is a coroutine, so the synchronous methods here cannot stage
        anything on it. Discarding that coroutine loses the row silently, which is
        the one failure an audit trail must never have; the async callers use this
        method instead, and the sync methods refuse the session rather than
        pretend.
        """
        event = self._row(
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata=metadata,
        )
        await self._stage_async(event)
        return event

    def _row(
        self,
        *,
        action: str,
        target_type: str | None,
        target_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None,
    ) -> AuditEvent:
        context = current_tenant()
        return AuditEvent(
            tenant_id=context.tenant_id,
            actor_type=context.principal.kind.value,
            actor_id=context.principal.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata_json=dict(metadata or {}),
            request_id=context.request_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
        )

    def record_security(self, event: SecurityAuditEvent) -> AuditEvent:
        """Persist a security audit event in the caller's transaction.

        Fail closed on attribution: an event that names a tenant or an actor
        other than the ambient one is refused rather than written, because a
        mis-attributed audit row is worse than a missing one — it points an
        investigation at the wrong tenant or blames the wrong principal.

        Fail closed on time: the event's timestamp must be corroborated by this
        recorder's clock (within :data:`MAX_TIMESTAMP_SKEW`), so request-derived
        data cannot backdate, postdate or replay an entry. ``export`` still
        rebuilds envelopes from stored rows with their original timestamps —
        reading history is not writing it.

        Transactional semantics are deliberate and identical to :meth:`record`:
        the row participates in the caller's transaction, so a rolled-back
        operation leaves no audit row, and audit never describes work that did
        not happen. See ``docs/security/audit-hardening.md``.
        """
        row = self._security_row(event)
        self._stage(row)
        return row


    def _security_row(self, event: SecurityAuditEvent) -> AuditEvent:
        """Build the row for a security event, after the fail-closed checks."""

        context = current_tenant()
        if event.tenant_id is not None and event.tenant_id != context.tenant_id:
            raise ValueError("audit event tenant does not match the ambient tenant context")
        principal = _ambient_actor(context)
        if event.principal_id is not None and event.principal_id != principal.id:
            raise ValueError("audit event actor does not match the ambient principal")
        if event.principal_kind is not None and event.principal_kind != principal.kind.value:
            raise ValueError("audit event actor kind does not match the ambient principal")
        now = self._clock.now()
        if abs(event.occurred_at - now) > MAX_TIMESTAMP_SKEW:
            raise ValueError(
                "audit event timestamp is not corroborated by the clock: "
                f"{event.occurred_at.isoformat()} is too far from {now.isoformat()}"
            )
        if event.principal_id is None and event.principal_kind is None:
            event = replace(
                event, principal_id=principal.id, principal_kind=principal.kind.value
            )
        fields = dict(event.as_row())
        metadata_json: dict[str, object] = dict(event.metadata)
        fields.pop("metadata")
        if event.principal_kind and event.principal_kind != fields["actor_type"]:
            # Preserve the real kind even when the column's vocabulary cannot
            # hold it, so nothing about the principal is lost.
            metadata_json.setdefault("principal_kind", event.principal_kind)
        fields["metadata_json"] = metadata_json
        return AuditEvent(tenant_id=context.tenant_id, **fields)

    async def arecord_security(self, event: SecurityAuditEvent) -> AuditEvent:
        """Stage a security event on a session whose ``add`` is awaitable.

        The sibling of :meth:`record_security` for the sinks that run inside an
        async transaction: awaiting the session's ``add`` is the difference
        between an audit row and an event that was never written.
        """

        row = self._security_row(event)
        await self._stage_async(row)
        return row

    def _stage(self, row: AuditEvent) -> None:
        added = self._session.add(row)  # type: ignore[attr-defined]
        if inspect.isawaitable(added):
            # Fail closed rather than drop the row: a synchronous caller that
            # hands this recorder an async session is asking for a write that
            # cannot happen here, and an audit trail with silent holes is worse
            # than an operation that refuses to run. The coroutine this refusal
            # abandons is closed, so the refusal is the only signal raised.
            close = getattr(added, "close", None)
            if callable(close):
                close()
            raise TypeError(
                "this session's add() is awaitable: use arecord()/arecord_security()"
            )

    async def _stage_async(self, row: AuditEvent) -> None:
        added = self._session.add(row)  # type: ignore[attr-defined]
        if inspect.isawaitable(added):
            await added
