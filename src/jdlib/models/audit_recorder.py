from __future__ import annotations

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
        context = current_tenant()
        event = AuditEvent(
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
        self._session.add(event)  # type: ignore[attr-defined]
        return event

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
            # No actor was named, so the event is attributed the same way the
            # tenant is: from the context. A row that names neither an actor nor
            # a reason is not evidence, and the ambient principal is the one the
            # operation is actually being performed as.
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
        row = AuditEvent(tenant_id=context.tenant_id, **fields)
        self._session.add(row)  # type: ignore[attr-defined]
        return row
