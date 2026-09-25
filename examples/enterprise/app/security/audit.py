"""Security events into the control plane's audit trail.

The library defines both halves -- the sink protocol (`SecurityEventSink`) and the platform audit
writer (`PlatformAudit`) -- and deliberately not the join, because the *action* a security event is
recorded under is the deployment's vocabulary, not the library's.

Identifiers are passed through explicitly rather than left to the ambient request context: the sink
is also called from places a request never reached (a shutdown drain, a background emitter), and a
row whose request id is NULL cannot be joined to the request that caused it.
"""

from __future__ import annotations

from jdlib.control.audit import PlatformAudit
from jdlib.security.audit.events import SecurityAuditEvent


class DatabaseSecuritySink:
    """Persist security events in the control plane, under a namespaced action."""

    def __init__(self, *, audit: PlatformAudit) -> None:
        self._audit = audit

    async def emit(self, event: SecurityAuditEvent) -> None:
        await self._audit.record(
            action=f"security.{event.event_type.value}.{event.outcome.value}",
            tenant_id=event.tenant_id,
            actor_id=event.principal_id,
            actor_type=event.principal_kind,
            request_id=event.request_id,
            correlation_id=event.correlation_id,
            trace_id=event.trace_id,
            metadata={
                "event_id": str(event.event_id),
                "action": event.action,
                "source": event.source.value,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                **dict(event.metadata),
            },
        )
