from __future__ import annotations

import uuid
from collections.abc import Mapping

from jdlib.context import current_tenant
from jdlib.models.audit import AuditEvent


class TenantAuditRecorder:
    def __init__(self, session: object) -> None:
        self._session = session

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
