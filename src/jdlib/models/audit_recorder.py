from __future__ import annotations

import uuid
from collections.abc import Mapping

from jdlib.context import current_tenant
from jdlib.models.audit import AuditEvent
from jdlib.security.audit import SecurityAuditEvent


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

    def record_security(self, event: SecurityAuditEvent) -> AuditEvent:
        """Persist a security audit event in the caller's transaction.

        Fail closed on attribution: an event that names a tenant other than the
        ambient one is refused rather than written, because a mis-attributed
        audit row is worse than a missing one — it points an investigation at the
        wrong tenant.

        Transactional semantics are deliberate and identical to :meth:`record`:
        the row participates in the caller's transaction, so a rolled-back
        operation leaves no audit row, and audit never describes work that did
        not happen. See ``docs/security/audit-hardening.md``.
        """
        context = current_tenant()
        if event.tenant_id is not None and event.tenant_id != context.tenant_id:
            raise ValueError("audit event tenant does not match the ambient tenant context")
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
