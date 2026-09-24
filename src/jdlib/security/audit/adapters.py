"""Adapters that turn existing library seams into audit events (directive §6.5).

The library already calls out at the moments that matter — when the context
factory mints a privilege, when privileged raw SQL runs, when privileged raw SQL
is refused — through small protocols (`PrivilegeAudit`, `RawSqlAuditor`). These
adapters implement those protocols on top of a
:class:`~jdlib.security.audit.emitters.SecurityEventSink`, so wiring the audit
trail is a constructor argument rather than a change to business code.

Two rules are deliberate:

* **An emission never swallows the original failure.** The adapters are called
  before a refusal is raised, and they do not catch anything: if the sink fails,
  that failure surfaces alongside the refusal rather than replacing it silently.
* **Statement text is not evidence.** A SQL statement can carry literals, so
  only its *kind* (`select`, `update`, …) is recorded — never the statement. The
  same restraint applies to free text: justifications pass through the shared
  redaction rules like any other metadata.
"""

from __future__ import annotations

import re
import uuid

from jdlib.context import Principal, PrivilegeKind
from jdlib.persistence.rawsql import RawSqlMode
from jdlib.security.audit.emitters import SecurityEventSink
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)

_STATEMENT_KEYWORD = re.compile(r"^[A-Za-z]{1,24}$")


def statement_kind(sql: object) -> str:
    """The leading keyword of a statement, or ``unknown``.

    Deliberately lexical, not a parser: the audit trail wants a routing label,
    not an interpretation of SQL we may not understand.
    """
    if not isinstance(sql, str):
        return "unknown"
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        token = stripped.split(None, 1)[0].rstrip(";(")
        return token.lower() if _STATEMENT_KEYWORD.match(token) else "unknown"
    return "unknown"


class AuditPrivilegeAudit:
    """Emit ``PRIVILEGE_ISSUED`` whenever a privilege is minted."""

    def __init__(self, sink: SecurityEventSink) -> None:
        self._sink = sink

    async def record_privilege(
        self,
        *,
        kind: PrivilegeKind,
        capability: str | None,
        justification: str | None,
        actor: Principal,
        tenant_id: uuid.UUID,
    ) -> None:
        metadata: dict[str, object] = {
            "kind": str(kind),
            "capability": capability or "none",
        }
        if justification:
            metadata["justification"] = justification
        await self._sink.emit(
            SecurityAuditEvent(
                event_type=SecurityEventType.PRIVILEGE_ISSUED,
                outcome=AuditOutcome.SUCCESS,
                action="privilege.issue",
                source=AuditSource.SYSTEM,
                tenant_id=tenant_id,
                principal_id=actor.id,
                principal_kind=str(actor.kind),
                resource_type="privilege",
                metadata=metadata,
            )
        )


class AuditRawSqlAuditor:
    """Emit the privileged raw-SQL trail, including refused attempts.

    Used in both seats: ``record_raw_sql`` for a statement that ran under a
    privilege, ``record_raw_sql_denied`` for a statement the gate refused. The
    refusal is recorded *before* ``AuthorizationError`` reaches the caller, so an
    attempt to escalate is visible even though it did not run.
    """

    def __init__(self, sink: SecurityEventSink) -> None:
        self._sink = sink

    async def record_raw_sql(
        self,
        *,
        mode: RawSqlMode,
        capability: str | None,
        tenant_id: uuid.UUID,
        sql: str,
    ) -> None:
        await self._sink.emit(
            SecurityAuditEvent(
                event_type=SecurityEventType.RAW_SQL_PRIVILEGED,
                outcome=AuditOutcome.SUCCESS,
                action="raw_sql.privileged",
                source=AuditSource.SYSTEM,
                tenant_id=tenant_id,
                resource_type="raw_sql",
                metadata=self._metadata(mode, capability, statement_kind(sql)),
            )
        )

    async def record_raw_sql_denied(
        self,
        *,
        mode: RawSqlMode,
        capability: str | None,
        tenant_id: uuid.UUID,
        sql: object,
        reason: str,
        principal_id: uuid.UUID | None = None,
        principal_kind: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        """Record a refusal. A refusal with no actor is not evidence, so the
        caller passes whoever attempted it and the ids that tie the attempt to a
        request; they are optional only so the method stays callable on its own.
        """
        metadata = self._metadata(mode, capability, statement_kind(sql))
        metadata["reason"] = reason
        await self._sink.emit(
            SecurityAuditEvent(
                event_type=SecurityEventType.RAW_SQL_REJECTED,
                outcome=AuditOutcome.DENIED,
                action="raw_sql.rejected",
                source=AuditSource.SYSTEM,
                tenant_id=tenant_id,
                principal_id=principal_id,
                principal_kind=principal_kind,
                request_id=request_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
                resource_type="raw_sql",
                metadata=metadata,
            )
        )

    @staticmethod
    def _metadata(mode: RawSqlMode, capability: str | None, kind: str) -> dict[str, object]:
        return {
            "mode": str(mode),
            "capability": capability or "none",
            "statement": kind,
        }


__all__ = ["AuditPrivilegeAudit", "AuditRawSqlAuditor", "statement_kind"]
