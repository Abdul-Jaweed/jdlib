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
from collections.abc import Mapping

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

    def __init__(
        self, sink: SecurityEventSink, extra_metadata: Mapping[str, object] | None = None
    ) -> None:
        self._sink = sink
        self._extra = dict(extra_metadata or {})

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
            **self._extra,
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


#: Every action the control plane records today, mapped to the vocabulary.
#: The table is the contract: a test enumerates the library's action strings and
#: asserts each one is present, so a new call site cannot quietly go unrecorded.
CONTROL_ACTION_EVENTS: dict[str, tuple[SecurityEventType, AuditOutcome]] = {
    # tenant lifecycle (jdlib.control.registry, jdlib.control.purge)
    "tenant.created": (SecurityEventType.TENANT_CREATED, AuditOutcome.SUCCESS),
    "tenant.activated": (SecurityEventType.TENANT_RESUMED, AuditOutcome.SUCCESS),
    "tenant.resumed": (SecurityEventType.TENANT_RESUMED, AuditOutcome.SUCCESS),
    "tenant.suspended": (SecurityEventType.TENANT_SUSPENDED, AuditOutcome.SUCCESS),
    "tenant.archived": (SecurityEventType.TENANT_ARCHIVED, AuditOutcome.SUCCESS),
    "tenant.deprovisioned": (SecurityEventType.TENANT_DEPROVISIONED, AuditOutcome.SUCCESS),
    "tenant.purge": (SecurityEventType.TENANT_PURGED, AuditOutcome.SUCCESS),
    "tenant.purged": (SecurityEventType.TENANT_PURGED, AuditOutcome.SUCCESS),
    "tenant.relocated": (SecurityEventType.TENANT_RELOCATED, AuditOutcome.SUCCESS),
    "tenant.migration.succeeded": (SecurityEventType.TENANT_PROVISIONED, AuditOutcome.SUCCESS),
    "tenant.migration.failed": (SecurityEventType.TENANT_PROVISIONED, AuditOutcome.FAILURE),
    # authentication
    "authn.failed": (SecurityEventType.AUTH_LOGIN_FAILURE, AuditOutcome.FAILURE),
    "authn.succeeded": (SecurityEventType.AUTH_LOGIN_SUCCESS, AuditOutcome.SUCCESS),
    "auth.token_invalid": (SecurityEventType.AUTH_TOKEN_INVALID, AuditOutcome.DENIED),
    "auth.token_expired": (SecurityEventType.AUTH_TOKEN_EXPIRED, AuditOutcome.DENIED),
    "auth.token_revoked": (SecurityEventType.AUTH_TOKEN_REVOKED, AuditOutcome.DENIED),
    "auth.service_authenticated": (
        SecurityEventType.AUTH_SERVICE_AUTHENTICATED,
        AuditOutcome.SUCCESS,
    ),
    "auth.api_key_used": (SecurityEventType.AUTH_API_KEY_USED, AuditOutcome.SUCCESS),
    # authorization changes
    "role.created": (SecurityEventType.ROLE_ASSIGNED, AuditOutcome.SUCCESS),
    "role.deleted": (SecurityEventType.ROLE_REVOKED, AuditOutcome.SUCCESS),
    "role.permissions_changed": (SecurityEventType.PERMISSION_CHANGED, AuditOutcome.SUCCESS),
    "permission.changed": (SecurityEventType.PERMISSION_CHANGED, AuditOutcome.SUCCESS),
    "resource.owner_changed": (SecurityEventType.PERMISSION_CHANGED, AuditOutcome.SUCCESS),
    "resource.grant_created": (SecurityEventType.RESOURCE_GRANT_CREATED, AuditOutcome.SUCCESS),
    "resource.grant_revoked": (SecurityEventType.RESOURCE_GRANT_REVOKED, AuditOutcome.SUCCESS),
    "policy.changed": (SecurityEventType.AUTHZ_POLICY_CHANGED, AuditOutcome.SUCCESS),
    # credentials and privileges
    "credential.created": (SecurityEventType.CREDENTIAL_CREATED, AuditOutcome.SUCCESS),
    "credential.revoked": (SecurityEventType.CREDENTIAL_REVOKED, AuditOutcome.SUCCESS),
    "credential.rotated": (SecurityEventType.CREDENTIAL_ROTATED, AuditOutcome.SUCCESS),
    "privilege.issued": (SecurityEventType.PRIVILEGE_ISSUED, AuditOutcome.SUCCESS),
    "privilege.used": (SecurityEventType.PRIVILEGE_USED, AuditOutcome.SUCCESS),
    "privilege.expired": (SecurityEventType.PRIVILEGE_EXPIRED, AuditOutcome.SUCCESS),
    # isolation and configuration
    "cross_tenant.denied": (SecurityEventType.CROSS_TENANT_ACCESS_REJECTED, AuditOutcome.DENIED),
    "security.configuration_changed": (
        SecurityEventType.SECURITY_CONFIGURATION_CHANGED,
        AuditOutcome.SUCCESS,
    ),
}


class AuditControlPlaneAudit:
    """Serve the control plane's audit seats from one object.

    `jdlib.control` (tenant lifecycle), its authentication helpers and its role
    administration all announce their transitions through ``PlatformAudit``, and
    the same object is used as the ``PrivilegeAudit`` seat. Implementing both here
    means wiring the audit trail is one constructor argument, with no edit to the
    code that performs the transitions.

    An action nobody has mapped does **not** raise — an unmapped string must never
    break a lifecycle transition that already happened — and it does not get
    guessed into a category either: it is skipped, with the mapping table as the
    contract that a test keeps complete.
    """

    def __init__(self, sink: SecurityEventSink) -> None:
        self._sink = sink
        self._privileges = AuditPrivilegeAudit(
            sink, extra_metadata={"control_action": "privilege.issued"}
        )

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: object | None = None,
        actor_type: str | None = None,
    ) -> None:
        mapped = CONTROL_ACTION_EVENTS.get(action)
        if mapped is None:
            return
        event_type, outcome = mapped
        payload: dict[str, object] = {"control_action": action}
        if metadata:
            payload.update(metadata)
        await self._sink.emit(
            SecurityAuditEvent(
                event_type=event_type,
                outcome=outcome,
                action=action,
                source=AuditSource.API if actor_id is not None else AuditSource.SYSTEM,
                tenant_id=tenant_id,
                principal_id=actor_id,
                principal_kind=actor_type,
                resource_type=_resource_of(action),
                metadata=payload,
            )
        )

    async def record_privilege(
        self,
        *,
        kind: PrivilegeKind,
        capability: str | None,
        justification: str | None,
        actor: Principal,
        tenant_id: uuid.UUID,
    ) -> None:
        await self._privileges.record_privilege(
            kind=kind,
            capability=capability,
            justification=justification,
            actor=actor,
            tenant_id=tenant_id,
        )


def _resource_of(action: str) -> str:
    """The object an action concerns, from its own naming convention."""
    return action.split(".", 1)[0] or "control"


__all__ = [
    "CONTROL_ACTION_EVENTS",
    "AuditControlPlaneAudit",
    "AuditPrivilegeAudit",
    "AuditRawSqlAuditor",
    "statement_kind",
]