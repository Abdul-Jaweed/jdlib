"""Emitters: turning security decisions into audit events (directive §4).

The enforcement point already exposes an observer seam (``on_decision``), so
audit is wired in without the authorization path knowing anything about storage:

.. code-block:: python

    pep = AuthorizationPEP(
        pdp=cerbos,
        on_decision=authorization_audit_observer(TransactionAuditSink(session)),
    )

Sink semantics, stated explicitly because audit availability is a security
decision (directive §24):

* :class:`TransactionAuditSink` writes through the caller's session, so the
  audit row commits with the operation it describes and a failure to write
  fails the operation — **fail closed**, and the reason this project uses it,
* :class:`NullSecurityEventSink` drops events. It exists for tests and for
  deployments that have not configured audit storage; it is never the default
  of a sink-taking API, and choosing it is a deliberate, documented gap,
* a sink that raises propagates to the caller. Nothing in this module swallows
  an audit failure: silent audit loss is worse than a visible failure.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Protocol, runtime_checkable

from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery

DecisionObserver = Callable[[AuthorizationQuery, AuthorizationDecision], Awaitable[None]]


@runtime_checkable
class SecurityEventSink(Protocol):
    """Where security events go."""

    async def emit(self, event: SecurityAuditEvent) -> None: ...


class NullSecurityEventSink:
    """Drop every event.

    Documented no-op: use it in tests, or when a deployment has deliberately
    decided not to retain audit records. It is never selected implicitly.
    """

    async def emit(self, event: SecurityAuditEvent) -> None:
        return None


class TransactionAuditSink:
    """Persist events in the caller's transaction.

    An audit row is written with the operation it describes: if the operation
    rolls back, so does its audit row, and if the audit write fails the operation
    fails. That is the fail-closed choice — an operation whose audit trail cannot
    be recorded is an operation whose evidence does not exist.
    """

    def __init__(self, session: object) -> None:
        self._session = session

    async def emit(self, event: SecurityAuditEvent) -> None:
        # Imported here because `jdlib.models.audit_recorder` imports this
        # package; a module-level import would close a cycle.
        from jdlib.models.audit_recorder import TenantAuditRecorder

        # The recorder's async entry point, not its synchronous one: this sink runs
        # in an async transaction, and the sync path cannot stage anything on a
        # session whose add() is a coroutine - it would drop the event, silently,
        # which is the one failure an audit trail must never have.
        await TenantAuditRecorder(self._session).arecord_security(event)


def authorization_audit_event(
    query: AuthorizationQuery,
    decision: AuthorizationDecision,
    *,
    source: AuditSource = AuditSource.API,
) -> SecurityAuditEvent:
    """Describe an authorization decision as an audit event.

    A degraded decision is recorded as ``AUTHZ_PDP_ERROR``/``ERROR``: it is a
    denial (never an allow) that must be diagnosable as an engine problem rather
    than mistaken for a policy verdict. Policy identifiers and versions are
    deliberately **not** copied into metadata — they are internal detail, and the
    decision's own ``safe_metadata()`` is the contract for anything that leaves
    the process.
    """
    if decision.allowed:
        event_type, outcome = SecurityEventType.AUTHZ_ALLOW, AuditOutcome.SUCCESS
    elif decision.degraded:
        event_type, outcome = SecurityEventType.AUTHZ_PDP_ERROR, AuditOutcome.ERROR
    else:
        event_type, outcome = SecurityEventType.AUTHZ_DENY, AuditOutcome.DENIED

    metadata: dict[str, object] = {
        "decision": str(decision.safe_metadata().get("decision", "")),
        "reason": decision.reason,
        "denied_actions": list(decision.denied_actions),
    }
    principal_uuid = _as_uuid(query.principal_id)
    if principal_uuid is None:
        # The audit table keys actors by UUID; a non-UUID principal (such as a
        # federated subject) is preserved by reference rather than dropped.
        metadata["principal_ref"] = query.principal_id

    return SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        action=",".join(query.actions),
        source=source,
        tenant_id=query.tenant_id,
        principal_id=principal_uuid,
        resource_type=query.resource_kind,
        resource_id=query.resource_id,
        request_id=query.request_id,
        metadata=metadata,
    )


def authorization_audit_observer(
    sink: SecurityEventSink,
    *,
    source: AuditSource = AuditSource.API,
) -> DecisionObserver:
    """Build the observer that feeds an authorization sink."""

    async def observe(query: AuthorizationQuery, decision: AuthorizationDecision) -> None:
        await sink.emit(authorization_audit_event(query, decision, source=source))

    return observe


def _as_uuid(value: str | None) -> uuid.UUID | None:
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


__all__ = [
    "DecisionObserver",
    "NullSecurityEventSink",
    "SecurityEventSink",
    "TransactionAuditSink",
    "authorization_audit_event",
    "authorization_audit_observer",
]
