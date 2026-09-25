"""The one place a statement is checked against the authenticated tenant (directive §11).

The client and the transaction both come through here. Two copies of this rule would be two
places to fix the same bug — and a transaction is exactly where a scope check gets forgotten.
"""

from __future__ import annotations

from jdlib.graph.errors import GraphTenantViolationError
from jdlib.graph.query import TENANT_PARAMETER, GraphQuery
from jdlib.security.audit.emitter import SecurityEventEmitter, emit_safely
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import SecurityContext

#: What a refusal is recorded as. The vocabulary already has this event: a refused graph
#: statement that named another tenant *is* a cross-tenant access attempt, and minting a second
#: name for it would split the record an investigation searches.
REFUSAL_EVENT = SecurityEventType.CROSS_TENANT_ACCESS_REJECTED


def _record_refusal(
    emitter: SecurityEventEmitter | None, *, action: str, reason: str
) -> None:
    """Write the refusal down before it is raised.

    The event fills its actor, tenant and request ids from the ambient context — which is why the
    caller runs the statement under the context it was given. Delivery never changes the outcome:
    an audit outage is not the caller's failure, and the refusal is raised either way.
    """
    emit_safely(
        emitter,
        SecurityAuditEvent(
            event_type=REFUSAL_EVENT,
            outcome=AuditOutcome.DENIED,
            action=action,
            source=AuditSource.SERVICE,
            resource_type="graph-statement",
            metadata={"reason": reason},
        ),
    )


def require_tenant_id(context: SecurityContext) -> str:
    """The authoritative tenant for this call, or a fail-closed refusal."""
    return str(context.require_tenant().tenant_id)


def require_open_tenant(
    context: SecurityContext,
    tenant_id: str | None,
    *,
    emitter: SecurityEventEmitter | None = None,
    action: str = "graph.statement",
) -> str:
    """Refuse a context naming a tenant the caller was not opened for.

    ``tenant_id`` is the tenant a client (or transaction) was opened with; ``None`` means it was
    not bound to one, in which case only the statement's own scope is checked.
    """
    current = require_tenant_id(context)
    if tenant_id is not None and current != tenant_id:
        _record_refusal(emitter, action=action, reason="the client is open for another tenant")
        raise GraphTenantViolationError(
            "a graph statement must run under the tenant this client was opened for"
        )
    return current


def require_scope(
    *,
    query: GraphQuery,
    context: SecurityContext,
    tenant_id: str | None = None,
    emitter: SecurityEventEmitter | None = None,
    action: str = "graph.statement",
) -> str:
    """Refuse a statement that is not scoped to the authenticated tenant.

    The tenant is returned so a caller does not resolve it twice.
    """
    current = require_open_tenant(context, tenant_id, emitter=emitter, action=action)
    if query.parameters.get(TENANT_PARAMETER) != current:
        _record_refusal(emitter, action=action, reason="the statement names another tenant")
        raise GraphTenantViolationError(
            "a graph statement must be scoped to the authenticated tenant"
        )
    return current
