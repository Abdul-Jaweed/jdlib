"""The one place a statement is checked against the authenticated tenant (directive §11).

The client and the transaction both come through here. Two copies of this rule would be two
places to fix the same bug — and a transaction is exactly where a scope check gets forgotten.
"""

from __future__ import annotations

from jdlib.graph.errors import GraphTenantViolationError
from jdlib.graph.query import TENANT_PARAMETER, GraphQuery
from jdlib.security.context import SecurityContext


def require_tenant_id(context: SecurityContext) -> str:
    """The authoritative tenant for this call, or a fail-closed refusal."""
    return str(context.require_tenant().tenant_id)


def require_open_tenant(context: SecurityContext, tenant_id: str | None) -> str:
    """Refuse a context naming a tenant the caller was not opened for.

    ``tenant_id`` is the tenant a client (or transaction) was opened with; ``None`` means it was
    not bound to one, in which case only the statement's own scope is checked.
    """
    current = require_tenant_id(context)
    if tenant_id is not None and current != tenant_id:
        raise GraphTenantViolationError(
            "a graph statement must run under the tenant this client was opened for"
        )
    return current


def require_scope(
    *, query: GraphQuery, context: SecurityContext, tenant_id: str | None = None
) -> str:
    """Refuse a statement that is not scoped to the authenticated tenant.

    The tenant is returned so a caller does not resolve it twice.
    """
    current = require_open_tenant(context, tenant_id)
    if query.parameters.get(TENANT_PARAMETER) != current:
        raise GraphTenantViolationError(
            "a graph statement must be scoped to the authenticated tenant"
        )
    return current
