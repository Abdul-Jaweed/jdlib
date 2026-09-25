"""The bridge's mapping, checked without an engine.

The policy files are written against these names, so this mapping is the contract between the two
halves: `resource_for` decides the Cerbos resource kind and id, `query_for` decides what the engine
is told about the tenant. The tenant it is told about is the *context's* -- which is what makes
"ask about another tenant's scope" unexpressible from a route rather than merely denied.
"""

from __future__ import annotations

import uuid

from examples.enterprise.app.security.authorization import query_for, resource_for
from jdlib.authz.scopes import ResourceRef, ScopeRef
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy, ScopeType

TENANT = uuid.UUID("00000000-0000-0000-0000-00000000000a")
PRINCIPAL_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _context(
    *, tenant_id: uuid.UUID = TENANT, principal_tenant: uuid.UUID | None = None
) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(
            kind=PrincipalKind.USER, id=PRINCIPAL_ID, tenant_id=principal_tenant or tenant_id
        ),
        request_id="req-1",
        correlation_id="corr-1",
    )


def test_a_scope_target_maps_to_the_scope_kind_and_the_scope_name() -> None:
    assert resource_for(ScopeRef(type=ScopeType.TENANT, id=None)) == ("scope", "tenant")
    assert resource_for(ScopeRef(type=ScopeType.TEAM, id=TENANT)) == ("scope", "team")


def test_a_resource_target_keeps_its_own_kind_and_id() -> None:
    invoice = uuid.uuid4()
    assert resource_for(ResourceRef(resource_type="invoice", resource_id=invoice)) == (
        "invoice",
        str(invoice),
    )


def test_the_query_asks_about_the_declared_permission_and_the_contexts_tenant() -> None:
    query = query_for(
        "tenant:read",
        ScopeRef(type=ScopeType.TENANT, id=None),
        context=_context(),
        roles=frozenset({"admin"}),
    )
    assert query.actions == ("tenant:read",)
    assert query.roles == frozenset({"admin"})
    assert query.resource_kind == "scope"
    assert query.resource_id == "tenant"
    assert query.tenant_id == TENANT
    assert query.attributes["tenantId"] == str(TENANT)
    assert query.principal_attributes["tenantId"] == str(TENANT)
    assert query.principal_id == str(PRINCIPAL_ID)
    assert query.request_id == "req-1"


def test_a_scope_target_carries_its_own_id_when_it_has_one() -> None:
    scope_id = uuid.uuid4()
    query = query_for(
        "tenant:read",
        ScopeRef(type=ScopeType.TEAM, id=scope_id),
        context=_context(),
        roles=frozenset(),
    )
    assert query.attributes["scopeId"] == str(scope_id)


def test_the_resource_tenant_is_the_contexts_even_when_the_principal_names_another() -> None:
    """The cross-tenant case at the only place a route could express it.

    A principal whose own record names another tenant still produces a query about *this* context's
    tenant: a route has no argument for a tenant, so the mismatch is caught by the policy's own rule
    rather than by the caller's restraint.
    """
    query = query_for(
        "tenant:read",
        ScopeRef(type=ScopeType.TENANT, id=None),
        context=_context(principal_tenant=uuid.uuid4()),
        roles=frozenset({"admin"}),
    )
    assert query.tenant_id == TENANT
    assert query.attributes["tenantId"] == str(TENANT)
