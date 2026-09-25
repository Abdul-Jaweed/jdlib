"""The MCP security boundary: the HTTP edge's own chain, run for a second surface (directive §19).

The directive is explicit that FastMCP is *another external application surface* that must not
bypass the library, and that every MCP request establishes an authoritative security context from
the approved mechanism — never from a `user_id`, a `tenant_id`, a `roles` list or an
`authenticated=true` a client sent.

The way to be sure of that is to make the boundary *be* the chain the HTTP edge runs, given the
same collaborators: the same `PrincipalProvider`, the same `ResolverChain`, the same
`ContextFactory`. These tests assert the composition by identity, and assert the two refusals that
come before any work: no principal, and no tenant.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext, TenantRef
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import AuthenticationError, TenantNotFound
from jdlib.integrations.mcp.boundary import McpSecurityBoundary
from jdlib.tenancy.resolution import RequestInfo

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
PRINCIPAL_ID = uuid.UUID("99999999-9999-9999-9999-999999999999")


class _PrincipalProvider:
    """The seam the middleware takes: a request in, a principal or nothing out."""

    def __init__(self, principal: Principal | None) -> None:
        self.principal = principal
        self.seen: list[RequestInfo] = []

    async def __call__(self, request: RequestInfo) -> Principal | None:
        self.seen.append(request)
        return self.principal


class _Chain:
    def __init__(self, tenant_id: uuid.UUID | None = TENANT_ID) -> None:
        self.tenant_id = tenant_id
        self.seen: list[tuple[RequestInfo, Principal | None]] = []

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> Any:
        self.seen.append((request, principal))
        if self.tenant_id is None:
            return None
        return TenantRef(id=self.tenant_id, slug="acme")


class _Factory:
    """The factory's contract: principal + tenant + ids in, a SecurityContext out."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def for_principal(
        self,
        principal: Principal,
        tenant_ref: Any,
        *,
        request_id: str,
        correlation_id: str | None,
        trace_id: str | None,
    ) -> TenantContext:
        self.calls.append(
            {
                "principal": principal,
                "tenant_ref": tenant_ref,
                "request_id": request_id,
                "correlation_id": correlation_id,
                "trace_id": trace_id,
            }
        )
        tenant = TenantContext(
            tenant_id=tenant_ref.id,
            tenant_slug=tenant_ref.slug,
            strategy=PlacementStrategy.SHARED,
            principal=principal,
            request_id=request_id,
            correlation_id=correlation_id or request_id,
            trace_id=trace_id,
        )
        return tenant


def _principal() -> Principal:
    return Principal(kind=PrincipalKind.USER, id=PRINCIPAL_ID)


def _request(**headers: str) -> RequestInfo:
    return RequestInfo(
        headers={key.replace("_", "-"): value for key, value in headers.items()},
        query={},
        path="mcp://tool/graph_get",
        host="mcp",
    )


def _boundary(
    *,
    provider: _PrincipalProvider | None = None,
    chain: _Chain | None = None,
    factory: _Factory | None = None,
) -> tuple[McpSecurityBoundary, _PrincipalProvider, _Chain, _Factory]:
    the_provider = provider or _PrincipalProvider(_principal())
    the_chain = chain or _Chain()
    the_factory = factory or _Factory()
    boundary = McpSecurityBoundary(
        principal_provider=the_provider, chain=the_chain, factory=the_factory
    )
    return boundary, the_provider, the_chain, the_factory


async def test_a_credential_becomes_the_context_the_chain_resolved() -> None:
    boundary, provider, chain, factory = _boundary()
    context = await boundary.establish(request=_request(authorization="Bearer fixture-marker"))
    assert context.tenant is not None
    assert str(context.tenant.tenant_id) == str(TENANT_ID)
    assert context.principal.id == PRINCIPAL_ID
    assert len(provider.seen) == 1
    assert len(chain.seen) == 1
    assert len(factory.calls) == 1


async def test_the_boundary_is_the_http_edges_own_chain_by_identity() -> None:
    """The composition is the assertion: the same collaborators, not lookalikes."""
    provider = _PrincipalProvider(_principal())
    chain = _Chain()
    factory = _Factory()
    boundary = McpSecurityBoundary(
        principal_provider=provider, chain=chain, factory=factory
    )
    await boundary.establish(request=_request(authorization="Bearer fixture-marker"))
    assert chain.seen[0][1] is provider.principal
    assert factory.calls[0]["principal"] is provider.principal
    assert factory.calls[0]["tenant_ref"].id == chain.tenant_id


async def test_no_credential_is_an_authentication_failure_and_stops_there() -> None:
    boundary, _, chain, factory = _boundary(provider=_PrincipalProvider(None))
    with pytest.raises(AuthenticationError):
        await boundary.establish(request=_request())
    assert chain.seen == []
    assert factory.calls == []


async def test_an_unresolvable_tenant_stops_before_the_context_is_built() -> None:
    boundary, _, _, factory = _boundary(chain=_Chain(tenant_id=None))
    with pytest.raises(TenantNotFound):
        await boundary.establish(request=_request(authorization="Bearer fixture-marker"))
    assert factory.calls == []


async def test_a_request_cannot_name_its_own_tenant_or_actor() -> None:
    """The forged values are carried, ignored, and absent from the context that is built."""
    boundary, _, _, factory = _boundary()
    context = await boundary.establish(
        request=RequestInfo(
            headers={
                "authorization": "Bearer fixture-marker",
                "x-tenant-id": "22222222-2222-2222-2222-222222222222",
                "x-user-id": "11111111-1111-1111-1111-111111111111",
            },
            query={"tenant_id": "22222222-2222-2222-2222-222222222222", "roles": "admin"},
            path="mcp://tool/graph_get",
            host="mcp",
        )
    )
    assert str(context.tenant.tenant_id) == str(TENANT_ID)
    assert context.principal.id == PRINCIPAL_ID
    assert "22222222-2222-2222-2222-222222222222" not in str(factory.calls[0]["tenant_ref"].id)
    assert context.principal.id != uuid.UUID("11111111-1111-1111-1111-111111111111")


async def test_the_request_id_is_minted_and_the_callers_correlation_id_is_honoured() -> None:
    """The middleware's own policy, reused rather than re-decided at a second edge."""
    boundary, _, _, factory = _boundary()
    context = await boundary.establish(
        request=_request(authorization="Bearer fixture-marker", x_correlation_id="corr-from-caller")
    )
    call = factory.calls[0]
    assert call["request_id"]
    assert call["request_id"] != "corr-from-caller"
    assert call["correlation_id"] == "corr-from-caller"
    assert context.request_id == call["request_id"]


async def test_a_malformed_trace_context_contributes_nothing() -> None:
    """The library's own W3C parser is strict: an unreadable header yields no trace id at all,
    rather than a guessed one — and it does not fail the request either."""
    boundary, _, chain, factory = _boundary()
    await boundary.establish(
        request=_request(authorization="Bearer fixture-marker", traceparent="not-a-traceparent")
    )
    assert factory.calls[0]["trace_id"] is None
    assert len(chain.seen) == 1


async def test_a_well_formed_trace_context_is_carried_into_the_context() -> None:
    boundary, _, _, factory = _boundary()
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    await boundary.establish(
        request=_request(
            authorization="Bearer fixture-marker",
            traceparent=f"00-{trace_id}-00f067aa0ba902b7-01",
        )
    )
    assert factory.calls[0]["trace_id"] == trace_id
