"""The MCP surface, without a lab: the inventory, the schemas, and the enforcer's tenant source.

What this file measures is what a *declaration* can be checked for before anything runs:

* the inventory is the declarations — no tool exists that is not declared, and every declared tool
  carries the capability its authorization is asked against (the registry refuses one that does not,
  so a tool added without a capability fails here rather than in production);
* no schema has a slot for an identity or a statement — the two classes of argument the library's
  own tools exist to make impossible, checked by walking the properties rather than by reading them;
* the MCP boundary is built from the *HTTP path's own collaborators*, asserted by identity: a
  surface that built its own authenticator or enforcer would be a second chain, and "the same
  security model on both surfaces" would stop being true without any test noticing;
* the inventory is the declarations — no tool exists that is not declared, and every declared
  MCP, the tenant context under HTTP — and fails closed when neither is bound.

The last one is a regression test for a defect found by writing this slice: the bridge read
`current_tenant()`, which the MCP boundary never binds, so every MCP call would have been refused
with a refusal that looked like a denial.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from dataclasses import fields
from types import SimpleNamespace
from typing import Any, cast

import pytest

from examples.enterprise.app.main import Collaborators
from examples.enterprise.app.mcp.asgi import build_mcp_surface
from examples.enterprise.app.mcp.server import McpSurface, build_example_mcp_server
from examples.enterprise.app.mcp.tools import READ_CAPABILITY, WRITE_CAPABILITY, resource_tools
from examples.enterprise.app.security.authorization import CerbosEnforcer
from jdlib.authz.scopes import ScopeRef
from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
from jdlib.control.enums import PlacementStrategy, ScopeType
from jdlib.errors import MissingTenantContext
from jdlib.integrations.mcp.tools import McpToolRegistry
from jdlib.security.context import AuthMethod, SecurityContext, security_context_scope
from jdlib.tenancy.resolution import RequestInfo

pytest.importorskip("fastmcp", reason="the mcp extra is not installed")

TENANT_ID = uuid.UUID("99999999-9999-9999-9999-999999999999")

#: The argument names no tool of this surface may accept: an identity (the call would be able to
#: name a tenant or a user) or a statement (the call would be able to name a query).
FORBIDDEN_PROPERTIES = frozenset(
    {
        "tenant",
        "tenant_id",
        "tenantId",
        "user",
        "user_id",
        "principal",
        "principal_id",
        "roles",
        "query",
        "statement",
        "cypher",
        "sql",
    }
)


def _tenant_context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="surface",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=TENANT_ID),
        request_id="req-surface",
        correlation_id="corr-surface",
    )


def _request() -> RequestInfo:
    return RequestInfo(
        headers={"authorization": "Bearer surface-marker"},
        query={},
        path="mcp://tool/resource_get",
        host="mcp",
    )


class _Pep:
    """A policy engine that answers allow and records the questions."""

    def __init__(self) -> None:
        self.queries: list[Any] = []

    async def require(self, query: Any) -> Any:
        self.queries.append(query)
        return SimpleNamespace(reason="allowed by the stub")


class _Roles:
    def __init__(self, roles: frozenset[str] = frozenset({"support"})) -> None:
        self._roles = roles
        self.asked: list[tuple[Principal, uuid.UUID]] = []

    async def names_for(self, principal: Principal, tenant_id: uuid.UUID) -> frozenset[str]:
        self.asked.append((principal, tenant_id))
        return self._roles


def _collaborators_with_doubles() -> Collaborators:
    """A `Collaborators` whose every field is its own object, so identity is checkable."""
    values = {field.name: cast(Any, object()) for field in fields(Collaborators)}
    return Collaborators(**values)


def _registry() -> McpToolRegistry:
    registry = McpToolRegistry()
    service = cast(Any, object())
    for tool in resource_tools(service):
        registry.register(tool)
    return registry


def test_the_inventory_is_the_declarations() -> None:
    names = [tool.name for tool in _registry().tools()]
    assert names == ["resource_archive", "resource_get", "resource_list"]


def test_every_tool_declares_the_capability_its_authorization_asks_for() -> None:
    capabilities = {tool.name: tool.capability for tool in _registry().tools()}
    assert capabilities == {
        "resource_get": READ_CAPABILITY,
        "resource_list": READ_CAPABILITY,
        "resource_archive": WRITE_CAPABILITY,
    }


def test_no_schema_has_a_slot_for_an_identity_or_a_statement() -> None:
    """The check that makes the claim structural rather than a reading of the file."""
    for tool in _registry().tools():
        declared = cast(Mapping[str, Any], tool.input_schema.get("properties") or {})
        properties = set(declared)
        assert not properties & FORBIDDEN_PROPERTIES, tool.name
        assert tool.input_schema.get("additionalProperties") is False, tool.name


def test_the_surface_reuses_the_http_paths_collaborators() -> None:
    collaborators = _collaborators_with_doubles()
    surface = build_mcp_surface(collaborators)
    assert surface.resources is collaborators.resources
    assert surface.principal_provider is collaborators.principal_provider
    assert surface.chain is collaborators.chain
    assert surface.factory is collaborators.factory
    assert surface.enforcer is collaborators.enforcer
    assert surface.sink is collaborators.security_sink
    assert surface.graph_plane is collaborators.graph


def test_the_server_registers_exactly_the_declared_tools() -> None:
    surface = McpSurface(
        resources=cast(Any, object()),
        principal_provider=cast(Any, object()),
        chain=cast(Any, object()),
        factory=cast(Any, object()),
        enforcer=cast(Any, object()),
        sink=cast(Any, object()),
        graph_plane=None,
    )
    server = build_example_mcp_server(surface, tracer=None)

    async def _listed() -> list[str]:
        return [tool.name for tool in await server.list_tools()]

    assert asyncio.run(_listed()) == ["resource_archive", "resource_get", "resource_list"]


def test_the_enforcer_reads_the_tenant_the_mcp_invocation_binds() -> None:
    """The MCP invocation's own shape: a security context *and* the tenant context it carries.

    This is what makes one enforcer serve both surfaces. It is asserted here rather than assumed
    from the library's source, because the assumption is exactly what a reader of the MCP module
    would otherwise get wrong.
    """
    pep, roles = _Pep(), _Roles()
    enforcer = CerbosEnforcer(pep=cast(Any, pep), roles=cast(Any, roles))
    context = SecurityContext.from_tenant_context(
        _tenant_context(), auth_method=AuthMethod.API_KEY
    )
    target = ScopeRef(type=ScopeType.TENANT, id=None)

    with security_context_scope(context), context_scope(context.require_tenant()):
        asyncio.run(enforcer.require("tenant:read", target, session=None))

    assert [query.tenant_id for query in pep.queries] == [TENANT_ID]
    assert [tenant_id for _principal, tenant_id in roles.asked] == [TENANT_ID]


def test_the_enforcer_reads_the_tenant_context_the_http_path_binds() -> None:
    """The HTTP path's shape: the middleware binds a tenant context and no security context."""
    pep, roles = _Pep(), _Roles()
    enforcer = CerbosEnforcer(pep=cast(Any, pep), roles=cast(Any, roles))
    target = ScopeRef(type=ScopeType.TENANT, id=None)

    with context_scope(_tenant_context()):
        asyncio.run(enforcer.require("tenant:read", target, session=None))

    assert [query.tenant_id for query in pep.queries] == [TENANT_ID]


def test_the_enforcer_fails_closed_with_neither_context_bound() -> None:
    pep, roles = _Pep(), _Roles()
    enforcer = CerbosEnforcer(pep=cast(Any, pep), roles=cast(Any, roles))
    target = ScopeRef(type=ScopeType.TENANT, id=None)

    with pytest.raises(MissingTenantContext):
        asyncio.run(enforcer.require("tenant:read", target, session=None))
    assert pep.queries == []
