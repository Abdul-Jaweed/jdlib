"""The MCP surface against the real chain: credential, tenant, policy, service, graph.

Bring the lab up and run this file:

    export JDLIB_ENTERPRISE_POSTGRES_PASSWORD=<owner password>      # any local value
    export JDLIB_ENTERPRISE_APP_PASSWORD=<runtime password>         # any local value
    export JDLIB_ENTERPRISE_GRAPH_PASSWORD=<graph password>         # any local value
    docker compose -f examples/enterprise/docker/docker-compose.yml up -d
    export JDLIB_EXAMPLE_LIVE_DSN="postgresql://jdlib_app:***@127.0.0.1:45432/jdlib_enterprise"
    export JDLIB_EXAMPLE_LIVE_MIGRATION_DSN="postgresql://jdlib:***@127.0.0.1:45432/jdlib_enterprise"
    export JDLIB_EXAMPLE_CERBOS_ENDPOINT=http://127.0.0.1:4592
    export JDLIB_EXAMPLE_GRAPH_URI=bolt://127.0.0.1:7688
    pytest examples/enterprise/tests/test_mcp_live.py -q -W error

This file drives the **whole chain** through the MCP entry point, and the credential is a real one:
a bearer API key, minted here, hashed into the control plane, and presented in a request — the
library's own authenticator verifies it, the resolver chain decides the tenant, the context factory
checks the service account is active and entitled, the tool's capability is put to the **live policy
engine**, and only then does the handler reach the service and the database. Nothing in this file
authenticates anything itself, which is the point: the surface reuses the HTTP path's collaborators,
and a chain that worked on one surface and not the other would show up here as a refusal.

What each test measures, and where else it could be measured:

* an allowed call **runs and returns the row** — the positive path, because a suite of refusals
  cannot see a handler that never returned anything;
* a denied call is refused **and the row is unchanged** — non-execution measured at the data rather
  than at a call counter, which is the only place it cannot be faked;
* an undeclared argument is refused before the handler runs (the schema the library advertises is
  the one it enforces);
* the tenant is the *credential's*: the same tool, called with another tenant's resource id, returns
  nothing — there is no argument that could have named it;
* the graph tools reach the real Neo4j through a runner that opens the calling tenant's client.

The role the caller holds is `support`, which the policy set allows to read and refuses to write —
so the denial above is a policy decision, not a missing role.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from examples.enterprise.app.dataplane import shared_strategy
from examples.enterprise.app.dsn import async_dsn
from examples.enterprise.app.graph import GraphPlane, graph_config
from examples.enterprise.app.main import build_collaborators
from examples.enterprise.app.mcp.server import McpSurface, build_example_mcp_server
from jdlib.authn.apikey import hash_api_key_secret
from jdlib.config import TenancyConfig
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import ApiKey, Role, RoleBinding, RolePermission, ServiceAccount
from jdlib.control.registry import TenantRegistry
from jdlib.migrations.runner import MigrationRunner
from jdlib.security.context import AuthMethod, SecurityContext
from jdlib.tenancy.resolution import RequestInfo

RUNTIME_DSN = os.environ.get("JDLIB_EXAMPLE_LIVE_DSN", "")
MIGRATION_DSN = os.environ.get("JDLIB_EXAMPLE_LIVE_MIGRATION_DSN", "")
CERBOS_ENDPOINT = os.environ.get("JDLIB_EXAMPLE_CERBOS_ENDPOINT", "")
GRAPH_URI = os.environ.get("JDLIB_EXAMPLE_GRAPH_URI", "")

pytestmark = pytest.mark.skipif(
    not (RUNTIME_DSN and MIGRATION_DSN and CERBOS_ENDPOINT),
    reason=(
        "the MCP lab is not running: docker compose -f "
        "examples/enterprise/docker/docker-compose.yml up -d, then export "
        "JDLIB_EXAMPLE_LIVE_DSN, JDLIB_EXAMPLE_LIVE_MIGRATION_DSN and "
        "JDLIB_EXAMPLE_CERBOS_ENDPOINT (see the module docstring)"
    ),
)


@dataclass(frozen=True)
class Lab:
    """What the module fixture provisions: a tenant, a caller, and the caller's key."""

    tenant_id: uuid.UUID
    principal_id: uuid.UUID
    token: str

    def context(self) -> TenantContext:
        """The tenant context the *application* uses for this caller."""
        return TenantContext(
            tenant_id=self.tenant_id,
            tenant_slug=f"mcp-{str(self.tenant_id)[:8]}",
            strategy=PlacementStrategy.SHARED,
            principal=Principal(
                kind=PrincipalKind.SERVICE_ACCOUNT, id=self.principal_id, tenant_id=self.tenant_id
            ),
            request_id=f"req-{uuid.uuid4().hex[:8]}",
            correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
        )

    def request(self, path: str = "mcp://tool/resource_get") -> RequestInfo:
        """The request the boundary begins with: the key, and nothing else that identifies."""
        return RequestInfo(
            headers={"authorization": f"Bearer {self.token}"},
            query={},
            path=path,
            host="mcp",
        )


def _mint_key(prefix: str) -> tuple[str, str, str]:
    """A key in the format the library parses: `prefix.salt.secret` -> (token, prefix, secret)."""
    salt = uuid.uuid4().hex[:8]
    secret = secrets.token_urlsafe(32)
    return f"{prefix}.{salt}.{secret}", f"{prefix}.{salt}", secret


async def _provision() -> Lab:
    """Provision a tenant and a caller holding `support`, with a real key in the control plane."""
    config = TenancyConfig()  # type: ignore[call-arg]  # env-filled
    engine = create_async_engine(async_dsn(MIGRATION_DSN))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        registry = TenantRegistry(
            session_factory=sessions,
            strategies={PlacementStrategy.SHARED: shared_strategy(engine)},
            runner=MigrationRunner(MIGRATION_DSN),
            audit=DatabaseAuditSink(sessions),
        )
        tenant = await registry.create(
            slug=f"mcp-{uuid.uuid4().hex[:8]}",
            name="MCP Lab",
            strategy=PlacementStrategy.SHARED,
            target_handle="default",
        )
        await registry.provision(tenant.id)

        account_id = uuid.uuid4()
        role_id = uuid.uuid4()
        token, key_prefix, secret = _mint_key(config.api_keys.prefix)
        async with sessions() as session:
            session.add(
                ServiceAccount(
                    tenant_id=tenant.id,
                    id=account_id,
                    name=f"mcp-{account_id.hex[:6]}",
                    status="active",
                )
            )
            # `support` reads and does not write, per `config/cerbos/policies/resource.yaml`.
            session.add(Role(tenant_id=tenant.id, id=role_id, name="support"))
            # Flushed before the rows that point at them: the composite foreign keys are declared
            # in the schema, not as ORM relationships, so the unit of work has no dependency to sort
            # by and would insert the referrers first.
            await session.flush()
            session.add(
                RolePermission(
                    tenant_id=tenant.id, role_id=role_id, permission_code="resource:read"
                )
            )
            session.add(
                RoleBinding(
                    tenant_id=tenant.id,
                    id=uuid.uuid4(),
                    role_id=role_id,
                    principal_type="service_account",
                    principal_id=account_id,
                    scope_type="tenant",
                )
            )
            session.add(
                ApiKey(
                    tenant_id=tenant.id,
                    id=uuid.uuid4(),
                    service_account_id=account_id,
                    key_prefix=key_prefix,
                    key_hash=hash_api_key_secret(secret),
                    status="active",
                )
            )
            await session.commit()
        return Lab(tenant_id=tenant.id, principal_id=account_id, token=token)
    finally:
        await engine.dispose()


@pytest.fixture(scope="module")
def lab() -> Iterator[Lab]:
    """The application's environment, pointed at the lab, plus the caller it provisions.

    The environment variables the application reads are set here and restored afterwards: the live
    file drives `build_collaborators` exactly as `create_app` does, so what it builds is the
    application's own composition rather than a test-shaped one.
    """
    previous = {
        key: os.environ.get(key)
        for key in ("JDLIB_CONTROL_DSN", "JDLIB_EXAMPLE_GRAPH_URI", "JDLIB_CONTEXT__SIGNING_KEY")
    }
    os.environ["JDLIB_CONTROL_DSN"] = RUNTIME_DSN
    os.environ.setdefault("JDLIB_CONTEXT__SIGNING_KEY", secrets.token_hex(32))
    if GRAPH_URI:
        os.environ["JDLIB_EXAMPLE_GRAPH_URI"] = GRAPH_URI
    try:
        yield asyncio.run(_provision())
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@asynccontextmanager
async def _application(lab: Lab) -> AsyncIterator[Any]:
    """The application's collaborators and its MCP server, in *this* event loop.

    Built per test and disposed at the end of it: an engine created in one loop cannot be closed in
    another, and an engine that is never disposed reports itself as an unclosed connection — which
    the gate's `-W error` turns into a failure of whichever test happens to run last. One loop, one
    composition, one teardown.
    """
    collaborators = build_collaborators()
    surface = McpSurface(
        resources=collaborators.resources,
        principal_provider=collaborators.principal_provider,
        chain=collaborators.chain,
        factory=collaborators.factory,
        enforcer=collaborators.enforcer,
        sink=collaborators.security_sink,
        graph_plane=collaborators.graph,
    )
    try:
        yield SimpleNamespace(
            collaborators=collaborators,
            server=build_example_mcp_server(surface, request_source=lab.request),
        )
    finally:
        await collaborators.aclose()


def _create(lab: Lab, *, name: str) -> uuid.UUID:
    """One resource, written through the service the tools call.

    In its own event loop, and therefore its own task: a tenant context bound by the service's own
    work would still be bound for the rest of the task, and the tool call below would then find a
    tenant the *boundary* never established. That is the difference between measuring the boundary
    and measuring whatever ran before it.
    """

    async def _body() -> uuid.UUID:
        async with _application(lab) as app:
            resource = await app.collaborators.resources.create(
                lab.context(), name=name, kind="dataset"
            )
            return uuid.UUID(str(resource.id))

    return asyncio.run(_body())


def _call(lab: Lab, tool: str, arguments: dict[str, object]) -> Any:
    """One tool call through the server, with the lab's own credential."""

    async def _body() -> Any:
        async with _application(lab) as app:
            return await _call_in(app, tool, arguments)

    return asyncio.run(_body())


async def _call_in(app: Any, tool: str, arguments: dict[str, object]) -> Any:
    """One tool call through the server, inside an application already built."""
    from fastmcp import Client

    async with Client(app.server) as client:
        return await client.call_tool(tool, arguments)


def test_an_allowed_call_runs_and_returns_the_row(lab: Lab) -> None:
    resource_id = _create(lab, name=f"allowed-{uuid.uuid4().hex[:6]}")
    result = _call(lab, "resource_get", {"resource_id": str(resource_id)})
    assert result.data["id"] == str(resource_id)
    assert result.data["status"] == "active"


def test_a_denied_call_is_refused_and_the_row_is_unchanged(lab: Lab) -> None:
    """Non-execution measured at the data: `support` may read, and the policy refuses the write."""
    from fastmcp.exceptions import ToolError

    resource_id = _create(lab, name=f"denied-{uuid.uuid4().hex[:6]}")
    # The *reason* is asserted, not just the class: an authentication failure raises the same
    # `ToolError`, and a test that accepted either would report a denial it never got.
    with pytest.raises(ToolError, match="authorization denied"):
        _call(lab, "resource_archive", {"resource_id": str(resource_id)})

    async def _status() -> str:
        async with _application(lab) as app:
            resource = await app.collaborators.resources.require(lab.context(), resource_id)
            return str(resource.status)

    assert asyncio.run(_status()) == "active"


def test_an_undeclared_argument_is_refused_before_the_handler_runs(lab: Lab) -> None:
    """The schema the library advertises is the schema it enforces, on a live call too."""
    from fastmcp.exceptions import ToolError

    resource_id = _create(lab, name=f"extra-{uuid.uuid4().hex[:6]}")
    with pytest.raises(ToolError, match="does not declare"):
        _call(
            lab,
            "resource_get",
            {"resource_id": str(resource_id), "tenant_id": str(uuid.uuid4())},
        )


def test_the_tenant_is_the_credentials_not_an_argument(lab: Lab) -> None:
    """Another tenant's resource is not forbidden here: for this caller it does not exist."""
    other = asyncio.run(_provision())
    theirs = _create(other, name=f"theirs-{uuid.uuid4().hex[:6]}")
    assert _call(lab, "resource_get", {"resource_id": str(theirs)}).data is None


@pytest.mark.skipif(not GRAPH_URI, reason="no graph configured: export JDLIB_EXAMPLE_GRAPH_URI")
def test_the_graph_tools_reach_the_real_neo4j(lab: Lab) -> None:
    """The graph tools through the surface, over a runner that opens the caller's own client."""
    resource_id = _create(lab, name=f"graph-{uuid.uuid4().hex[:6]}")

    async def _project() -> None:
        plane = GraphPlane(graph_config(uri=GRAPH_URI, database="neo4j", username="neo4j"))
        try:
            context = SecurityContext.from_tenant_context(
                lab.context(), auth_method=AuthMethod.API_KEY
            )
            await plane.project_resource(
                context=context,
                resource_id=resource_id,
                properties={"name": "mcp-graph", "kind": "dataset", "status": "active"},
            )
        finally:
            await plane.aclose()

    asyncio.run(_project())
    assert _call(lab, "graph_get", {"label": "Resource", "node_id": str(resource_id)}).data[
        "id"
    ] is not None


def test_the_key_that_authenticated_is_the_one_in_the_control_plane(lab: Lab) -> None:
    """A negative control for the credential: a key that is not in the control plane is refused.

    Without this, every test above would also pass on a boundary that authenticated nothing.
    """
    from fastmcp.exceptions import ToolError

    forged = Lab(
        tenant_id=lab.tenant_id,
        principal_id=lab.principal_id,
        token=_mint_key("jd")[0],
    )

    resource_id = _create(lab, name=f"control-{uuid.uuid4().hex[:6]}")
    with pytest.raises(ToolError, match="no credentials presented"):
        _call(forged, "resource_get", {"resource_id": str(resource_id)})
