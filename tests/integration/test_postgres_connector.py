"""PostgreSQL connector against a real server (successor Phase 7). RED first.

This is the integration layer. The connector reuses what the library already has - the async
engine layer and its pool rules - rather than inventing an engine abstraction, and it builds
its engine per open from the RESOLVED target, never from a stored DSN: the target arrives
through section 4's hydration, which is the only thing that knows the current credential.

Two refusals are the point of the file, not incidental coverage:

* a tenant mismatch between the authorized context and the target refuses to open;
* a statement that is not a read is refused, because this connector declares reads=True,
  writes=False and a declaration nothing enforces is a comment.
"""

from __future__ import annotations

import uuid

import pytest
from testcontainers.community.postgres import PostgresContainer

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.data.connector import AuthorizationRefusedError
from jdlib.data.errors import ConnectorError, ConnectorTimeoutError
from jdlib.data.policy import ConnectionPolicy
from jdlib.data.postgres import PostgresConnector
from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import AuthMethod, SecurityContext

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture(scope="module")
def async_dsn() -> str:
    with PostgresContainer("postgres:16-alpine") as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(5432)
        yield (
            f"postgresql+asyncpg://{container.username}:{container.password}"
            f"@{host}:{port}/{container.dbname}"
        )


def _context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


def _target(dsn: str, tenant_id: uuid.UUID = TENANT_ID) -> ConnectionConfig:
    return ConnectionConfig(
        handle="db-tenant-acme",
        target=dsn,
        credential_version="1",
        tenant_id=str(tenant_id),
    )


async def test_a_live_round_trip_through_the_connector(async_dsn) -> None:
    connector = PostgresConnector(policy=ConnectionPolicy(statement_timeout=10))

    async with connector.opened(target=_target(async_dsn), context=_context()):
        rows = await connector.execute(statement="select 1 as one")

    assert rows == [{"one": 1}]
    assert connector.capabilities.reads is True
    assert connector.capabilities.writes is False


async def test_the_connector_refuses_a_tenant_mismatch(async_dsn) -> None:
    connector = PostgresConnector()

    with pytest.raises(AuthorizationRefusedError):
        await connector.open(
            target=_target(async_dsn, TENANT_ID), context=_context(OTHER_TENANT_ID)
        )


async def test_the_connector_refuses_a_statement_that_is_not_a_read(async_dsn) -> None:
    """The declared capability is enforced, not decorative."""
    connector = PostgresConnector()

    async with connector.opened(target=_target(async_dsn), context=_context()):
        for statement in ("delete from nothing", "update t set x = 1", "insert into t values (1)"):
            with pytest.raises(ConnectorError):
                await connector.execute(statement=statement)


async def test_a_slow_statement_times_out_as_a_timeout(async_dsn) -> None:
    connector = PostgresConnector(policy=ConnectionPolicy(statement_timeout=1))

    with pytest.raises(ConnectorTimeoutError):
        async with connector.opened(target=_target(async_dsn), context=_context()):
            await connector.execute(statement="select pg_sleep(5)")


async def test_health_reports_the_connection_state(async_dsn) -> None:
    connector = PostgresConnector()

    assert await connector.health() is False

    async with connector.opened(target=_target(async_dsn), context=_context()):
        assert await connector.health() is True

    assert await connector.health() is False
