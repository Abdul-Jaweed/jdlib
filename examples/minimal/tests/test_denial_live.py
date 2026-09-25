"""The denial path, driven through the example's own wiring (directive §28's chain, in miniature).

Two requests over one seeded database, and both matter:

* the **control** -- an allowing policy decision answers 200 with the caller's tenant, which proves
  the request really was authenticated and resolved, so the refusal in the next test is the
  policy's answer rather than a refusal of the test's own making;
* the **denial** -- a denying one answers ``403 PERMISSION_DENIED`` in the canonical envelope, the
  enforcer was consulted for the declared permission, and the handler's output is absent.

The enforcer is swapped for a recording double rather than a policy engine being stood up: what is
under test here is the example's wiring -- that the guard reaches the container's enforcer with the
permission the route declares -- not the engine, which has its own live suite.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncGenerator
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from jdlib.authn.apikey import hash_api_key_secret
from jdlib.authz.pdp import Decision
from jdlib.errors import PermissionDenied
from jdlib.integrations.fastapi import JdlibContainer

pytestmark = pytest.mark.integration

TENANT_SLUG = "denial-live"


class RecordingEnforcer:
    """Answers as told, and keeps what it was asked -- the guard's own evidence."""

    def __init__(self, *, allow: bool) -> None:
        self.allow = allow
        self.calls: list[tuple[str, object]] = []

    async def require(self, permission: str, target: object, *, session: object) -> Decision:
        self.calls.append((permission, target))
        if not self.allow:
            raise PermissionDenied(f"{permission}: denied by policy")
        return Decision(True, "allowed", ())


async def _seed(engine: AsyncEngine, tenant_id: uuid.UUID, secret: str, prefix: str) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            sa.text(
                "INSERT INTO jd_control.service_accounts (id, tenant_id, name, status)"
                " VALUES (:id, :tenant_id, 'denial-live', 'active')"
            ),
            {"id": uuid.uuid4(), "tenant_id": tenant_id},
        )
    async with engine.begin() as connection:
        await connection.execute(
            sa.text(
                "INSERT INTO jd_control.api_keys"
                " (id, tenant_id, service_account_id, key_prefix, key_hash, status)"
                " VALUES (:id, :tenant_id, (SELECT id FROM jd_control.service_accounts"
                " WHERE tenant_id = :tenant_id LIMIT 1), :prefix, :key_hash, 'active')"
            ),
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "prefix": prefix,
                "key_hash": hash_api_key_secret(secret),
            },
        )


async def _tenant_id(engine: AsyncEngine) -> uuid.UUID:
    async with engine.connect() as connection:
        row = await connection.execute(
            sa.text("SELECT id FROM jd_control.tenants WHERE slug = :slug"),
            {"slug": TENANT_SLUG},
        )
        return row.scalar_one()


@pytest.fixture
async def denial_setup(example_database: str) -> AsyncGenerator[str, None]:
    """Provision the tenant with the example's own operator step, then seed one API key."""
    from examples.minimal.app.bootstrap import bootstrap
    from examples.minimal.app.dsn import async_dsn

    await bootstrap(slug=TENANT_SLUG, name="Denial Live")
    engine = create_async_engine(async_dsn(example_database))
    secret = uuid.uuid4().hex
    prefix = f"jd.k{uuid.uuid4().hex[:8]}"
    try:
        tenant_id = await _tenant_id(engine)
        await _seed(engine, tenant_id, secret, prefix)
    finally:
        await engine.dispose()
    yield f"Bearer {prefix}.{secret}"
    engine = create_async_engine(async_dsn(example_database))
    async with engine.begin() as connection:
        await connection.execute(
            sa.text("DELETE FROM jd_control.api_keys WHERE key_prefix = :prefix"),
            {"prefix": prefix},
        )
        await connection.execute(
            sa.text("DELETE FROM jd_control.service_accounts WHERE tenant_id = :tenant_id"),
            {"tenant_id": tenant_id},
        )
    await engine.dispose()


def _app_with(enforcer: RecordingEnforcer) -> tuple[FastAPI, str]:
    """The example's own app, with the enforcer swapped on the *tenant* app's container.

    `create_app()` returns the outer application; the container `install` put on the tenant plane
    is what the guard reads, so the double goes there.
    """
    from fastapi.routing import Mount

    from examples.minimal.app.main import TENANT_PREFIX, create_app

    outer = create_app()
    mount = next(route for route in outer.routes if isinstance(route, Mount))
    tenant_app = cast(FastAPI, mount.app)
    container: JdlibContainer = tenant_app.state.jdlib_container
    # `JdlibContainer` is frozen, so the double replaces the container rather than mutating it.
    # `Enforcer` is a concrete class rather than a protocol, so a double is an arg-type ignore
    # here -- the same one the library's own denial test carries.
    tenant_app.state.jdlib_container = dataclasses.replace(
        container, enforcer=enforcer  # type: ignore[arg-type]
    )
    return outer, f"{TENANT_PREFIX}/me"


async def _get(app: Any, path: str, token: str) -> Response:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://example.invalid") as client:
        return await client.get(path, headers={"Authorization": token})


async def test_an_allowed_request_reports_the_callers_tenant(denial_setup: str) -> None:
    """The control: without it, the 403 below could be any refusal at all."""
    app, path = _app_with(RecordingEnforcer(allow=True))

    response = await _get(app, path, denial_setup)

    assert response.status_code == 200
    assert response.json() == {"tenant": TENANT_SLUG}


async def test_a_denied_request_answers_the_envelope_and_runs_no_handler(
    denial_setup: str,
) -> None:
    enforcer = RecordingEnforcer(allow=False)
    app, path = _app_with(enforcer)

    response = await _get(app, path, denial_setup)

    assert response.status_code == 403
    body = response.json()
    assert set(body) == {"code", "message", "request_id", "correlation_id"}
    assert body["code"] == "PERMISSION_DENIED"
    assert TENANT_SLUG not in response.text, "the handler's output must not be reachable"
    assert [permission for permission, _ in enforcer.calls] == ["tenant:read"], (
        "the guard must reach the enforcer with the permission the route declares"
    )
