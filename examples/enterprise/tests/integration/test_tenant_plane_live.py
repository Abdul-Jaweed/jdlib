"""The tenant plane against a real PostgreSQL: each property, measured rather than assumed.

This file drives the service directly (no HTTP) so a failure names the layer that owns it. What it
checks is what the library claims about a tenant-bound session:

* a write is readable back over a **fresh connection**, not from the identity map;
* a page comes back ordered (the `order_by` path the repository exposes);
* another tenant's row is not "forbidden", it is **invisible** -- the session is bound to one tenant
  and the policy compares `tenant_id` to `app.tenant_id`;
* a cross-tenant reference is refused **twice over**: by the session's own check, and by the
  composite foreign key in the database, which is the layer that survives the check being removed;
* an unscoped statement is refused rather than run -- both a raw text statement and a bulk update
  without the tenant predicate -- with the scoped form beside them as the safe path;
* a failed operation leaves nothing behind (the unit of work rolls back);
* a suspended tenant cannot write, and the same tenant writes again once it is resumed.

Bring the lab up and provision it, then run this file:

    export JDLIB_ENTERPRISE_POSTGRES_PASSWORD=<owner password>      # any local value
    export JDLIB_ENTERPRISE_APP_PASSWORD=<runtime password>         # any local value
    docker compose -f examples/enterprise/docker/docker-compose.yml up -d
    export JDLIB_EXAMPLE_LIVE_DSN="postgresql://jdlib_app:<pw>@127.0.0.1:45432/jdlib_enterprise"
    export JDLIB_EXAMPLE_LIVE_MIGRATION_DSN="postgresql://jdlib:<pw>@127.0.0.1:45432/jdlib_enterprise"
    pytest examples/enterprise/tests/test_tenant_plane_live.py -q -W error

(Mint each with `python -c 'import secrets; print(secrets.token_urlsafe(24))'`.)

Two DSNs, because the example runs two roles: the *runtime* role (`jdlib_app`) serves requests and
is the one the policies constrain, and the owner migrates and installs them. A single superuser DSN
would install policies that apply to nobody -- row-level security does not constrain a superuser
-- and the library refuses it outright (`StrategyCapabilityError`).

With either variable unset the whole file skips with that reason. They are separate from the
application's own: the application's placeholder must never make a live test look failing.

Each test owns its event loop (`asyncio.run`) and builds its collaborators inside it. An engine
created in one loop cannot be closed in another, so a module-scoped async fixture handed to per-test
loops is how a suite reports "Event loop is closed" from its teardown instead of an assertion: the
fixture provisions once and returns **data**, and each test builds its own service.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from examples.enterprise.app.dataplane import (
    TenantPlane,
    inspect_tenant_rls,
    install_tenant_rls,
    shared_strategy,
    tables_in_schema,
)
from examples.enterprise.app.dsn import async_dsn
from examples.enterprise.app.models.resources import Resource
from examples.enterprise.app.repositories.resources import ResourceRepository
from examples.enterprise.app.services.resources import ResourceService
from examples.enterprise.tests.support.lab import wait_for_database
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.errors import (
    CrossTenantReferenceError,
    InvalidReference,
    TenantNotWritable,
    TenantSuspended,
    UnscopedRawSql,
)
from jdlib.migrations.runner import MigrationRunner

RUNTIME_DSN = os.environ.get("JDLIB_EXAMPLE_LIVE_DSN", "")
MIGRATION_DSN = os.environ.get("JDLIB_EXAMPLE_LIVE_MIGRATION_DSN", "")

pytestmark = pytest.mark.skipif(
    not (RUNTIME_DSN and MIGRATION_DSN),
    reason=(
        "the tenant plane's lab is not running: docker compose -f "
        "examples/enterprise/docker/docker-compose.yml up -d, then export "
        "JDLIB_EXAMPLE_LIVE_DSN=postgresql://jdlib_app:<app-password>"
        "@127.0.0.1:45432/jdlib_enterprise and JDLIB_EXAMPLE_LIVE_MIGRATION_DSN="
        "postgresql://jdlib:<owner-password>@127.0.0.1:45432/jdlib_enterprise"
    ),
)


@dataclass(frozen=True)
class Lab:
    """What the module fixture provisions: two tenants, and nothing that holds an event loop."""

    tenant_a: uuid.UUID
    tenant_b: uuid.UUID

    def context(self, tenant_id: uuid.UUID) -> TenantContext:
        return TenantContext(
            tenant_id=tenant_id,
            tenant_slug=f"live-{str(tenant_id)[:8]}",
            strategy=PlacementStrategy.SHARED,
            principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=tenant_id),
            request_id=f"req-{uuid.uuid4().hex[:8]}",
            correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
        )


@pytest.fixture(scope="module")
def lab() -> Lab:
    """Migrate the control plane, create the tables, install the policies, make two tenants."""

    async def _provision() -> Lab:
        await wait_for_database(MIGRATION_DSN)
        MigrationRunner(MIGRATION_DSN).upgrade_control()
        app_role = sa.engine.make_url(RUNTIME_DSN).username
        assert app_role is not None

        # Tenants first, policies second: `registry.provision` is what runs the library's tenant
        # migration and creates the tables, and a policy cannot be installed on a table that does
        # not exist yet. (The tables are shared, so this happens once per database -- but it happens
        # *here*, not in the control migration.)
        engine = create_async_engine(async_dsn(MIGRATION_DSN))
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        registry = TenantRegistry(
            session_factory=sessions,
            strategies={PlacementStrategy.SHARED: shared_strategy(engine)},
            runner=MigrationRunner(MIGRATION_DSN),
            audit=DatabaseAuditSink(sessions),
        )
        run = secrets.token_hex(3)
        ids: list[uuid.UUID] = []
        for label in ("a", "b"):
            tenant = await registry.create(
                slug=f"live-{label}-{run}",
                name=f"Live {label}",
                strategy=PlacementStrategy.SHARED,
                target_handle=f"live-{run}",
            )
            await registry.provision(tenant.id)
            ids.append(tenant.id)
        await engine.dispose()

        await install_tenant_rls(MIGRATION_DSN, "public", app_role=app_role)
        return Lab(tenant_a=ids[0], tenant_b=ids[1])

    # No teardown: every engine is created and disposed inside a test's own loop.
    return asyncio.run(_provision())


@asynccontextmanager
async def _service() -> AsyncIterator[tuple[ResourceService, TenantRegistry]]:
    """The application's collaborators, built inside the caller's event loop and closed there.

    The plane connects as the *runtime* role -- the one the policies constrain -- while the registry
    (which suspends a tenant, and therefore writes to the control plane) connects as the owner.
    Reading the tenant plane as the owner is how a live test reports a false negative: row-level
    security hides the write from a reader that is exempt from it.
    """
    plane = TenantPlane(RUNTIME_DSN)
    engine = create_async_engine(async_dsn(MIGRATION_DSN))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    registry = TenantRegistry(
        session_factory=sessions,
        strategies={PlacementStrategy.SHARED: shared_strategy(engine)},
        runner=MigrationRunner(MIGRATION_DSN),
        audit=DatabaseAuditSink(sessions),
    )
    try:
        yield (
            ResourceService(plane=plane, fence=RegistryWriteFence(session_factory=sessions)),
            registry,
        )
    finally:
        await plane.aclose()
        await engine.dispose()


def test_the_tables_that_are_policed_are_the_examples_own(lab: Lab) -> None:
    """What was installed, not merely that installing raised nothing.

    The installation is scoped to the tables this database has, because the library's eligible set
    is process-global: a process that imported any other tenant-routed model (this repository's own
    test double is one) makes the installer emit DDL for tables that are not here, and the whole
    installation fails on the first one -- exactly what the full suite did while this file passed on
    its own. Narrowing to "what exists" would install *nothing* if the query or the
    eligible set were wrong, and a suite that only checks for an exception would not notice, so the
    enforced set is asserted here.
    """

    async def _body() -> None:
        inspection = await inspect_tenant_rls(MIGRATION_DSN, "public")
        assert {"resources", "entities", "audit_events"} <= set(inspection.tables_enforced)
        assert inspection.is_enforced
        assert not inspection.tables_unprovisioned

        # The scope is the database's own tables: nothing outside it was considered.
        present = set(await tables_in_schema(MIGRATION_DSN, "public"))
        assert set(inspection.tables_checked) <= present

    asyncio.run(_body())


def test_a_created_resource_is_readable_over_a_fresh_connection(lab: Lab) -> None:
    async def _body() -> None:
        async with _service() as (service, _registry):
            context = lab.context(lab.tenant_a)
            name = f"readback-{uuid.uuid4().hex[:8]}"
            created = await service.create(context, name=name, kind="dataset")

            # A separate call: a separate unit of work, a separate session, a separate connection.
            fetched = await service.require(context, created.id)
            assert fetched.name == name
            assert fetched.kind == "dataset"
            assert fetched.tenant_id == lab.tenant_a

    asyncio.run(_body())


def test_a_page_is_ordered_by_creation_time_descending(lab: Lab) -> None:
    """The `order_by` path, at runtime.

    The repository's annotation once rejected every idiomatic argument for it, so no caller in the
    library or in the reference application had ever exercised ordering; this is the first caller
    that does, and it does it against the database rather than in a type checker.
    """

    async def _body() -> None:
        async with _service() as (service, _registry):
            context = lab.context(lab.tenant_a)
            run = uuid.uuid4().hex[:6]
            created = [await service.create(context, name=f"order-{run}-{n}") for n in range(3)]

            page = await service.list(context, limit=50)
            ours = [row.id for row in page if row.name.startswith(f"order-{run}-")]
            assert ours == [row.id for row in reversed(created)]

    asyncio.run(_body())


def test_another_tenants_resource_is_invisible_through_the_service(lab: Lab) -> None:
    """The API-level property: the row is unreachable, not forbidden.

    Tenant B asking for tenant A's resource gets `None` and then a refusal that names the id.

    What this measures is the *session's* scoping -- the tenant-bound session adds the predicate, so
    the row is not found. It does **not** measure the policy: with row-level security disabled on
    `resources` this test still passes, which is how that was found. The policy has its own test
    below, on a statement the session never filtered.
    """

    async def _body() -> None:
        async with _service() as (service, _registry):
            a = lab.context(lab.tenant_a)
            b = lab.context(lab.tenant_b)
            created = await service.create(a, name=f"isolation-{uuid.uuid4().hex[:8]}")

            assert await service.get(b, created.id) is None
            with pytest.raises(InvalidReference):
                await service.require(b, created.id)
            # And it is still there for its owner.
            assert (await service.require(a, created.id)).name == created.name

    asyncio.run(_body())


def test_the_policy_alone_hides_another_tenants_rows(lab: Lab) -> None:
    """The policy, measured on a statement the session did not filter.

    A raw connection as the runtime role -- the one row-level security constrains -- with the tenant
    setting bound by hand. Nothing here adds a `WHERE tenant_id = ...`: the predicate under test is
    the policy's, so this test fails the moment the policy stops applying (proved by disabling RLS
    on the table and watching exactly this test fail).

    Both arms are measured, because a count of zero is also what a broken connection returns: the
    owner's binding must see its own row.
    """

    async def _body() -> None:
        async with _service() as (service, _registry):
            a = lab.context(lab.tenant_a)
            name = f"policy-{uuid.uuid4().hex[:8]}"
            await service.create(a, name=name)

        async def _count(bound_to: uuid.UUID) -> int:
            engine = create_async_engine(
                async_dsn(RUNTIME_DSN),
                connect_args={"server_settings": {"app.tenant_id": str(bound_to)}},
            )
            try:
                async with engine.connect() as connection:
                    result = await connection.execute(
                        sa.text("SELECT count(*) FROM resources WHERE name = :name"),
                        {"name": name},
                    )
                    return int(result.scalar_one())
            finally:
                await engine.dispose()

        assert await _count(lab.tenant_a) == 1
        assert await _count(lab.tenant_b) == 0

    asyncio.run(_body())


def test_a_cross_tenant_reference_is_refused_by_the_session(lab: Lab) -> None:
    async def _body() -> None:
        async with _service() as (service, _registry):
            a = lab.context(lab.tenant_a)
            b = lab.context(lab.tenant_b)
            created = await service.create(a, name=f"ref-{uuid.uuid4().hex[:8]}")

            with pytest.raises((InvalidReference, CrossTenantReferenceError)):
                await service.add_entity(b, resource_id=created.id, label="stowaway")

    asyncio.run(_body())


def test_the_database_itself_refuses_a_cross_tenant_reference(lab: Lab) -> None:
    """The other layer, attacked directly: the composite foreign key.

    The statement below is what a caller reaching past the session would write, and the connection
    is *bound to the attacker's tenant* so that row-level security passes -- otherwise the policy
    would refuse it first and this test would be proving the wrong control. What refuses it is the
    composite `(tenant_id, resource_id)` reference into `resources (tenant_id, id)`, which is the
    protection that survives even if the session's own check were removed.
    """

    async def _body() -> None:
        async with _service() as (service, _registry):
            a = lab.context(lab.tenant_a)
            b = lab.context(lab.tenant_b)
            created = await service.create(a, name=f"fk-{uuid.uuid4().hex[:8]}")

        engine = create_async_engine(
            async_dsn(RUNTIME_DSN),
            connect_args={"server_settings": {"app.tenant_id": str(b.tenant_id)}},
        )
        try:
            async with engine.begin() as connection:
                with pytest.raises(sa.exc.IntegrityError):
                    await connection.execute(
                        sa.text(
                            "INSERT INTO entities (tenant_id, id, resource_id, label, weight, "
                            "created_at, updated_at) VALUES (:tenant, :id, :resource, :label, 1, "
                            "now(), now())"
                        ),
                        {
                            "tenant": str(b.tenant_id),
                            "id": str(uuid.uuid4()),
                            "resource": str(created.id),
                            "label": "stowaway",
                        },
                    )
        finally:
            await engine.dispose()

    asyncio.run(_body())


def test_an_unscoped_text_statement_is_refused(lab: Lab) -> None:
    async def _body() -> None:
        async with _service() as (service, _registry):
            context = lab.context(lab.tenant_a)
            async with service.unit_of_work(context) as session:
                with pytest.raises(UnscopedRawSql):
                    await session.execute(sa.text("SELECT count(*) FROM resources"))

    asyncio.run(_body())


def test_a_raw_update_without_a_tenant_predicate_is_refused(lab: Lab) -> None:
    async def _body() -> None:
        async with _service() as (service, _registry):
            context = lab.context(lab.tenant_a)
            async with service.unit_of_work(context) as session:
                with pytest.raises(UnscopedRawSql):
                    await session.raw_sql(sa.text("UPDATE resources SET status = 'archived'"))

    asyncio.run(_body())


def test_the_scoped_bulk_update_is_the_safe_path(lab: Lab) -> None:
    """The other half of the pair: the same intent, through the call that adds the predicate."""

    async def _body() -> None:
        async with _service() as (service, _registry):
            context = lab.context(lab.tenant_a)
            name = f"bulk-{uuid.uuid4().hex[:8]}"
            created = await service.create(context, name=name)

            async with service.unit_of_work(context) as session:
                changed = await session.update_where(
                    Resource, {"status": "archived"}, Resource.name == name
                )
            assert changed == 1
            assert (await service.require(context, created.id)).status == "archived"

    asyncio.run(_body())


def test_a_failed_operation_leaves_nothing_behind(lab: Lab) -> None:
    async def _body() -> None:
        async with _service() as (service, _registry):
            context = lab.context(lab.tenant_a)
            name = f"rollback-{uuid.uuid4().hex[:8]}"
            before = await service.count(context)

            with pytest.raises(RuntimeError):
                async with service.unit_of_work(context) as session:
                    await ResourceRepository(session).add(
                        Resource(
                            tenant_id=lab.tenant_a,
                            id=uuid.uuid4(),
                            name=name,
                            kind="document",
                        )
                    )
                    raise RuntimeError("the operation failed after the write")

            assert await service.count(context) == before
            async with service.unit_of_work(context) as session:
                assert await ResourceRepository(session).by_name(name) is None

    asyncio.run(_body())


def test_a_suspended_tenant_cannot_write(lab: Lab) -> None:
    """The fence, and where it fires: before a connection is taken, so nothing half-applied."""

    async def _body() -> None:
        async with _service() as (service, registry):
            context = lab.context(lab.tenant_a)
            await registry.suspend(lab.tenant_a, reason="live test")
            try:
                with pytest.raises((TenantNotWritable, TenantSuspended)):
                    await service.create(context, name=f"suspended-{uuid.uuid4().hex[:8]}")
            finally:
                await registry.resume(lab.tenant_a)

            # And the same tenant writes again once it is resumed.
            created = await service.create(context, name=f"resumed-{uuid.uuid4().hex[:8]}")
            assert created.status == "active"

    asyncio.run(_body())
