"""The tenant plane: engines, sessions, provisioning and the row-level security policy.

The isolation this example runs is **row-level security in one schema**, which is what the
`shared` placement means: tenants share `public`, every tenant-routed table carries a policy
comparing `tenant_id` to the session setting `app.tenant_id`, and a connection that never sets it
sees no rows and can insert none. A different placement (`schema-per-tenant`) is a configuration
change — the strategy the registry provisions with — rather than a change to any code below.

Two properties are structural rather than checked:

* the engine **binds the tenant at connect time** (`server_settings: {search_path, app.tenant_id}`),
  so there is no window in which a session exists without a tenant, and no code path can forget to
  bind it;
* the session factory is cached per schema, so a request does not open a pool of its own.

The library owns the schema, the policies and the write fence. This module owns the DSN, the
engine's connect arguments, and the privileges — the library deliberately grants none, because a
role with no `SELECT` is not protected by a policy, it is simply locked out.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from examples.enterprise.app import models as _app_models  # noqa: F401
from examples.enterprise.app.dsn import async_dsn, sync_dsn
from jdlib.context import TenantContext
from jdlib.migrations.runner import MigrationRunner

# Imported for their side effect: the library's tenant tables and this application's join
# `TenantBase.metadata`, which is the metadata the migration creates and the RLS installer walks.
from jdlib.models import audit as _audit_models  # noqa: F401
from jdlib.models import settings as _settings_models  # noqa: F401
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import (
    RlsInspection,
    inspect_rls,
    install_rls,
    rls_eligible_tables,
)
from jdlib.persistence.strategies.shared import SharedSchemaStrategy

__all__ = [
    "APPLICATION_NAME",
    "TENANT_SCHEMA",
    "TenantPlane",
    "app_metadata",
    "grant_tenant_privileges",
    "install_tenant_rls",
    "inspect_tenant_rls",
    "provision_tenant_schema",
    "scoped_tables",
    "shared_strategy",
    "tables_in_schema",
]

#: The schema the shared placement puts tenants in. The control plane lives in `jd_control`, so
#: `public` holds the tenant plane only.
TENANT_SCHEMA = "public"

#: What every pool in this application reports to PostgreSQL: a `pg_stat_activity` row or a log
#: line should say which component is talking.
APPLICATION_NAME = "jdlib-enterprise-example"

_SCHEMA_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
_ROLE_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")


def app_metadata() -> sa.MetaData:
    """The metadata both the library and this application build their tables on."""
    return TenantBase.metadata


def _quote(name: str, pattern: re.Pattern[str]) -> str:
    if pattern.match(name) is None:
        raise ValueError(
            f"refusing to quote an identifier that does not match its pattern: {name!r}"
        )
    return f'"{name}"'


def tenant_engine(
    database_url: str, *, tenant_id: uuid.UUID, schema: str = TENANT_SCHEMA
) -> AsyncEngine:
    """A tenant-bound engine: schema *and* tenant, both fixed at connect time."""
    return create_async_engine(
        async_dsn(database_url),
        connect_args={
            "server_settings": {
                "search_path": schema,
                "app.tenant_id": str(tenant_id),
                "application_name": APPLICATION_NAME,
            }
        },
    )


def tenant_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def shared_strategy(engine: AsyncEngine, *, rls_enabled: bool = True) -> SharedSchemaStrategy:
    """The isolation strategy the registry provisions tenants with.

    `rls_enabled` is not cosmetic: with it false the strategy never binds `app.tenant_id`, and a
    schema whose policies are installed then answers every query with no rows — the failure mode is
    closed, which is the property that makes turning it on a *default* rather than a hardening step.
    """
    from jdlib.config import RlsConfig

    return SharedSchemaStrategy(engine, TENANT_SCHEMA, rls=RlsConfig(enabled=rls_enabled))


def provision_tenant_schema(database_url: str, schema: str) -> None:
    """Create a *dedicated* schema's tables from the library's own tenant migration.

    This is the schema-per-tenant path, and the library validates the name against its tenant
    pattern (`t_...`) because it is about to create a schema. A **shared** placement has no schema
    of its own: its tables are created by the registry's provisioning
    (`TenantRegistry.provision` -> `strategy.migrate` -> `upgrade_tenant`), which validates the
    *deployment* schema instead and therefore accepts `public`. Calling this helper for a shared
    placement is refused by the library -- `ProvisioningError: invalid tenant schema name: 'public'`
    -- and the example's tests pin that refusal, because the mistake is a natural one to make.
    """
    MigrationRunner(database_url).provision_tenant_schema(schema)


async def tables_in_schema(database_url: str, schema: str) -> tuple[str, ...]:
    """The tables this database actually has in ``schema``.

    The eligible set the library computes is *process-global* -- `TenantRouted.__subclasses__()` --
    so a process that imported any other tenant-routed model (in this repository, a test double)
    would have the installer emit DDL for tables that are not here, and the installation would fail
    on the first one. Asking the database what it has is what keeps the example installable in a
    test process and in a deployment alike.
    """
    engine = create_async_engine(async_dsn(database_url))
    try:
        async with engine.connect() as connection:
            rows = await connection.execute(
                sa.text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = :schema"
                ),
                {"schema": schema},
            )
            return tuple(sorted(str(row[0]) for row in rows))
    finally:
        await engine.dispose()


def scoped_tables(present: tuple[str, ...]) -> tuple[str, ...]:
    """The tenant-routed tables that exist here: the eligible set, narrowed to what is present."""
    return rls_eligible_tables(app_metadata(), tables=present)


async def install_tenant_rls(database_url: str, schema: str, *, app_role: str) -> RlsInspection:
    """Install the policies, grant what makes them reachable, and read back what landed."""
    present = await tables_in_schema(database_url, schema)
    scope = scoped_tables(present)
    engine = create_async_engine(async_dsn(database_url))
    try:
        await install_rls(engine, metadata=app_metadata(), app_role=app_role, tables=scope)
        await grant_tenant_privileges(database_url, schema, app_role)
        return await inspect_rls(engine, metadata=app_metadata(), tables=scope)
    finally:
        await engine.dispose()


async def inspect_tenant_rls(database_url: str, schema: str) -> RlsInspection:
    """Read the RLS state without judging it (evidence, not a gate)."""
    scope = scoped_tables(await tables_in_schema(database_url, schema))
    engine = create_async_engine(async_dsn(database_url))
    try:
        return await inspect_rls(engine, metadata=app_metadata(), tables=scope)
    finally:
        await engine.dispose()


async def grant_tenant_privileges(database_url: str, schema: str, app_role: str) -> None:
    """Grant the runtime role what it needs inside the tenant schema.

    Identifiers cannot be bound as parameters, so both are validated against a strict pattern and
    quoted; nothing here comes from user input.
    """
    tenant = _quote(schema, _SCHEMA_RE)
    role = _quote(app_role, _ROLE_RE)
    statements = (
        f"GRANT USAGE ON SCHEMA {tenant} TO {role}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {tenant} TO {role}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {tenant} TO {role}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {tenant} "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {tenant} GRANT USAGE, SELECT ON SEQUENCES TO {role}",
    )
    engine = sa.create_engine(sync_dsn(database_url), future=True)
    try:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(sa.text(statement))
    finally:
        engine.dispose()


class TenantPlane:
    """Per-tenant engines and session factories, cached by schema.

    A request asks for the factory its context needs; the engine behind it is created once and
    reused, so the tenant binding is paid for at connect time rather than per query.
    """

    def __init__(self, database_url: str, *, schema: str = TENANT_SCHEMA) -> None:
        self._database_url = database_url
        self._schema = schema
        self._engines: dict[uuid.UUID, AsyncEngine] = {}

    def session_factory_for(self, context: TenantContext) -> Callable[[], AsyncSession]:
        engine = self._engines.get(context.tenant_id)
        if engine is None:
            engine = tenant_engine(
                self._database_url, tenant_id=context.tenant_id, schema=self._schema
            )
            self._engines[context.tenant_id] = engine
        return tenant_session_factory(engine)

    async def aclose(self) -> None:
        for engine in self._engines.values():
            await engine.dispose()
        self._engines.clear()
