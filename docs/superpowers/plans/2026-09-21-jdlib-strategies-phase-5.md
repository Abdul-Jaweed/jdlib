# jdlib Isolation Strategies & RLS (Phase 5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the remaining isolation strategies — schema-per-tenant (validated `search_path`, per-schema DDL/migrations, pool reset) and database-per-tenant (secret-resolved handles, capped pool cache, admin DDL) — plus Postgres RLS emission and fail-closed session binding for shared mode, and privileged tenant-plane purge so shared `purge`/`destroy` actually delete tenant data.

**Architecture:** Strategies stay behind the existing `IsolationStrategy` protocol; `TenantRecord` gains an optional `target_handle` so adapters can route without new ports. RLS is emitted by a metadata walk over `TenantRouted` models and enforced by `SET LOCAL app.tenant_id` at session creation; the policy predicate is fail-closed via `NULLIF(current_setting(...))`. Tenant-plane purge runs through a privileged `TenantSession` using the shipped scoped bulk helpers.

**Tech Stack:** SQLAlchemy 2.0 async, asyncpg/psycopg, Alembic runner, testcontainers PostgreSQL 16. No new dependencies.

**Specs (frozen):** `docs/jdlib/06-strategy-matrix.md` §1–§9; `docs/jdlib/03-isolation-invariants.md` I2/I9/I13; `docs/jdlib/05-tenant-lifecycle.md` §5; `docs/jdlib/02-relational-schema.md` §7.

## Global Constraints

- Schema names come only from the registry-validated `target_handle`; quoting is driver-level; `search_path` is set by the framework on every checkout and reset on checkin; application code never sets it.
- Database handles are opaque; credentials resolve through `SecretProvider`; pool cache never evicts a pool with checked-out connections; cap exhaustion raises `PoolCapacityError`.
- RLS: `FORCE ROW LEVEL SECURITY` on every `TenantRouted` table; runtime role `NOBYPASSRLS`; unset `app.tenant_id` yields zero rows and zero writes; startup self-check fails closed.
- Shared `purge`/`destroy` deletes tenant-plane rows through a privileged context with per-model counts audited; `archive` deletes nothing.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` and a fresh DB.
- No comments in source; pristine test output; commit after every task.

---

### Task 1: `target_handle` on `TenantRecord` and the schema-per-tenant strategy

**Files:**
- Modify: `src/jdlib/context.py` (`TenantRecord.target_handle`)
- Modify: `src/jdlib/control/registry.py` (`_record` sets handle)
- Modify: `src/jdlib/persistence/strategies/base.py` (document handle)
- Create: `src/jdlib/persistence/strategies/schema.py`
- Create: `tests/unit/test_schema_strategy.py`
- Create: `tests/integration/test_schema_strategy_db.py`

**Interfaces:**
- Produces: `TenantRecord(id, slug, status, strategy, target_handle: str | None = None)`; `SchemaPerTenantStrategy(engine, runner, *, admin_engine=None)` with `session(tenant)`, `provision(tenant)`, `migrate(tenant, runner)`, `deprovision(tenant, mode)`, `migration_schema(tenant)`; `validate_schema_name(value) -> str`.

- [ ] **Step 1: Write the failing unit tests**

`tests/unit/test_schema_strategy.py`:

```python
import uuid

import pytest

from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.context import TenantRecord
from jdlib.errors import StrategyCapabilityError
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy, validate_schema_name


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        self.calls.append((schema, revision))

    def tenant_version(self, schema: str) -> str | None:
        return "0001_tenant_baseline"


def _record(handle: str | None = "t_acme") -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SCHEMA, target_handle=handle,
    )


def test_schema_name_validation():
    assert validate_schema_name("t_acme_1") == "t_acme_1"
    for bad in ("public", "t_", "t_BAD", 't_x"; DROP TABLE x', ""):
        with pytest.raises(StrategyCapabilityError):
            validate_schema_name(bad)


def test_capabilities():
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    assert strategy.name == "schema"
    assert strategy.capabilities.supports_rls is False
    assert strategy.capabilities.supports_ddl is True


async def test_missing_handle_fails_closed():
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    with pytest.raises(StrategyCapabilityError):
        await strategy.session(_record(handle=None))


async def test_migrate_uses_handle_schema():
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    runner = _Runner()
    await strategy.migrate(_record(), runner)  # type: ignore[arg-type]
    assert runner.calls == [("t_acme", "head")]
    assert strategy.migration_schema(_record()) == "t_acme"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_schema_strategy.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.strategies.schema'`

- [ ] **Step 3: Implement the record field, validation, and strategy**

`src/jdlib/context.py` — extend `TenantRecord`:

```python
@dataclass(frozen=True, slots=True)
class TenantRecord:
    id: uuid.UUID
    slug: str
    status: TenantStatus
    strategy: PlacementStrategy
    target_handle: str | None = None
```

`src/jdlib/control/registry.py` — `_record` sets `target_handle=placement.target_handle`; `find` sets it too.

`src/jdlib/persistence/strategies/schema.py`:

```python
from __future__ import annotations

import re

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from jdlib.context import TenantRecord
from jdlib.errors import StrategyCapabilityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.deprovision import DeprovisionMode

_SCHEMA_RE = re.compile(r"^t_[a-z0-9][a-z0-9_]{0,50}$")


def validate_schema_name(value: str) -> str:
    if not _SCHEMA_RE.match(value):
        raise StrategyCapabilityError(f"invalid tenant schema name: {value!r}")
    return value


def _handle(tenant: TenantRecord) -> str:
    if tenant.target_handle is None:
        raise StrategyCapabilityError(f"tenant {tenant.slug} has no schema handle")
    return validate_schema_name(tenant.target_handle)


class SchemaPerTenantStrategy:
    name = "schema"
    capabilities = StrategyCapabilities(supports_rls=False, supports_ddl=True)

    def __init__(
        self,
        engine: AsyncEngine | None,
        runner: MigrationRunner | None = None,
        *,
        admin_engine: AsyncEngine | None = None,
    ) -> None:
        self._engine = engine
        self._runner = runner
        self._admin_engine = admin_engine

    def migration_schema(self, tenant: TenantRecord) -> str:
        return _handle(tenant)

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        if self._engine is None:
            raise StrategyCapabilityError("schema strategy has no engine configured")
        schema = _handle(tenant)
        session = AsyncSession(self._engine, expire_on_commit=False)
        quoted = session.bind.dialect.identifier_preparer.quote(schema)
        await session.execute(sa.text(f"SET search_path TO {quoted}"))
        return session

    async def provision(self, tenant: TenantRecord) -> None:
        schema = _handle(tenant)
        engine = self._admin_engine or self._engine
        if engine is None:
            raise StrategyCapabilityError("schema strategy has no engine configured")
        async with engine.begin() as connection:
            quoted = connection.dialect.identifier_preparer.quote(schema)
            await connection.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {quoted}"))

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        runner.upgrade_tenant(self.migration_schema(tenant))

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        if mode is DeprovisionMode.ARCHIVE:
            return
        schema = _handle(tenant)
        engine = self._admin_engine or self._engine
        if engine is None:
            raise StrategyCapabilityError("schema strategy has no engine configured")
        async with engine.begin() as connection:
            quoted = connection.dialect.identifier_preparer.quote(schema)
            await connection.execute(sa.text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
```

Pool reset (add to `SchemaPerTenantStrategy.__init__` via engine event):

```python
        if self._engine is not None:
            self._engine.sync_engine.pool._dialect = self._engine.sync_engine.dialect
            sa.event.listen(
                self._engine.sync_engine, "reset", _reset_search_path, retval=False
            )


def _reset_search_path(dbapi_connection, connection_record, reset_state) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("RESET search_path")
    finally:
        cursor.close()
```

Note for the implementer: the `"reset"` event on the sync engine fires with `(dbapi_connection, connection_record, reset_state)` for pool checkin; verify it runs under the asyncpg/psycopg facade in the integration test (a wrong signature raises at test time). If the event cannot run synchronously for the installed driver, keep checkout-set (which is mandatory) and record the reset-on-checkin as a documented deviation in the plan.

- [ ] **Step 4: Integration test — real schemas and isolation**

`tests/integration/test_schema_strategy_db.py`:

```python
import uuid

import pytest
import sqlalchemy as sa

from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.context import TenantRecord
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice


def _record(handle: str) -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug=handle, status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SCHEMA, target_handle=handle,
    )


class _Runner:
    def __init__(self, engine) -> None:
        self._engine = engine

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        from sqlalchemy import create_engine

        from jdlib.models.base import TenantBase

        sync_engine = create_engine(self._engine.url.render_as_string(hide_password=False).replace("+asyncpg", "+psycopg"))
        with sync_engine.begin() as connection:
            connection.exec_driver_sql(f'SET search_path TO "{schema}"')
            TenantBase.metadata.create_all(connection)
        sync_engine.dispose()


async def test_two_schemas_are_isolated(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, _Runner(async_engine))
    tenant_a, tenant_b = _record(f"t_{uuid.uuid4().hex[:10]}"), _record(f"t_{uuid.uuid4().hex[:10]}")
    for tenant in (tenant_a, tenant_b):
        await strategy.provision(tenant)
        await strategy.migrate(tenant, _Runner(async_engine))
    raw_a = await strategy.session(tenant_a)
    raw_b = await strategy.session(tenant_b)
    from tests.integration.test_session_isolation import _context

    session_a = TenantSession(raw_a, _context(tenant_a.id))
    session_b = TenantSession(raw_b, _context(tenant_b.id))
    await session_a.add(Invoice(number="INV-A"))
    await session_a.flush()
    assert await session_b.get(Invoice, (await session_a.execute(sa.select(Invoice.id))).scalar_one()) is None
    assert [row.number for row in (await session_b.execute(sa.select(Invoice))).scalars()] == []
    await session_a.close()
    await session_b.close()
```

Note: `_context` builds a shared-strategy context; add an optional `strategy` parameter there or construct a `TenantContext` inline with `PlacementStrategy.SCHEMA`. Prefer inline construction in this test to avoid touching shared helpers.

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/context.py src/jdlib/control/registry.py src/jdlib/persistence/strategies/schema.py tests/unit/test_schema_strategy.py tests/integration/test_schema_strategy_db.py
git commit -m "feat: schema-per-tenant strategy with search_path isolation"
```

---

### Task 2: Database-per-tenant strategy

**Files:**
- Create: `src/jdlib/persistence/secrets.py`
- Create: `src/jdlib/persistence/strategies/database.py`
- Create: `tests/unit/test_database_strategy.py`
- Create: `tests/integration/test_database_strategy_db.py`

**Interfaces:**
- Produces: `SecretProvider` protocol (`resolve(handle) -> str`), `MemorySecretProvider`, `EnvSecretProvider(prefix)`; `DatabasePerTenantStrategy(admin_dsn, secrets, runner, *, max_targets=32)` with `session/provision/migrate/deprovision/migration_schema` and `async dispose()`; `PoolCapacityError` on cap exhaustion.

- [ ] **Step 1: Write the failing unit tests**

`tests/unit/test_database_strategy.py`:

```python
import uuid

import pytest

from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.context import TenantRecord
from jdlib.errors import PoolCapacityError, StrategyCapabilityError
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.persistence.strategies.database import DatabasePerTenantStrategy
from jdlib.persistence.strategies.deprovision import DeprovisionMode


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return "0001_tenant_baseline"


def _record(handle: str | None = "db-acme") -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.DATABASE, target_handle=handle,
    )


def test_capabilities_and_validation():
    strategy = DatabasePerTenantStrategy(
        admin_dsn="postgresql+asyncpg://u:p@h/db",
        secrets=MemorySecretProvider({"db-acme": "postgresql+asyncpg://u:p@h/acme"}),
        runner=_Runner(),
    )
    assert strategy.name == "database"
    assert strategy.capabilities.supports_ddl is True
    with pytest.raises(StrategyCapabilityError):
        strategy.migration_schema(_record(handle=None))
    with pytest.raises(StrategyCapabilityError):
        strategy.migration_schema(_record(handle="missing-handle"))


def test_handle_is_opaque_never_a_dsn():
    strategy = DatabasePerTenantStrategy(
        admin_dsn="postgresql+asyncpg://u:p@h/db",
        secrets=MemorySecretProvider({"db-acme": "postgresql+asyncpg://u:p@h/acme"}),
        runner=_Runner(),
    )
    with pytest.raises(StrategyCapabilityError):
        strategy.migration_schema(_record(handle="postgresql://u:p@h/x"))


async def test_pool_cap_raises():
    strategy = DatabasePerTenantStrategy(
        admin_dsn="postgresql+asyncpg://u:p@h/db",
        secrets=MemorySecretProvider({"db-acme": "postgresql+asyncpg://u:p@h/acme"}),
        runner=_Runner(),
        max_targets=0,
    )
    with pytest.raises(PoolCapacityError):
        await strategy.session(_record())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_database_strategy.py -v`
Expected: FAIL (missing modules)

- [ ] **Step 3: Implement secrets and the strategy**

`src/jdlib/persistence/secrets.py`:

```python
from __future__ import annotations

import os
from typing import Protocol


class SecretProvider(Protocol):
    def resolve(self, handle: str) -> str: ...


class MemorySecretProvider:
    def __init__(self, mapping: dict[str, str]) -> None:
        self._mapping = dict(mapping)

    def resolve(self, handle: str) -> str:
        try:
            return self._mapping[handle]
        except KeyError as exc:
            raise KeyError(f"no secret for handle {handle}") from exc


class EnvSecretProvider:
    def __init__(self, prefix: str = "JDLIB_TENANT_DB_") -> None:
        self._prefix = prefix

    def resolve(self, handle: str) -> str:
        key = self._prefix + handle.upper().replace("-", "_")
        value = os.environ.get(key)
        if value is None:
            raise KeyError(f"missing environment variable {key}")
        return value
```

`src/jdlib/persistence/strategies/database.py`:

```python
from __future__ import annotations

import re
from collections import OrderedDict

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from jdlib.context import TenantRecord
from jdlib.errors import PoolCapacityError, StrategyCapabilityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.secrets import SecretProvider
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.deprovision import DeprovisionMode

_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,50}$")


def _handle(tenant: TenantRecord) -> str:
    if tenant.target_handle is None or not _HANDLE_RE.match(tenant.target_handle):
        raise StrategyCapabilityError(f"invalid database handle for tenant {tenant.slug}")
    return tenant.target_handle


class DatabasePerTenantStrategy:
    name = "database"
    capabilities = StrategyCapabilities(supports_rls=False, supports_ddl=True)

    def __init__(
        self,
        *,
        admin_dsn: str,
        secrets: SecretProvider,
        runner: MigrationRunner | None = None,
        max_targets: int = 32,
    ) -> None:
        self._admin_dsn = admin_dsn
        self._secrets = secrets
        self._runner = runner
        self._max_targets = max_targets
        self._engines: OrderedDict[str, AsyncEngine] = OrderedDict()
        self._admin_engine: AsyncEngine | None = None

    def migration_schema(self, tenant: TenantRecord) -> str:
        _handle(tenant)
        return "public"

    def _engine_for(self, tenant: TenantRecord) -> AsyncEngine:
        handle = _handle(tenant)
        engine = self._engines.get(handle)
        if engine is not None:
            self._engines.move_to_end(handle)
            return engine
        self._evict_idle()
        if len(self._engines) >= self._max_targets:
            raise PoolCapacityError(f"database pool cap reached ({self._max_targets})")
        engine = create_async_engine(self._secrets.resolve(handle))
        self._engines[handle] = engine
        return engine

    def _evict_idle(self) -> None:
        for handle in list(self._engines):
            engine = self._engines[handle]
            if engine.pool.checkedout() == 0:
                del self._engines[handle]

    def _admin(self) -> AsyncEngine:
        if self._admin_engine is None:
            self._admin_engine = create_async_engine(self._admin_dsn)
        return self._admin_engine

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        return AsyncSession(self._engine_for(tenant), expire_on_commit=False)

    async def provision(self, tenant: TenantRecord) -> None:
        handle = _handle(tenant)
        database = self._secrets.resolve(handle).rsplit("/", 1)[-1].split("?", 1)[0]
        quoted = self._admin().dialect.identifier_preparer.quote(database)
        async with self._admin().begin() as connection:
            exists = (
                await connection.execute(
                    sa.text("SELECT 1 FROM pg_database WHERE datname = :name"),
                    {"name": database},
                )
            ).scalar_one_or_none()
            if exists is None:
                await connection.execute(sa.text(f"CREATE DATABASE {quoted}"))

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        engine = self._engine_for(tenant)
        dsn = str(engine.url.render_as_string(hide_password=False))
        runner.upgrade_tenant("public")
        del dsn

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        if mode is DeprovisionMode.ARCHIVE:
            return
        handle = _handle(tenant)
        database = self._secrets.resolve(handle).rsplit("/", 1)[-1].split("?", 1)[0]
        engine = self._engines.pop(handle, None)
        if engine is not None:
            await engine.dispose()
        quoted = self._admin().dialect.identifier_preparer.quote(database)
        async with self._admin().begin() as connection:
            await connection.execute(
                sa.text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": database},
            )
            await connection.execute(sa.text(f"DROP DATABASE IF EXISTS {quoted}"))

    async def dispose(self) -> None:
        for engine in list(self._engines.values()):
            await engine.dispose()
        self._engines.clear()
        if self._admin_engine is not None:
            await self._admin_engine.dispose()
            self._admin_engine = None
```

Notes for the implementer: `migrate` as sketched is wrong — `MigrationRunner.upgrade_tenant(schema)` runs Alembic against `self._database_url` (the runner's own DSN), so a per-tenant database needs a runner bound to that tenant's DSN. Extend `MigrationRunner` with `upgrade_tenant_url(database_url, schema, revision="head")` (same as `upgrade_tenant` but overriding `sqlalchemy.url`) and call it with the tenant DSN; do the same for `tenant_version_url`. Add unit coverage for the URL override (monkeypatch `alembic.command.upgrade`). Drop the placeholder `dsn` lines from the sketch.

- [ ] **Step 4: Integration test with a real second database**

`tests/integration/test_database_strategy_db.py`: derive the tenant DSN from the container URL with a unique database name, use `MemorySecretProvider`, `provision` → `migrate` (real runner via the new URL override) → insert/read through a `TenantSession`; then `deprovision(PURGE)` and assert the database no longer exists (`pg_database` lookup); assert `dispose()` in a fixture teardown.

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/secrets.py src/jdlib/persistence/strategies/database.py src/jdlib/migrations/runner.py tests/unit/test_database_strategy.py tests/integration/test_database_strategy_db.py
git commit -m "feat: database-per-tenant strategy with secret-resolved handles"
```

---

### Task 3: RLS emission and fail-closed session binding

**Files:**
- Create: `src/jdlib/persistence/strategies/rls.py`
- Modify: `src/jdlib/config.py` (`RlsConfig`)
- Modify: `src/jdlib/persistence/strategies/shared.py` (RLS session setting)
- Create: `tests/unit/test_rls_policies.py`
- Create: `tests/integration/test_rls_db.py`

**Interfaces:**
- Produces: `RlsConfig(enabled: bool = False, app_role: str | None = None)` on `TenancyConfig.rls`; `emit_rls_policies(connection, *, metadata, app_role)`; `rls_eligible_tables(metadata) -> tuple[str, ...]`; `SharedSchemaStrategy(engine, schema="public", *, rls: RlsConfig | None = None)` setting `SET LOCAL app.tenant_id` when enabled; `verify_rls(engine, app_role)` startup self-check.

- [ ] **Step 1: Write the failing unit tests**

`tests/unit/test_rls_policies.py`:

```python
import sqlalchemy as sa

from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import rls_eligible_tables


def test_rls_eligible_tables_covers_tenant_routed_models():
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    tables = set(rls_eligible_tables(TenantBase.metadata))
    assert {"organizations", "teams", "tenant_settings", "audit_events", "invoices"} <= tables
```

`tests/integration/test_rls_db.py` (create a `NOBYPASSRLS` role, enable policies on the tenant schema, assert unset → zero rows/writes, set → scoped rows, new transaction → fail-closed again):

```python
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from jdlib.persistence.strategies.rls import emit_rls_policies
from jdlib.models.base import TenantBase
from tests.support.invoice import Invoice

APP_ROLE = "jdlib_rls_app"


@pytest.fixture()
async def rls_engine(postgres_url: str):
    engine = create_async_engine(postgres_url.replace("postgresql+psycopg", "postgresql+asyncpg"))
    async with engine.begin() as connection:
        await connection.execute(
            sa.text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') "
                f"THEN CREATE ROLE {APP_ROLE} LOGIN PASSWORD 'rls-test' NOBYPASSRLS; END IF; END $$;"
            )
        )
        await connection.execute(sa.text(f'GRANT USAGE ON SCHEMA "jt_test" TO {APP_ROLE}'))
        await connection.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "jt_test" TO {APP_ROLE}')
        )
        await connection.execute(sa.text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "jt_test" TO {APP_ROLE}'))
        await connection.run_sync(lambda sync: emit_rls_policies_sync(sync))
    yield engine
    await engine.dispose()


def emit_rls_policies_sync(connection):
    import asyncio

    asyncio.get_event_loop().run_until_complete(
        emit_rls_policies(connection, metadata=TenantBase.metadata, app_role=APP_ROLE)
    )


async def test_rls_fail_closed_and_scoped(async_engine, postgres_url, rls_engine):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    async with async_engine.begin() as connection:
        await connection.execute(sa.text('SET search_path TO "jt_test"'))
        await connection.execute(
            sa.insert(Invoice.__table__),
            [
                {"tenant_id": tenant_a, "id": uuid.uuid4(), "number": f"A-{uuid.uuid4().hex[:6]}"},
                {"tenant_id": tenant_b, "id": uuid.uuid4(), "number": f"B-{uuid.uuid4().hex[:6]}"},
            ],
        )
    app_dsn = postgres_url.replace("postgresql+psycopg", "postgresql+asyncpg").replace(
        "://", f"://{APP_ROLE}:rls-test@"
    )
    app_engine = create_async_engine(app_dsn)
    try:
        async with app_engine.connect() as connection:
            unset = (await connection.execute(sa.text("SELECT count(*) FROM invoices"))).scalar_one()
            assert unset == 0
            await connection.rollback()
        async with app_engine.connect() as connection:
            await connection.execute(
                sa.text("SET LOCAL app.tenant_id = :id"), {"id": str(tenant_a)}
            )
            scoped = (
                await connection.execute(
                    sa.text("SELECT tenant_id FROM invoices")
                )
            ).scalars().all()
            assert scoped == [tenant_a]
            await connection.rollback()
        async with app_engine.connect() as connection:
            again = (await connection.execute(sa.text("SELECT count(*) FROM invoices"))).scalar_one()
            assert again == 0
            with pytest.raises(sa.exc.IntegrityError):
                await connection.execute(sa.text("INSERT INTO invoices (tenant_id, id, number) VALUES ('00000000-0000-0000-0000-0000000000ff', gen_random_uuid(), 'X')"))
            await connection.rollback()
    finally:
        await app_engine.dispose()
```

Notes for the implementer: `emit_rls_policies` is async because connections are async — that fixture helper is awkward; prefer making `emit_rls_policies` a **sync** function taking a sync `sa.Connection` (migrations run under a sync Alembic connection), and call it in the fixture via `await connection.run_sync(lambda sync: emit_rls_policies(sync, metadata=..., app_role=...))`. Update Task 3 Step 3 accordingly (sync signature), and use `run_sync` everywhere. `gen_random_uuid()` requires pgcrypto on PG16? It is built-in since PG13 — fine.

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_rls_policies.py -v`
Expected: FAIL (missing module)

- [ ] **Step 3: Implement RLS**

`src/jdlib/persistence/strategies/rls.py`:

```python
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from jdlib.errors import StrategyCapabilityError
from jdlib.models.base import TenantRouted

_POLICY = (
    "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)"
)


def rls_eligible_tables(metadata: sa.MetaData) -> tuple[str, ...]:
    found: list[str] = []

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if table is not None and table.metadata is metadata:
                found.append(table.name)
            walk(subclass)

    walk(TenantRouted)
    return tuple(sorted(set(found)))


async def emit_rls_policies(
    connection: sa.Connection, *, metadata: sa.MetaData, app_role: str | None = None
) -> None:
    for name in rls_eligible_tables(metadata):
        quoted = connection.dialect.identifier_preparer.quote(name)
        await connection.execute(sa.text(f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY"))
        await connection.execute(sa.text(f"ALTER TABLE {quoted} FORCE ROW LEVEL SECURITY"))
        await connection.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {quoted}"))
        await connection.execute(
            sa.text(f"CREATE POLICY tenant_isolation ON {quoted} {_POLICY}")
        )
        if app_role:
            role = connection.dialect.identifier_preparer.quote(app_role)
            await connection.execute(
                sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {quoted} TO {role}")
            )


async def verify_rls(engine: AsyncEngine, app_role: str) -> None:
    async with engine.connect() as connection:
        role = (
            await connection.execute(
                sa.text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = :name"),
                {"name": app_role},
            )
        ).one_or_none()
    if role is None:
        raise StrategyCapabilityError(f"RLS app role does not exist: {app_role}")
    bypass, is_super = role
    if bypass or is_super:
        raise StrategyCapabilityError(f"RLS app role {app_role} can bypass row level security")
```

`src/jdlib/config.py`:

```python
class RlsConfig(BaseModel):
    enabled: bool = False
    app_role: str | None = None
```

`TenancyConfig.rls: RlsConfig = RlsConfig()`.

`SharedSchemaStrategy`: accept `rls: RlsConfig | None = None`; when `rls and rls.enabled`, set the setting in `session()`:

```python
        session = AsyncSession(self._engine, expire_on_commit=False)
        if self._rls is not None and self._rls.enabled:
            await session.execute(
                sa.text("SET LOCAL app.tenant_id = :tenant_id"),
                {"tenant_id": str(tenant.id)},
            )
        return session
```

Note: `SET LOCAL` requires an open transaction; SQLAlchemy's autobegin on `execute` provides it, and the UoW's single transaction uses the same connection — verify in the integration test.

- [ ] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_rls_policies.py tests/integration/test_rls_db.py -v -W error`

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/strategies/rls.py src/jdlib/config.py src/jdlib/persistence/strategies/shared.py tests/unit/test_rls_policies.py tests/integration/test_rls_db.py
git commit -m "feat: postgres RLS emission and fail-closed tenant binding"
```

---

### Task 4: Privileged tenant-plane purge

**Files:**
- Create: `src/jdlib/control/purge.py`
- Modify: `src/jdlib/control/registry.py` (call the purger for shared purge/destroy)
- Create: `tests/integration/test_tenant_purge.py`

**Interfaces:**
- Produces: `TenantPlanePurger(session_factory, *, issuer)` with `async purge(tenant: TenantRecord) -> dict[str, int]`; `TenantRegistry(..., purger: TenantPlanePurger | None = None)`.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_tenant_purge.py`:

```python
import uuid
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa

from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.control.purge import TenantPlanePurger
from jdlib.control.registry import TenantRegistry
from jdlib.context import ContextFactory, PRIVILEGE_ISSUER, TenantRecord
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from jdlib.authn.wiring import EntitlementAdapter, PrincipalDirectoryAdapter, TenantDirectoryAdapter
from jdlib.authz.reader import ControlAccessReader
from tests.support.invoice import Invoice
from tests.support.context_fakes import FrozenClock
from jdlib.models.settings import TenantSetting


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return "0001_tenant_baseline"


def _context_factory(control_session_factory, registry, reader) -> ContextFactory:
    return ContextFactory(
        config=__import__("jdlib.config", fromlist=["ContextConfig"]).ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=reader,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )


async def test_purge_deletes_tenant_plane_rows(control_session_factory, async_engine):
    registry = TenantRegistry(
        session_factory=control_session_factory, strategies={}, runner=_Runner(),
        audit=RecordingPlatformAudit(), desired_version="0001_tenant_baseline",
    )
    reader = ControlAccessReader(control_session_factory)
    factory = _context_factory(control_session_factory, registry, reader)
    purger = TenantPlanePurger(lambda: async_engine.connect().__aenter__(), factory=factory)
    ...
```

Note for the implementer: the sketch above for `TenantPlanePurger` construction is deliberately suggestive — the purger needs an **AsyncSession factory**, so pass the existing `session_factory` fixture used by other tests, not `async_engine.connect()`. Write the real test as:

```python
async def test_purge_deletes_tenant_plane_rows(control_session_factory, session_factory):
    registry = TenantRegistry(
        session_factory=control_session_factory, strategies={}, runner=_Runner(),
        audit=RecordingPlatformAudit(), desired_version="0001_tenant_baseline",
    )
    reader = ControlAccessReader(control_session_factory)
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=reader,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )
    purger = TenantPlanePurger(session_factory, factory=factory)
    tenant_id = uuid.uuid4()
    record = TenantRecord(id=tenant_id, slug="purge", status=TenantStatus.ACTIVE,
                          strategy=PlacementStrategy.SHARED, target_handle="jt_test")
    async with await _tenant_session(session_factory, tenant_id) as session:
        await session.add(Invoice(number="INV-PURGE"))
        await session.add(TenantSetting(key="billing.currency", value={"code": "EUR"}))
        await session.flush()
        await session.commit()
    counts = await purger.purge(record)
    assert counts["invoices"] == 1
    assert counts["tenant_settings"] == 1
    async with await _tenant_session(session_factory, tenant_id) as session:
        assert (await session.execute(sa.select(sa.func.count()).select_from(Invoice))).scalar_one() == 0
        assert (await session.execute(sa.select(sa.func.count()).select_from(TenantSetting))).scalar_one() == 0
```

where `_tenant_session` mirrors the isolation helper (creates the raw session, sets `search_path` to `jt_test`, wraps in `TenantSession` with a context for `tenant_id`). Import `ContextConfig` directly at the top instead of `__import__`.

- [ ] **Step 2: Implement the purger**

```python
from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import PRIVILEGE_ISSUER, ContextFactory, TenantRecord
from jdlib.persistence.models import tenant_table_map
from jdlib.persistence.session import TenantSession


class TenantPlanePurger:
    def __init__(self, session_factory: Callable[[], AsyncSession], *, factory: ContextFactory) -> None:
        self._session_factory = session_factory
        self._factory = factory

    async def purge(self, tenant: TenantRecord) -> dict[str, int]:
        context = self._factory.for_system(tenant, purpose="tenant.purge", issuer=PRIVILEGE_ISSUER)
        counts: dict[str, int] = {}
        async with TenantSession(self._session_factory(), context) as session:
            for name, model in tenant_table_map().items():
                counts[name] = await session.delete_where(model)
            await session.commit()
        return counts
```

Notes for the implementer: `for_system` is async — await it. `delete_where` on `SoftDelete` models requires a privileged context (system context qualifies). `tenant_table_map()` returns every `TenantRouted` model, including application resources registered at import time; the integration test must import `tests.support.invoice` first. Registry wiring: after `strategy.deprovision`, if `placement.strategy == "shared"` and `mode is not ARCHIVE`, call the purger and include `counts` in the `tenant.deprovisioned` audit metadata. The purger needs a `ContextFactory`; construct one in `TenantRegistry.__init__` from injected ports (add optional `purger` argument and call it when present, raising `ProvisioningError` when purge is requested without one).

- [ ] **Step 3: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/control/purge.py src/jdlib/control/registry.py tests/integration/test_tenant_purge.py
git commit -m "feat: privileged tenant-plane purge for shared deprovisioning"
```

---

### Task 5: Strategy matrix suite and docs

**Files:**
- Create: `tests/integration/test_strategy_matrix.py`
- Modify: `docs/jdlib/06-strategy-matrix.md` (note shipped behavior: search_path reset, purge coverage)
- Modify: `docs/jdlib/07-implementation-design.md` (file map: secrets.py, rls.py, purge.py)
- Modify: `docs/superpowers/plans/2026-09-21-jdlib-strategies-phase-5.md` (back-ports)

**Interfaces:** none new.

- [ ] **Step 1: Write the matrix test**

Parametrize over `("shared", "schema", "database")` (and `rls on/off` for shared): for each strategy, provision a tenant, run the shared behavioral assertions (scoped read isolation, cross-tenant `get` → `None`, stamped writes, `tenant_id` immutability, unscoped bulk DML rejection, entity-less count scoping) through `TenantSession`/`TenantRepository`. Reuse the per-strategy setup helpers from Tasks 1–2. Skip RLS-on cases when `rls` is not configured.

- [ ] **Step 2: Run the matrix**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_strategy_matrix.py -v -W error`

- [ ] **Step 3: Docs sync and commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add tests/integration/test_strategy_matrix.py docs
git commit -m "test: strategy matrix; docs sync"
```

---

## Phase 5 Exit Criteria

- [ ] Full suite green on real PostgreSQL 16.
- [ ] Schema strategy: validated handles, checkout-set `search_path`, per-schema DDL/migration, cross-schema isolation proven.
- [ ] Database strategy: opaque handles, secret resolution, capped pool cache with no live eviction, real second-database provision/migrate/deprovision.
- [ ] RLS: policies on every tenant-routed table, fail-closed unset setting, scoped reads/writes as the `NOBYPASSRLS` role, startup self-check.
- [ ] Shared `purge`/`destroy` deletes tenant-plane rows with audited counts; `archive` untouched.
- [ ] Strategy matrix runs the same behavioral assertions under all three strategies.
- [ ] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 6 — Phase 10: durable audit sink, `jdlib.testing` kit, FastAPI/CLI integrations, public API exports, docs.
