from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import PoolCapacityError, StrategyCapabilityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.secrets import EnvSecretProvider, MemorySecretProvider
from jdlib.persistence.strategies.database import DatabasePerTenantStrategy
from jdlib.persistence.strategies.deprovision import DeprovisionMode

_TENANT_DSNS = {
    "db-acme": "postgresql+asyncpg://u:p@h/acme",
    "db-beta": "postgresql+asyncpg://u:p@h/beta",
    "db-gamma": "postgresql+asyncpg://u:p@h/gamma",
}


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return "0001_tenant_baseline"


class _UrlRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def upgrade_tenant_url(
        self, database_url: str, schema: str, revision: str = "head"
    ) -> None:
        self.calls.append((database_url, schema, revision))


class _FakePool:
    def __init__(self) -> None:
        self.checked_out = 0

    def checkedout(self) -> int:
        return self.checked_out


class _FakeEngine:
    def __init__(self, dsn: str) -> None:
        self.url = dsn
        self.pool = _FakePool()
        self.disposed = False

    async def dispose(self) -> None:
        self.disposed = True


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeAdminConnection:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def __enter__(self) -> _FakeAdminConnection:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, statement: object, params: object = None) -> _FakeResult:
        sql = str(statement)
        self.queries.append(sql)
        if "to_regclass" in sql:
            return _FakeResult("public.alembic_version")
        return _FakeResult("0001_tenant_baseline")


class _FakeAdminEngine:
    def __init__(self) -> None:
        self.connection = _FakeAdminConnection()
        self.disposed = False

    def begin(self) -> _FakeAdminConnection:
        return self.connection

    def dispose(self) -> None:
        self.disposed = True


def _record(handle: str | None = "db-acme") -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.DATABASE, target_handle=handle,
    )


def _strategy(*, max_targets: int = 32) -> DatabasePerTenantStrategy:
    return DatabasePerTenantStrategy(
        admin_dsn="postgresql+asyncpg://u:p@h/db",
        secrets=MemorySecretProvider(_TENANT_DSNS),
        runner=_Runner(),
        max_targets=max_targets,
    )


def _fake_engines(monkeypatch) -> dict[str, _FakeEngine]:
    created: dict[str, _FakeEngine] = {}

    def fake_create(dsn: str, **kwargs: object) -> _FakeEngine:
        engine = _FakeEngine(dsn)
        created[dsn] = engine
        return engine

    monkeypatch.setattr(
        "jdlib.persistence.strategies.database.create_async_engine", fake_create
    )
    monkeypatch.setattr(
        "jdlib.persistence.strategies.database.AsyncSession",
        lambda engine, **kwargs: engine,
    )
    return created


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


def test_memory_secret_provider_reports_missing_handle():
    with pytest.raises(KeyError):
        MemorySecretProvider(_TENANT_DSNS).resolve("db-missing")


def test_env_secret_provider_reads_environment(monkeypatch):
    monkeypatch.setenv("JDLIB_TENANT_DB_DB_ACME", "postgresql+asyncpg://u:p@h/acme")
    assert EnvSecretProvider().resolve("db-acme") == "postgresql+asyncpg://u:p@h/acme"


def test_env_secret_provider_reports_missing_handle(monkeypatch):
    monkeypatch.delenv("JDLIB_TENANT_DB_DB_ACME", raising=False)
    with pytest.raises(KeyError):
        EnvSecretProvider().resolve("db-acme")


def test_env_secret_provider_custom_prefix(monkeypatch):
    monkeypatch.setenv("ACME_TENANT_DB_X", "postgresql+asyncpg://u:p@h/x")
    assert EnvSecretProvider("ACME_TENANT_DB_").resolve("x") == "postgresql+asyncpg://u:p@h/x"


@pytest.mark.parametrize(
    "handle",
    [None, "", "db-acme\n", "DB-acme", "db_acme", "postgresql+asyncpg://u:p@h/x"],
)
def test_invalid_handles_fail_closed(handle):
    with pytest.raises(StrategyCapabilityError):
        _strategy().migration_schema(_record(handle=handle))


def test_unknown_handle_fails_closed():
    with pytest.raises(StrategyCapabilityError):
        _strategy().migration_schema(_record(handle="db-unknown"))


def test_migration_schema_is_public():
    assert _strategy().migration_schema(_record()) == "public"


async def test_migrate_uses_tenant_dsn():
    runner = _UrlRunner()
    await _strategy().migrate(_record(), runner)
    assert runner.calls == [("postgresql+asyncpg://u:p@h/acme", "public", "head")]


async def test_deprovision_archive_is_a_noop():
    strategy = DatabasePerTenantStrategy(
        admin_dsn="postgresql+asyncpg://u:p@h/db",
        secrets=MemorySecretProvider({}),
        runner=_Runner(),
    )
    await strategy.deprovision(_record(handle=None), DeprovisionMode.ARCHIVE)


async def test_checked_out_engine_is_never_evicted(monkeypatch):
    created = _fake_engines(monkeypatch)
    strategy = _strategy(max_targets=1)
    session_a = await strategy.session(_record(handle="db-acme"))
    engine_a = created["postgresql+asyncpg://u:p@h/acme"]
    assert session_a is engine_a
    engine_a.pool.checked_out = 1
    with pytest.raises(PoolCapacityError):
        await strategy.session(_record(handle="db-beta"))
    assert engine_a.disposed is False
    engine_a.pool.checked_out = 0
    session_b = await strategy.session(_record(handle="db-beta"))
    assert engine_a.disposed is True
    assert session_b is created["postgresql+asyncpg://u:p@h/beta"]


async def test_idle_engines_evict_least_recently_used(monkeypatch):
    created = _fake_engines(monkeypatch)
    strategy = _strategy(max_targets=2)
    await strategy.session(_record(handle="db-acme"))
    await strategy.session(_record(handle="db-beta"))
    await strategy.session(_record(handle="db-acme"))
    await strategy.session(_record(handle="db-gamma"))
    assert created["postgresql+asyncpg://u:p@h/beta"].disposed is True
    assert created["postgresql+asyncpg://u:p@h/acme"].disposed is False
    assert created["postgresql+asyncpg://u:p@h/gamma"].disposed is False


def test_upgrade_tenant_url_overrides_sqlalchemy_url(monkeypatch):
    captured: dict[str, object] = {}

    def fake_upgrade(config, revision):
        captured["url"] = config.get_main_option("sqlalchemy.url")
        captured["schema"] = config.attributes["tenant_schema"]
        captured["revision"] = revision

    monkeypatch.setattr("jdlib.migrations.runner.command.upgrade", fake_upgrade)
    runner = MigrationRunner("postgresql+psycopg://u:p@h/base")
    runner.upgrade_tenant_url("postgresql+asyncpg://u:p@h/tenant_db", "public")
    assert captured == {
        "url": "postgresql+psycopg://u:p@h/tenant_db",
        "schema": "public",
        "revision": "head",
    }


def test_tenant_version_url_overrides_sqlalchemy_url(monkeypatch):
    engine = _FakeAdminEngine()
    captured: dict[str, str] = {}

    def fake_create(url, **kwargs):
        captured["url"] = url
        return engine

    monkeypatch.setattr(sa, "create_engine", fake_create)
    runner = MigrationRunner("postgresql+psycopg://u:p@h/base")
    version = runner.tenant_version_url("postgresql+asyncpg://u:p@h/tenant_db", "public")
    assert version == "0001_tenant_baseline"
    assert captured["url"] == "postgresql+psycopg://u:p@h/tenant_db"
    assert engine.disposed is True


def test_percent_encoded_dsn_survives_config_interpolation(monkeypatch):
    secret = "p%40ss%25word"
    dsn = f"postgresql+asyncpg://u:{secret}@h/tenant_db"
    captured: list[str] = []
    messages: list[str] = []

    def fake_upgrade(config, revision):
        captured.append(config.get_main_option("sqlalchemy.url"))

    monkeypatch.setattr("jdlib.migrations.runner.command.upgrade", fake_upgrade)
    monkeypatch.setattr(sa, "create_engine", lambda *args, **kwargs: _FakeAdminEngine())
    runner = MigrationRunner(dsn)
    calls = (runner.upgrade_control, lambda: runner.upgrade_tenant_url(dsn, "t_abc"))
    for call in calls:
        try:
            call()
        except Exception as exc:
            messages.append(str(exc))
    assert secret not in "".join(messages)
    assert messages == []
    expected = f"postgresql+psycopg://u:{secret}@h/tenant_db"
    assert captured == [expected, expected]
