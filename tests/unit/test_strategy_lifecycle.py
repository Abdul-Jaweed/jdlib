from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import ProvisioningError, StrategyCapabilityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.shared import SharedSchemaStrategy


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        self.calls.append((schema, revision))


class _UpgradeRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str | None, str]] = []

    def __call__(self, config, revision: str) -> None:
        self.calls.append((config.attributes["tenant_schema"], revision))


def test_upgrade_tenant_accepts_deployment_configured_schemas(monkeypatch):
    recorder = _UpgradeRecorder()
    monkeypatch.setattr("jdlib.migrations.runner.command.upgrade", recorder)
    runner = MigrationRunner("postgresql+psycopg://unused")
    for schema in ("public", "jt_test", "tenant_plane", "a", "x" * 63):
        runner.upgrade_tenant(schema)
    assert [schema for schema, _ in recorder.calls] == [
        "public",
        "jt_test",
        "tenant_plane",
        "a",
        "x" * 63,
    ]


@pytest.mark.parametrize(
    "schema",
    ["", "T_Bad", "bad-name", 'bad"quote', "bad;drop", "9leading", "x" * 64],
)
def test_upgrade_tenant_rejects_unsafe_schemas(monkeypatch, schema):
    calls: list[str] = []
    monkeypatch.setattr(
        "jdlib.migrations.runner.command.upgrade", lambda *args, **kwargs: calls.append("upgrade")
    )
    runner = MigrationRunner("postgresql+psycopg://unused")
    with pytest.raises(ProvisioningError):
        runner.upgrade_tenant(schema)
    assert calls == []


@pytest.mark.parametrize("schema", ["public", "jt_test", "schema1", "t_", "t_A"])
def test_provision_tenant_schema_keeps_strict_tenant_prefix(monkeypatch, schema):
    calls: list[str] = []
    monkeypatch.setattr(sa, "create_engine", lambda *args, **kwargs: calls.append("engine"))
    monkeypatch.setattr(
        "jdlib.migrations.runner.command.upgrade", lambda *args, **kwargs: calls.append("upgrade")
    )
    runner = MigrationRunner("postgresql+psycopg://unused")
    with pytest.raises(ProvisioningError):
        runner.provision_tenant_schema(schema)
    assert calls == []


@pytest.mark.parametrize("schema", ["Bad-Schema", "T_UP", 'x"; DROP', "", "1x", "x" * 64])
def test_shared_strategy_rejects_invalid_schema(schema):
    with pytest.raises(StrategyCapabilityError):
        SharedSchemaStrategy(engine=None, schema=schema)  # type: ignore[arg-type]


@pytest.mark.parametrize("schema", ["public", "jt_test"])
def test_shared_strategy_accepts_deployment_configured_schemas(schema):
    SharedSchemaStrategy(engine=None, schema=schema)  # type: ignore[arg-type]


def _record() -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )


def test_deprovision_modes_are_frozen():
    assert {mode.value for mode in DeprovisionMode} == {"archive", "purge", "destroy"}


async def test_shared_provision_is_a_noop():
    strategy = SharedSchemaStrategy(engine=None, schema="jt_test")  # type: ignore[arg-type]
    await strategy.provision(_record())


async def test_shared_migrate_runs_tenant_chain_for_schema():
    strategy = SharedSchemaStrategy(engine=None, schema="jt_test")  # type: ignore[arg-type]
    runner = _Runner()
    await strategy.migrate(_record(), runner)  # type: ignore[arg-type]
    assert runner.calls == [("jt_test", "head")]


async def test_shared_deprovision_is_a_noop_for_all_modes():
    strategy = SharedSchemaStrategy(engine=None, schema="jt_test")  # type: ignore[arg-type]
    for mode in DeprovisionMode:
        await strategy.deprovision(_record(), mode)
