import uuid

import pytest

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
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


async def test_invalid_handle_fails_closed():
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    with pytest.raises(StrategyCapabilityError):
        await strategy.session(_record(handle="public"))


async def test_migrate_uses_handle_schema():
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    runner = _Runner()
    await strategy.migrate(_record(), runner)  # type: ignore[arg-type]
    assert runner.calls == [("t_acme", "head")]
    assert strategy.migration_schema(_record()) == "t_acme"


async def test_deprovision_archive_is_a_noop():
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    await strategy.deprovision(_record(), DeprovisionMode.ARCHIVE)


@pytest.mark.parametrize("mode", [DeprovisionMode.PURGE, DeprovisionMode.DESTROY])
async def test_deprovision_drop_requires_engine(mode):
    strategy = SchemaPerTenantStrategy(engine=None, runner=_Runner())  # type: ignore[arg-type]
    with pytest.raises(StrategyCapabilityError):
        await strategy.deprovision(_record(), mode)
