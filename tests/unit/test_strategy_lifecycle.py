import uuid

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.shared import SharedSchemaStrategy


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        self.calls.append((schema, revision))


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
