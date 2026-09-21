import uuid

import pytest

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import StrategyCapabilityError
from jdlib.persistence.router import SessionRouter
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.shared import SharedSchemaStrategy


class _FakeEngine:
    sync_engine = None


def _record(strategy: PlacementStrategy) -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE, strategy=strategy
    )


def test_shared_strategy_capabilities():
    strategy = SharedSchemaStrategy(_FakeEngine())  # type: ignore[arg-type]
    assert strategy.name == "shared"
    assert strategy.capabilities == StrategyCapabilities(
        supports_rls=True, supports_ddl=False
    )


async def test_router_requires_known_strategy():
    router = SessionRouter({PlacementStrategy.SHARED: SharedSchemaStrategy(_FakeEngine())})  # type: ignore[arg-type]
    with pytest.raises(StrategyCapabilityError):
        await router.session(_record(PlacementStrategy.DATABASE))


async def test_router_routes_shared_tenant():
    router = SessionRouter({PlacementStrategy.SHARED: SharedSchemaStrategy(_FakeEngine())})  # type: ignore[arg-type]
    session = await router.session(_record(PlacementStrategy.SHARED))
    assert session is not None
    await session.close()
