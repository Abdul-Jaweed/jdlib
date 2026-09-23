from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
)
from jdlib.authz.reader import ControlAccessReader
from jdlib.config import ContextConfig
from jdlib.context import ContextFactory, Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.control.models import Tenant
from jdlib.control.purge import TenantPlanePurger
from jdlib.control.registry import TenantRegistry
from jdlib.errors import ProvisioningError
from jdlib.models.settings import TenantSetting
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from tests.support.context_fakes import FrozenClock, RecordingPrivilegeAudit
from tests.support.invoice import Invoice

TENANT_SCHEMA = "jt_test"
DESIRED_VERSION = "0001_tenant_baseline"


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return DESIRED_VERSION


class _RecordingPurger:
    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []

    async def purge(self, tenant: TenantRecord) -> dict[str, int]:
        self.calls.append(tenant.id)
        return {"invoices": 1}


def _context_factory(control_session_factory, registry: TenantRegistry) -> ContextFactory:
    reader = ControlAccessReader(control_session_factory)
    return ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=reader,
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )


def _schema_factory(
    session_factory: Callable[[], AsyncSession], schema: str = TENANT_SCHEMA
) -> Callable[[], AsyncSession]:
    def factory() -> AsyncSession:
        session = session_factory()

        def _bind(
            sync_session: sa.orm.Session, transaction: object, connection: sa.Connection
        ) -> None:
            connection.exec_driver_sql(f'SET search_path TO "{schema}"')

        sa.event.listen(session.sync_session, "after_begin", _bind)
        return session

    return factory


def _tenant_context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="purge",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


async def _tenant_session(session_factory, tenant_id: uuid.UUID) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
    return TenantSession(raw, _tenant_context(tenant_id))


async def _invoice_count(session_factory, tenant_id: uuid.UUID) -> int:
    async with await _tenant_session(session_factory, tenant_id) as session:
        result = await session.execute(sa.select(sa.func.count()).select_from(Invoice))
        return int(result.scalar_one())


def _registry(control_session_factory, *, strategies=None, purger=None):
    audit = RecordingPlatformAudit()
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies=(
            strategies
            if strategies is not None
            else {PlacementStrategy.SHARED: SharedSchemaStrategy(engine=None, schema=TENANT_SCHEMA)}
        ),
        runner=_Runner(),
        audit=audit,
        desired_version=DESIRED_VERSION,
        purger=purger,
    )
    return registry, audit


async def _archived_tenant(registry: TenantRegistry) -> Tenant:
    tenant = await registry.create(
        slug=f"purge-{uuid.uuid4().hex[:8]}",
        name="Purge Tenant",
        strategy=PlacementStrategy.SHARED,
        target_handle=TENANT_SCHEMA,
    )
    await registry.provision(tenant.id)
    await registry.archive(tenant.id)
    return tenant


async def _seed_invoice(session_factory, tenant_id: uuid.UUID, number: str) -> None:
    async with await _tenant_session(session_factory, tenant_id) as session:
        await session.add(Invoice(number=number))
        await session.commit()


def _record(tenant_id: uuid.UUID) -> TenantRecord:
    return TenantRecord(
        id=tenant_id,
        slug="purge",
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SHARED,
        target_handle=TENANT_SCHEMA,
    )


async def test_purge_deletes_tenant_plane_rows(control_session_factory, session_factory):
    registry, _ = _registry(control_session_factory, strategies={})
    purger = TenantPlanePurger(
        _schema_factory(session_factory),
        factory=_context_factory(control_session_factory, registry),
    )
    tenant_id = uuid.uuid4()
    async with await _tenant_session(session_factory, tenant_id) as session:
        await session.add(Invoice(number="INV-PURGE"))
        await session.add(TenantSetting(key="billing.currency", value={"code": "EUR"}))
        await session.flush()
        await session.commit()
    counts = await purger.purge(_record(tenant_id))
    assert counts["invoices"] == 1
    assert counts["tenant_settings"] == 1
    async with await _tenant_session(session_factory, tenant_id) as session:
        assert (
            await session.execute(sa.select(sa.func.count()).select_from(Invoice))
        ).scalar_one() == 0
        assert (
            await session.execute(sa.select(sa.func.count()).select_from(TenantSetting))
        ).scalar_one() == 0


async def test_purge_only_deletes_the_target_tenant_rows(
    control_session_factory, session_factory
):
    registry, _ = _registry(control_session_factory, strategies={})
    purger = TenantPlanePurger(
        _schema_factory(session_factory),
        factory=_context_factory(control_session_factory, registry),
    )
    target_id, other_id = uuid.uuid4(), uuid.uuid4()
    await _seed_invoice(session_factory, target_id, "INV-TARGET")
    await _seed_invoice(session_factory, other_id, "INV-OTHER")
    counts = await purger.purge(_record(target_id))
    assert counts["invoices"] == 1
    assert await _invoice_count(session_factory, target_id) == 0
    assert await _invoice_count(session_factory, other_id) == 1


@pytest.mark.parametrize("mode", [DeprovisionMode.PURGE, DeprovisionMode.DESTROY])
async def test_shared_deprovision_purges_and_audits_counts(
    control_session_factory, session_factory, mode
):
    probe, _ = _registry(control_session_factory, strategies={})
    purger = TenantPlanePurger(
        _schema_factory(session_factory), factory=_context_factory(control_session_factory, probe)
    )
    registry, audit = _registry(control_session_factory, purger=purger)
    tenant = await _archived_tenant(registry)
    await _seed_invoice(session_factory, tenant.id, f"INV-{mode.value.upper()}")
    purged = await registry.deprovision(tenant.id, mode=mode)
    assert purged.status == TenantStatus.DELETED
    assert await _invoice_count(session_factory, tenant.id) == 0
    entry = audit.entries[-1]
    assert entry["action"] == "tenant.deprovisioned"
    assert entry["metadata"]["mode"] == mode.value
    assert entry["metadata"]["counts"]["invoices"] == 1


async def test_shared_deprovision_without_purger_fails_closed(
    control_session_factory, session_factory
):
    registry, _ = _registry(control_session_factory)
    tenant = await _archived_tenant(registry)
    await _seed_invoice(session_factory, tenant.id, "INV-KEEP")
    with pytest.raises(ProvisioningError, match="purger"):
        await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE)
    assert (await registry.get(tenant.id)).status == TenantStatus.ARCHIVED
    assert await _invoice_count(session_factory, tenant.id) == 1


async def test_archive_never_calls_the_purger(control_session_factory):
    purger = _RecordingPurger()
    registry, _ = _registry(control_session_factory, purger=purger)
    tenant = await _archived_tenant(registry)
    archived = await registry.deprovision(tenant.id, mode=DeprovisionMode.ARCHIVE)
    assert archived.status == TenantStatus.ARCHIVED
    assert purger.calls == []
