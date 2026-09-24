from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
)
from jdlib.authz.reader import ControlAccessReader
from jdlib.config import ContextConfig, RlsConfig
from jdlib.context import ContextFactory, Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.control.models import Tenant
from jdlib.control.purge import TenantPlanePurger
from jdlib.control.registry import TenantRegistry
from jdlib.errors import ProvisioningError
from jdlib.models.base import TenantBase
from jdlib.models.org import Organization, Team
from jdlib.models.settings import TenantSetting
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.rls import emit_rls_policies
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from tests.integration.rls_support import run_rls_ddl
from tests.support.context_fakes import FrozenClock, RecordingPrivilegeAudit
from tests.support.invoice import Invoice, LineItem

TENANT_SCHEMA = "jt_test"
DESIRED_VERSION = "0002_security_audit_columns"
APP_ROLE = "jdlib_rls_app"
APP_PASSWORD = "rls-test"


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


async def _row_count(session_factory, tenant_id: uuid.UUID, model: type) -> int:
    async with await _tenant_session(session_factory, tenant_id) as session:
        result = await session.execute(sa.select(sa.func.count()).select_from(model))
        return int(result.scalar_one())


async def _invoice_count(session_factory, tenant_id: uuid.UUID) -> int:
    return await _row_count(session_factory, tenant_id, Invoice)


def _app_url(postgres_url: str) -> URL:
    return sa.engine.make_url(postgres_url).set(
        drivername="postgresql+asyncpg", username=APP_ROLE, password=APP_PASSWORD
    )


@pytest.fixture()
async def rls_app_engine(async_engine: AsyncEngine, postgres_url: str):
    def _install(sync: sa.Connection) -> None:
        sync.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        sync.execute(
            sa.text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') "
                f"THEN CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PASSWORD}' NOBYPASSRLS; "
                "END IF; END $$;"
            )
        )
        sync.execute(sa.text(f'GRANT USAGE ON SCHEMA "{TENANT_SCHEMA}" TO {APP_ROLE}'))
        sync.execute(
            sa.text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "
                f'"{TENANT_SCHEMA}" TO {APP_ROLE}'
            )
        )
        sync.execute(
            sa.text(
                f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{TENANT_SCHEMA}" TO {APP_ROLE}'
            )
        )
        emit_rls_policies(sync, metadata=TenantBase.metadata, app_role=APP_ROLE)

    await run_rls_ddl(async_engine, _install)
    engine = create_async_engine(_app_url(postgres_url))
    yield engine
    await engine.dispose()


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


async def _seed_org_tree(session_factory, tenant_id: uuid.UUID, prefix: str) -> None:
    org = Organization(id=uuid.uuid4(), name=f"{prefix} Org", slug=f"{prefix.lower()}-org")
    team = Team(
        id=uuid.uuid4(),
        organization_id=org.id,
        name=f"{prefix} Team",
        slug=f"{prefix.lower()}-team",
    )
    invoice = Invoice(
        id=uuid.uuid4(),
        number=f"INV-{prefix}",
        status="draft",
        organization_id=org.id,
        team_id=team.id,
    )
    line_item = LineItem(invoice_id=invoice.id, amount_cents=500)
    async with await _tenant_session(session_factory, tenant_id) as session:
        await session.add(org)
        await session.add(team)
        await session.add(invoice)
        await session.add(line_item)
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


async def test_purge_deletes_children_before_parents(control_session_factory, session_factory):
    registry, _ = _registry(control_session_factory, strategies={})
    purger = TenantPlanePurger(
        _schema_factory(session_factory),
        factory=_context_factory(control_session_factory, registry),
    )
    target_id, other_id = uuid.uuid4(), uuid.uuid4()
    await _seed_org_tree(session_factory, target_id, "TARGET")
    await _seed_org_tree(session_factory, other_id, "OTHER")
    counts = await purger.purge(_record(target_id))
    assert counts["organizations"] == 1
    assert counts["teams"] == 1
    assert counts["invoices"] == 1
    assert counts["line_items"] == 1
    for model in (Organization, Team, Invoice, LineItem):
        assert await _row_count(session_factory, target_id, model) == 0
        assert await _row_count(session_factory, other_id, model) == 1


async def test_purge_with_rls_binds_tenant_setting(
    control_session_factory, session_factory, rls_app_engine
):
    probe, _ = _registry(control_session_factory, strategies={})
    purger = TenantPlanePurger(
        _schema_factory(async_sessionmaker(rls_app_engine, expire_on_commit=False)),
        factory=_context_factory(control_session_factory, probe),
        rls=RlsConfig(enabled=True, app_role=APP_ROLE),
    )
    registry, audit = _registry(control_session_factory, purger=purger)
    tenant = await _archived_tenant(registry)
    await _seed_invoice(session_factory, tenant.id, "INV-RLS")
    async with rls_app_engine.connect() as connection:
        await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        hidden = (
            await connection.execute(sa.text("SELECT count(*) FROM invoices"))
        ).scalar_one()
        await connection.rollback()
    assert hidden == 0
    purged = await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE)
    assert purged.status == TenantStatus.DELETED
    assert await _invoice_count(session_factory, tenant.id) == 0
    entry = audit.entries[-1]
    assert entry["action"] == "tenant.deprovisioned"
    assert entry["metadata"]["tenant_counts"]["invoices"] == 1


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
    assert entry["metadata"]["tenant_counts"]["invoices"] == 1
    assert "invoices" not in entry["metadata"]["counts"]


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
