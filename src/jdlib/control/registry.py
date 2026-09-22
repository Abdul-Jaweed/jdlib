from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from typing import Protocol

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord
from jdlib.control.audit import PlatformAudit
from jdlib.control.enums import MigrationStatus, PlacementStrategy, RelocationPhase, TenantStatus
from jdlib.control.models import (
    Membership,
    Tenant,
    TenantMigrationState,
    TenantPlacement,
    TenantRelocation,
)
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import (
    ProvisioningError,
    TenantNotFound,
    TenantNotWritable,
    TenantSuspended,
)
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.base import IsolationStrategy
from jdlib.persistence.strategies.deprovision import DeprovisionMode

CRITICAL_RELOCATION_PHASES = {
    RelocationPhase.COPYING.value,
    RelocationPhase.VERIFYING.value,
    RelocationPhase.FLIPPING.value,
    RelocationPhase.POST_FLIP_VERIFICATION.value,
}


class SeedHook(Protocol):
    async def seed(self, tenant: TenantRecord) -> None: ...


class _NoopSeedHook:
    async def seed(self, tenant: TenantRecord) -> None:
        return None


class TenantRegistry:
    def __init__(
        self,
        *,
        session_factory: Callable[[], AsyncSession],
        strategies: Mapping[PlacementStrategy, IsolationStrategy],
        runner: MigrationRunner,
        audit: PlatformAudit,
        seeder: SeedHook | None = None,
        desired_version: str = "0001_tenant_baseline",
    ) -> None:
        self._session_factory = session_factory
        self._strategies = dict(strategies)
        self._runner = runner
        self._audit = audit
        self._seeder = seeder or _NoopSeedHook()
        self._desired_version = desired_version

    def _strategy_for(self, placement: TenantPlacement) -> IsolationStrategy:
        strategy = self._strategies.get(PlacementStrategy(placement.strategy))
        if strategy is None:
            raise ProvisioningError("no strategy registered for tenant placement")
        return strategy

    async def _control(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def get(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            tenant: Tenant | None = await session.get(Tenant, tenant_id)
            if tenant is None:
                raise TenantNotFound(str(tenant_id))
            return tenant

    async def create(
        self,
        *,
        slug: str,
        name: str,
        strategy: PlacementStrategy,
        target_handle: str,
        region: str | None = None,
        parent_tenant_id: uuid.UUID | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> Tenant:
        async with await self._control() as session:
            existing: Tenant | None = (
                await session.execute(sa.select(Tenant).where(Tenant.slug == slug))
            ).scalar_one_or_none()
            if existing is not None:
                return existing
            tenant = Tenant(
                slug=slug,
                name=name,
                status=TenantStatus.PROVISIONING.value,
                parent_tenant_id=parent_tenant_id,
            )
            session.add(tenant)
            await session.flush()
            session.add(
                TenantPlacement(
                    tenant_id=tenant.id,
                    strategy=strategy.value,
                    target_handle=target_handle,
                    region=region,
                )
            )
            session.add(
                TenantMigrationState(
                    tenant_id=tenant.id,
                    current_version=None,
                    desired_version=self._desired_version,
                    status=MigrationStatus.PENDING.value,
                )
            )
            await self._audit.record(
                action="tenant.created",
                tenant_id=tenant.id,
                actor_id=actor_id,
                metadata={"slug": slug},
            )
            await session.commit()
            return tenant

    async def _lock(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> None:
        await session.execute(
            sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))").bindparams(
                key=f"jdlib:tenant:{tenant_id}"
            )
        )

    async def provision(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant: Tenant | None = await session.get(Tenant, tenant_id)
            if tenant is None:
                raise TenantNotFound(str(tenant_id))
            if tenant.status == TenantStatus.ACTIVE.value:
                return tenant
            placement = await session.get(TenantPlacement, tenant_id)
            state = await session.get(TenantMigrationState, tenant_id)
            assert placement is not None and state is not None
            record = _record(tenant, placement)
            strategy = self._strategy_for(placement)
            try:
                await strategy.provision(record)
                state.status = MigrationStatus.RUNNING.value
                await session.flush()
                await strategy.migrate(record, self._runner)
                state.current_version = state.desired_version
                state.status = MigrationStatus.SUCCESS.value
                await self._seeder.seed(record)
                await self._audit.record(
                    action="tenant.migration.succeeded", tenant_id=tenant_id, actor_id=None
                )
            except Exception as exc:
                state.status = MigrationStatus.FAILED.value
                state.last_error = str(exc)
                await session.commit()
                await self._audit.record(
                    action="tenant.migration.failed",
                    tenant_id=tenant_id,
                    actor_id=None,
                    metadata={"error": str(exc)},
                )
                raise
            tenant.status = TenantStatus.ACTIVE.value
            tenant.suspended_reason = None
            await self._audit.record(
                action="tenant.activated", tenant_id=tenant_id, actor_id=None
            )
            await session.commit()
            return tenant

    async def migrate(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant: Tenant | None = await session.get(Tenant, tenant_id)
            if tenant is None:
                raise TenantNotFound(str(tenant_id))
            placement = await session.get(TenantPlacement, tenant_id)
            state = await session.get(TenantMigrationState, tenant_id)
            assert placement is not None and state is not None
            record = _record(tenant, placement)
            try:
                await self._strategies[PlacementStrategy(placement.strategy)].migrate(
                    record, self._runner
                )
            except Exception as exc:
                state.status = MigrationStatus.FAILED.value
                state.last_error = str(exc)
                if tenant.status == TenantStatus.ACTIVE.value:
                    tenant.status = TenantStatus.SUSPENDED.value
                    tenant.suspended_reason = "migration_failed"
                await session.commit()
                await self._audit.record(
                    action="tenant.migration.failed",
                    tenant_id=tenant_id,
                    actor_id=None,
                    metadata={"error": str(exc)},
                )
                raise
            state.current_version = state.desired_version
            state.status = MigrationStatus.SUCCESS.value
            state.last_error = None
            await self._audit.record(
                action="tenant.migration.succeeded", tenant_id=tenant_id, actor_id=None
            )
            await session.commit()
            return tenant

    async def suspend(
        self, tenant_id: uuid.UUID, *, reason: str, actor_id: uuid.UUID | None = None
    ) -> Tenant:
        return await self._transition(
            tenant_id,
            TenantStatus.SUSPENDED,
            action="tenant.suspended",
            reason=reason,
            actor_id=actor_id,
        )

    async def resume(
        self, tenant_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> Tenant:
        return await self._transition(
            tenant_id, TenantStatus.ACTIVE, action="tenant.resumed", reason=None, actor_id=actor_id
        )

    async def archive(
        self, tenant_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> Tenant:
        return await self._transition(
            tenant_id,
            TenantStatus.ARCHIVED,
            action="tenant.archived",
            reason=None,
            actor_id=actor_id,
        )

    async def _transition(
        self,
        tenant_id: uuid.UUID,
        target: TenantStatus,
        *,
        action: str,
        reason: str | None,
        actor_id: uuid.UUID | None,
    ) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant: Tenant | None = await session.get(Tenant, tenant_id)
            if tenant is None:
                raise TenantNotFound(str(tenant_id))
            tenant.status = target.value
            tenant.suspended_reason = reason if target is TenantStatus.SUSPENDED else None
            await self._audit.record(
                action=action, tenant_id=tenant_id, actor_id=actor_id, metadata={"reason": reason}
            )
            await session.commit()
            return tenant

    async def deprovision(
        self,
        tenant_id: uuid.UUID,
        *,
        mode: DeprovisionMode,
        actor_id: uuid.UUID | None = None,
        detach_children: bool = False,
    ) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant: Tenant | None = await session.get(Tenant, tenant_id)
            if tenant is None:
                raise TenantNotFound(str(tenant_id))
            children = (
                await session.execute(
                    sa.select(Tenant.id).where(Tenant.parent_tenant_id == tenant_id)
                )
            ).scalars().all()
            if children and not detach_children:
                raise ProvisioningError("tenant has children; detach them explicitly")
            if children:
                await session.execute(
                    sa.update(Tenant)
                    .where(Tenant.parent_tenant_id == tenant_id)
                    .values(parent_tenant_id=None)
                )
            placement = await session.get(TenantPlacement, tenant_id)
            assert placement is not None
            record = _record(tenant, placement)
            if mode is not DeprovisionMode.ARCHIVE:
                await self._strategies[PlacementStrategy(placement.strategy)].deprovision(
                    record, mode
                )
            tenant.status = (
                TenantStatus.ARCHIVED.value
                if mode is DeprovisionMode.ARCHIVE
                else TenantStatus.DELETED.value
            )
            await self._audit.record(
                action="tenant.deprovisioned",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"mode": mode.value},
            )
            await session.commit()
            return tenant

    async def assert_servable(self, tenant: Tenant) -> None:
        async with await self._control() as session:
            state = await session.get(TenantMigrationState, tenant.id)
            relocating = (
                await session.execute(
                    sa.select(TenantRelocation.id).where(
                        TenantRelocation.tenant_id == tenant.id,
                        TenantRelocation.status.in_(CRITICAL_RELOCATION_PHASES),
                    )
                )
            ).scalar_one_or_none()
        if tenant.status != TenantStatus.ACTIVE.value:
            raise TenantSuspended(f"tenant {tenant.slug} is {tenant.status}")
        if (
            state is None
            or state.status != MigrationStatus.SUCCESS.value
            or state.current_version != state.desired_version
        ):
            raise TenantSuspended(f"tenant {tenant.slug} migration is not current")
        if relocating is not None:
            raise TenantSuspended(f"tenant {tenant.slug} relocation in progress")

    async def list_for_user(self, user_id: uuid.UUID) -> list[Tenant]:
        async with await self._control() as session:
            statement = (
                sa.select(Tenant)
                .join(Membership, Membership.tenant_id == Tenant.id)
                .where(Membership.user_id == user_id, Membership.status == "active")
            )
            return list((await session.execute(statement)).scalars().all())


def _record(tenant: Tenant, placement: TenantPlacement) -> TenantRecord:
    return TenantRecord(
        id=tenant.id,
        slug=tenant.slug,
        status=TenantStatus(tenant.status),
        strategy=PlacementStrategy(placement.strategy),
    )


class RegistryWriteFence:
    def __init__(self, *, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        async with ControlPlaneSession(self._session_factory()) as session:
            tenant: Tenant | None = await session.get(Tenant, tenant_id)
            if tenant is None:
                raise TenantNotWritable(f"tenant {tenant_id} not found")
            relocating = (
                await session.execute(
                    sa.select(TenantRelocation.id).where(
                        TenantRelocation.tenant_id == tenant_id,
                        TenantRelocation.status.in_(CRITICAL_RELOCATION_PHASES),
                    )
                )
            ).scalar_one_or_none()
        if tenant.status != TenantStatus.ACTIVE.value:
            raise TenantNotWritable(f"tenant {tenant.slug} is {tenant.status}")
        if relocating is not None:
            raise TenantNotWritable(f"tenant {tenant.slug} relocation in progress")
