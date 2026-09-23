from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord, TenantRef
from jdlib.control.audit import PlatformAudit
from jdlib.control.enums import MigrationStatus, PlacementStrategy, RelocationPhase, TenantStatus
from jdlib.control.models import (
    ApiKey,
    Invitation,
    Membership,
    ResourceGrant,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
    Tenant,
    TenantMigrationState,
    TenantPlacement,
    TenantRelocation,
)
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import (
    ProvisioningError,
    StrategyCapabilityError,
    TenantNotFound,
    TenantNotWritable,
    TenantOperationInProgress,
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

_ALLOWED_TENANT_TRANSITIONS: dict[TenantStatus, frozenset[TenantStatus]] = {
    TenantStatus.PROVISIONING: frozenset({TenantStatus.ACTIVE, TenantStatus.DELETED}),
    TenantStatus.ACTIVE: frozenset({TenantStatus.SUSPENDED, TenantStatus.ARCHIVED}),
    TenantStatus.SUSPENDED: frozenset({TenantStatus.ACTIVE, TenantStatus.ARCHIVED}),
    TenantStatus.ARCHIVED: frozenset({TenantStatus.ACTIVE, TenantStatus.DEPROVISIONING}),
    TenantStatus.DEPROVISIONING: frozenset({TenantStatus.DELETED, TenantStatus.ARCHIVED}),
    TenantStatus.DELETED: frozenset(),
}

_ACCESS_ROW_DELETION_ORDER: tuple[tuple[str, Any], ...] = (
    ("api_keys", ApiKey),
    ("service_accounts", ServiceAccount),
    ("invitations", Invitation),
    ("role_bindings", RoleBinding),
    ("resource_grants", ResourceGrant),
    ("role_permissions", RolePermission),
    ("roles", Role),
    ("memberships", Membership),
)


class SeedHook(Protocol):
    async def seed(self, tenant: TenantRecord) -> None: ...


class _NoopSeedHook:
    async def seed(self, tenant: TenantRecord) -> None:
        return None


def _require_transition(current: TenantStatus, target: TenantStatus) -> None:
    if target not in _ALLOWED_TENANT_TRANSITIONS[current]:
        raise TenantOperationInProgress(
            f"tenant transition {current.value} -> {target.value} is not allowed"
        )


def _apply_status(tenant: Tenant, target: TenantStatus, *, reason: str | None) -> None:
    tenant.status = target.value
    if target is TenantStatus.SUSPENDED:
        tenant.suspended_at = datetime.now(UTC)
        tenant.suspended_reason = reason
    elif target is TenantStatus.ACTIVE:
        tenant.suspended_at = None
        tenant.suspended_reason = None
    elif target is TenantStatus.ARCHIVED:
        tenant.archived_at = datetime.now(UTC)


async def _relocating(session: ControlPlaneSession, tenant_id: uuid.UUID) -> bool:
    relocation = (
        await session.execute(
            sa.select(TenantRelocation.id).where(
                TenantRelocation.tenant_id == tenant_id,
                TenantRelocation.status.in_(CRITICAL_RELOCATION_PHASES),
            )
        )
    ).scalar_one_or_none()
    return relocation is not None


def _servability_error(
    tenant: Tenant,
    state: TenantMigrationState | None,
    *,
    relocating: bool,
) -> str | None:
    if tenant.status != TenantStatus.ACTIVE.value:
        return f"tenant {tenant.slug} is {tenant.status}"
    if (
        state is None
        or state.status != MigrationStatus.SUCCESS.value
        or state.current_version != state.desired_version
    ):
        return f"tenant {tenant.slug} migration is not current"
    if relocating:
        return f"tenant {tenant.slug} relocation in progress"
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
            raise StrategyCapabilityError("no strategy registered for tenant placement")
        return strategy

    async def _control(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def _tenant(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> Tenant:
        tenant: Tenant | None = await session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFound(str(tenant_id))
        return tenant

    async def _reread_tenant(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> Tenant:
        tenant: Tenant | None = (
            await session.execute(
                sa.select(Tenant)
                .where(Tenant.id == tenant_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if tenant is None:
            raise TenantNotFound(str(tenant_id))
        return tenant

    async def get(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            return await self._tenant(session, tenant_id)

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
            await self._slug_lock(session, slug)
            existing: Tenant | None = (
                await session.execute(sa.select(Tenant).where(Tenant.slug == slug))
            ).scalar_one_or_none()
            if existing is not None:
                placement: TenantPlacement | None = await session.get(
                    TenantPlacement, existing.id
                )
                if placement is None:
                    raise ProvisioningError("tenant is missing a placement record")
                if (
                    PlacementStrategy(placement.strategy) != strategy
                    or placement.target_handle != target_handle
                    or placement.region != region
                ):
                    raise ProvisioningError(
                        f"tenant {slug} already exists with a different placement"
                    )
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

    async def _slug_lock(self, session: ControlPlaneSession, slug: str) -> None:
        await session.execute(
            sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))").bindparams(
                key=f"jdlib:tenant-slug:{slug}"
            )
        )

    async def provision(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant = await self._tenant(session, tenant_id)
            current = TenantStatus(tenant.status)
            if current is TenantStatus.ACTIVE:
                return tenant
            if current is not TenantStatus.PROVISIONING:
                raise TenantOperationInProgress(
                    f"cannot provision tenant in state {current.value}"
                )
            placement: TenantPlacement | None = await session.get(TenantPlacement, tenant_id)
            state: TenantMigrationState | None = await session.get(
                TenantMigrationState, tenant_id
            )
            if placement is None or state is None:
                raise ProvisioningError("tenant is missing placement or migration state")
            record = _record(tenant, placement)
            strategy = self._strategy_for(placement)
            try:
                await strategy.provision(record)
                state.status = MigrationStatus.RUNNING.value
                await session.flush()
                await strategy.migrate(record, self._runner)
                await self._seeder.seed(record)
                actual_version = self._runner.tenant_version(strategy.migration_schema(record))
                if actual_version != state.desired_version:
                    raise ProvisioningError(
                        f"tenant target version {actual_version!r} does not match"
                        f" desired {state.desired_version!r}"
                    )
                state.current_version = state.desired_version
                state.status = MigrationStatus.SUCCESS.value
                state.last_error = None
                await self._audit.record(
                    action="tenant.migration.succeeded", tenant_id=tenant_id, actor_id=None
                )
            except Exception as exc:
                state.status = MigrationStatus.FAILED.value
                state.last_error = str(exc)
                await self._audit.record(
                    action="tenant.migration.failed",
                    tenant_id=tenant_id,
                    actor_id=None,
                    metadata={"error": str(exc)},
                )
                await session.commit()
                raise
            tenant.status = TenantStatus.ACTIVE.value
            tenant.suspended_reason = None
            tenant.suspended_at = None
            await self._audit.record(
                action="tenant.activated", tenant_id=tenant_id, actor_id=None
            )
            await session.commit()
            return tenant

    async def migrate(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant = await self._tenant(session, tenant_id)
            placement: TenantPlacement | None = await session.get(TenantPlacement, tenant_id)
            state: TenantMigrationState | None = await session.get(
                TenantMigrationState, tenant_id
            )
            if placement is None or state is None:
                raise ProvisioningError("tenant is missing placement or migration state")
            record = _record(tenant, placement)
            strategy = self._strategy_for(placement)
            try:
                await strategy.migrate(record, self._runner)
            except Exception as exc:
                state.status = MigrationStatus.FAILED.value
                state.last_error = str(exc)
                if tenant.status == TenantStatus.ACTIVE.value:
                    tenant.status = TenantStatus.SUSPENDED.value
                    tenant.suspended_reason = "migration_failed"
                    tenant.suspended_at = datetime.now(UTC)
                await self._audit.record(
                    action="tenant.migration.failed",
                    tenant_id=tenant_id,
                    actor_id=None,
                    metadata={"error": str(exc)},
                )
                await session.commit()
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
            tenant = await self._tenant(session, tenant_id)
            current = TenantStatus(tenant.status)
            if current is target:
                return tenant
            _require_transition(current, target)
            _apply_status(tenant, target, reason=reason)
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
            tenant = await self._tenant(session, tenant_id)
            current = TenantStatus(tenant.status)
            if mode is DeprovisionMode.ARCHIVE:
                if current is TenantStatus.ARCHIVED:
                    return tenant
                _require_transition(current, TenantStatus.ARCHIVED)
            else:
                if current is TenantStatus.DELETED:
                    return tenant
                if current is not TenantStatus.DEPROVISIONING:
                    _require_transition(current, TenantStatus.DEPROVISIONING)
            children = (
                await session.execute(
                    sa.select(Tenant.id).where(Tenant.parent_tenant_id == tenant_id)
                )
            ).scalars().all()
            if children and not detach_children:
                raise ProvisioningError("tenant has children; detach them explicitly")
            placement: TenantPlacement | None = await session.get(TenantPlacement, tenant_id)
            if placement is None:
                raise ProvisioningError("tenant is missing a placement record")
            metadata: dict[str, object] = {"mode": mode.value}
            if mode is DeprovisionMode.ARCHIVE:
                if children:
                    await self._detach_children(session, tenant_id)
                    metadata["detach_children"] = True
                    metadata["detached_children"] = [str(child) for child in children]
                _apply_status(tenant, TenantStatus.ARCHIVED, reason=None)
                await self._audit.record(
                    action="tenant.deprovisioned",
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    metadata=metadata,
                )
                await session.commit()
                return tenant
            record = _record(tenant, placement)
            strategy = self._strategy_for(placement)
            _apply_status(tenant, TenantStatus.DEPROVISIONING, reason=None)
            await session.commit()
            await self._lock(session, tenant_id)
            tenant = await self._reread_tenant(session, tenant_id)
            if tenant.status != TenantStatus.DEPROVISIONING.value:
                raise TenantOperationInProgress(
                    f"tenant {tenant.slug} deprovision was superseded by state {tenant.status}"
                )
            children = (
                await session.execute(
                    sa.select(Tenant.id).where(Tenant.parent_tenant_id == tenant_id)
                )
            ).scalars().all()
            if children and not detach_children:
                raise TenantOperationInProgress(
                    f"tenant {tenant.slug} gained children during deprovision"
                )
            if children:
                await self._detach_children(session, tenant_id)
                metadata["detach_children"] = True
                metadata["detached_children"] = [str(child) for child in children]
            counts = await self._delete_access_rows(session, tenant_id)
            await strategy.deprovision(record, mode)
            tenant.status = TenantStatus.DELETED.value
            metadata["counts"] = counts
            await self._audit.record(
                action="tenant.deprovisioned",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata=metadata,
            )
            await session.commit()
            return tenant

    async def _detach_children(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> None:
        await session.execute(
            sa.update(Tenant)
            .where(Tenant.parent_tenant_id == tenant_id)
            .values(parent_tenant_id=None)
        )

    async def _delete_access_rows(
        self, session: ControlPlaneSession, tenant_id: uuid.UUID
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for name, model in _ACCESS_ROW_DELETION_ORDER:
            result = await session.execute(sa.delete(model).where(model.tenant_id == tenant_id))
            counts[name] = int(getattr(result, "rowcount", 0) or 0)
        return counts

    async def assert_servable(self, tenant_id: uuid.UUID) -> TenantRecord:
        async with await self._control() as session:
            tenant = await self._tenant(session, tenant_id)
            state: TenantMigrationState | None = await session.get(
                TenantMigrationState, tenant_id
            )
            error = _servability_error(
                tenant, state, relocating=await _relocating(session, tenant_id)
            )
            if error is not None:
                raise TenantSuspended(error)
            placement: TenantPlacement | None = await session.get(TenantPlacement, tenant_id)
            if placement is None:
                raise ProvisioningError("tenant is missing a placement record")
            return _record(tenant, placement)

    async def list_for_user(self, user_id: uuid.UUID) -> list[Tenant]:
        async with await self._control() as session:
            statement = (
                sa.select(Tenant)
                .join(Membership, Membership.tenant_id == Tenant.id)
                .where(Membership.user_id == user_id, Membership.status == "active")
            )
            return list((await session.execute(statement)).scalars().all())

    async def find(self, ref: TenantRef) -> TenantRecord | None:
        async with await self._control() as session:
            statement = sa.select(Tenant)
            if ref.id is not None:
                statement = statement.where(Tenant.id == ref.id)
            elif ref.slug is not None:
                statement = statement.where(Tenant.slug == ref.slug)
            else:
                return None
            tenant = (await session.execute(statement)).scalar_one_or_none()
            if tenant is None:
                return None
            placement: TenantPlacement | None = await session.get(TenantPlacement, tenant.id)
            if placement is None:
                return None
            return TenantRecord(
                id=tenant.id,
                slug=tenant.slug,
                status=TenantStatus(tenant.status),
                strategy=PlacementStrategy(placement.strategy),
            )


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
            state: TenantMigrationState | None = await session.get(
                TenantMigrationState, tenant_id
            )
            error = _servability_error(
                tenant, state, relocating=await _relocating(session, tenant_id)
            )
            if error is not None:
                raise TenantNotWritable(error)
