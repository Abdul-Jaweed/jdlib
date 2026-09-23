from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from jdlib._uuid import uuid7
from jdlib.context import TenantRecord, TenantRef
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import MigrationStatus, PlacementStrategy, TenantStatus
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
    User,
)
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.errors import (
    ProvisioningError,
    StrategyCapabilityError,
    TenantNotFound,
    TenantNotWritable,
    TenantOperationInProgress,
    TenantSuspended,
)
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.shared import SharedSchemaStrategy

DESIRED_VERSION = "0001_tenant_baseline"
TENANT_SCHEMA = "jt_test"

ACCESS_MODELS: dict[str, type] = {
    "api_keys": ApiKey,
    "service_accounts": ServiceAccount,
    "invitations": Invitation,
    "role_bindings": RoleBinding,
    "resource_grants": ResourceGrant,
    "role_permissions": RolePermission,
    "roles": Role,
    "memberships": Membership,
}


class _Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail = False
        self.version: str | None = DESIRED_VERSION
        self.version_calls: list[str] = []

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        if self.fail:
            raise RuntimeError("migration boom")
        self.calls.append(schema)

    def tenant_version(self, schema: str) -> str | None:
        self.version_calls.append(schema)
        return self.version


class _Seeder:
    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []

    async def seed(self, tenant) -> None:
        self.calls.append(tenant.id)


class _FailingAudit(RecordingPlatformAudit):
    def __init__(self, fail_on: str) -> None:
        super().__init__()
        self._fail_on = fail_on

    async def record(self, *, action, tenant_id, actor_id, metadata=None, session=None) -> None:
        if action == self._fail_on:
            raise RuntimeError("audit sink unavailable")
        await super().record(
            action=action,
            tenant_id=tenant_id,
            actor_id=actor_id,
            metadata=metadata,
            session=session,
        )


class _StubPurger:
    async def purge(self, tenant: TenantRecord) -> dict[str, int]:
        return {}


class _FlakyStrategy(SharedSchemaStrategy):
    def __init__(self, *, fail_times: int = 1) -> None:
        super().__init__(engine=None, schema=TENANT_SCHEMA)
        self._fail_times = fail_times
        self.deprovision_calls = 0

    async def deprovision(self, tenant, mode) -> None:
        self.deprovision_calls += 1
        if self.deprovision_calls <= self._fail_times:
            raise RuntimeError("storage deprovision failed")
        await super().deprovision(tenant, mode)


def _registry(
    control_session_factory,
    runner: _Runner | None = None,
    seeder=None,
    audit: RecordingPlatformAudit | None = None,
    strategy: SharedSchemaStrategy | None = None,
):
    audit = audit or RecordingPlatformAudit()
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={
            PlacementStrategy.SHARED: strategy
            or SharedSchemaStrategy(engine=None, schema="jt_test")
        },
        runner=runner or _Runner(),
        seeder=seeder or _Seeder(),
        audit=audit,
        purger=_StubPurger(),
    )
    return registry, audit


def _real_registry(
    control_session_factory,
    postgres_url: str,
    desired_version: str = DESIRED_VERSION,
) -> TenantRegistry:
    runner = MigrationRunner(postgres_url)
    return TenantRegistry(
        session_factory=control_session_factory,
        strategies={
            PlacementStrategy.SHARED: SharedSchemaStrategy(engine=None, schema=TENANT_SCHEMA)
        },
        runner=runner,
        audit=RecordingPlatformAudit(),
        desired_version=desired_version,
    )


async def _create(registry: TenantRegistry, prefix: str = "tenant", **overrides) -> Tenant:
    values: dict[str, object] = {
        "slug": f"{prefix}-{uuid.uuid4().hex[:8]}",
        "name": prefix.title(),
        "strategy": PlacementStrategy.SHARED,
        "target_handle": "default",
    }
    values.update(overrides)
    return await registry.create(**values)


async def _active(registry: TenantRegistry, prefix: str = "tenant", **overrides) -> Tenant:
    tenant = await _create(registry, prefix, **overrides)
    return await registry.provision(tenant.id)


async def _execute(control_session_factory, statement) -> None:
    async with control_session_factory() as session:
        await session.execute(statement)
        await session.commit()


async def _migration_state(control_session_factory, tenant_id: uuid.UUID) -> TenantMigrationState:
    async with control_session_factory() as session:
        state: TenantMigrationState | None = await session.get(TenantMigrationState, tenant_id)
        assert state is not None
        return state


async def _set_version(
    control_session_factory,
    tenant_id: uuid.UUID,
    current_version: str | None,
    status: str = MigrationStatus.SUCCESS.value,
) -> None:
    await _execute(
        control_session_factory,
        sa.update(TenantMigrationState)
        .where(TenantMigrationState.tenant_id == tenant_id)
        .values(current_version=current_version, status=status),
    )


async def _insert_relocation(
    control_session_factory, tenant_id: uuid.UUID, status: str = "copying"
) -> None:
    async with control_session_factory() as session:
        session.add(
            TenantRelocation(
                tenant_id=tenant_id,
                id=uuid7(),
                from_strategy="shared",
                from_target_handle="default",
                to_strategy="database",
                to_target_handle="db-target",
                status=status,
            )
        )
        await session.commit()


async def _seed_access_rows(control_session_factory, tenant_id: uuid.UUID) -> None:
    user_id = uuid7()
    service_account_id = uuid7()
    role_id = uuid7()
    async with control_session_factory() as session:
        session.add(User(id=user_id))
        session.add(ServiceAccount(tenant_id=tenant_id, id=service_account_id, name="bot"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name="admin"))
        await session.flush()
        session.add(
            RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code="invoice.read")
        )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid7(),
                role_id=role_id,
                principal_type="user",
                principal_id=user_id,
                scope_type="tenant",
            )
        )
        session.add(
            ResourceGrant(
                tenant_id=tenant_id,
                id=uuid7(),
                resource_type="invoice",
                resource_id=uuid7(),
                principal_type="user",
                principal_id=user_id,
                permission_code="invoice.read",
            )
        )
        session.add(
            Invitation(
                tenant_id=tenant_id,
                id=uuid7(),
                email="invite@example.com",
                scope_type="tenant",
                role_id=role_id,
                token_id=uuid.uuid4().hex,
                token_hash="hash",
                status="pending",
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
        )
        session.add(Membership(tenant_id=tenant_id, id=uuid7(), user_id=user_id, status="active"))
        session.add(
            ApiKey(
                tenant_id=tenant_id,
                id=uuid7(),
                service_account_id=service_account_id,
                key_prefix=uuid.uuid4().hex[:12],
                key_hash="hash",
            )
        )
        await session.commit()


async def _access_counts(control_session_factory, tenant_id: uuid.UUID) -> dict[str, int]:
    counts: dict[str, int] = {}
    async with control_session_factory() as session:
        for name, model in ACCESS_MODELS.items():
            result = await session.execute(
                sa.select(sa.func.count()).select_from(model).where(model.tenant_id == tenant_id)
            )
            counts[name] = int(result.scalar_one())
    return counts


async def test_create_and_provision_activates_tenant(control_session_factory):
    registry, audit = _registry(control_session_factory)
    tenant = await _create(registry, "acme")
    assert tenant.status == TenantStatus.PROVISIONING
    provisioned = await registry.provision(tenant.id)
    assert provisioned.status == TenantStatus.ACTIVE
    assert [entry["action"] for entry in audit.entries] == [
        "tenant.created",
        "tenant.migration.succeeded",
        "tenant.activated",
    ]


async def test_create_rejects_target_handle_owned_by_another_tenant(control_session_factory):
    registry, _ = _registry(control_session_factory)
    owner = await _create(
        registry, "handle-owner", strategy=PlacementStrategy.SCHEMA, target_handle="t_dup"
    )
    with pytest.raises(ProvisioningError):
        await _create(
            registry, "handle-thief", strategy=PlacementStrategy.SCHEMA, target_handle="t_dup"
        )
    database_owner = await _create(
        registry, "handle-owner-db", strategy=PlacementStrategy.DATABASE, target_handle="db-dup"
    )
    with pytest.raises(ProvisioningError):
        await _create(
            registry,
            "handle-thief-db",
            strategy=PlacementStrategy.DATABASE,
            target_handle="db-dup",
        )
    allowed = await _create(
        registry, "shared-handle", strategy=PlacementStrategy.SHARED, target_handle="t_dup"
    )
    assert allowed.status == TenantStatus.PROVISIONING
    assert (await registry.get(owner.id)).status == TenantStatus.PROVISIONING
    assert (await registry.get(database_owner.id)).status == TenantStatus.PROVISIONING


async def test_create_normalizes_plain_string_strategy(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await registry.create(
        slug=f"string-strategy-{uuid.uuid4().hex[:8]}",
        name="String Strategy",
        strategy="shared",  # type: ignore[arg-type]
        target_handle="default",
    )
    assert tenant.status == TenantStatus.PROVISIONING
    with pytest.raises(ProvisioningError, match="database"):
        await registry.create(
            slug=f"string-strategy-bad-{uuid.uuid4().hex[:8]}",
            name="String Strategy Bad",
            strategy="database",  # type: ignore[arg-type]
            target_handle="bad handle",
        )


async def test_create_unknown_strategy_raises_provisioning_error(control_session_factory):
    registry, _ = _registry(control_session_factory)
    with pytest.raises(ProvisioningError, match="unknown placement strategy"):
        await registry.create(
            slug=f"unknown-strategy-{uuid.uuid4().hex[:8]}",
            name="Unknown Strategy",
            strategy="bogus",  # type: ignore[arg-type]
            target_handle="default",
        )
    tenant = await registry.create(
        slug=f"valid-strategy-{uuid.uuid4().hex[:8]}",
        name="Valid Strategy",
        strategy="shared",  # type: ignore[arg-type]
        target_handle="default",
    )
    assert tenant.status == TenantStatus.PROVISIONING


async def test_create_rejects_invalid_schema_handle(control_session_factory):
    registry, _ = _registry(control_session_factory)
    for handle in ("public", "t_BAD", "t_", "t_x y"):
        with pytest.raises(ProvisioningError, match="schema"):
            await _create(
                registry,
                "bad-schema",
                strategy=PlacementStrategy.SCHEMA,
                target_handle=handle,
            )


async def test_create_rejects_invalid_database_handle(control_session_factory):
    registry, _ = _registry(control_session_factory)
    for handle in ("db_acme", "DB-acme", "", "-db-acme"):
        with pytest.raises(ProvisioningError, match="database"):
            await _create(
                registry,
                "bad-db",
                strategy=PlacementStrategy.DATABASE,
                target_handle=handle,
            )


async def test_create_rejects_empty_shared_handle(control_session_factory):
    registry, _ = _registry(control_session_factory)
    with pytest.raises(ProvisioningError, match="shared"):
        await _create(registry, "empty-shared", target_handle="")


async def test_create_accepts_valid_handles(control_session_factory):
    registry, _ = _registry(control_session_factory)
    schema_tenant = await _create(
        registry, "good-schema", strategy=PlacementStrategy.SCHEMA, target_handle="t_acme_1"
    )
    database_tenant = await _create(
        registry, "good-db", strategy=PlacementStrategy.DATABASE, target_handle="db-acme-1"
    )
    shared_tenant = await _create(registry, "good-shared", target_handle="default")
    assert schema_tenant.status == TenantStatus.PROVISIONING
    assert database_tenant.status == TenantStatus.PROVISIONING
    assert shared_tenant.status == TenantStatus.PROVISIONING


async def test_create_repeat_returns_existing_for_same_placement(control_session_factory):
    registry, _ = _registry(control_session_factory)
    first = await _create(registry, "same", region="eu")
    repeat = await registry.create(
        slug=first.slug,
        name="Renamed",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
        region="eu",
    )
    assert repeat.id == first.id


async def test_create_conflicting_placement_raises(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "conflict")
    with pytest.raises(ProvisioningError):
        await registry.create(
            slug=tenant.slug,
            name="Conflict",
            strategy=PlacementStrategy.SHARED,
            target_handle="other",
        )
    with pytest.raises(ProvisioningError):
        await registry.create(
            slug=tenant.slug,
            name="Conflict",
            strategy=PlacementStrategy.SCHEMA,
            target_handle="default",
        )
    with pytest.raises(ProvisioningError):
        await registry.create(
            slug=tenant.slug,
            name="Conflict",
            strategy=PlacementStrategy.SHARED,
            target_handle="default",
            region="us",
        )


async def test_provision_is_idempotent(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "beta")
    for _ in range(3):
        await registry.provision(tenant.id)
    assert (await registry.get(tenant.id)).status == TenantStatus.ACTIVE


async def test_provision_unknown_strategy_raises_capability_error(control_session_factory):
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        seeder=_Seeder(),
        audit=RecordingPlatformAudit(),
    )
    tenant = await _create(registry, "nostrategy")
    with pytest.raises(StrategyCapabilityError):
        await registry.provision(tenant.id)
    assert (await registry.get(tenant.id)).status == TenantStatus.PROVISIONING


async def test_provision_missing_placement_raises(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "noplacement")
    await _execute(
        control_session_factory,
        sa.delete(TenantPlacement).where(TenantPlacement.tenant_id == tenant.id),
    )
    with pytest.raises(ProvisioningError):
        await registry.provision(tenant.id)
    assert (await registry.get(tenant.id)).status == TenantStatus.PROVISIONING


async def test_provision_missing_migration_state_raises(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "nostate")
    await _execute(
        control_session_factory,
        sa.delete(TenantMigrationState).where(TenantMigrationState.tenant_id == tenant.id),
    )
    with pytest.raises(ProvisioningError):
        await registry.provision(tenant.id)


async def test_concurrent_provisions_serialize(control_session_factory):
    runner = _Runner()
    registry, audit = _registry(control_session_factory, runner=runner)
    tenant = await _create(registry, "racing")
    first, second = await asyncio.gather(
        registry.provision(tenant.id), registry.provision(tenant.id)
    )
    assert first.status == TenantStatus.ACTIVE
    assert second.status == TenantStatus.ACTIVE
    assert runner.calls == [TENANT_SCHEMA]
    assert runner.version_calls == [TENANT_SCHEMA]
    assert [entry["action"] for entry in audit.entries] == [
        "tenant.created",
        "tenant.migration.succeeded",
        "tenant.activated",
    ]
    state = await _migration_state(control_session_factory, tenant.id)
    assert state.status == MigrationStatus.SUCCESS.value
    assert (await registry.get(tenant.id)).status == TenantStatus.ACTIVE


async def test_concurrent_provisions_of_distinct_tenants(control_session_factory):
    runner = _Runner()
    registry, _ = _registry(control_session_factory, runner=runner)

    async def provision_new(prefix: str) -> Tenant:
        tenant = await _create(registry, prefix)
        return await registry.provision(tenant.id)

    first, second = await asyncio.gather(
        provision_new("parallel-a"), provision_new("parallel-b")
    )
    assert first.id != second.id
    assert first.status == TenantStatus.ACTIVE
    assert second.status == TenantStatus.ACTIVE
    assert sorted(runner.calls) == [TENANT_SCHEMA, TENANT_SCHEMA]


async def test_provision_health_check_failure_stays_provisioning(control_session_factory):
    runner = _Runner()
    runner.version = "0000_old"
    registry, audit = _registry(control_session_factory, runner=runner)
    tenant = await _create(registry, "healthcheck")
    with pytest.raises(ProvisioningError):
        await registry.provision(tenant.id)
    assert runner.version_calls == ["jt_test"]
    assert (await registry.get(tenant.id)).status == TenantStatus.PROVISIONING
    state = await _migration_state(control_session_factory, tenant.id)
    assert state.status == MigrationStatus.FAILED.value
    assert state.current_version is None
    assert [entry["action"] for entry in audit.entries] == [
        "tenant.created",
        "tenant.migration.failed",
    ]


async def test_provision_with_real_runner_activates_tenant(control_session_factory, postgres_url):
    registry = _real_registry(control_session_factory, postgres_url)
    tenant = await _create(registry, "e2e")
    provisioned = await registry.provision(tenant.id)
    assert provisioned.status == TenantStatus.ACTIVE
    state = await _migration_state(control_session_factory, tenant.id)
    assert state.status == MigrationStatus.SUCCESS.value
    assert state.current_version == DESIRED_VERSION


async def test_provision_version_mismatch_stays_provisioning(
    control_session_factory, postgres_url
):
    registry = _real_registry(
        control_session_factory, postgres_url, desired_version="0002_nonexistent"
    )
    tenant = await _create(registry, "e2e-mismatch")
    with pytest.raises(ProvisioningError):
        await registry.provision(tenant.id)
    assert (await registry.get(tenant.id)).status == TenantStatus.PROVISIONING
    state = await _migration_state(control_session_factory, tenant.id)
    assert state.status == MigrationStatus.FAILED.value
    assert state.current_version is None


async def test_failed_migration_suspends_active_tenant(control_session_factory):
    runner = _Runner()
    registry, _ = _registry(control_session_factory, runner=runner)
    tenant = await _active(registry, "gamma")
    runner.fail = True
    with pytest.raises(RuntimeError):
        await registry.migrate(tenant.id)
    stored = await registry.get(tenant.id)
    assert stored.status == TenantStatus.SUSPENDED
    assert stored.suspended_reason == "migration_failed"
    assert stored.suspended_at is not None
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(stored.id)


async def test_failure_audit_error_prevents_failure_state_commit(control_session_factory):
    runner = _Runner()
    registry, _ = _registry(
        control_session_factory, runner=runner, audit=_FailingAudit("tenant.migration.failed")
    )
    tenant = await _active(registry, "auditfail")
    runner.fail = True
    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        await registry.migrate(tenant.id)
    assert (await registry.get(tenant.id)).status == TenantStatus.ACTIVE
    state = await _migration_state(control_session_factory, tenant.id)
    assert state.status == MigrationStatus.SUCCESS.value
    assert state.current_version == DESIRED_VERSION


async def test_find_returns_record_for_id_and_slug(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "findable")
    by_id = await registry.find(TenantRef(id=tenant.id))
    by_slug = await registry.find(TenantRef(slug=tenant.slug))
    assert by_id is not None
    assert by_id == by_slug
    assert by_id == TenantRecord(
        id=tenant.id,
        slug=tenant.slug,
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )


async def test_find_unknown_id_and_slug_return_none(control_session_factory):
    registry, _ = _registry(control_session_factory)
    assert await registry.find(TenantRef(id=uuid7())) is None
    assert await registry.find(TenantRef(slug="no-such-slug")) is None
    assert await registry.find(TenantRef()) is None


async def test_find_missing_placement_returns_none(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "find-noplace")
    await _execute(
        control_session_factory,
        sa.delete(TenantPlacement).where(TenantPlacement.tenant_id == tenant.id),
    )
    assert await registry.find(TenantRef(id=tenant.id)) is None


async def test_assert_servable_returns_active_tenant(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "servable")
    record = await registry.assert_servable(tenant.id)
    assert record == TenantRecord(
        id=tenant.id,
        slug=tenant.slug,
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )


async def test_assert_servable_missing_placement_raises(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "servable-noplace")
    await _execute(
        control_session_factory,
        sa.delete(TenantPlacement).where(TenantPlacement.tenant_id == tenant.id),
    )
    with pytest.raises(ProvisioningError):
        await registry.assert_servable(tenant.id)


async def test_assert_servable_requires_migration_success(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "delta")
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(tenant.id)


async def test_assert_servable_rejects_version_mismatch(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "mismatch")
    await _set_version(control_session_factory, tenant.id, "0000_old")
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(tenant.id)


async def test_assert_servable_rejects_critical_relocation(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "moving")
    await _insert_relocation(control_session_factory, tenant.id, status="copying")
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(tenant.id)


async def test_assert_servable_rejects_suspended_and_unknown(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "stopped")
    await registry.suspend(tenant.id, reason="operator_action")
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(tenant.id)
    with pytest.raises(TenantNotFound):
        await registry.assert_servable(uuid7())


async def test_write_fence_allows_active_and_blocks_suspended(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "zeta")
    fence = RegistryWriteFence(session_factory=control_session_factory)
    await fence.assert_writable(tenant.id)
    await registry.suspend(tenant.id, reason="operator_action")
    with pytest.raises(TenantNotWritable):
        await fence.assert_writable(tenant.id)


async def test_write_fence_blocks_stale_migration(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "fencestale")
    fence = RegistryWriteFence(session_factory=control_session_factory)
    await _set_version(control_session_factory, tenant.id, "0000_old")
    with pytest.raises(TenantNotWritable):
        await fence.assert_writable(tenant.id)


async def test_write_fence_blocks_critical_relocation(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "fencemove")
    fence = RegistryWriteFence(session_factory=control_session_factory)
    await _insert_relocation(control_session_factory, tenant.id, status="flipping")
    with pytest.raises(TenantNotWritable):
        await fence.assert_writable(tenant.id)


async def test_write_fence_blocks_unknown_tenant(control_session_factory):
    fence = RegistryWriteFence(session_factory=control_session_factory)
    with pytest.raises(TenantNotWritable):
        await fence.assert_writable(uuid7())


async def test_suspend_resume_archive_sets_timestamps(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "epsilon")
    suspended = await registry.suspend(tenant.id, reason="operator_action")
    assert suspended.status == TenantStatus.SUSPENDED
    assert suspended.suspended_reason == "operator_action"
    assert suspended.suspended_at is not None
    resumed = await registry.resume(tenant.id)
    assert resumed.status == TenantStatus.ACTIVE
    assert resumed.suspended_reason is None
    assert resumed.suspended_at is None
    archived = await registry.archive(tenant.id)
    assert archived.status == TenantStatus.ARCHIVED
    assert archived.archived_at is not None


async def test_deleted_tenant_is_terminal(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "terminal")
    await _execute(
        control_session_factory,
        sa.update(Tenant).where(Tenant.id == tenant.id).values(status="deleted"),
    )
    with pytest.raises(TenantOperationInProgress):
        await registry.resume(tenant.id)
    with pytest.raises(TenantOperationInProgress):
        await registry.archive(tenant.id)
    with pytest.raises(TenantOperationInProgress):
        await registry.suspend(tenant.id, reason="operator_action")


async def test_suspend_rejects_disallowed_source_states(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _create(registry, "premature")
    with pytest.raises(TenantOperationInProgress):
        await registry.suspend(tenant.id, reason="operator_action")
    await registry.provision(tenant.id)
    await registry.archive(tenant.id)
    with pytest.raises(TenantOperationInProgress):
        await registry.suspend(tenant.id, reason="operator_action")


async def test_deprovision_purge_requires_archived_state(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "purgeguard")
    with pytest.raises(TenantOperationInProgress):
        await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE)


async def test_deprovision_purge_deletes_access_rows_and_marks_deleted(control_session_factory):
    registry, audit = _registry(control_session_factory)
    tenant = await _active(registry, "purge")
    await _seed_access_rows(control_session_factory, tenant.id)
    seeded = await _access_counts(control_session_factory, tenant.id)
    assert set(seeded.values()) == {1}
    await registry.archive(tenant.id)
    purged = await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE)
    assert purged.status == TenantStatus.DELETED
    assert (await registry.get(tenant.id)).status == TenantStatus.DELETED
    assert await _access_counts(control_session_factory, tenant.id) == dict.fromkeys(
        ACCESS_MODELS, 0
    )
    entry = audit.entries[-1]
    assert entry["action"] == "tenant.deprovisioned"
    assert entry["metadata"]["mode"] == "purge"
    assert entry["metadata"]["counts"] == dict.fromkeys(ACCESS_MODELS, 1)


async def test_deprovision_archive_retains_access_rows(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "retain")
    await _seed_access_rows(control_session_factory, tenant.id)
    await registry.archive(tenant.id)
    archived = await registry.deprovision(tenant.id, mode=DeprovisionMode.ARCHIVE)
    assert archived.status == TenantStatus.ARCHIVED
    assert archived.archived_at is not None
    assert set((await _access_counts(control_session_factory, tenant.id)).values()) == {1}


async def test_deprovisioning_retry_resumes_after_strategy_failure(control_session_factory):
    strategy = _FlakyStrategy()
    registry, audit = _registry(control_session_factory, strategy=strategy)
    tenant = await _active(registry, "retry")
    await _seed_access_rows(control_session_factory, tenant.id)
    await registry.archive(tenant.id)
    with pytest.raises(RuntimeError, match="storage deprovision failed"):
        await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE)
    assert strategy.deprovision_calls == 1
    assert (await registry.get(tenant.id)).status == TenantStatus.DEPROVISIONING
    purged = await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE)
    assert purged.status == TenantStatus.DELETED
    assert strategy.deprovision_calls == 2
    assert await _access_counts(control_session_factory, tenant.id) == dict.fromkeys(
        ACCESS_MODELS, 0
    )
    assert audit.entries[-1]["metadata"]["counts"] == dict.fromkeys(ACCESS_MODELS, 1)


async def test_deprovision_superseded_after_lock_release_raises(
    control_session_factory, monkeypatch
):
    registry, _ = _registry(control_session_factory)
    parent = await _active(registry, "supersede")
    child = await _create(registry, "attached", parent_tenant_id=parent.id)
    await registry.provision(child.id)
    await _seed_access_rows(control_session_factory, parent.id)
    await registry.archive(parent.id)
    original_lock = registry._lock
    lock_calls = 0

    async def racing_lock(session, tenant_id):
        nonlocal lock_calls
        lock_calls += 1
        if lock_calls == 2:
            await _execute(
                control_session_factory,
                sa.update(Tenant)
                .where(Tenant.id == tenant_id)
                .values(status=TenantStatus.ARCHIVED.value),
            )
        await original_lock(session, tenant_id)

    monkeypatch.setattr(registry, "_lock", racing_lock)
    with pytest.raises(TenantOperationInProgress):
        await registry.deprovision(parent.id, mode=DeprovisionMode.PURGE, detach_children=True)
    assert lock_calls == 2
    assert (await registry.get(parent.id)).status == TenantStatus.ARCHIVED
    assert (await registry.get(child.id)).parent_tenant_id == parent.id
    assert set((await _access_counts(control_session_factory, parent.id)).values()) == {1}


async def test_deprovision_child_race_fails_closed(control_session_factory, monkeypatch):
    registry, _ = _registry(control_session_factory)
    parent = await _active(registry, "childrace")
    await registry.archive(parent.id)
    original_lock = registry._lock
    lock_calls = 0
    child_id: uuid.UUID | None = None

    async def racing_lock(session, tenant_id):
        nonlocal lock_calls, child_id
        lock_calls += 1
        if lock_calls == 2:
            child = await registry.create(
                slug=f"late-child-{uuid.uuid4().hex[:8]}",
                name="Late Child",
                strategy=PlacementStrategy.SHARED,
                target_handle="default",
                parent_tenant_id=tenant_id,
            )
            child_id = child.id
        await original_lock(session, tenant_id)

    monkeypatch.setattr(registry, "_lock", racing_lock)
    with pytest.raises(TenantOperationInProgress):
        await registry.deprovision(parent.id, mode=DeprovisionMode.PURGE)
    assert lock_calls == 2
    assert child_id is not None
    assert (await registry.get(parent.id)).status == TenantStatus.DEPROVISIONING
    assert (await registry.get(child_id)).parent_tenant_id == parent.id


async def test_deprovision_archive_ignores_unregistered_strategy(control_session_factory):
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        seeder=_Seeder(),
        audit=RecordingPlatformAudit(),
    )
    tenant = await _create(registry, "nostrategy")
    await _execute(
        control_session_factory,
        sa.update(Tenant).where(Tenant.id == tenant.id).values(status=TenantStatus.ACTIVE.value),
    )
    archived = await registry.deprovision(tenant.id, mode=DeprovisionMode.ARCHIVE)
    assert archived.status == TenantStatus.ARCHIVED
    assert (await registry.get(tenant.id)).status == TenantStatus.ARCHIVED


async def test_list_for_user_returns_only_active_memberships(control_session_factory):
    registry, _ = _registry(control_session_factory)
    user_id = uuid7()
    joined = await _create(registry, "joined")
    suspended = await _create(registry, "left")
    deleted = await _create(registry, "gone")
    async with control_session_factory() as session:
        session.add(User(id=user_id))
        await session.flush()
        session.add(Membership(tenant_id=joined.id, id=uuid7(), user_id=user_id, status="active"))
        session.add(
            Membership(tenant_id=suspended.id, id=uuid7(), user_id=user_id, status="suspended")
        )
        session.add(Membership(tenant_id=deleted.id, id=uuid7(), user_id=user_id, status="deleted"))
        await session.commit()
    tenants = await registry.list_for_user(user_id)
    assert [tenant.id for tenant in tenants] == [joined.id]


async def test_parent_with_children_cannot_be_archived(control_session_factory):
    registry, audit = _registry(control_session_factory)
    parent = await _create(registry, "parent")
    child = await _create(registry, "child", parent_tenant_id=parent.id)
    await registry.provision(parent.id)
    await registry.provision(child.id)
    with pytest.raises(ProvisioningError):
        await registry.deprovision(parent.id, mode=DeprovisionMode.ARCHIVE)
    await registry.deprovision(parent.id, mode=DeprovisionMode.ARCHIVE, detach_children=True)
    assert (await registry.get(child.id)).parent_tenant_id is None
    assert (await registry.get(parent.id)).status == TenantStatus.ARCHIVED
    entry = audit.entries[-1]
    assert entry["action"] == "tenant.deprovisioned"
    assert entry["metadata"]["mode"] == "archive"
    assert entry["metadata"]["detach_children"] is True
    assert entry["metadata"]["detached_children"] == [str(child.id)]
