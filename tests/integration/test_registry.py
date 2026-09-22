import uuid

import pytest

from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.errors import ProvisioningError, TenantNotWritable, TenantSuspended
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.shared import SharedSchemaStrategy


class _Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail = False

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        if self.fail:
            raise RuntimeError("migration boom")
        self.calls.append(schema)


class _Seeder:
    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []

    async def seed(self, tenant) -> None:
        self.calls.append(tenant.id)


def _registry(control_session_factory, runner: _Runner | None = None, seeder=None):
    audit = RecordingPlatformAudit()
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={
            PlacementStrategy.SHARED: SharedSchemaStrategy(engine=None, schema="jt_test")
        },
        runner=runner or _Runner(),
        seeder=seeder or _Seeder(),
        audit=audit,
    )
    return registry, audit


async def test_create_and_provision_activates_tenant(control_session_factory):
    registry, audit = _registry(control_session_factory)
    tenant = await registry.create(
        slug=f"acme-{uuid.uuid4().hex[:8]}",
        name="Acme",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    assert tenant.status == TenantStatus.PROVISIONING
    provisioned = await registry.provision(tenant.id)
    assert provisioned.status == TenantStatus.ACTIVE
    assert [entry["action"] for entry in audit.entries] == [
        "tenant.created",
        "tenant.migration.succeeded",
        "tenant.activated",
    ]


async def test_provision_is_idempotent(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await registry.create(
        slug=f"beta-{uuid.uuid4().hex[:8]}",
        name="Beta",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    for _ in range(3):
        await registry.provision(tenant.id)
    assert (await registry.get(tenant.id)).status == TenantStatus.ACTIVE


async def test_failed_migration_suspends_active_tenant(control_session_factory):
    runner = _Runner()
    registry, audit = _registry(control_session_factory, runner)
    tenant = await registry.create(
        slug=f"gamma-{uuid.uuid4().hex[:8]}",
        name="Gamma",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    await registry.provision(tenant.id)
    runner.fail = True
    with pytest.raises(RuntimeError):
        await registry.migrate(tenant.id)
    stored = await registry.get(tenant.id)
    assert stored.status == TenantStatus.SUSPENDED
    assert stored.suspended_reason == "migration_failed"
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(stored)


async def test_assert_servable_requires_migration_success(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await registry.create(
        slug=f"delta-{uuid.uuid4().hex[:8]}",
        name="Delta",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    with pytest.raises(TenantSuspended):
        await registry.assert_servable(await registry.get(tenant.id))


async def test_suspend_resume_archive(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await registry.create(
        slug=f"epsilon-{uuid.uuid4().hex[:8]}",
        name="Epsilon",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    await registry.provision(tenant.id)
    suspended = await registry.suspend(tenant.id, reason="operator_action")
    assert suspended.status == TenantStatus.SUSPENDED
    resumed = await registry.resume(tenant.id)
    assert resumed.status == TenantStatus.ACTIVE
    archived = await registry.archive(tenant.id)
    assert archived.status == TenantStatus.ARCHIVED


async def test_write_fence_blocks_suspended_and_relocating(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await registry.create(
        slug=f"zeta-{uuid.uuid4().hex[:8]}",
        name="Zeta",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    await registry.provision(tenant.id)
    fence = RegistryWriteFence(session_factory=control_session_factory)
    await fence.assert_writable(tenant.id)
    await registry.suspend(tenant.id, reason="operator_action")
    with pytest.raises(TenantNotWritable):
        await fence.assert_writable(tenant.id)


async def test_parent_with_children_cannot_be_archived(control_session_factory):
    registry, _ = _registry(control_session_factory)
    parent = await registry.create(
        slug=f"parent-{uuid.uuid4().hex[:8]}",
        name="Parent",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    child = await registry.create(
        slug=f"child-{uuid.uuid4().hex[:8]}",
        name="Child",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
        parent_tenant_id=parent.id,
    )
    with pytest.raises(ProvisioningError):
        await registry.deprovision(parent.id, mode=DeprovisionMode.ARCHIVE)
    await registry.deprovision(parent.id, mode=DeprovisionMode.ARCHIVE, detach_children=True)
    assert (await registry.get(child.id)).parent_tenant_id is None
