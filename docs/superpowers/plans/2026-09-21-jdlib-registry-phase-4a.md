# jdlib Tenant Lifecycle & Registry (Phase 4a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the platform control-plane services: `ControlPlaneSession`, `TenantRegistry` (create/provision/suspend/resume/archive/deprovision/migrate/assert_servable/list_for_user), the `RegistryWriteFence` implementation, provisioning pipeline with per-step idempotency and lifecycle locking, and the seed port — delivering the first end-to-end shared-schema deployment.

**Architecture:** `TenantRegistry` runs inside the control plane (schema `jd_control`) through a framework-internal `ControlPlaneSession`; it orchestrates the tenant-plane `IsolationStrategy` and the programmatic `MigrationRunner`, records `tenant_migration_states`, and is the single source of truth for the servability predicate and the write fence. A `PlatformAudit` port records mandatory lifecycle events (Phase 10 wires the durable sink; tests inject a recorder).

**Tech Stack:** SQLAlchemy 2.0 async, Alembic runner (Phase 1), PostgreSQL 16 testcontainers. No new dependencies.

**Specs (frozen):** `docs/jdlib/05-tenant-lifecycle.md` §1–§5, §8; `docs/jdlib/02-relational-schema.md` §3.1–§3.3.1; `docs/jdlib/03-isolation-invariants.md` I9, failure semantics; `docs/jdlib/06-strategy-matrix.md` §2; `docs/jdlib/07-implementation-design.md` §7–§8.

## Global Constraints

- Servability is one predicate: `tenants.status = 'active'` AND `tenant_migration_states.status = 'success'` AND `current_version = desired_version` AND no relocation in `copying|verifying|flipping|post_flip_verification`. `assert_servable` is the only implementation.
- Failed/blocked migration on an active tenant immediately suspends it (`suspended_reason='migration_failed'`) and audits; no "failed but usable".
- Lifecycle operations are serialized per tenant with a Postgres transaction advisory lock; concurrent operations either no-op (already in target state) or raise `TenantOperationInProgress`.
- Provisioning steps are idempotent/resumable; no partial tenant becomes `active`; activation happens only after place → migrate → seed → health.
- Parent deletion is blocked while children exist unless `detach_children=True`; no DB cascade from `tenants`.
- Mandatory audit events (lifecycle transitions, migration results) are recorded through the `PlatformAudit` port before the operation is considered complete; a failing mandatory audit fails the operation closed.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` and a fresh DB.
- No comments in source; docstrings only where the plan shows them; pristine test output; commit after every task.

---

### Task 1: ControlPlaneSession and PlatformAudit port

**Files:**
- Create: `src/jdlib/control/session.py`
- Create: `src/jdlib/control/audit.py`
- Create: `tests/unit/test_control_session.py`

**Interfaces:**
- Consumes: `AsyncSession`.
- Produces: `ControlPlaneSession` (wrapping `AsyncSession`, with `execute/get/add/flush/commit/rollback/close`); `PlatformAudit` protocol (`async record(*, action: str, tenant_id: uuid.UUID | None, actor_id: uuid.UUID | None, metadata: Mapping[str, object] | None = None) -> None`); `RecordingPlatformAudit` for tests; `NullPlatformAudit` (raises on use).

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_control_session.py`:

```python
import uuid

import pytest

from jdlib.control.audit import NullPlatformAudit, PlatformAudit, RecordingPlatformAudit


class _FakeAsyncSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False
        self.closed = False

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def close(self) -> None:
        self.closed = True


async def test_recording_audit_records_entries():
    audit = RecordingPlatformAudit()
    await audit.record(
        action="tenant.created", tenant_id=uuid.uuid4(), actor_id=None, metadata={"slug": "acme"}
    )
    assert audit.entries[0]["action"] == "tenant.created"
    assert audit.entries[0]["metadata"] == {"slug": "acme"}


async def test_null_audit_fails_closed():
    audit = NullPlatformAudit()
    with pytest.raises(RuntimeError):
        await audit.record(action="tenant.created", tenant_id=None, actor_id=None, metadata=None)


def test_protocol_shape():
    assert hasattr(PlatformAudit, "record")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_control_session.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.control.audit'`

- [ ] **Step 3: Implement `src/jdlib/control/audit.py`**

```python
from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


class PlatformAudit(Protocol):
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
    ) -> None: ...


class NullPlatformAudit:
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        raise RuntimeError("no platform audit sink is configured")


@dataclass
class RecordingPlatformAudit:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        self.entries.append(
            {
                "action": action,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "metadata": dict(metadata or {}),
            }
        )
```

- [ ] **Step 4: Implement `src/jdlib/control/session.py`**

```python
from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession


class ControlPlaneSession:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> ControlPlaneSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._session.close()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()

    async def flush(self) -> None:
        await self._session.flush()

    async def execute(self, statement: sa.Executable) -> sa.Result[Any]:
        return await self._session.execute(statement)

    async def get(self, model: type[Any], entity_id: Any) -> Any | None:
        return await self._session.get(model, entity_id)

    def add(self, obj: Any) -> None:
        self._session.add(obj)

    async def delete(self, obj: Any) -> None:
        await self._session.delete(obj)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_control_session.py -v -W error`
Expected: PASS (3 passed)

- [ ] **Step 6: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/control/session.py src/jdlib/control/audit.py tests/unit/test_control_session.py
git commit -m "feat: control plane session and platform audit port"
```

---

### Task 2: Strategy lifecycle methods and shared-schema provisioning

**Files:**
- Modify: `src/jdlib/persistence/strategies/base.py`
- Modify: `src/jdlib/persistence/strategies/shared.py`
- Create: `src/jdlib/persistence/strategies/deprovision.py`
- Create: `tests/unit/test_strategy_lifecycle.py`

**Interfaces:**
- Consumes: `TenantRecord`; `MigrationRunner`.
- Produces: `DeprovisionMode` (`archive`, `purge`, `destroy`) in `deprovision.py`; extended `IsolationStrategy` protocol with `async provision(tenant) -> None`, `async migrate(tenant, runner: MigrationRunner) -> None`, `async deprovision(tenant, mode: DeprovisionMode) -> None`; `SharedSchemaStrategy` implementations (`provision` no-op; `migrate` runs the tenant chain against the configured schema; `deprovision` no-op for `archive`, no-op for `purge`/`destroy` on shared since data is not physically separated).

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_strategy_lifecycle.py`:

```python
import uuid

import pytest

from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.context import TenantRecord
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_strategy_lifecycle.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.strategies.deprovision'`

- [ ] **Step 3: Implement the strategy lifecycle methods**

`src/jdlib/persistence/strategies/deprovision.py`:

```python
from __future__ import annotations

from enum import StrEnum


class DeprovisionMode(StrEnum):
    ARCHIVE = "archive"
    PURGE = "purge"
    DESTROY = "destroy"
```

`src/jdlib/persistence/strategies/base.py` (extend):

```python
class IsolationStrategy(Protocol):
    name: str
    capabilities: StrategyCapabilities

    async def session(self, tenant: TenantRecord) -> AsyncSession: ...

    async def provision(self, tenant: TenantRecord) -> None: ...

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None: ...

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None: ...
```

with imports `from jdlib.migrations.runner import MigrationRunner` and `from jdlib.persistence.strategies.deprovision import DeprovisionMode`.

`src/jdlib/persistence/strategies/shared.py` (extend):

```python
class SharedSchemaStrategy:
    name = "shared"
    capabilities = StrategyCapabilities(supports_rls=True, supports_ddl=False)

    def __init__(self, engine: AsyncEngine | None, schema: str = "public") -> None:
        self._engine = engine
        self._schema = schema

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        if self._engine is None:
            raise StrategyCapabilityError("shared strategy has no engine configured")
        return AsyncSession(self._engine, expire_on_commit=False)

    async def provision(self, tenant: TenantRecord) -> None:
        return None

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        runner.upgrade_tenant(self._schema)

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_strategy_lifecycle.py -v -W error`
Expected: PASS (4 passed). Existing `tests/unit/test_router.py` must still pass; update its construction if the `SharedSchemaStrategy(engine)` signature changed (it now accepts `engine=None` and an optional schema — the positional engine call still works).

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/strategies tests/unit/test_strategy_lifecycle.py
git commit -m "feat: strategy lifecycle methods and deprovision modes"
```

---

### Task 3: TenantRegistry — creation, servability, suspension

**Files:**
- Create: `src/jdlib/control/registry.py`
- Create: `tests/integration/test_registry.py`
- Modify: `tests/integration/conftest.py` (control async session factory fixture)

**Interfaces:**
- Consumes: `ControlPlaneSession`, `PlatformAudit`, `TenantRecord`, `MigrationRunner`, `IsolationStrategy`, `DeprovisionMode`, errors.
- Produces: `TenantRegistry` with `create`, `provision`, `migrate`, `suspend`, `resume`, `archive`, `deprovision`, `assert_servable`, `list_for_user`; `RegistryWriteFence` with `assert_writable`; `SeedHook` protocol (`async seed(tenant) -> None`).

- [ ] **Step 1: Add the control async fixture**

Append to `tests/integration/conftest.py`:

```python
@pytest.fixture()
async def control_session_factory(async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from jdlib.control.base import ControlBase
    from jdlib.control.models import Tenant  # noqa: F401

    async with async_engine.begin() as connection:
        await connection.run_sync(ControlBase.metadata.create_all)
    return async_sessionmaker(async_engine, expire_on_commit=False)
```

- [ ] **Step 2: Write the failing tests**

`tests/integration/test_registry.py`:

```python
import uuid

import pytest

from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import MigrationStatus, PlacementStrategy, TenantStatus
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.errors import TenantNotWritable, TenantOperationInProgress, TenantSuspended
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
    with pytest.raises(Exception):
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
    with pytest.raises(Exception):
        await registry.deprovision(parent.id, mode=DeprovisionMode.ARCHIVE)
    await registry.deprovision(parent.id, mode=DeprovisionMode.ARCHIVE, detach_children=True)
    assert (await registry.get(child.id)).parent_tenant_id is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.control.registry'`

- [ ] **Step 4: Implement `src/jdlib/control/registry.py`**

```python
from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

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
    TenantNotWritable,
    TenantNotFound,
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
            tenant = await session.get(Tenant, tenant_id)
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
            existing = (
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
                action="tenant.created", tenant_id=tenant.id, actor_id=actor_id, metadata={"slug": slug}
            )
            await session.commit()
            return tenant

    async def _lock(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> None:
        await session.execute(
            sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"jdlib:tenant:{tenant_id}"},
        )

    async def provision(self, tenant_id: uuid.UUID) -> Tenant:
        async with await self._control() as session:
            await self._lock(session, tenant_id)
            tenant = await session.get(Tenant, tenant_id)
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
            tenant = await session.get(Tenant, tenant_id)
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
            tenant_id, TenantStatus.SUSPENDED, action="tenant.suspended", reason=reason,
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
            tenant_id, TenantStatus.ARCHIVED, action="tenant.archived", reason=None,
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
            tenant = await session.get(Tenant, tenant_id)
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
            tenant = await session.get(Tenant, tenant_id)
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
            tenant = await session.get(Tenant, tenant_id)
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
```

Notes for the implementer: provisioning failure semantics are frozen in
`docs/jdlib/05-tenant-lifecycle.md` §2: a failed provisioning leaves the tenant
in `provisioning` (never `active`); a failed migration on an already-active
tenant suspends it (`suspended_reason='migration_failed'`) as the `migrate`
path does. The `provision` code above already follows this; keep it. Do not
reintroduce a `tenant_placement_strategy` helper.

- [ ] **Step 5: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_registry.py -v -W error`
Expected: PASS (8 passed)

- [ ] **Step 6: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/control/registry.py tests/integration/test_registry.py tests/integration/conftest.py
git commit -m "feat: tenant registry with provisioning, servability, and write fence"
```

---

## Phase 4a Exit Criteria

- [ ] Full suite green (Phase 1–3 plus registry tests) on real PostgreSQL 16.
- [ ] `create` → `provision` activates only after place/migrate/seed; provisioning is idempotent and resumable.
- [ ] Failed migration on an active tenant suspends it with `suspended_reason='migration_failed'` and audits; `assert_servable` enforces the single predicate.
- [ ] Lifecycle transitions are locked per tenant; parent/child deletion semantics enforced.
- [ ] `RegistryWriteFence` blocks writes for non-active tenants.
- [ ] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 4b — Phases 5–6: authorization (catalog, `ResourceTypeRegistry`, scopes, PDP, guards, `AccessControl`) and authentication adapters (OIDC, API keys).
- Plan 5 — Phases 7–9: schema and database strategies, RLS emission and tests.
- Plan 6 — Phase 10: audit sinks, `jdlib.testing`, FastAPI/CLI integrations, docs.
