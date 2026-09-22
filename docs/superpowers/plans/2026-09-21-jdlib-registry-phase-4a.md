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
- Parent deletion is blocked while children exist unless `detach_children=True`; no DB cascade from `tenants`. The guard is re-checked inside the final locked purge transaction: a child inserted after the entry pre-check fails the purge closed (`TenantOperationInProgress`, tenant stays `deprovisioning` for retry) instead of being silently detached.
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
    strategy = SharedSchemaStrategy(engine=None, schema="jt_test")
    await strategy.provision(_record())


async def test_shared_migrate_runs_tenant_chain_for_schema():
    strategy = SharedSchemaStrategy(engine=None, schema="jt_test")
    runner = _Runner()
    await strategy.migrate(_record(), runner)  # type: ignore[arg-type]
    assert runner.calls == [("jt_test", "head")]


async def test_shared_deprovision_is_a_noop_for_all_modes():
    strategy = SharedSchemaStrategy(engine=None, schema="jt_test")
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

    def migration_schema(self, tenant: TenantRecord) -> str: ...

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

    def migration_schema(self, tenant: TenantRecord) -> str:
        return self._schema

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
- Modify: `src/jdlib/migrations/runner.py` (`tenant_version` health read)
- Modify: `tests/integration/test_migrations.py` (`tenant_version` coverage)
- Modify: `tests/integration/conftest.py` (control async session factory fixture)
- Modify: `src/jdlib/context.py` (`ServabilityChecker.assert_servable(tenant_id) -> TenantRecord`)
- Modify: `docs/jdlib/05-tenant-lifecycle.md`, `docs/jdlib/07-implementation-design.md` (doc sync)

**Interfaces:**
- Consumes: `ControlPlaneSession`, `PlatformAudit`, `TenantRecord`, `MigrationRunner`, `IsolationStrategy`, `DeprovisionMode`, errors.
- Produces: `TenantRegistry` with `create`, `provision`, `migrate`, `suspend`, `resume`, `archive`, `deprovision`, `assert_servable(tenant_id) -> TenantRecord`, `list_for_user`; `RegistryWriteFence` with `assert_writable`; `SeedHook` protocol (`async seed(tenant) -> None`); `MigrationRunner.tenant_version(schema) -> str | None`.

**Review-fix invariants (frozen docs `05-tenant-lifecycle.md` §1–§6):**
- Tenant transitions are exactly `provisioning → active|deleted`; `active → suspended|archived`; `suspended → active|archived`; `archived → active|deprovisioning`; `deprovisioning → deleted|archived`; `deleted` terminal. Invalid transitions raise `TenantOperationInProgress`; a repeat in the target state is an idempotent no-op.
- `create` is idempotent per `(strategy, target_handle, region)` on an existing slug and raises `ProvisioningError` on a conflicting placement; the create race is serialized by `pg_advisory_xact_lock(hashtextextended('jdlib:tenant-slug:' || slug, 0))`.
- `purge`/`destroy` order: `deprovisioning` commit → re-acquired lock + state re-verify → re-query children (children present with `detach_children=false` raise `TenantOperationInProgress`; otherwise detach when `detach_children=true`) → access-row deletes in dependency order (`api_keys`, `service_accounts`, `invitations`, `role_bindings`, `resource_grants`, `role_permissions`, `roles`, `memberships`) → `strategy.deprovision` → `deleted` + audit with mode, counts, and detached child ids. `archive` deletes nothing, never resolves the placement strategy, detaches children in its own transaction, and sets `archived_at`. The ordered deletion block applies to both `purge` and `destroy` (see the §5 wording note below).
- Mandatory failure audits are recorded **before** committing the failure-state mutation (audit failure prevents the commit).
- `provision` health step reads `MigrationRunner.tenant_version(strategy.migration_schema(record))` after migrate/seed and fails closed on any mismatch with `desired_version`.
- `assert_servable(tenant_id)` loads tenant, migration state, relocation, and placement in one control session (no stale caller snapshot); it returns the `TenantRecord` built from the tenant row and placement (missing placement raises `ProvisioningError`), and the `ServabilityChecker` port is `-> TenantRecord` (mirrored by `ServabilityStub`). `RegistryWriteFence.assert_writable` enforces the same predicate with `TenantNotWritable`. Both call the one internal `_servability_error(tenant, state, relocating=...) -> str | None` helper and differ only in the raised error.
- `deprovision(purge|destroy)` re-acquires the lifecycle advisory lock after committing `deprovisioning` (the xact-scoped lock is released by that commit), re-reads the tenant, and raises `TenantOperationInProgress` if the state changed; the child detach and access-row deletes run only in that post-re-lock transaction, so a superseded or failed purge rolls them back. `strategy` is resolved after the `archive` early-return and before the `deprovisioning` commit, so `archive` works without a registered strategy while `purge`/`destroy` still fail closed before any state change.
- `deprovision` re-queries children inside the final transaction, raises `TenantOperationInProgress` when children exist and `detach_children=false` (fail closed: the `deprovisioning` state is already committed, so the tenant stays retryable), and its audit metadata carries `detach_children=true` and `detached_children=[id, ...]` when children were detached (same transaction as the detach, so the ids match what was actually detached).
- A placement with no registered strategy raises `StrategyCapabilityError` (same error as `SessionRouter`) from `_strategy_for`, before any state change for `provision`/`migrate`/`purge`/`destroy`; `archive` never calls `_strategy_for`.

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
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from jdlib._uuid import uuid7
from jdlib.context import TenantRecord
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

    async def record(self, *, action, tenant_id, actor_id, metadata=None) -> None:
        if action == self._fail_on:
            raise RuntimeError("audit sink unavailable")
        await super().record(
            action=action, tenant_id=tenant_id, actor_id=actor_id, metadata=metadata
        )


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


async def test_assert_servable_returns_active_tenant(control_session_factory):
    registry, _ = _registry(control_session_factory)
    tenant = await _active(registry, "servable")
    record = await registry.assert_servable(tenant.id)
    assert record == TenantRecord(
        id=tenant.id,
        slug=tenant.slug,
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SHARED,
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
                slug="late-child",
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.control.registry'`

- [ ] **Step 4: Implement `src/jdlib/control/registry.py`**

```python
from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord
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
```

Notes for the implementer: provisioning failure semantics are frozen in
`docs/jdlib/05-tenant-lifecycle.md` §2: a failed provisioning leaves the tenant
in `provisioning` (never `active`); a failed migration on an already-active
tenant suspends it (`suspended_reason='migration_failed'`) as the `migrate`
path does. The `provision` code above already follows this; keep it. Do not
reintroduce a `tenant_placement_strategy` helper.

Review-fix notes (frozen-doc compliance):

- Transitions (`05` §1) are enforced by `_ALLOWED_TENANT_TRANSITIONS`; a repeat
  in the target state is an idempotent no-op, anything else raises
  `TenantOperationInProgress`. `provision` may only activate from
  `provisioning`; `purge`/`destroy` may only enter `deprovisioning` from
  `archived` (or resume from `deprovisioning`), and `deleted` is terminal.
- The health step (`05` §2 step 6) calls
  `MigrationRunner.tenant_version(strategy.migration_schema(record))` after
  migrate/seed; any mismatch with `desired_version` raises `ProvisioningError`
  and follows the failure path (tenant stays `provisioning`, migration state
  `failed`, audited). `migration_schema` is a new synchronous member of the
  `IsolationStrategy` protocol (`src/jdlib/persistence/strategies/base.py`);
  `SharedSchemaStrategy` returns its configured deployment schema. Add to
  `src/jdlib/migrations/runner.py`:

```python
    def tenant_version(self, schema: str) -> str | None:
        self._validate_deployment_schema(schema)
        engine = sa.create_engine(self._database_url, future=True)
        try:
            with engine.begin() as connection:
                present = connection.execute(
                    sa.text("SELECT to_regclass(:quoted)").bindparams(
                        quoted=f"{schema}.alembic_version"
                    )
                ).scalar_one_or_none()
                if present is None:
                    return None
                return connection.execute(
                    sa.text(f'SELECT version_num FROM "{schema}".alembic_version LIMIT 1')
                ).scalar_one_or_none()
        finally:
            engine.dispose()
```

  `target_handle` remains opaque (`05` §7) and is never used as a schema:
  the strategy that performed the migration resolves the schema the health
  read must inspect. Payload-schema strategies return their configured schema
  the same way. A missing `alembic_version` reads as `None` and thus fails the
  comparison closed.
- Failure audits are recorded before committing the failure-state mutation
  (`05` §5.1), so an unavailable audit sink leaves the previous state committed
  (fail closed).
- `deprovision(purge|destroy)` commits `deprovisioning` first, re-acquires the
  lifecycle lock and re-verifies the state (superseded → `TenantOperationInProgress`),
  then re-queries children (a child that appeared after the entry pre-check with
  `detach_children=false` raises `TenantOperationInProgress` and the tenant stays
  `deprovisioning` for an explicit retry; otherwise detach when
  `detach_children=true`) and deletes
  control-plane access rows in dependency order
  (`_ACCESS_ROW_DELETION_ORDER`: `api_keys`, `service_accounts`, `invitations`,
  `role_bindings`, `resource_grants`, `role_permissions`, `roles`,
  `memberships`), then calls `strategy.deprovision`, then commits `deleted`
  with the mode, per-table counts, and detached child ids in the audit metadata.
  `archive` deletes nothing, never resolves the placement strategy, detaches
  children in its own transaction, and sets `archived_at`.
- **§5 `purge` wording (frozen doc):** the §5 mode table says `purge` retains
  "control-plane rows"; the ordered deletion block in §5 (steps 2–4) is the
  authoritative operation sequence and the implementation follows it for both
  `purge` and `destroy` — access rows (`api_keys`, `service_accounts`,
  `invitations`, `role_bindings`, `resource_grants`, `role_permissions`,
  `roles`, `memberships`) are deleted for both modes. "Retained" refers to the
  control-plane records outside that block: `tenant_placements`,
  `tenant_migration_states`, tenant/audit rows (§5 step 6) and
  `platform_audit_events`. Only `strategy.deprovision` (tenant-plane storage)
  differentiates the modes.
- Integration coverage for the health step: the fake-runner assertion expects
  the strategy schema (`jt_test`), and `test_provision_with_real_runner_activates_tenant`
  / `test_provision_version_mismatch_stays_provisioning` run the real
  `MigrationRunner` against the migrated shared schema (activation vs
  non-existent desired revision → stays `provisioning`); unit coverage:
  `test_shared_migration_schema_returns_configured_schema`.
- `create` reuses an existing slug only when `(strategy, target_handle, region)`
  match the stored placement; otherwise `ProvisioningError`. The create race is
  serialized with `pg_advisory_xact_lock(hashtextextended('jdlib:tenant-slug:' || slug, 0))`.
- `assert_servable(tenant_id)` loads the tenant, migration state, relocation
  check, and placement in one control session (a caller's stale `Tenant` snapshot
  can no longer fail open) and returns the `TenantRecord` (`-> TenantRecord` on
  the port; missing placement raises `ProvisioningError`);
  `RegistryWriteFence.assert_writable` enforces the same predicate
  with `TenantNotWritable`.
- Integration coverage also includes `tests/integration/test_migrations.py`
  (`tenant_version` reads the tenant baseline, missing schema returns `None`,
  invalid identifier rejected before SQL).
- Concurrency coverage (real PostgreSQL): `test_concurrent_provisions_serialize`
  (two `asyncio.gather` provisions of one tenant → both return `active`, one
  migration run, one `tenant.activated` audit),
  `test_concurrent_provisions_of_distinct_tenants` (two tenants provision
  concurrently, each migrating once), and
  `test_deprovision_superseded_after_lock_release_raises` (a state change
  between the `deprovisioning` commit and the re-acquired lock raises
  `TenantOperationInProgress`; with seeded access rows and an attached child,
  both survive the rollback — the lock-gap regression guard), and
  `test_deprovision_child_race_fails_closed` (a child inserted after the entry
  pre-check, with `detach_children=false`, raises `TenantOperationInProgress`;
  the parent stays `deprovisioning` and the child stays attached — the
  detach-guard race regression guard).
- Deprovision retry: `test_deprovisioning_retry_resumes_after_strategy_failure`
  (archive → failed purge leaves `deprovisioning` → retry purge resumes,
  deletes access rows, marks `deleted`).
- `_strategy_for` direct paths: `test_provision_unknown_strategy_raises_capability_error`
  (`StrategyCapabilityError`), `test_provision_missing_placement_raises` and
  `test_provision_missing_migration_state_raises` (`ProvisioningError`), and
  `test_deprovision_archive_ignores_unregistered_strategy` (`archive` succeeds
  with `strategies={}`).
- Servability return contract: `test_assert_servable_returns_active_tenant`
  asserts the returned `TenantRecord` (id, slug, status, strategy) and
  `test_assert_servable_missing_placement_raises` asserts `ProvisioningError`.
- Detach audit: `test_parent_with_children_cannot_be_archived` asserts
  `detach_children=true` and `detached_children=[child_id]` in the
  `tenant.deprovisioned` metadata (children re-queried in the transaction that
  performs the detach).
- The end-to-end test is real: `_real_registry` no longer pre-runs
  `upgrade_tenant`; `provision` performs the migration itself.

- [ ] **Step 5: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_registry.py -v -W error`
Expected: PASS (36 passed)

- [ ] **Step 6: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/control/registry.py src/jdlib/migrations/runner.py tests/integration/test_registry.py tests/integration/test_migrations.py tests/integration/conftest.py
git commit -m "feat: tenant registry with provisioning, servability, and write fence"
```

---

## Phase 4a Exit Criteria

- [ ] Full suite green (Phase 1–3 plus registry tests) on real PostgreSQL 16.
- [ ] `create` → `provision` activates only after place/migrate/seed/health; provisioning is idempotent and resumable.
- [ ] Failed migration on an active tenant suspends it with `suspended_reason='migration_failed'` and audits; `assert_servable` enforces the single predicate.
- [ ] Lifecycle transitions follow the frozen table; invalid transitions raise `TenantOperationInProgress`; parent/child deletion semantics enforced.
- [ ] `RegistryWriteFence` blocks writes for tenants that are not servable (status, migration currency, relocation).
- [ ] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 4b — Phases 5–6: authorization (catalog, `ResourceTypeRegistry`, scopes, PDP, guards, `AccessControl`) and authentication adapters (OIDC, API keys).
- Plan 5 — Phases 7–9: schema and database strategies, RLS emission and tests.
- Plan 6 — Phase 10: audit sinks, `jdlib.testing`, FastAPI/CLI integrations, docs.
