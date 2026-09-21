# jdlib Foundation (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the jdlib package foundation: project scaffold, error hierarchy, UUIDv7, declarative bases and mixins, all control-plane and tenant-plane models, metadata lint L1–L19, and baseline migrations for both planes.

**Architecture:** Two SQLAlchemy declarative bases — `ControlBase` (schema `jd_control`, never routed) and `TenantBase` (unqualified, routed by strategy later) — with composite `(tenant_id, id)` identity and tenant-aware FKs. A metadata lint module enforces the schema contract (L1–L19) offline in tests and at app startup. Alembic migrations are invoked programmatically; baseline revisions materialize each plane's metadata.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0, Alembic, Pydantic v2 + pydantic-settings, psycopg 3, asyncpg, pglast, PyJWT, httpx, argon2-cffi; pytest + pytest-asyncio + testcontainers for integration; ruff + mypy for quality.

**Specs (frozen):** `docs/superpowers/specs/2026-09-21-jdlib-multitenancy-foundation-design.md` (rev 7) and `docs/jdlib/02-relational-schema.md`, `03-isolation-invariants.md`, `04-authorization-model.md`, `05-tenant-lifecycle.md`, `06-strategy-matrix.md`, `07-implementation-design.md`.

## Global Constraints

- Python `>=3.12`; PostgreSQL `>=15` only (integration tests use a `postgres:16` container).
- Async-first for runtime; Phase 1 code is synchronous metadata/DDL only.
- Two planes: control tables live in schema `jd_control`; tenant tables are schema-unqualified.
- Tenant-scoped tables use `PRIMARY KEY (tenant_id, id)` with `tenant_id` first; every FK between tenant-scoped tables is composite and includes `tenant_id`.
- `tenant_id` is `NOT NULL` and immutable on tenant-scoped rows.
- Timestamps are `timestamptz`, stored UTC.
- UUIDv7 identifiers generated in-process (`jdlib._uuid.uuid7`), no uuid dependency.
- `ON DELETE RESTRICT` is the default; `CASCADE` only for composition rows (identity_links, role_permissions, api_keys).
- No DB cascade path may start at `tenants`.
- All schema names/table names as in `docs/jdlib/02-relational-schema.md` — do not rename anything.
- Commands (run from repo root, venv active): `python -m pytest ...`, `python -m ruff check .`, `python -m mypy src/jdlib`.
- No comments in source code unless the design docs require one; use docstrings only where they add contract information.
- Commit after every task; never commit `.env`, secrets, or container credentials.

---

### Task 1: Project scaffold, errors, UUIDv7

**Files:**
- Create: `pyproject.toml`
- Create: `src/jdlib/__init__.py`
- Create: `src/jdlib/errors.py`
- Create: `src/jdlib/_uuid.py`
- Create: `tests/unit/test_errors.py`
- Create: `tests/unit/test_uuid.py`
- Create: `.gitignore`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: `jdlib.errors.JdlibError` and the full subclass tree (names frozen in spec §9); `jdlib._uuid.uuid7() -> uuid.UUID`.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "jdlib"
version = "0.1.0"
description = "Reusable multi-tenant foundation"
requires-python = ">=3.12"
dependencies = [
    "alembic>=1.13",
    "argon2-cffi>=23.1",
    "asyncpg>=0.29",
    "httpx>=0.27",
    "pglast>=6.0",
    "psycopg[binary]>=3.2",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "pyjwt[crypto]>=2.8",
    "sqlalchemy[asyncio]>=2.0.30",
]

[project.optional-dependencies]
dev = [
    "mypy>=1.10",
    "pytest>=8.2",
    "pytest-asyncio>=0.23",
    "ruff>=0.5",
    "testcontainers[postgres]>=4.5",
]
fastapi = ["fastapi>=0.111"]
cli = ["typer>=0.12"]

[tool.hatch.build.targets.wheel]
packages = ["src/jdlib"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.12"
strict = true
files = ["src/jdlib"]
```

- [ ] **Step 2: Write `.gitignore` and CI**

`.gitignore`:

```
__pycache__/
*.pyc
.venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
dist/
build/
*.egg-info/
.env
.worktrees/
.superpowers/
```

`.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e ".[dev]"
      - run: python -m ruff check .
      - run: python -m mypy src/jdlib
      - run: python -m pytest -q
```

- [ ] **Step 3: Write the failing tests**

`tests/unit/test_errors.py`:

```python
import pytest

from jdlib import errors


def test_all_errors_derive_from_jdlib_error():
    for name in errors.__all__:
        cls = getattr(errors, name)
        assert issubclass(cls, errors.JdlibError)


def test_expected_error_names_exist():
    expected = {
        "MissingTenantContext",
        "TenantNotFound",
        "TenantAccessDenied",
        "TenantSuspended",
        "TenantNotWritable",
        "CrossTenantReferenceError",
        "UnscopedBulkOperation",
        "InvalidReference",
        "InvalidResourcePermission",
        "UnknownResourceType",
        "UnknownPermission",
        "RoleScopeMismatch",
        "AuthenticationError",
        "InvalidToken",
        "ExpiredToken",
        "UnknownPrincipal",
        "AuthorizationError",
        "PermissionDenied",
        "RoleEscalationBlocked",
        "StrategyCapabilityError",
        "PoolCapacityError",
        "TenantOperationInProgress",
        "RelocationPhaseError",
        "UnscopedRawSql",
        "SchemaLintError",
        "ProvisioningError",
        "MigrationError",
    }
    assert expected == set(errors.__all__)


def test_error_messages_include_context():
    err = errors.CrossTenantReferenceError("invoices.project_id", "tenant A", "tenant B")
    assert "invoices.project_id" in str(err)
    assert "tenant A" in str(err)
    assert "tenant B" in str(err)
```

`tests/unit/test_uuid.py`:

```python
import time
import uuid

from jdlib._uuid import uuid7


def test_uuid7_version_and_variant():
    value = uuid7()
    assert value.version == 7


def test_uuid7_is_unique_and_ordered_by_time():
    first = uuid7()
    time.sleep(0.002)
    second = uuid7()
    assert first != second
    assert first.hex < second.hex


def test_uuid7_returns_stdlib_uuid():
    assert isinstance(uuid7(), uuid.UUID)
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_errors.py tests/unit/test_uuid.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib'`

- [ ] **Step 5: Implement `src/jdlib/errors.py`**

```python
class JdlibError(Exception):
    pass


class MissingTenantContext(JdlibError):
    pass


class TenantNotFound(JdlibError):
    def __init__(self, tenant: str) -> None:
        super().__init__(f"tenant not found: {tenant}")


class TenantAccessDenied(JdlibError):
    pass


class TenantSuspended(JdlibError):
    pass


class TenantNotWritable(JdlibError):
    pass


class CrossTenantReferenceError(JdlibError):
    def __init__(self, reference: str, expected_tenant: str, actual_tenant: str) -> None:
        super().__init__(
            f"cross-tenant reference {reference}: expected {expected_tenant}, got {actual_tenant}"
        )


class UnscopedBulkOperation(JdlibError):
    pass


class InvalidReference(JdlibError):
    pass


class InvalidResourcePermission(JdlibError):
    pass


class UnknownResourceType(JdlibError):
    pass


class UnknownPermission(JdlibError):
    pass


class RoleScopeMismatch(JdlibError):
    pass


class AuthenticationError(JdlibError):
    pass


class InvalidToken(AuthenticationError):
    pass


class ExpiredToken(AuthenticationError):
    pass


class UnknownPrincipal(AuthenticationError):
    pass


class AuthorizationError(JdlibError):
    pass


class PermissionDenied(AuthorizationError):
    pass


class RoleEscalationBlocked(AuthorizationError):
    pass


class StrategyCapabilityError(JdlibError):
    pass


class PoolCapacityError(JdlibError):
    pass


class TenantOperationInProgress(JdlibError):
    pass


class RelocationPhaseError(JdlibError):
    pass


class UnscopedRawSql(JdlibError):
    pass


class SchemaLintError(JdlibError):
    def __init__(self, issues: list[str]) -> None:
        super().__init__("schema lint failed: " + "; ".join(issues))
        self.issues = issues


class ProvisioningError(JdlibError):
    pass


class MigrationError(JdlibError):
    pass


__all__ = [
    "JdlibError",
    "MissingTenantContext",
    "TenantNotFound",
    "TenantAccessDenied",
    "TenantSuspended",
    "TenantNotWritable",
    "CrossTenantReferenceError",
    "UnscopedBulkOperation",
    "InvalidReference",
    "InvalidResourcePermission",
    "UnknownResourceType",
    "UnknownPermission",
    "RoleScopeMismatch",
    "AuthenticationError",
    "InvalidToken",
    "ExpiredToken",
    "UnknownPrincipal",
    "AuthorizationError",
    "PermissionDenied",
    "RoleEscalationBlocked",
    "StrategyCapabilityError",
    "PoolCapacityError",
    "TenantOperationInProgress",
    "RelocationPhaseError",
    "UnscopedRawSql",
    "SchemaLintError",
    "ProvisioningError",
    "MigrationError",
]
```

- [ ] **Step 6: Implement `src/jdlib/_uuid.py`**

```python
from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    timestamp_ms = int(time.time() * 1000)
    raw = bytearray(os.urandom(16))
    raw[0:6] = timestamp_ms.to_bytes(6, "big")
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(raw))
```

- [ ] **Step 7: Write `src/jdlib/__init__.py`**

```python
from jdlib import errors

__all__ = ["errors"]
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_errors.py tests/unit/test_uuid.py -v`
Expected: PASS (6 passed)

- [ ] **Step 9: Run lint and type checks**

Run: `python -m ruff check . && python -m mypy src/jdlib`
Expected: `Success: no issues found`

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml .gitignore .github src tests
git commit -m "feat: scaffold jdlib, error hierarchy, uuid7"
```

---

### Task 2: Declarative bases, mixins, ownership constraints

**Files:**
- Create: `src/jdlib/control/base.py`
- Create: `src/jdlib/models/base.py`
- Create: `tests/unit/test_bases.py`

**Interfaces:**
- Consumes: `jdlib._uuid.uuid7`.
- Produces:
  - `jdlib.control.base.ControlBase`, `CONTROL_SCHEMA = "jd_control"`, `ControlBase.metadata`.
  - `jdlib.models.base.TenantBase`, `TenantBase.metadata`.
  - Mixins `TenantOwned`, `TenantRouted`, `Timestamped`, `SoftDelete`, `OwnableByOrg`, `OwnableByTeam`.
  - `ownership_constraints() -> tuple[Constraint, ...]` for concrete-model `__table_args__`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_bases.py`:

```python
import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib.control.base import CONTROL_SCHEMA, ControlBase
from jdlib.models.base import (
    SoftDelete,
    TenantBase,
    TenantOwned,
    TenantRouted,
    Timestamped,
    ownership_constraints,
)


class ControlProbe(ControlBase):
    __tablename__ = "control_probe"
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)


class TenantProbe(TenantBase, TenantRouted, Timestamped, SoftDelete):
    __tablename__ = "tenant_probe"
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)


def test_control_metadata_uses_control_schema():
    assert ControlBase.metadata.schema == CONTROL_SCHEMA == "jd_control"
    assert ControlProbe.__table__.schema == "jd_control"


def test_tenant_metadata_is_unqualified():
    assert TenantBase.metadata.schema is None
    assert TenantProbe.__table__.schema is None


def test_tenant_routed_subclasses_tenant_owned():
    assert issubclass(TenantRouted, TenantOwned)


def test_tenant_scoped_pk_leads_with_tenant_id():
    pk = TenantProbe.__table__.primary_key
    assert [column.name for column in pk.columns] == ["tenant_id", "id"]


def test_mixins_contribute_columns():
    names = {column.name for column in TenantProbe.__table__.columns}
    assert {"tenant_id", "created_at", "updated_at", "deleted_at"} <= names
    assert all(
        column.type.timezone for column in TenantProbe.__table__.columns
        if column.name in {"created_at", "updated_at", "deleted_at"}
    )


def test_ownership_constraints_shape():
    constraints = ownership_constraints()
    kinds = [type(constraint).__name__ for constraint in constraints]
    assert kinds == ["CheckConstraint", "ForeignKeyConstraint", "ForeignKeyConstraint"]
    assert {constraint.name for constraint in constraints} == {
        "team_requires_org",
        "organization",
        "team",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_bases.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.control'`

- [ ] **Step 3: Implement `src/jdlib/control/base.py`**

```python
from __future__ import annotations

from sqlalchemy import MetaData, text
from sqlalchemy.orm import DeclarativeBase

CONTROL_SCHEMA = "jd_control"

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s",
    "pk": "pk_%(table_name)s",
}


class ControlBase(DeclarativeBase):
    metadata = MetaData(
        schema=CONTROL_SCHEMA,
        naming_convention=NAMING_CONVENTION,
    )
```

- [ ] **Step 4: Implement `src/jdlib/models/base.py`**

```python
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from jdlib.control.base import NAMING_CONVENTION


class TenantBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TenantOwned:
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        primary_key=True,
        nullable=False,
        index=True,
        sort_order=-1,
    )


class TenantRouted(TenantOwned):
    pass


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )


class SoftDelete:
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class OwnableByOrg:
    organization_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)


class OwnableByTeam:
    team_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)


def ownership_constraints() -> tuple[sa.schema.Constraint, ...]:
    return (
        sa.CheckConstraint(
            "team_id IS NULL OR organization_id IS NOT NULL",
            name="team_requires_org",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "organization_id"],
            ["organizations.tenant_id", "organizations.id"],
            name="organization",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "team_id", "organization_id"],
            ["teams.tenant_id", "teams.id", "teams.organization_id"],
            name="team",
            ondelete="RESTRICT",
        ),
    )
```

Note: `uuid7` is intentionally not imported here; each model module imports it from
`jdlib._uuid` directly.

Note: `sort_order=-1` on the mixin's `tenant_id` is required — declarative mixin
columns otherwise sort after subclass columns, producing a `(id, tenant_id)`
column order that violates the frozen `PRIMARY KEY (tenant_id, id)` contract and
lint L4. Models that declare `tenant_id` explicitly (rather than via the mixin)
must declare it before `id`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_bases.py -v`
Expected: PASS (6 passed)

- [ ] **Step 6: Lint, type check, commit**

Run: `python -m ruff check . && python -m mypy src/jdlib`
Expected: clean.

```bash
git add src tests
git commit -m "feat: declarative bases, tenant mixins, ownership constraints"
```

---

### Task 3: Control registry models

**Files:**
- Create: `src/jdlib/control/enums.py`
- Create: `src/jdlib/control/models.py`
- Create: `tests/integration/conftest.py`
- Create: `tests/integration/test_registry_models.py`

**Interfaces:**
- Consumes: `ControlBase`, `uuid7`.
- Produces: `Tenant`, `TenantPlacement`, `TenantMigrationState`, `TenantRelocation` ORM classes; `TenantStatus`, `PlacementStrategy`, `MigrationStatus`, `RelocationPhase` StrEnums; `control_engine`/`control_schema` pytest fixtures.

- [ ] **Step 1: Write the integration fixtures**

`tests/integration/conftest.py`:

```python
from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

CONTROL_SCHEMA = "jd_control"
TENANT_SCHEMA = "jt_test"


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    if url := os.environ.get("JDLIB_TEST_DATABASE_URL"):
        yield url
        return
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16", driver="psycopg") as container:
        yield container.get_connection_url()


@pytest.fixture(scope="session")
def control_engine(postgres_url: str) -> Iterator[Engine]:
    engine = sa.create_engine(postgres_url, future=True)
    with engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE EXTENSION IF NOT EXISTS citext')
        connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{CONTROL_SCHEMA}"')
        connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{TENANT_SCHEMA}"')
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def control_metadata(control_engine: Engine) -> Iterator[None]:
    from jdlib.control.models import Tenant  # noqa: F401
    from jdlib.control.base import ControlBase

    ControlBase.metadata.create_all(control_engine)
    yield
```

- [ ] **Step 2: Write the failing tests**

`tests/integration/test_registry_models.py`:

```python
from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib._uuid import uuid7
from jdlib.control.base import CONTROL_SCHEMA
from jdlib.control.models import (
    Tenant,
    TenantMigrationState,
    TenantPlacement,
    TenantRelocation,
)


def _table(model: type) -> sa.Table:
    return model.__table__  # type: ignore[attr-defined]


def test_registry_tables_live_in_control_schema():
    for model in (Tenant, TenantPlacement, TenantMigrationState, TenantRelocation):
        assert _table(model).schema == CONTROL_SCHEMA


def test_placement_pk_is_tenant_id():
    assert [c.name for c in _table(TenantPlacement).primary_key.columns] == ["tenant_id"]


def test_relocation_pk_and_active_unique_index():
    table = _table(TenantRelocation)
    assert [c.name for c in table.primary_key.columns] == ["tenant_id", "id"]
    indexes = {index.name: index for index in table.indexes}
    active = next(
        index for index in indexes.values()
        if index.unique and index.dialect_options["postgresql"].get("where") is not None
    )
    assert "status NOT IN" in str(active.dialect_options["postgresql"]["where"])


def test_tenant_check_constraints_exist():
    table = _table(Tenant)
    names = {constraint.name for constraint in table.constraints
             if isinstance(constraint, sa.CheckConstraint)}
    assert names == {"ck_tenants_status", "ck_tenants_slug_format"}


def test_slug_format_rejected(control_engine, control_metadata):
    with control_engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(_table(Tenant)).values(
                    id=uuid7(), slug="BAD SLUG", name="Bad", status="provisioning"
                )
            )


def test_duplicate_placement_rejected(control_engine, control_metadata):
    tenant_id = uuid7()
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=tenant_id, slug=f"acme-{tenant_id.hex[:8]}", name="Acme", status="active"
            )
        )
        connection.execute(
            sa.insert(_table(TenantPlacement)).values(
                tenant_id=tenant_id, strategy="shared", target_handle="default"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(_table(TenantPlacement)).values(
                    tenant_id=tenant_id, strategy="schema", target_handle="t_other"
                )
            )


def test_invalid_strategy_rejected(control_engine, control_metadata):
    tenant_id = uuid7()
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=tenant_id, slug=f"beta-{tenant_id.hex[:8]}", name="Beta", status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(_table(TenantPlacement)).values(
                    tenant_id=tenant_id, strategy="sharded", target_handle="x"
                )
            )


def test_duplicate_active_relocation_rejected(control_engine, control_metadata):
    tenant_id = uuid7()
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=tenant_id, slug=f"gamma-{tenant_id.hex[:8]}", name="Gamma", status="active"
            )
        )
        values = {
            "tenant_id": tenant_id,
            "from_strategy": "shared",
            "from_target_handle": "default",
            "to_strategy": "database",
            "to_target_handle": "db-gamma",
            "status": "copying",
        }
        connection.execute(sa.insert(_table(TenantRelocation)).values(id=uuid7(), **values))
        with pytest.raises(IntegrityError):
            connection.execute(sa.insert(_table(TenantRelocation)).values(id=uuid7(), **values))
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_registry_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.control.models'`

- [ ] **Step 4: Implement `src/jdlib/control/enums.py`**

```python
from __future__ import annotations

from enum import StrEnum


class TenantStatus(StrEnum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    DEPROVISIONING = "deprovisioning"
    DELETED = "deleted"


class PlacementStrategy(StrEnum):
    SHARED = "shared"
    SCHEMA = "schema"
    DATABASE = "database"


class MigrationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


class RelocationPhase(StrEnum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    COPYING = "copying"
    VERIFYING = "verifying"
    FLIPPING = "flipping"
    POST_FLIP_VERIFICATION = "post_flip_verification"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class OperatorLevel(StrEnum):
    SUPPORT = "support"
    OPERATOR = "operator"
    ADMIN = "admin"


class PrincipalType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"


class ScopeType(StrEnum):
    TENANT = "tenant"
    ORG = "org"
    TEAM = "team"


class MembershipStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class InvitationStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ApiKeyStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ActorType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    PLATFORM_OPERATOR = "platform_operator"
    SYSTEM = "system"


class AuditSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


def sql_in(column: str, values: type[StrEnum]) -> str:
    rendered = ", ".join(f"'{member.value}'" for member in values)
    return f"{column} IN ({rendered})"
```

- [ ] **Step 5: Implement registry models in `src/jdlib/control/models.py`**

```python
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.control.base import ControlBase
from jdlib.control.enums import (
    MigrationStatus,
    PlacementStrategy,
    RelocationPhase,
    TenantStatus,
    sql_in,
)


class Tenant(ControlBase):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=TenantStatus.PROVISIONING.value
    )
    suspended_reason: Mapped[str | None] = mapped_column(sa.Text)
    parent_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
    suspended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    archived_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint(sql_in("status", TenantStatus), name="status"),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name="slug_format"),
    )


class TenantPlacement(ControlBase):
    __tablename__ = "tenant_placements"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    region: Mapped[str | None] = mapped_column(sa.Text)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("strategy", PlacementStrategy), name="strategy"),
    )


class TenantMigrationState(ControlBase):
    __tablename__ = "tenant_migration_states"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    current_version: Mapped[str | None] = mapped_column(sa.Text)
    desired_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=MigrationStatus.PENDING.value
    )
    last_error: Mapped[str | None] = mapped_column(sa.Text)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("status", MigrationStatus), name="status"),
    )


class TenantRelocation(ControlBase):
    __tablename__ = "tenant_relocations"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    from_strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_region: Mapped[str | None] = mapped_column(sa.Text)
    to_strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_region: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=RelocationPhase.PENDING.value
    )
    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    flipped_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(sa.Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.CheckConstraint(sql_in("from_strategy", PlacementStrategy), name="from_strategy"),
        sa.CheckConstraint(sql_in("to_strategy", PlacementStrategy), name="to_strategy"),
        sa.CheckConstraint(sql_in("status", RelocationPhase), name="status"),
        sa.Index(
            "uq_tenant_relocations_active",
            "tenant_id",
            unique=True,
            postgresql_where=sa.text(
                "status NOT IN ('completed', 'failed', 'rolled_back')"
            ),
        ),
    )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_registry_models.py -v`
Expected: PASS (8 passed)

- [ ] **Step 7: Lint, type check, commit**

Run: `python -m ruff check . && python -m mypy src/jdlib`

```bash
git add src tests
git commit -m "feat: control registry models (tenants, placements, migration state, relocations)"
```

---

### Task 4: Control identity and access models

**Files:**
- Modify: `src/jdlib/control/models.py` (append)
- Create: `tests/integration/test_identity_models.py`

**Interfaces:**
- Consumes: `ControlBase`, enums, `sql_in`.
- Produces: `User`, `IdentityLink`, `PlatformOperator`, `ServiceAccount`, `ApiKey`, `Membership`, `Invitation` ORM classes.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_identity_models.py`:

```python
from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib._uuid import uuid7
from jdlib.control.models import (
    ApiKey,
    IdentityLink,
    Invitation,
    Membership,
    PlatformOperator,
    ServiceAccount,
    Tenant,
    User,
)


def _new_tenant(connection: sa.Connection, slug: str) -> str:
    tenant_id = uuid7()
    connection.execute(
        sa.insert(Tenant.__table__).values(id=tenant_id, slug=slug, name=slug, status="active")
    )
    return tenant_id


def test_user_email_partial_unique_and_citext(control_engine, control_metadata):
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(User.__table__).values(
                id=uuid7(), email="Alice@Example.com", display_name="Alice", status="active"
            )
        )
        connection.execute(
            sa.insert(User.__table__).values(
                id=uuid7(), email=None, display_name="NoMail", status="active"
            )
        )
        connection.execute(
            sa.insert(User.__table__).values(
                id=uuid7(), email=None, display_name="NoMail2", status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(User.__table__).values(
                    id=uuid7(), email="alice@example.com", display_name="Dup", status="active"
                )
            )


def test_identity_link_unique_issuer_subject(control_engine, control_metadata):
    with control_engine.begin() as connection:
        user_id = uuid7()
        connection.execute(
            sa.insert(User.__table__).values(id=user_id, status="active")
        )
        connection.execute(
            sa.insert(IdentityLink.__table__).values(
                id=uuid7(), user_id=user_id, issuer="https://idp", subject="abc"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(IdentityLink.__table__).values(
                    id=uuid7(), user_id=user_id, issuer="https://idp", subject="abc"
                )
            )


def test_service_account_name_unique_per_tenant(control_engine, control_metadata):
    with control_engine.begin() as connection:
        tenant_a = _new_tenant(connection, "sa-tenant-a")
        tenant_b = _new_tenant(connection, "sa-tenant-b")
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_a, id=uuid7(), name="worker", status="active"
            )
        )
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_b, id=uuid7(), name="worker", status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(ServiceAccount.__table__).values(
                    tenant_id=tenant_a, id=uuid7(), name="worker", status="active"
                )
            )


def test_api_key_prefix_globally_unique_and_sa_scoped(control_engine, control_metadata):
    with control_engine.begin() as connection:
        tenant_a = _new_tenant(connection, "key-tenant-a")
        tenant_b = _new_tenant(connection, "key-tenant-b")
        sa_id = uuid7()
        sa_b_id = uuid7()
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_a, id=sa_id, name="svc", status="active"
            )
        )
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_b, id=sa_b_id, name="svc", status="active"
            )
        )
        connection.execute(
            sa.insert(ApiKey.__table__).values(
                tenant_id=tenant_a,
                id=uuid7(),
                service_account_id=sa_id,
                key_prefix="jd_abc",
                key_hash="hash",
                status="active",
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(ApiKey.__table__).values(
                    tenant_id=tenant_b,
                    id=uuid7(),
                    service_account_id=sa_b_id,
                    key_prefix="jd_abc",
                    key_hash="hash",
                    status="active",
                )
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(ApiKey.__table__).values(
                    tenant_id=tenant_a,
                    id=uuid7(),
                    service_account_id=sa_b_id,
                    key_prefix="jd_cross",
                    key_hash="hash",
                    status="active",
                )
            )


def test_membership_unique_per_tenant_and_cross_tenant_fk(control_engine, control_metadata):
    with control_engine.begin() as connection:
        tenant_a = _new_tenant(connection, "mem-tenant-a")
        tenant_b = _new_tenant(connection, "mem-tenant-b")
        user_id = uuid7()
        connection.execute(sa.insert(User.__table__).values(id=user_id, status="active"))
        connection.execute(
            sa.insert(Membership.__table__).values(
                tenant_id=tenant_a, id=uuid7(), user_id=user_id, status="active"
            )
        )
        connection.execute(
            sa.insert(Membership.__table__).values(
                tenant_id=tenant_b, id=uuid7(), user_id=user_id, status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Membership.__table__).values(
                    tenant_id=tenant_a, id=uuid7(), user_id=user_id, status="active"
                )
            )


def test_invitation_single_pending_per_email_scope(control_engine, control_metadata):
    from jdlib.control.models import Role

    with control_engine.begin() as connection:
        tenant_id = _new_tenant(connection, "inv-tenant")
        role_id = uuid7()
        connection.execute(
            sa.insert(Role.__table__).values(
                tenant_id=tenant_id, id=role_id, name="member", is_system=False
            )
        )
        base = {
            "tenant_id": tenant_id,
            "email": "invitee@example.com",
            "scope_type": "tenant",
            "role_id": role_id,
            "status": "pending",
        }
        connection.execute(
            sa.insert(Invitation.__table__).values(
                id=uuid7(), token_id="tok-1", token_hash="hash", **base
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Invitation.__table__).values(
                    id=uuid7(), token_id="tok-2", token_hash="hash", **base
                )
            )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_identity_models.py -v`
Expected: FAIL with `ImportError: cannot import name 'User'`

- [ ] **Step 3: Append models to `src/jdlib/control/models.py`**

Add imports at the top of the file:

```python
from sqlalchemy.dialects.postgresql import CITEXT, ARRAY, INET, JSONB
from jdlib.control.enums import (
    ApiKeyStatus,
    AuditSeverity,
    ActorType,
    InvitationStatus,
    MembershipStatus,
    OperatorLevel,
    PrincipalType,
    ScopeType,
)
```

Append:

```python
class User(ControlBase):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    email: Mapped[str | None] = mapped_column(CITEXT)
    display_name: Mapped[str | None] = mapped_column(sa.Text)
    locale: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint("status IN ('active','suspended','deleted')", name="status"),
        sa.Index(
            "uq_users_email",
            "email",
            unique=True,
            postgresql_where=sa.text("email IS NOT NULL"),
        ),
    )


class IdentityLink(ControlBase):
    __tablename__ = "identity_links"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    issuer: Mapped[str] = mapped_column(sa.Text, nullable=False)
    subject: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (sa.UniqueConstraint("issuer", "subject"),)


class PlatformOperator(ControlBase):
    __tablename__ = "platform_operators"

    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    level: Mapped[str] = mapped_column(sa.Text, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (sa.CheckConstraint(sql_in("level", OperatorLevel), name="level"),)


class ServiceAccount(ControlBase):
    __tablename__ = "service_accounts"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "name"),
        sa.CheckConstraint("status IN ('active','suspended','deleted')", name="status"),
    )


class ApiKey(ControlBase):
    __tablename__ = "api_keys"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    service_account_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    key_prefix: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_hash: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(sa.Text))
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["service_accounts.tenant_id", "service_accounts.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("key_prefix"),
        sa.CheckConstraint(sql_in("status", ApiKeyStatus), name="status"),
        sa.Index("ix_api_keys_tenant_id_service_account_id", "tenant_id", "service_account_id"),
    )


class Membership(ControlBase):
    __tablename__ = "memberships"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    joined_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    suspended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "user_id"),
        sa.CheckConstraint(sql_in("status", MembershipStatus), name="status"),
    )


class Role(ControlBase):
    __tablename__ = "roles"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text)
    is_system: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (sa.UniqueConstraint("tenant_id", "name"),)


class RolePermission(ControlBase):
    __tablename__ = "role_permissions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    permission_code: Mapped[str] = mapped_column(sa.Text, primary_key=True)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            ondelete="CASCADE",
        ),
        sa.Index("ix_role_permissions_tenant_id_permission_code", "tenant_id", "permission_code"),
    )


class RoleBinding(ControlBase):
    __tablename__ = "role_bindings"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    role_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    principal_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    principal_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    scope_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "role_id",
            "principal_type",
            "principal_id",
            "scope_type",
            "scope_id",
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(sql_in("principal_type", PrincipalType), name="principal_type"),
        sa.CheckConstraint(
            "scope_type = 'tenant' AND scope_id IS NULL"
            " OR scope_type IN ('org','team') AND scope_id IS NOT NULL",
            name="scope",
        ),
        sa.Index("ix_role_bindings_tenant_id_principal_type_principal_id",
                 "tenant_id", "principal_type", "principal_id"),
        sa.Index("ix_role_bindings_tenant_id_scope_type_scope_id",
                 "tenant_id", "scope_type", "scope_id"),
    )


class ResourceGrant(ControlBase):
    __tablename__ = "resource_grants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    resource_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    principal_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    principal_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    permission_code: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.UniqueConstraint(
            "tenant_id",
            "resource_type",
            "resource_id",
            "principal_type",
            "principal_id",
            "permission_code",
        ),
        sa.CheckConstraint(sql_in("principal_type", PrincipalType), name="principal_type"),
        sa.Index("ix_resource_grants_tenant_id_resource_type_resource_id",
                 "tenant_id", "resource_type", "resource_id"),
        sa.Index("ix_resource_grants_tenant_id_principal_type_principal_id",
                 "tenant_id", "principal_type", "principal_id"),
    )


class Invitation(ControlBase):
    __tablename__ = "invitations"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    scope_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    role_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    token_id: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    token_hash: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    invited_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(sql_in("scope_type", ScopeType), name="scope_type"),
        sa.CheckConstraint(
            "scope_type = 'tenant' AND scope_id IS NULL"
            " OR scope_type IN ('org','team') AND scope_id IS NOT NULL",
            name="scope",
        ),
        sa.CheckConstraint(sql_in("status", InvitationStatus), name="status"),
        sa.Index(
            "uq_invitations_pending",
            "tenant_id",
            "email",
            "scope_type",
            sa.text("COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)"),
            unique=True,
            postgresql_where=sa.text("status = 'pending'"),
        ),
    )


class PlatformAuditEvent(ControlBase):
    __tablename__ = "platform_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, index=True)
    actor_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    action: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_type: Mapped[str | None] = mapped_column(sa.Text)
    target_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(sa.Text)
    correlation_id: Mapped[str | None] = mapped_column(sa.Text)
    trace_id: Mapped[str | None] = mapped_column(sa.Text)
    severity: Mapped[str] = mapped_column(sa.Text, nullable=False, default="info")
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("actor_type", ActorType), name="actor_type"),
        sa.CheckConstraint(sql_in("severity", AuditSeverity), name="severity"),
        sa.Index("ix_platform_audit_events_occurred_at", "occurred_at"),
        sa.Index("ix_platform_audit_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
        sa.Index("ix_platform_audit_events_action_occurred_at", "action", "occurred_at"),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_identity_models.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `python -m ruff check . && python -m mypy src/jdlib`

```bash
git add src tests
git commit -m "feat: control identity and access models"
```

---

### Task 5: Tenant-plane models and demo consumer resource

**Files:**
- Create: `src/jdlib/models/org.py`
- Create: `src/jdlib/models/settings.py`
- Create: `src/jdlib/models/audit.py`
- Create: `tests/support/__init__.py`
- Create: `tests/support/invoice.py`
- Create: `tests/integration/test_tenant_models.py`

**Interfaces:**
- Consumes: `TenantBase`, mixins, `ownership_constraints`, `sql_in`.
- Produces: `Organization`, `Team`, `TenantSetting`, `AuditEvent`; test-only `Invoice` used by lint and migration tests.

- [ ] **Step 1: Write the failing tests**

`tests/support/invoice.py`:

```python
from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.models.base import (
    OwnableByOrg,
    OwnableByTeam,
    SoftDelete,
    TenantBase,
    TenantRouted,
    Timestamped,
    ownership_constraints,
)


class Invoice(TenantBase, TenantRouted, Timestamped, SoftDelete, OwnableByOrg, OwnableByTeam):
    __tablename__ = "invoices"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    number: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="draft")

    __table_args__ = (
        *ownership_constraints(),
        sa.Index(
            "uq_invoices_tenant_id_number",
            "tenant_id",
            "number",
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        ),
    )
```

`tests/integration/test_tenant_models.py`:

```python
from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib._uuid import uuid7
from jdlib.models.audit import AuditEvent
from jdlib.models.base import TenantBase
from jdlib.models.org import Organization, Team
from jdlib.models.settings import TenantSetting
from tests.support.invoice import Invoice


@pytest.fixture(scope="session")
def tenant_metadata(postgres_url: str):
    from sqlalchemy import create_engine

    engine = create_engine(postgres_url, future=True)
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        TenantBase.metadata.create_all(connection)
    yield engine


def _seed_tenant(engine, slug: str):
    from jdlib.control.models import Tenant

    tenant_id = uuid7()
    with engine.begin() as connection:
        connection.execute(
            sa.insert(Tenant.__table__).values(
                id=tenant_id, slug=slug, name=slug, status="active"
            )
        )
    return tenant_id


def test_org_tree_and_unique_slug(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "org-tenant")
    root_id, child_id = uuid7(), uuid7()
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=root_id, name="Root", slug="root"
            )
        )
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=child_id, name="Child", slug="child",
                parent_organization_id=root_id,
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Organization.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), name="Dup", slug="root"
                )
            )


def test_team_composite_ownership_and_resource_consistency(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "team-tenant")
    other_tenant = _seed_tenant(engine, "team-tenant-2")
    org_id, other_org_id, team_id = uuid7(), uuid7(), uuid7()
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=org_id, name="Org", slug="org"
            )
        )
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=other_org_id, name="Org2", slug="org2"
            )
        )
        connection.execute(
            sa.insert(Team.__table__).values(
                tenant_id=tenant_id, id=team_id, organization_id=org_id,
                name="Team", slug="team",
            )
        )
        connection.execute(
            sa.insert(Invoice.__table__).values(
                tenant_id=tenant_id, id=uuid7(), number="INV-1",
                organization_id=org_id, team_id=team_id,
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), number="INV-2",
                    organization_id=other_org_id, team_id=team_id,
                )
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), number="INV-3", team_id=team_id
                )
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=other_tenant, id=uuid7(), number="INV-4",
                    organization_id=org_id, team_id=team_id,
                )
            )


def test_soft_delete_partial_unique(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "soft-tenant")
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(Invoice.__table__).values(
                tenant_id=tenant_id, id=uuid7(), number="INV-9"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), number="INV-9"
                )
            )
        connection.exec_driver_sql(
            "DELETE FROM invoices WHERE number = 'INV-9'"
        )
        connection.execute(
            sa.insert(Invoice.__table__).values(
                tenant_id=tenant_id, id=uuid7(), number="INV-9"
            )
        )


def test_tenant_setting_pk_and_upsert_shape(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "settings-tenant")
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(TenantSetting.__table__).values(
                tenant_id=tenant_id, key="billing.currency", value={"code": "EUR"}
            )
        )
        assert [c.name for c in TenantSetting.__table__.primary_key.columns] == [
            "tenant_id", "key",
        ]


def test_tenant_audit_event_shape(tenant_metadata):
    assert [c.name for c in AuditEvent.__table__.primary_key.columns] == ["tenant_id", "id"]
```
Note: `test_soft_delete_partial_unique` deletes the row hard to re-test the partial unique; this table has no soft-delete filter at the DB level in Phase 1 (soft delete semantics are application-side).

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_tenant_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.models.org'`

- [ ] **Step 3: Implement `src/jdlib/models/org.py`**

```python
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.models.base import SoftDelete, TenantBase, TenantRouted, Timestamped


class Organization(TenantBase, TenantRouted, Timestamped, SoftDelete):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    parent_organization_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "parent_organization_id"],
            ["organizations.tenant_id", "organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.Index(
            "uq_organizations_tenant_id_slug",
            "tenant_id",
            "slug",
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        ),
        sa.Index("ix_organizations_tenant_id_parent_organization_id",
                 "tenant_id", "parent_organization_id"),
    )


class Team(TenantBase, TenantRouted, Timestamped, SoftDelete):
    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    organization_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "organization_id"],
            ["organizations.tenant_id", "organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "id", "organization_id"),
        sa.Index(
            "uq_teams_tenant_id_organization_id_slug",
            "tenant_id",
            "organization_id",
            "slug",
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        ),
        sa.Index("ix_teams_tenant_id_organization_id", "tenant_id", "organization_id"),
    )
```

- [ ] **Step 4: Implement `src/jdlib/models/settings.py` and `src/jdlib/models/audit.py`**

`settings.py`:

```python
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from jdlib.models.base import TenantBase, TenantOwned


class TenantSetting(TenantBase, TenantOwned):
    __tablename__ = "tenant_settings"

    key: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
```

`audit.py`:

```python
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.control.enums import ActorType, sql_in
from jdlib.models.base import TenantBase, TenantOwned


class AuditEvent(TenantBase, TenantOwned):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    actor_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    action: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_type: Mapped[str | None] = mapped_column(sa.Text)
    target_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(sa.Text)
    correlation_id: Mapped[str | None] = mapped_column(sa.Text)
    trace_id: Mapped[str | None] = mapped_column(sa.Text)
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("actor_type", ActorType), name="actor_type"),
        sa.Index("ix_audit_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
        sa.Index("ix_audit_events_tenant_id_target_type_target_id",
                 "tenant_id", "target_type", "target_id"),
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_tenant_models.py -v`
Expected: PASS (5 passed)

- [ ] **Step 6: Lint, type check, commit**

Run: `python -m ruff check . && python -m mypy src/jdlib`

```bash
git add src tests
git commit -m "feat: tenant-plane models and demo invoice resource"
```

---

### Task 6: Metadata lint L1–L19

**Files:**
- Create: `src/jdlib/lint.py`
- Create: `tests/unit/test_lint.py`
- Modify: `docs/jdlib/07-implementation-design.md` (file map: add `lint.py`)

Rules implemented in this phase: L1, L2, L3, L4, L6, L9, L11, L12, L13, L15,
L17, L19. Deferred: L5 (structurally covered by L9 plus the nullable-tenant
allowlist), L10 (same shape as L2), L7/L8/L14/L16 (write-path checks shipped
with the persistence and access-control plans), L18 (requires the
`ResourceTypeRegistry`, Plan 4).

**Interfaces:**
- Consumes: `ControlBase.metadata`, `TenantBase.metadata`, mixins, `SchemaLintError`.
- Produces:
  - `LintIssue(rule: str, table: str, message: str)`
  - `lint_metadata(controls: list[MetaData], rls_enabled: bool = False) -> list[LintIssue]`
  - `assert_clean(controls: list[MetaData], rls_enabled: bool = False) -> None`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_lint.py`:

```python
from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from jdlib.control.base import ControlBase
from jdlib.lint import assert_clean, lint_metadata
from jdlib.models.base import TenantBase, TenantOwned


def test_framework_metadata_is_clean():
    import jdlib.control.models  # noqa: F401
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401

    issues = lint_metadata([ControlBase.metadata, TenantBase.metadata], rls_enabled=True)
    assert issues == []


def test_tenant_owned_without_routed_is_l17_violation():
    class BadBase(DeclarativeBase):
        metadata = MetaData()

    class Bad(TenantOwned, BadBase):  # type: ignore[misc]
        __tablename__ = "bad"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    issues = lint_metadata([BadBase.metadata])
    assert any(issue.rule == "L17" for issue in issues)


def test_control_model_marked_routed_is_l19_violation():
    class BadControlBase(DeclarativeBase):
        metadata = MetaData(schema="jd_control")

    from jdlib.models.base import TenantRouted

    class BadControl(TenantRouted, BadControlBase):  # type: ignore[misc]
        __tablename__ = "bad_control"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    issues = lint_metadata([BadControlBase.metadata])
    assert any(issue.rule == "L19" for issue in issues)


def test_single_column_fk_between_tenant_tables_is_l2_violation():
    class BadBase(DeclarativeBase):
        metadata = MetaData()

    class Parent(BadBase, TenantOwned):
        __tablename__ = "parents"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    class Child(BadBase, TenantOwned):
        __tablename__ = "children"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
        parent_id: Mapped[uuid.UUID] = mapped_column(
            sa.Uuid, sa.ForeignKey("parents.id"), nullable=False
        )

    issues = lint_metadata([BadBase.metadata])
    assert any(issue.rule in {"L2", "L10"} and issue.table == "children" for issue in issues)


def test_assert_clean_raises_schema_lint_error():
    from jdlib.errors import SchemaLintError

    class BadBase(DeclarativeBase):
        metadata = MetaData()

    class Orphan(BadBase, TenantOwned):
        __tablename__ = "orphans"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    with pytest.raises(SchemaLintError) as caught:
        assert_clean([BadBase.metadata])
    assert "orphans" in str(caught.value)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_lint.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.lint'`

- [ ] **Step 3: Implement `src/jdlib/lint.py`**

```python
from __future__ import annotations

from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy import MetaData

from jdlib.control.base import ControlBase
from jdlib.errors import SchemaLintError
from jdlib.models.base import TenantBase, TenantOwned, TenantRouted

GLOBAL_UNIQUE_WHITELIST = {
    ("api_keys", "uq_api_keys_key_prefix"),
    ("invitations", "uq_invitations_token_id"),
    ("tenants", "uq_tenants_slug"),
}

TENANT_ID_REFERENCE_ONLY = {"platform_audit_events"}


@dataclass(frozen=True)
class LintIssue:
    rule: str
    table: str
    message: str


def _tenant_scoped(table: sa.Table) -> bool:
    return "tenant_id" in table.columns and table.name not in TENANT_ID_REFERENCE_ONLY


def _model_tables() -> dict[int, type]:
    found: dict[int, type] = {}

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if table is not None:
                found[id(table)] = subclass
            walk(subclass)

    for root in (ControlBase, TenantBase, TenantOwned):
        walk(root)
    return found


def _model_for(table: sa.Table, known: dict[int, type]) -> type | None:
    registered = table.info.get("jdlib_model")
    if registered is not None:
        return registered
    return known.get(id(table))


def _cascade_reachable(metadata: MetaData) -> set[str]:
    graph: dict[str, set[str]] = {}
    for table in metadata.tables.values():
        for constraint in table.constraints:
            if isinstance(constraint, sa.ForeignKeyConstraint) and constraint.ondelete == "CASCADE":
                graph.setdefault(table.name, set()).add(constraint.referred_table.name)
    reached: set[str] = set()
    frontier = list(graph.get("tenants", set()))
    while frontier:
        name = frontier.pop()
        if name in reached or name == "tenants":
            continue
        reached.add(name)
        frontier.extend(graph.get(name, set()))
    return reached


def lint_metadata(controls: list[MetaData], rls_enabled: bool = False) -> list[LintIssue]:
    issues: list[LintIssue] = []
    known_models = _model_tables()

    for metadata in controls:
        for table in metadata.tables.values():
            if table.name.startswith("alembic_version"):
                continue
            tenant_scoped = _tenant_scoped(table)
            model = _model_for(table, known_models)

            if tenant_scoped:
                pk_names = [column.name for column in table.primary_key.columns]
                if "tenant_id" not in pk_names:
                    issues.append(
                        LintIssue("L1", table.name, "primary key does not include tenant_id")
                    )
                elif pk_names[0] != "tenant_id":
                    issues.append(
                        LintIssue("L4", table.name, "primary key does not lead with tenant_id")
                    )
                if table.columns["tenant_id"].nullable:
                    issues.append(LintIssue("L9", table.name, "tenant_id is nullable"))
                if model is not None and not issubclass(model, TenantOwned):
                    issues.append(
                        LintIssue("L11", table.name, "tenant-scoped model is not TenantOwned")
                    )

            if model is not None:
                if table.schema == "jd_control" and issubclass(model, TenantRouted):
                    issues.append(
                        LintIssue("L19", table.name, "control-plane model must not be TenantRouted")
                    )
                if table.schema is None and not issubclass(model, TenantRouted):
                    issues.append(
                        LintIssue("L17", table.name, "tenant-plane model must be TenantRouted")
                    )

            for constraint in table.constraints:
                if not isinstance(constraint, sa.ForeignKeyConstraint):
                    continue
                target = constraint.referred_table
                if _tenant_scoped(table) and _tenant_scoped(target):
                    if "tenant_id" not in set(constraint.column_keys):
                        issues.append(
                            LintIssue("L2", table.name, f"FK {constraint.name} omits tenant_id")
                        )
                if table.schema != target.schema:
                    issues.append(
                        LintIssue("L3", table.name, f"FK {constraint.name} crosses planes")
                    )

            if tenant_scoped:
                for constraint in table.constraints:
                    if isinstance(constraint, sa.UniqueConstraint):
                        columns = {column.name for column in constraint.columns}
                        key = (table.name, constraint.name or "")
                        if "tenant_id" not in columns and key not in GLOBAL_UNIQUE_WHITELIST:
                            issues.append(
                                LintIssue(
                                    "L12",
                                    table.name,
                                    f"unique {constraint.name} is not tenant-scoped",
                                )
                            )
                for index in table.indexes:
                    if not index.unique:
                        continue
                    columns = {column.name for column in index.columns}
                    key = (table.name, index.name or "")
                    if "tenant_id" not in columns and key not in GLOBAL_UNIQUE_WHITELIST:
                        issues.append(
                            LintIssue(
                                "L12",
                                table.name,
                                f"unique index {index.name} is not tenant-scoped",
                            )
                        )

            if rls_enabled and table.schema is None:
                if model is None or not issubclass(model, TenantRouted) or not tenant_scoped:
                    issues.append(
                        LintIssue("L13", table.name, "tenant-plane table is not RLS-eligible")
                    )

            if "team_id" in table.columns:
                has_check = any(
                    isinstance(constraint, sa.CheckConstraint)
                    and "team_id" in str(constraint.sqltext)
                    and "organization_id" in str(constraint.sqltext)
                    for constraint in table.constraints
                )
                has_hierarchy_fk = any(
                    isinstance(constraint, sa.ForeignKeyConstraint)
                    and set(constraint.column_keys) == {"tenant_id", "team_id", "organization_id"}
                    and constraint.referred_table.name == "teams"
                    for constraint in table.constraints
                )
                if not has_check or not has_hierarchy_fk:
                    issues.append(
                        LintIssue("L15", table.name, "team ownership constraints missing")
                    )

    for metadata in controls:
        for name in _cascade_reachable(metadata):
            issues.append(LintIssue("L6", name, "cascade path from tenants"))

    return issues


def assert_clean(controls: list[MetaData], rls_enabled: bool = False) -> None:
    issues = lint_metadata(controls, rls_enabled=rls_enabled)
    if issues:
        raise SchemaLintError([f"{issue.rule} {issue.table}: {issue.message}" for issue in issues])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_lint.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `python -m ruff check . && python -m mypy src/jdlib`

```bash
git add src tests docs/jdlib/07-implementation-design.md
git commit -m "feat: metadata lint L1-L19"
```

---

### Task 7: Migration runner and baseline migrations

**Files:**
- Create: `src/jdlib/migrations/__init__.py`
- Create: `src/jdlib/migrations/runner.py`
- Create: `src/jdlib/migrations/alembic.ini` (template only; config built in code)
- Create: `src/jdlib/migrations/control/env.py`
- Create: `src/jdlib/migrations/control/script.py.mako`
- Create: `src/jdlib/migrations/control/versions/0001_control_baseline.py`
- Create: `src/jdlib/migrations/tenant/env.py`
- Create: `src/jdlib/migrations/tenant/script.py.mako`
- Create: `src/jdlib/migrations/tenant/versions/0001_tenant_baseline.py`
- Create: `tests/integration/test_migrations.py`

**Interfaces:**
- Consumes: `ControlBase.metadata`, `TenantBase.metadata`, `CONTROL_SCHEMA`.
- Produces: `MigrationRunner(control_url: str, tenant_url_template: str)` with `upgrade_control(revision="head")`, `upgrade_tenant(schema: str, revision="head")`, and `provision_tenant_schema(schema: str)`.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_migrations.py`:

```python
from __future__ import annotations

import sqlalchemy as sa

from jdlib.migrations.runner import MigrationRunner


def test_control_baseline_migrates_all_tables(postgres_url: str):
    runner = MigrationRunner(postgres_url)
    runner.upgrade_control()
    engine = sa.create_engine(postgres_url, future=True)
    with engine.connect() as connection:
        tables = set(
            sa.inspect(connection).get_table_names(schema="jd_control")
        )
    expected = {
        "tenants",
        "tenant_placements",
        "tenant_migration_states",
        "tenant_relocations",
        "users",
        "identity_links",
        "platform_operators",
        "service_accounts",
        "api_keys",
        "memberships",
        "roles",
        "role_permissions",
        "role_bindings",
        "resource_grants",
        "invitations",
        "platform_audit_events",
    }
    assert expected <= tables
    assert "alembic_version" in tables


def test_tenant_baseline_creates_schema_tables(postgres_url: str):
    runner = MigrationRunner(postgres_url)
    runner.provision_tenant_schema("jt_migrated")
    engine = sa.create_engine(postgres_url, future=True)
    with engine.connect() as connection:
        tables = set(sa.inspect(connection).get_table_names(schema="jt_migrated"))
    assert {"organizations", "teams", "tenant_settings", "audit_events"} <= tables
    assert "alembic_version" in tables


def test_upgrade_is_idempotent(postgres_url: str):
    runner = MigrationRunner(postgres_url)
    runner.upgrade_control()
    runner.upgrade_control()
    runner.provision_tenant_schema("jt_migrated")
    runner.provision_tenant_schema("jt_migrated")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_migrations.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.migrations'`

- [ ] **Step 3: Implement migration packages**

`src/jdlib/migrations/runner.py`:

```python
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from jdlib.control.base import CONTROL_SCHEMA


class MigrationRunner:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def _config(self, plane: str, **attributes: object) -> Config:
        config = Config()
        config.set_main_option(
            "script_location",
            str(Path(__file__).parent / plane),
        )
        config.set_main_option("sqlalchemy.url", self._database_url)
        config.attributes["tenant_schema"] = attributes.get("tenant_schema")
        return config

    def upgrade_control(self, revision: str = "head") -> None:
        command.upgrade(self._config("control"), revision)

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        config = self._config("tenant", tenant_schema=schema)
        command.upgrade(config, revision)

    def provision_tenant_schema(self, schema: str, revision: str = "head") -> None:
        import sqlalchemy as sa

        engine = sa.create_engine(self._database_url, future=True)
        with engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        engine.dispose()
        self.upgrade_tenant(schema, revision)
```

`src/jdlib/migrations/control/env.py`:

```python
from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from jdlib.control.base import ControlBase
from jdlib.control import models  # noqa: F401

config = context.config
target_metadata = ControlBase.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        version_table_schema=ControlBase.metadata.schema,
        include_schemas=True,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=ControlBase.metadata.schema,
            include_schemas=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

`src/jdlib/migrations/control/versions/0001_control_baseline.py`:

```python
from __future__ import annotations

from alembic import op
from sqlalchemy import text

from jdlib.control.base import ControlBase

revision = "0001_control_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(text('CREATE SCHEMA IF NOT EXISTS "jd_control"'))
    bind.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))
    ControlBase.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    ControlBase.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
```

`src/jdlib/migrations/control/script.py.mako`:

```mako
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
```

`src/jdlib/migrations/tenant/env.py`:

```python
from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from jdlib.models import audit, org, settings  # noqa: F401
from jdlib.models.base import TenantBase

config = context.config
target_metadata = TenantBase.metadata
tenant_schema = config.attributes.get("tenant_schema")


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        version_table_schema=tenant_schema,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        if tenant_schema:
            connection.exec_driver_sql(f'SET search_path TO "{tenant_schema}"')
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=tenant_schema,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

`src/jdlib/migrations/tenant/versions/0001_tenant_baseline.py`:

```python
from __future__ import annotations

from alembic import op

from jdlib.models.base import TenantBase

revision = "0001_tenant_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    TenantBase.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    TenantBase.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
```

Copy the control `script.py.mako` verbatim to `src/jdlib/migrations/tenant/script.py.mako`. Create empty `src/jdlib/migrations/__init__.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_migrations.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Run the full suite, lint, type check**

Run: `python -m pytest -q && python -m ruff check . && python -m mypy src/jdlib`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: programmatic migration runner with control and tenant baselines"
```

---

## Phase 1 Exit Criteria

- [ ] `python -m pytest -q` green (unit + Postgres integration).
- [ ] `python -m ruff check .` and `python -m mypy src/jdlib` clean.
- [ ] Metadata lint L1–L19 passes on framework + demo consumer metadata.
- [ ] Control and tenant baselines migrate idempotently on PostgreSQL 16.
- [ ] Ownership hierarchy (I12) and soft-delete partial uniqueness enforced at DB level.
- [ ] Rev 7 design documents still match the shipped names (no renames).

## Plan Series (next plans, not this one)

- Plan 2 — Phase 2: context (`Principal`, `TenantContext`, `PrivilegeContext`, `ContextFactory`, envelope), resolver chain, middleware/job decorators.
- Plan 3 — Phase 3: `TenantSession`, scoping/stamping/validation events, `rawsql.py` validator, `UnitOfWork`, `TenantRepository`, `SessionRouter`, `IsolationStrategy` + shared adapter.
- Plan 4 — Phases 4–6: `TenantRegistry` lifecycle/provisioning, authorization (catalog, registry, PDP, guards, `AccessControl`), authentication adapters.
- Plan 5 — Phases 7–9: schema and database strategies, RLS emission and tests.
- Plan 6 — Phase 10: audit sinks, `jdlib.testing`, FastAPI/CLI integrations, docs.
