# jdlib Integrations & Release (Phase 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the foundation: durable audit sinks (platform control-plane audit written in the caller's transaction; tenant audit written in the tenant transaction), the `jdlib.testing` consumer kit, FastAPI and CLI integrations, the public API surface, and a README — then run the final whole-project validation.

**Architecture:** The `PlatformAudit` port gains an optional `session` so control-plane mutations record audit rows in the same transaction (`05` §5.1); a `TenantAuditRecorder` writes `AuditEvent` rows inside `TenantSession` transactions. `jdlib.testing` exposes fixtures/assertions over the shipped stack. Integrations are thin: FastAPI reuses `TenantMiddleware` and the frozen HTTP mapping; the CLI wires `TenantRegistry`, `MigrationRunner`, `AccessControl`, and RLS install/verify. `jdlib/__init__.py` re-exports the public API.

**Tech Stack:** SQLAlchemy async, FastAPI + Starlette TestClient (dev extra, already declared as optional), Typer + CliRunner (optional extra), pytest. Add `fastapi`, `typer`, `httpx` (already present) to the `dev` extra for integration tests.

**Specs (frozen):** `docs/jdlib/07-implementation-design.md` §8/§11/§12/§14/§16; `docs/jdlib/05-tenant-lifecycle.md` §5.1; `docs/jdlib/03-isolation-invariants.md` I6/I8; `docs/jdlib/06-strategy-matrix.md` §6.

## Global Constraints

- Audit: mandatory platform events recorded in the caller's control-plane transaction when a session is provided (or its own transaction otherwise); failure aborts the mutation. Audit metadata never contains secrets, tokens, or key material.
- Public API is exactly the re-exports in `jdlib/__init__.py`; everything else stays module-path internal.
- Integrations must not add hard dependencies: FastAPI/Typer live behind extras and tests use `pytest.importorskip`.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` and a fresh DB.
- No comments in source; pristine test output; commit after every task.

---

### Task 1: Transactional audit sinks

**Files:**
- Modify: `src/jdlib/control/audit.py` (optional `session` parameter + `DatabaseAuditSink` + `CompositeAuditSink`)
- Modify: `src/jdlib/control/registry.py`, `src/jdlib/authz/access.py`, `src/jdlib/context.py` (pass the control session where one exists)
- Create: `src/jdlib/models/audit_recorder.py` (tenant-transaction audit)
- Create: `tests/integration/test_audit_sinks.py`
- Create: `tests/unit/test_audit_recorder.py`

**Interfaces:**
- Produces: `PlatformAudit.record(*, action, tenant_id, actor_id, metadata=None, session: ControlPlaneSession | None = None)`; `DatabaseAuditSink(session_factory)` writing `PlatformAuditEvent` (uses the provided session without committing); `CompositeAuditSink(*sinks)`; `TenantAuditRecorder.record(*, action, target_type=None, target_id=None, metadata=None)` inserting `AuditEvent` in the tenant session.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_audit_recorder.py`:

```python
import uuid

from jdlib.control.enums import ActorType, PlacementStrategy, PrincipalKind
from jdlib.context import Principal, TenantContext
from jdlib.context import context_scope
from jdlib.errors import MissingTenantContext
from jdlib.models.audit_recorder import TenantAuditRecorder


class _Session:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=uuid.uuid4(),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
        trace_id="trace",
    )


def test_recorder_requires_context():
    recorder = TenantAuditRecorder(_Session())  # type: ignore[arg-type]
    try:
        recorder.record(action="invoice.updated")
    except MissingTenantContext:
        pass
    else:
        raise AssertionError("expected MissingTenantContext")


def test_recorder_stamps_context_fields():
    session = _Session()
    recorder = TenantAuditRecorder(session)  # type: ignore[arg-type]
    with context_scope(_context()):
        record = recorder.record(
            action="invoice.updated", target_type="invoice", target_id=uuid.uuid4(),
            metadata={"status": "paid"},
        )
    assert record.action == "invoice.updated"
    assert record.actor_type == ActorType.USER.value
    assert record.request_id == "req"
    assert record.correlation_id == "corr"
    assert record.trace_id == "trace"
    assert record in session.added
```

`tests/integration/test_audit_sinks.py`:

```python
import uuid

import pytest
import sqlalchemy as sa

from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.models import PlatformAuditEvent


async def test_database_sink_writes_event_in_own_transaction(control_session_factory):
    sink = DatabaseAuditSink(control_session_factory)
    tenant_id = uuid.uuid4()
    await sink.record(action="tenant.created", tenant_id=tenant_id, actor_id=None, metadata={"x": 1})
    async with control_session_factory() as session:
        row = (
            await session.execute(
                sa.select(PlatformAuditEvent).where(PlatformAuditEvent.tenant_id == tenant_id)
            )
        ).scalar_one()
    assert row.action == "tenant.created"
    assert row.metadata_json == {"x": 1}


async def test_database_sink_uses_caller_transaction(control_session_factory):
    sink = DatabaseAuditSink(control_session_factory)
    async with control_session_factory() as session:
        from jdlib.control.session import ControlPlaneSession

        await sink.record(
            action="tenant.suspended", tenant_id=None, actor_id=None, session=ControlPlaneSession(session)
        )
        await session.rollback()
    async with control_session_factory() as session:
        count = (
            await session.execute(
                sa.select(sa.func.count()).select_from(PlatformAuditEvent).where(
                    PlatformAuditEvent.action == "tenant.suspended"
                )
            )
        ).scalar_one()
    assert count == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_audit_recorder.py tests/integration/test_audit_sinks.py -v`
Expected: FAIL (missing modules/parameters)

- [ ] **Step 3: Implement the sinks and recorder**

`src/jdlib/control/audit.py` — extend the protocol and both implementations with `session: ControlPlaneSession | None = None` (recording implementations accept and ignore it), and append:

```python
class DatabaseAuditSink:
    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
    ) -> None:
        from jdlib.control.models import PlatformAuditEvent

        owns_session = session is None
        control = session or ControlPlaneSession(self._session_factory())
        control.add(
            PlatformAuditEvent(
                action=action,
                tenant_id=tenant_id,
                actor_id=actor_id,
                actor_type="system" if actor_id is None else "user",
                metadata_json=dict(metadata or {}),
            )
        )
        await control.flush()
        if owns_session:
            await control.commit()
        await control.close()


class CompositeAuditSink:
    def __init__(self, *sinks: PlatformAudit) -> None:
        self._sinks = sinks

    async def record(self, *, action, tenant_id, actor_id, metadata=None, session=None) -> None:
        for sink in self._sinks:
            await sink.record(
                action=action, tenant_id=tenant_id, actor_id=actor_id,
                metadata=metadata, session=session,
            )
```

`src/jdlib/models/audit_recorder.py`:

```python
from __future__ import annotations

import uuid
from collections.abc import Mapping

from jdlib.context import current_tenant
from jdlib.models.audit import AuditEvent


class TenantAuditRecorder:
    def __init__(self, session: object) -> None:
        self._session = session

    def record(
        self,
        *,
        action: str,
        target_type: str | None = None,
        target_id: uuid.UUID | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        context = current_tenant()
        event = AuditEvent(
            tenant_id=context.tenant_id,
            actor_type=context.principal.kind.value,
            actor_id=context.principal.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata_json=dict(metadata or {}),
            request_id=context.request_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
        )
        self._session.add(event)  # type: ignore[attr-defined]
        return event
```

Then update the call sites that already hold a `ControlPlaneSession` to pass `session=session` (registry `create/provision/migrate/transitions/deprovision`, access control mutations); constructors that create their own session keep `session=None` and get their own transaction. Update `NullPlatformAudit` and `RecordingPlatformAudit` signatures accordingly.

- [ ] **Step 4: Run tests to verify they pass; full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/control/audit.py src/jdlib/control/registry.py src/jdlib/authz/access.py src/jdlib/context.py src/jdlib/models/audit_recorder.py tests/unit/test_audit_recorder.py tests/integration/test_audit_sinks.py
git commit -m "feat: transactional audit sinks and tenant audit recorder"
```

---

### Task 2: `jdlib.testing` consumer kit

**Files:**
- Create: `src/jdlib/testing/__init__.py`
- Create: `src/jdlib/testing/assertions.py`
- Create: `src/jdlib/testing/pytest_plugin.py`
- Create: `tests/unit/test_testing_kit.py`
- Modify: `pyproject.toml` (`[project.entry-points.pytest11] jdlib = "jdlib.testing.pytest_plugin"`; add `fastapi`, `typer` to `dev`)

**Interfaces:**
- Produces: `assert_tenant_isolated(session_factory, context_a, context_b, model, **values)`; `assert_scoped_count(session, model, expected)`; pytest fixtures `jdlib_database_url` (env `JDLIB_TEST_DATABASE_URL`), `jdlib_schema` and `jdlib_session_factory` (async, creates the tenant schema and `TenantBase` metadata).

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_testing_kit.py`: exercise the kit's pure helpers against fakes (no DB) — `assert_scoped_count` raising on mismatch, `assert_tenant_isolated` calling the injected session factory and failing when the "other tenant" row is visible (use a tiny fake exposing `execute(...).scalars().all()`), and `pytest_plugin` exposing the fixture names.

- [ ] **Step 2: Implement the kit**

`assertions.py`: `assert_scoped_count(session, model, expected)` runs `select(func.count()).select_from(model)` through `TenantSession` and asserts; `assert_tenant_isolated(session_factory, context_a, context_b, model, **values)` creates a row for B through a `TenantSession` for B, commits, then asserts an A-session sees zero rows and `get(...)` is `None` for B's id. `pytest_plugin.py`: fixtures as described; the engine fixture creates the schema and `TenantBase.metadata` (importing framework + a configurable `jdlib_models` hook via `pytest_configure` or an autouse import of a conftest-defined module list).

Keep the plugin minimal and documented: consumers either set `JDLIB_TEST_DATABASE_URL` or use testcontainers themselves; the kit never hard-fails without a database unless a kit fixture is requested.

- [ ] **Step 3: Run tests; full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/testing pyproject.toml tests/unit/test_testing_kit.py
git commit -m "feat: jdlib.testing consumer kit and pytest plugin"
```

---

### Task 3: FastAPI and CLI integrations

**Files:**
- Create: `src/jdlib/integrations/__init__.py`
- Create: `src/jdlib/integrations/fastapi.py`
- Create: `src/jdlib/integrations/cli.py`
- Create: `tests/integration/test_fastapi_integration.py`
- Create: `tests/unit/test_cli.py`

**Interfaces:**
- Produces: `install(app, *, factory, resolvers, principal_provider, audit)` adding `TenantMiddleware` and JdlibError exception handlers using `http_status_for`; dependencies `get_context()` and `get_uow(...)`; `require(permission, *, enforcer, target_factory=None)`. CLI: `app` Typer with `tenant create|provision|list`, `db upgrade-control|upgrade-tenants`, `rls install|verify`, `schema lint`; commands build a system/operator context and audit.

- [ ] **Step 1: FastAPI integration test**

`tests/integration/test_fastapi_integration.py` (`pytest.importorskip("fastapi")`): build a tiny app with `install(...)`, an API-key principal provider (reuse `ApiKeyAuthenticator` + a seeded key via `control_session_factory`), a route calling `get_context()` and returning `{"tenant": str(ctx.tenant_id)}`; assert 200 with the tenant id; assert a missing key returns 401 JSON and an unauthorized tenant returns 404 (resolver chain header-first).

- [ ] **Step 2: CLI tests**

`tests/unit/test_cli.py` (`pytest.importorskip("typer")`, `CliRunner`): `--help` lists groups; `schema lint` exits 0 on framework metadata; `rls --help`; a command missing config exits non-zero with a clear message (no crash).

- [ ] **Step 3: Implement integrations**

`fastapi.py`: `install` registers the middleware with the provided collaborators and handlers built from `http_status_for`; `get_context` returns `current_tenant()`; `get_uow` yields a `UnitOfWork` from an injected app-state container (`app.state.jdlib = container`); `require` wraps `Enforcer`. Keep it small; no route classes.

`cli.py`: Typer app; commands accept `--database-url` (or env `JDLIB_CONTROL_DSN`), build `MigrationRunner`/`TenantRegistry` with a shared async runner (`asyncio.run`), and print results; `rls install/verify` call `install_rls`/`verify_rls`; `schema lint` calls `lint_metadata` with `rls_enabled` from the flag.

- [ ] **Step 4: Run tests; full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/integrations tests/integration/test_fastapi_integration.py tests/unit/test_cli.py
git commit -m "feat: fastapi and cli integrations"
```

---

### Task 4: Public API, README, final validation

**Files:**
- Modify: `src/jdlib/__init__.py` (public re-exports + `__all__`)
- Create: `README.md`
- Modify: `docs/jdlib/07-implementation-design.md` (public API final list)
- Create: `tests/unit/test_public_api.py`

**Interfaces:** none new.

- [ ] **Step 1: Public API test**

`tests/unit/test_public_api.py`: assert the exact `jdlib.__all__` set and that every name resolves; assert key names are importable (`TenancyConfig`, `TenantContext`, `current_tenant`, `current_principal`, `ContextFactory`, `UnitOfWork`, `TenantRepository`, `TenantRegistry`, `AccessControl`, `requires`, `authorize`, `JdlibError`).

- [ ] **Step 2: Implement `__init__.py` re-exports and README**

`__init__.py` re-exports only the stable surface (imports from the real modules; no wildcard). README: install, quickstart (config via env, migrations, provisioning, middleware/authn wiring, tenant-scoped data access, RLS, CLI), strategy matrix table, extension points, and the local testcontainers note.

- [ ] **Step 3: Final whole-project validation**

Run, in order:
- `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error`
- `.venv/Scripts/python -m ruff check .`
- `.venv/Scripts/python -m mypy src/jdlib`
- `python -c "import jdlib; print(jdlib.__version__)"` (add `__version__ = "0.1.0"` if missing)
- Grep for placeholders/TODOs: `rg -n "TODO|FIXME|XXX|NotImplementedError" src tests` and fix or justify each hit.
- Confirm no secret material is logged (grep for `echo=True`, `print(` in `src/jdlib`).

- [ ] **Step 4: Commit**

```bash
git add src/jdlib/__init__.py README.md docs tests/unit/test_public_api.py
git commit -m "feat: public api, readme, final validation"
```

---

## Phase 6 Exit Criteria

- [ ] Platform audit is written in the caller's transaction when a session is provided; tenant audit rows are written in tenant transactions; no secrets in metadata.
- [ ] `jdlib.testing` kit and pytest plugin ship and are tested.
- [ ] FastAPI integration: middleware + handlers + dependencies proven with a TestClient end-to-end auth flow; CLI groups and lint command proven.
- [ ] Public API is exactly the documented re-exports; README complete.
- [ ] Full suite, ruff, strict mypy green; no TODOs/placeholders; repository pushed.
