# Module: Testing Kit (`src/jdlib/testing/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

jdlib ships two things for consumers: assertions that encode the isolation
contract, and a pytest plugin (registered through the `pytest11` entry point, so
it loads automatically once `jdlib` is installed — no `conftest.py` needed).

## `testing/assertions.py`

```python
async def assert_scoped_count(session_factory, context, model, expected) -> None
async def assert_tenant_isolated(session_factory, context_a, context_b, model, **values) -> uuid.UUID
async def assert_cross_tenant_write_rejected(session_factory, context_a, model, **values) -> None
```

- `assert_scoped_count` opens a `TenantSession` for `context` and asserts
  `SELECT count(*) FROM model` equals `expected` — the cheap "tenant A sees
  exactly what it should" check.
- `assert_tenant_isolated` inserts a row **as `context_b`** (committing it), then
  opens a session for `context_a` and asserts (a) the count is 0 and (b)
  `session.get(model, row_id)` returns `None`. Returns the created row id so the
  caller can clean up or continue. This is the executable form of invariant I2.
- `assert_cross_tenant_write_rejected` creates a row owned by a random **other**
  tenant and asserts the flush raises `CrossTenantReferenceError`; if the flush
  succeeds it raises `AssertionError` explaining exactly what was accepted. This
  is invariant I4 on the write path.

All three take a `session_factory: Callable[[], AsyncSession]` so they work
against shared, schema, database or RLS placements without modification — the
strategy-specific routing lives in whatever factory the caller passes.

## `testing/pytest_plugin.py` — fixtures

| Fixture | Scope | Provides |
|---|---|---|
| `jdlib_database_url` | session | `JDLIB_TEST_DATABASE_URL`; **skips** the test when unset (with a message telling you how to set it or override the fixture in `conftest.py`). |
| `jdlib_schema` | session | `JDLIB_TEST_SCHEMA`, default `jdlib_test`. |
| `jdlib_models` | function | The model modules the engine fixture imports — `jdlib_test_models()` returns `("jdlib.models.org", "jdlib.models.settings", "jdlib.models.audit")`; override to add your own. |
| `jdlib_engine` | function | An `AsyncEngine` with `<schema>` created and `TenantBase.metadata.create_all` run inside it; DSN rewriting via `_async_dsn` (`postgresql://`, `+psycopg`, `+psycopg2` → `+asyncpg`). Disposed in a `finally`. |
| `jdlib_session_factory` | function | `async_sessionmaker(jdlib_engine, expire_on_commit=False)` — the `expire_on_commit=False` matters, see [authn.md](authn.md). |

Implementation notes:

- Without `pytest-asyncio` installed, `jdlib_engine` degrades to a synchronous
  fixture that calls `pytest.skip("install pytest-asyncio to use jdlib
  fixtures")` — the plugin never hard-fails an unrelated test run.
- The schema name is quoted through the dialect identifier preparer, so an
  unusual name (`odd"name`) still produces valid DDL; when `engine.begin()`
  fails, the engine is still disposed (both cases are unit-tested in
  `tests/unit/test_testing_kit.py`).
- Fixtures are *not* generated per test class or per strategy; a consumer that
  wants the strategy matrix writes its own parametrized fixture on top (the way
  `tests/integration/test_strategy_matrix.py` does).

## Using the kit in a consumer project

```python
# conftest.py
import pytest
from myapp.models import Invoice  # a TenantRouted model

@pytest.fixture()
def jdlib_models() -> tuple[str, ...]:
    # extend the framework list with your app's model modules
    from jdlib.testing.pytest_plugin import jdlib_test_models
    return (*jdlib_test_models(), "myapp.models")
```

```bash
export JDLIB_TEST_DATABASE_URL="postgresql+psycopg://jd:secret@localhost:5432/jdlib_test"
pytest -q
```

```python
async def test_my_resource_is_isolated(jdlib_session_factory, context_a, context_b):
    await assert_tenant_isolated(jdlib_session_factory, context_a, context_b, Invoice,
                                 number="B-1")
```

## Test-double conventions used by this repository

Consumers writing fast tests can copy the patterns in `tests/support/`:

- `tests/support/context_fakes.py` — `FrozenClock`, `StaticPrincipals`,
  `DictTenants`, `ServabilityStub`, `EntitlementsStub`,
  `ServiceAccountEntitlementsStub`, `OperatorsStub`, `RecordingPrivilegeAudit`.
  Together they let `ContextFactory` run with no database.
- `tests/support/invoice.py` — a complete consumer-style resource pair
  (`Invoice` with ownership + soft delete, `LineItem` with a composite FK).
- `tests/integration/strategy_support.py` — handle/DSN helpers, a `SchemaRunner`
  that mimics `MigrationRunner` for schema strategies, and provisioning utilities.
- `tests/integration/rls_support.py` — runs RLS DDL with a bounded lock timeout,
  terminates lingering `idle in transaction` backends (test-owned database), and
  retries transient lock errors.

These are **not** exported by the library (`jdlib.testing` exports exactly the
three assertions); copy or re-implement them in your own suite.
