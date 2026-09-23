# Testing

Verified on this tree (commit `a30601d`, `.venv` Python 3.12.10, Docker running):

```
$ .venv/Scripts/python.exe -m pytest -q
568 passed in 46.98s

$ .venv/Scripts/python.exe -m ruff check .
All checks passed!

$ .venv/Scripts/python.exe -m mypy src/jdlib
Success: no issues found in 64 source files
```

## Layout

```
tests/
├── unit/         36 test modules — pure logic, no database, no Docker
├── integration/  26 test modules + 3 support modules — real PostgreSQL via testcontainers
│   ├── conftest.py          — engines, schemas, session factories
│   ├── strategy_support.py  — helpers for the strategy matrix
│   └── rls_support.py       — RLS DDL helpers with lock-timeout + cleanup
└── support/      3 files    — consumer-style fakes: context_fakes.py, invoice.py
```

568 collected tests come from 527 test functions; parametrization (e.g. schema
name variants, resolver orders, key-scope sets) accounts for the rest.

## Integration harness (`tests/integration/conftest.py`)

| Fixture | Scope | What it does |
|---|---|---|
| `postgres_url` | session | `$JDLIB_TEST_DATABASE_URL` when set, otherwise `PostgresContainer("postgres:16", driver="psycopg")` from `testcontainers`. |
| `control_engine` | session | Sync engine (psycopg) that creates `citext`, `jd_control`, `jt_test`. |
| `control_metadata` | session | `ControlBase.metadata.create_all(control_engine)`. |
| `async_engine` | function | asyncpg engine; creates the schemas, sets `search_path` to `jt_test`, `TenantBase.metadata.create_all` including `tests/support/invoice.py` models. |
| `session_factory` | function | `async_sessionmaker(engine, expire_on_commit=False)`. |
| `control_session_factory` | function | Same, with control-plane metadata created and `search_path = jt_test, public`. |

Two environment requirements:

- **Docker** must be reachable (or `JDLIB_TEST_DATABASE_URL` must point at a real
  PostgreSQL 15+ instance with the `citext` extension available).
- On Docker Desktop for Windows the container IP is not routable from the host;
  the suite is run with `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` so the mapped
  port on localhost is used:

```bash
TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python.exe -m pytest -q
```

## What the integration suites cover

| File | Focus |
|---|---|
| `test_strategy_matrix.py` | The behavioural contract of every placement: shared, shared+RLS, schema, database — each case runs provisioning, migration, scoped reads/writes, cross-tenant rejection, soft delete and teardown. This is the strongest single piece of evidence that placement is transparent to application code. |
| `test_session_isolation.py` | `TenantSession` scoping: reads, `get`, joins/relationship loads, bulk rejections, cross-tenant flush rejection. |
| `test_rls_db.py` | Real RLS: policies enforced for a non-superuser role, unset `app.tenant_id` ⇒ zero rows, `WITH CHECK` denies foreign writes. |
| `test_schema_strategy_db.py` | `search_path` survives transaction and savepoint rollback; pool reset clears `search_path` between checkouts. |
| `test_database_strategy_db.py` | Database provisioning, per-tenant DSNs, LRU eviction, `invalidate()` rotation. |
| `test_registry.py` / `test_registry_models.py` | Lifecycle: create idempotency, handle ownership, transitions, provisioning failures, fence behaviour. |
| `test_repository.py` | Soft-delete awareness, `list/count/update/soft_delete`. |
| `test_access_roles.py`, `test_access_bindings.py`, `test_access_grants.py`, `test_access_invitations.py` | `AccessControl` including anti-escalation, owner-role protections, invitation claim races, team moves and ownership transfer. |
| `test_role_action_matrix.py` | A role × action permission matrix — exhaustive allow/deny coverage of the builtin catalog. |
| `test_apikey_auth.py`, `test_oidc_linking.py`, `test_authn_composite.py`, `test_auth_wiring.py` | Credential paths and identity linking, including prefix gating and audit reasons. |
| `test_fastapi_integration.py`, `test_cli_integration.py` | Adapters end to end (401/403/404/409 JSON, CLI audit row). |
| `test_migrations.py` | Baseline existence, upgrade idempotency, version reads. |
| `test_tenant_purge.py` | Shared-placement purge ordering through `TenantPlanePurger`. |
| `test_scopes.py`, `test_pdp_control_reader.py`, `test_audit_sinks.py`, `test_identity_models.py`, `test_tenant_models.py` | Supporting subsystems. |

## Unit suites worth knowing

`test_rawsql.py` (rule-by-rule validator coverage), `test_pdp.py` (gate order,
scope narrowing, resource grants), `test_public_api.py` (the 13-name surface,
`__version__`, no optional imports), `test_context_factory.py` +
`test_envelope.py` (gates, privileged issuance, envelope TTL/permissions),
`test_middleware.py` (status mapping incl. the 404-before-423 rule),
`test_lint.py` (each lint rule fires and stays silent when satisfied),
`test_testing_kit.py` (assertions and fixture degradation), `test_session.py`,
`test_uow.py`, `test_guards.py`, `test_permissions.py`, `test_resource_types.py`,
`test_resolution.py`, `test_jobs.py`, `test_oidc_verification.py`,
`test_apikey_parser.py`, `test_config.py`, `test_errors.py`,
`test_platform_audit_sinks.py`, `test_control_session.py`,
`test_persistence_models.py`, `test_bases.py`, `test_audit_recorder.py`,
`test_rls_policies.py`, `test_schema_strategy.py`, `test_database_strategy.py`,
`test_strategy_lifecycle.py`, `test_router.py`, `test_uuid.py`, `test_cli.py`.

## CI (`.github/workflows/ci.yml`, 14 lines)

```yaml
on: [push, pull_request]
jobs.test.runs-on: ubuntu-latest
steps:
  - actions/checkout@v4
  - actions/setup-python@v5 (python-version: "3.12")
  - python -m pip install -e ".[dev]"
  - python -m ruff check .
  - python -m mypy src/jdlib
  - python -m pytest -q
```

There is no service-container declaration: on GitHub-hosted runners the
testcontainers fixtures use the preinstalled Docker daemon. There is no coverage
gate, no matrix across PostgreSQL versions, and no Windows/macOS job.

## Running things locally

```bash
cd J:/ai-agents-resources/jdlib

# whole suite (Docker required; Windows needs the host override)
TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python.exe -m pytest -q

# fast loop
.venv/Scripts/python.exe -m pytest tests/unit -q

# a single concern
.venv/Scripts/python.exe -m pytest tests/integration/test_rls_db.py -q

# quality gates (both currently clean)
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy src/jdlib

# against a real database instead of a container
JDLIB_TEST_DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/jdlib_test" \
  .venv/Scripts/python.exe -m pytest -q
```

`pytest-asyncio` runs in `asyncio_mode = "auto"`, so async tests need no marker.
