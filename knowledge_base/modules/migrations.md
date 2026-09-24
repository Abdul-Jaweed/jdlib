# Module: Migrations (`src/jdlib/migrations/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

jdlib runs Alembic **programmatically**: there is no `alembic.ini`, no
CLI-installed `alembic` command, and no `script.py.mako`. The runner constructs a
`Config` object in memory, points it at one of two embedded script locations, and
invokes `alembic.command.upgrade`.

```
src/jdlib/migrations/
├── runner.py                               119 lines — MigrationRunner
├── control/                                script location for the control plane
│   ├── env.py                               45
│   └── versions/0001_control_baseline.py    22
└── tenant/                                 script location for one tenant schema
    ├── env.py                               48
    └── versions/0001_tenant_baseline.py     18
```

Neither script location has an `__init__.py`; `MigrationRunner._config` passes
`Path(__file__).parent / plane` as `script_location`.

## `MigrationRunner`

```python
MigrationRunner(database_url: str)      # any postgres DSN; async drivers are normalized
```

| Method | Behaviour |
|---|---|
| `upgrade_control(revision="head")` | Creates schema `jd_control` if missing (`CREATE SCHEMA IF NOT EXISTS`) using a short-lived sync engine, then upgrades the control chain. |
| `upgrade_tenant(schema, revision="head")` | Validates `schema` against the **deployment** pattern before touching SQL, then upgrades the tenant chain bound to that schema. |
| `upgrade_tenant_url(database_url, schema, revision="head")` | Same, but for a different database (database-per-tenant). |
| `provision_tenant_schema(schema, revision="head")` | Validates against the **strict tenant** pattern (`^t_[a-z0-9][a-z0-9_]{0,50}$`), creates the schema, then upgrades. Operator helper; the registry path uses `strategy.provision()` + `strategy.migrate()` instead. |
| `tenant_version(schema)` / `tenant_version_url(url, schema)` | Returns the schema's `alembic_version.version_num` or `None` when the table/schema does not exist. This is the value `TenantRegistry.provision` compares with `desired_version`. |

Two validation regexes exist because provisioning and deployment differ:

```python
_TENANT_SCHEMA_RE     = r"t_[a-z0-9][a-z0-9_]{0,50}"        # strict: tenant schemas
DEPLOYMENT_SCHEMA_RE  = r"[a-z_][a-z0-9_]{0,62}"            # permissive: shared schema names
```

- `_sync_url()` rewrites `postgresql`, `postgresql+asyncpg` and
  `postgresql+psycopg2` to `postgresql+psycopg` (Alembic is synchronous; the
  project installs `psycopg[binary]` for exactly this).
- `_config()` escapes `%` in the URL (`replace("%", "%%")`) so a percent-encoded
  password survives Alembic's `configparser` interpolation — covered by
  `tests/unit/test_database_strategy.py::test_percent_encoded_dsn_survives_config_interpolation`.
- `_read_version()` uses `to_regclass(:quoted)` first, so a missing schema/table
  is a clean `None` rather than an error.

## The two baseline chains

| Revision | Script location | Contents |
|---|---|---|
| `0001_control_baseline` | `migrations/control/` | `CREATE SCHEMA IF NOT EXISTS "jd_control"`, `CREATE EXTENSION IF NOT EXISTS citext`, then `ControlBase.metadata.create_all(bind, checkfirst=True)`. |
| `0001_tenant_baseline` | `migrations/tenant/` | `TenantBase.metadata.create_all(bind, checkfirst=True)` in the schema selected by `search_path`. |

Both baselines are **metadata-driven** (`create_all`) rather than explicit
`op.create_table` calls. Consequences worth knowing:

- Adding a model to `ControlBase`/`TenantBase` metadata changes what a *fresh*
  baseline install contains; existing databases are unaffected because
  `checkfirst=True` only creates what is missing and Alembic will not re-run an
  applied revision.
- A real schema change to an existing deployment therefore needs a new revision
  file (the repo has none beyond `0001`), and `downgrade()` mirrors `upgrade()`
  with `drop_all(checkfirst=True)` — destructive but symmetric.
- `env.py` for the control plane sets `version_table_schema=jd_control` and
  `include_schemas=True`; the tenant `env.py` reads
  `config.attributes["tenant_schema"]`, issues `SET search_path TO <quoted>` on
  the connection (committed before migrations), and sets `version_table_schema`
  to that schema so `alembic_version` lives inside the tenant schema.

## Who calls what

| Caller | Path |
|---|---|
| CLI `jdlib db upgrade-control` | `MigrationRunner(url).upgrade_control()` |
| CLI `jdlib db upgrade-tenants` | iterates tenants, `registry.migrate(tenant_id)` → `strategy.migrate()` |
| `TenantRegistry.provision` | `strategy.provision()` (CREATE SCHEMA / CREATE DATABASE) then `strategy.migrate()` (`runner.upgrade_tenant` / `upgrade_tenant_url`) then `runner.tenant_version(...)` to verify the target reached `desired_version` |
| Consumer apps | build their own Alembic env for **application** models and call `emit_rls_policies` after creating tables (`README.md`, "RLS enablement") |

Note `MigrationRunner` is constructed with the **control** DSN in every shipped
call site (`integrations/cli.py`, `README.md`); database-per-tenant migrations
pass a per-tenant DSN through `upgrade_tenant_url`/`tenant_version_url`, and
schema-per-tenant migrations reuse the same cluster with a different schema.

Tests: `tests/integration/test_migrations.py` (baseline tables exist, upgrade is
idempotent, version reads work, invalid schema names are rejected before SQL),
plus `tests/unit/test_strategy_lifecycle.py` for the validation regexes.
