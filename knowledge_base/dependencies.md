# Dependencies

## Runtime (required)

```toml
dependencies = [
  "alembic>=1.13",         # programmatic migrations (control + tenant chains)
  "argon2-cffi>=23.1",     # API-key secrets and invitation secrets
  "asyncpg>=0.29",         # default async DBAPI for app sessions
  "httpx>=0.27",           # JWKS fetching (authn/wiring.fetch_jwks)
  "pglast>=6.0",           # PostgreSQL AST parsing for raw_sql validation
  "psycopg[binary]>=3.2",  # sync driver used by MigrationRunner (Alembic)
  "pydantic>=2.7",
  "pydantic-settings>=2.3",
  "pyjwt[crypto]>=2.8",    # OIDC token verification (RS256 etc.)
  "sqlalchemy[asyncio]>=2.0.30",
]
```

## Optional extras (`pyproject.toml` lines 23–34, verbatim)

```toml
[project.optional-dependencies]
dev     = ["fastapi>=0.111", "mypy>=1.10", "pytest>=8.2", "pytest-asyncio>=0.23",
           "ruff>=0.5", "testcontainers[postgres]>=4.5", "typer>=0.12"]
fastapi = ["fastapi>=0.111"]   # jdlib.integrations.fastapi
cli     = ["typer>=0.12"]      # jdlib.integrations.cli
```

`dev` is a superset that installs both adapters so the full test matrix (including
`tests/integration/test_fastapi_integration.py` and `test_cli*.py`) can run.

Also declared in `pyproject.toml`:

| Section | Content |
|---|---|
| `[project.entry-points.pytest11]` | `jdlib = "jdlib.testing.pytest_plugin"` — the fixtures ship as a plugin. |
| `[tool.hatch.build.targets.wheel]` | `packages = ["src/jdlib"]` (src layout). |
| `[tool.pytest.ini_options]` | `asyncio_mode = "auto"`, `testpaths = ["tests"]`. |
| `[tool.ruff]` | `line-length = 100`, `target-version = "py312"`, lint select `E,F,I,UP,B,SIM`. |
| `[tool.mypy]` | `python_version = "3.12"`, `strict = true`, `files = ["src/jdlib"]`. |
| build backend | `hatchling`. |

There is **no** `[project.scripts]` entry point in the shipped `pyproject.toml`;
consumers add `jdlib = "jdlib.integrations.cli:app"` themselves if they want the
operator CLI on `PATH`.

`tests/unit/test_public_api.py::test_import_does_not_pull_optional_dependencies`
asserts that `import jdlib` leaves `fastapi` and `typer` out of
`sys.modules` — keep adapter imports inside `integrations/*`.

## Where each dependency is actually used

| Package | Used by | Notes |
|---|---|---|
| `sqlalchemy[asyncio]` | everything in `persistence/`, `models/`, `control/` | ORM + Core, `AsyncSession`, events, `with_loader_criteria`. |
| `asyncpg` | runtime sessions | `_async_dsn` normalizes `postgresql://`, `+psycopg`, `+psycopg2` → `+asyncpg`. |
| `psycopg` | `MigrationRunner` | `_sync_url` normalizes to `postgresql+psycopg` because Alembic is sync; the `[binary]` extra avoids a compiler. |
| `alembic` | `migrations/runner.py`, `migrations/*/env.py` | `Config`/`command.upgrade` in-process; no `alembic.ini`. |
| `pglast` | `persistence/rawsql.py` | `parse_sql` + node visitors for the tenant-predicate proof. |
| `argon2-cffi` | `authn/apikey.py`, `authz/access.py` | `PasswordHasher` defaults (Argon2id). |
| `pyjwt[crypto]` | `authn/oidc.py` | `decode`, `get_unverified_header`, `PyJWK`; `crypto` extra gives RSA/EC algorithms. |
| `httpx` | `authn/wiring.py` | JWKS fetch only (async client, `raise_for_status`). |
| `pydantic` / `pydantic-settings` | `config.py` | Validation, `SecretStr`, `env_prefix="JDLIB_"`, `env_nested_delimiter="__"`. |
| `fastapi` (extra) | `integrations/fastapi.py` | `Request`, `HTTPException`-free design: it registers its own handler. |
| `typer` (extra) | `integrations/cli.py` | Commands, options, `--json` flag. |
| `testcontainers` (dev) | `tests/integration/conftest.py` | Real PostgreSQL 16 container; needs Docker (or a host override via `TESTCONTAINERS_HOST_OVERRIDE`). |
| `pytest-asyncio` (dev) | tests, `testing/pytest_plugin.py` | `asyncio_mode=auto` in `pyproject.toml`; the plugin degrades gracefully when it is absent. |
| `ruff`, `mypy` (dev) | CI + local | `mypy` is strict (`pyproject.toml [tool.mypy]`); both are clean on the current tree. |

No dependency is declared but unused, and the library uses only the standard
library for the pieces people usually reach for a helper library for: envelopes
(`hmac`, `hashlib`, `base64`, `json`), ids (`uuid`), context propagation
(`contextvars`), clocks (`datetime`). See
[design_decisions.md](design_decisions.md) §"Standard library over helpers".

## Supported versions and platform expectations

- **Python**: `requires-python = ">=3.12"` in `pyproject.toml`; the code uses
  PEP 695 generics (`class TenantRepository[ModelT]`), `StrEnum`, `slots=True`
  dataclasses and `X | None` unions. The repository's `.venv` runs
  **Python 3.12.10**, and `mypy` is pinned to `python_version = "3.12"`, so 3.12 is
  the tested (and only supported) target — a 3.11 interpreter will fail at import
  on the generic class syntax.
- **PostgreSQL**: 15+ is required by the feature set (RLS `FORCE` policies,
  `pg_advisory_xact_lock`, `citext`, `NULLIF(current_setting(...))`), and the test
  suite starts a real `postgres:16` container per session
  (`tests/integration/conftest.py:21`, `PostgresContainer("postgres:16")`).
- **Extensions**: `citext` (created by the control baseline). RLS itself needs
  no extension.
- **No asyncpg-only APIs** are relied upon beyond DSN scheme handling; a different
  async driver would need `_async_dsn` and the pool-reset listener checked (the
  listener inspects `pool._dialect`/`_asyncio_safe`, which is asyncpg-oriented).

## Reverse dependencies (who imports what, verified)

The import graph was extracted with `ast` from all 64 source files. Two rules
hold throughout:

1. **No cycles between packages**: `context` ← `control` ← `persistence`, with
   `authn`/`authz`/`tenancy` above them and `integrations` on top.
2. **Adapters import inward only**: `integrations/*` and `testing/*` are the only
   packages that import the framework at large.

Notable inward edges (worth knowing when refactoring):

| Edge | Why it exists |
|---|---|
| `models/base.py` → `control/base.py` | tenant tables reuse the control plane's naming convention and `TenantBase` metadata keys. |
| `persistence/session.py` → `models/base.py`, `persistence/rawsql.py` | scoping needs `TenantRouted`/`SoftDelete` and the raw-SQL validator. |
| `persistence/strategies/schema.py` → `migrations/runner.py` (duck-typed) | `migrate()` receives the runner as a parameter, so the import is type-only. |
| `control/registry.py` → `migrations/runner.py`, `persistence/strategies/*` | lifecycle drives DDL and migration. |
| `authn/wiring.py` → `authz/reader.py`, `control/registry.py` | adapters wrap the reader and the registry. |
| `testing/*` → `persistence/*`, `models/*` | the assertions are written against the real session types. |

## Development environment in this repository

- `.venv/` — a Windows virtualenv with the dev extra installed (pytest, mypy,
  ruff, testcontainers, fastapi, typer, alembic, pglast, jwt, argon2 all import
  cleanly).
- Docker must be running for the integration suite: the fixtures start a
  `postgres:16` container (see [testing.md](testing.md)).
- `git-bash` environment: use `.venv/Scripts/python.exe`, and pass native
  (forward-slash `C:/…`) paths to native tools.
