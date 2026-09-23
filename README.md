# jdlib

Reusable multi-tenant foundation for PostgreSQL + SQLAlchemy applications.
jdlib owns the repetitive, failure-prone parts of SaaS tenancy: request-scoped
tenant context, three isolation strategies behind one data-access API,
fail-closed row scoping, authorization, authentication, audit, tenant
lifecycle, and a test kit.

- **Tenant context**: `TenantContext` + `current_tenant()` / `current_principal()`,
  resolver chain (JWT claim, subdomain, path, header, API key), signed envelope
  for internal hops (`EnvelopeCodec`).
- **One data-access API** across placements: `UnitOfWork`, `TenantSession`,
  `TenantRepository` — shared schema, schema per tenant, or database per tenant.
- **Fail-closed persistence**: automatic `tenant_id` scoping/stamping,
  cross-tenant reference rejection, raw-SQL validation, optional PostgreSQL RLS.
- **Authorization**: permission catalog, roles/bindings/grants/invitations, PDP
  with frozen precedence gates, `requires` / `authorize` guards.
- **Authentication**: OIDC (JWKS, claim mapping, user linking) and API keys
  behind one provider.
- **Lifecycle**: provisioning, per-placement migrations, suspend/resume/archive/
  deprovision, relocation, plus transactional platform and tenant audit.
- **Integrations**: FastAPI middleware + dependencies; Typer CLI for operators.
- **Testing kit**: `jdlib.testing` assertions, pytest fixtures, and a pytest
  plugin that autoloads from the `pytest11` entry point.

Design docs live in `docs/jdlib/`: `02` relational schema, `03` isolation
invariants, `04` authorization model, `05` tenant lifecycle, `06` strategy
matrix, `07` implementation design.

## Install

Python 3.12+ and PostgreSQL 15+.

```bash
pip install jdlib
pip install "jdlib[fastapi]"   # FastAPI integration
pip install "jdlib[cli]"       # Typer CLI
pip install -e ".[dev]"        # from a checkout, with tests/lint/mypy
```

## 60-second quickstart

### 1. Configure

`TenancyConfig` is a pydantic-settings model; every field is settable through
`JDLIB_*` environment variables (`__` nests, secrets stay wrapped):

```bash
export JDLIB_CONTROL_DSN="postgresql+psycopg://jd:secret@localhost:5432/app"
export JDLIB_CONTEXT__SIGNING_KEY="$(openssl rand -hex 32)"
export JDLIB_OIDC__ISSUER="https://login.example.com/"
export JDLIB_OIDC__AUDIENCE="my-api"
```

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from jdlib import TenancyConfig

config = TenancyConfig()  # fails fast when JDLIB_CONTEXT__SIGNING_KEY is missing
engine = create_async_engine(config.control_dsn.get_secret_value())
control_sessions = async_sessionmaker(engine, expire_on_commit=False)
```

### 2. Migrate and provision

Expose the CLI as a script (or invoke the Typer app from your own entry point):

```toml
[project.scripts]
jdlib = "jdlib.integrations.cli:app"
```

```bash
jdlib db upgrade-control --database-url "$JDLIB_CONTROL_DSN"
jdlib tenant create --slug acme --name "Acme Inc" --strategy shared --target-handle default
jdlib tenant provision <tenant-id>   # provisions the placement plane, migrates, activates
```

Programmatically: `MigrationRunner(url).upgrade_control()` then
`TenantRegistry(...).create(...)` / `.provision(tenant.id)`.

### 3. Wire FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from jdlib import (
    ContextFactory,
    TenancyConfig,
    TenantContext,
    TenantRepository,
    UnitOfWork,
    current_tenant,
)
from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
    build_authenticator,
)
from jdlib.authz.guards import Enforcer
from jdlib.authz.pdp import DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.authz.scopes import ScopeResolver
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.integrations.fastapi import (
    JdlibContainer,
    get_context,
    get_uow,
    install,
    require,
)
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from jdlib.tenancy.resolution import ApiKeyResolver, HeaderResolver, ResolverChain

config = TenancyConfig()
engine = create_async_engine(config.control_dsn.get_secret_value())
control_sessions = async_sessionmaker(engine, expire_on_commit=False)
tenant_sessions = async_sessionmaker(engine, expire_on_commit=False)

audit = DatabaseAuditSink(control_sessions)
reader = ControlAccessReader(control_sessions)
runner = MigrationRunner(config.control_dsn.get_secret_value())
strategies = {
    PlacementStrategy.SHARED: SharedSchemaStrategy(engine, "public"),
    PlacementStrategy.SCHEMA: SchemaPerTenantStrategy(engine, runner),
}
registry = TenantRegistry(
    session_factory=control_sessions,
    strategies=strategies,
    runner=runner,
    audit=audit,
)
pdp = DefaultPDP(
    catalog=PermissionCatalog.with_builtins(),
    reader=reader,
    scopes=ScopeResolver(ResourceTypeRegistry()),
)


class OperatorAuthorizer:
    """Support-access gate; back it with your operator directory."""

    async def authorize(self, principal, capability: str) -> bool:
        return False


def uow_factory() -> UnitOfWork:
    context = current_tenant()
    fence = RegistryWriteFence(session_factory=control_sessions)
    return UnitOfWork(tenant_sessions, context, fence=fence)


app = FastAPI()
install(
    app,
    factory=ContextFactory(
        config=config.context,
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=OperatorAuthorizer(),
        audit=audit,
    ),
    chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug"), ApiKeyResolver()]),
    principal_provider=build_authenticator(config, control_sessions, audit).authenticate,
    container=JdlibContainer(
        session_factory=control_sessions,
        uow_factory=uow_factory,
        enforcer=Enforcer(pdp),
    ),
)


@app.get("/me")
async def me(context: Annotated[TenantContext, Depends(get_context)]) -> dict[str, str]:
    return {"tenant": context.tenant_slug}


@app.get("/invoices", dependencies=[Depends(require("resource:read"))])
async def list_invoices(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> list[str]:
    async with uow as session:
        return [row.number for row in await TenantRepository(session, Invoice).list()]
```

`install` adds the ASGI middleware, the `JdlibError` -> JSON exception handler
(401/403/404/409/423/500 mapped from the error class), and stores the container
on `app.state`. The example uses one shared tenant engine; hybrid deployments
route inside `uow_factory` by `context.strategy` (see `SessionRouter`).

## Tenant-scoped data access

Writes go through a `UnitOfWork`, which checks the write fence, opens a
`TenantSession`, applies `tenant_id` scoping/stamping, and commits or rolls
back. Reads use `TenantRepository` on the same session:

```python
from jdlib import TenantRepository, UnitOfWork, current_tenant
from jdlib.control.registry import RegistryWriteFence

write_fence = RegistryWriteFence(session_factory=control_sessions)


async def create_invoice(number: str) -> Invoice:
    context = current_tenant()
    async with UnitOfWork(tenant_sessions, context, fence=write_fence) as session:
        return await TenantRepository(session, Invoice).add(Invoice(number=number))


async def count_invoices() -> int:
    context = current_tenant()
    async with UnitOfWork(tenant_sessions, context, fence=write_fence) as session:
        return await TenantRepository(session, Invoice).count()
```

`TenantRepository` exposes `get`, `list`, `add`, `update`, `soft_delete`, and
`count`; every statement is scoped to the context tenant, and flushing a row
owned by another tenant raises `CrossTenantReferenceError`. Raw SQL is allowed
only when tenant-scoped or explicitly privileged, and is audited.

For schema/database placements the routed session comes from the registry
placement: `await SessionRouter(strategies).session(await registry.assert_servable(tenant_id))`.
Application code above the session factory does not change with placement.

## Tenancy strategies

Placement is data, not code. `registry.create(..., strategy=..., target_handle=...)`
records it; all strategies expose the same `TenantSession` surface.

| | `shared` | `schema` | `database` |
|---|---|---|---|
| Placement config | `target_handle="default"` (shared plane) | `target_handle="t_<slug>"` (schema name) | `target_handle` -> `SecretProvider` DSN |
| Isolation | logical: `tenant_id` scoping (+ optional RLS) | namespace: per-tenant schema + `search_path` | physical: database per tenant |
| Provision cost | O(row) | O(schema DDL) | O(database + DDL) |
| Migrations | once | per schema | per database |
| RLS | supported | not applicable | not applicable |
| Best for | many small tenants | mid-market | enterprise / compliance |

```python
tenant = await registry.create(
    slug="acme",
    name="Acme Inc",
    strategy=PlacementStrategy.SCHEMA,
    target_handle="t_acme",
)
await registry.provision(tenant.id)
```

A deployment can mix all three: `acme -> shared`, `globex -> schema t_globex`,
`initech -> database db-initech`. The database strategy keeps a bounded,
handle-keyed engine cache (`max_targets`, default 32; LRU eviction of idle
engines only, `PoolCapacityError` under pressure).

## RLS enablement

RLS is opt-in for shared-schema placements. The runtime role must be
`NOBYPASSRLS`, not the table owner, and not a superuser; every transaction
re-asserts `app.tenant_id` from the `TenantContext`, so an unset setting yields
zero rows, never all rows.

```bash
export JDLIB_RLS__ENABLED=true
export JDLIB_RLS__APP_ROLE=jdlib_app
jdlib rls install --schema public --app-role jdlib_app --database-url "$JDLIB_CONTROL_DSN"
jdlib rls verify  --schema public --app-role jdlib_app --database-url "$JDLIB_CONTROL_DSN"
jdlib schema lint --rls   # fails if any tenant-routed table lacks a policy
```

Pass `rls=config.rls` to `SharedSchemaStrategy` so sessions bind the tenant
setting per transaction. Consumer Alembic environments call
`jdlib.persistence.strategies.rls.emit_rls_policies(...)` after table creation;
`install_rls` / `verify_rls` fail closed on any partial deployment.

## Testing kit

```python
from jdlib.testing import (
    assert_cross_tenant_write_rejected,
    assert_scoped_count,
    assert_tenant_isolated,
)
```

The autoloaded pytest plugin provides database fixtures:

| Fixture | Purpose |
|---|---|
| `jdlib_database_url` | `JDLIB_TEST_DATABASE_URL` (skips when unset) |
| `jdlib_schema` | `JDLIB_TEST_SCHEMA`, default `jdlib_test` |
| `jdlib_models` | model modules imported into `TenantBase`; override to extend |
| `jdlib_engine` | async engine with the tenant schema and tables created |
| `jdlib_session_factory` | `async_sessionmaker` over `jdlib_engine` |

Running the integration suite locally uses testcontainers (`postgres:16`):

```bash
TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q
```

The override is required on Docker Desktop, where the container IP is not
routable from the host. To reuse an existing database instead, set
`JDLIB_TEST_DATABASE_URL` and skip testcontainers.

## CLI

`jdlib.integrations.cli:app` is a Typer application (`--json` on every command;
`--database-url` defaults to `JDLIB_CONTROL_DSN`):

| Group | Commands |
|---|---|
| `tenant` | `create`, `provision`, `list` |
| `db` | `upgrade-control`, `upgrade-tenants` |
| `rls` | `install`, `verify` |
| `schema` | `lint` |

## Extension points

- **Models**: subclass `jdlib.models.base.TenantBase`; mix in `TenantOwned`,
  `TenantRouted`, `Timestamped`, `SoftDelete`, `OwnableByOrg`, `OwnableByTeam`.
- **Resources and permissions**: register `ResourceTypeDefinition` with
  `ResourceTypeRegistry` (authorization scope walk + ownership transfer) and
  custom `Permission` codes with `PermissionCatalog.with_builtins()`.
- **Resolution**: implement the `TenantResolver` protocol and pass your
  resolvers to `ResolverChain` (or build one from `ResolverConfig` with
  `build_chain`).
- **Authentication**: implement the `Authenticator` protocol; compose it with
  the shipped OIDC/API-key authenticators via `CompositeAuthenticator`.
- **Isolation**: implement the `IsolationStrategy` protocol and register it in
  the `strategies` mapping; `SessionRouter` dispatches by placement.
- **Lifecycle**: implement `SeedHook` for per-tenant seed data and
  `SecretProvider` for database-per-tenant DSNs.
- **Audit**: implement the `PlatformAudit` protocol, or fan out with
  `CompositeAuditSink`; tenant-scoped events go through `TenantAuditRecorder`.
- **Access control collaborators**: `ScopeLookup` / `ResourceLookup` plug your
  org/team/resource ownership into `AccessControl` validation; `Enforcer` takes
  any `PolicyDecisionPoint`.
- **Errors**: only `JdlibError` subclasses cross module boundaries; adapters are
  expected to map driver exceptions to them.
