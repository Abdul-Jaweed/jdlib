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

`pip install "jdlib[cli]"` puts the `jdlib` console script on PATH
(`jdlib.integrations.cli:main`; the module's Typer application is `app`, for
embedding in your own entry point):

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
from jdlib.authz.pdp import Decision, DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.authz.scopes import ScopeResolver, Target
from jdlib.control.audit import DatabaseAuditSink, PrivilegeAuditAdapter
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
from myapp.models import Invoice  # your TenantBase + TenantRouted model

config = TenancyConfig()
engine = create_async_engine(config.control_dsn.get_secret_value())
control_sessions = async_sessionmaker(engine, expire_on_commit=False)
tenant_sessions = async_sessionmaker(engine, expire_on_commit=False)

audit = DatabaseAuditSink(control_sessions)
privilege_audit = PrivilegeAuditAdapter(audit)
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
catalog = PermissionCatalog.with_builtins()
resource_types = ResourceTypeRegistry()


def make_pdp() -> DefaultPDP:
    """Build a fresh PDP: its ``AuthzCache`` is request-scoped only."""
    return DefaultPDP(catalog=catalog, reader=reader, scopes=ScopeResolver(resource_types))


class RequestScopedEnforcer(Enforcer):
    """Builds a fresh PDP (and ``AuthzCache``) for every guard evaluation."""

    async def require(self, permission: str, target: Target, *, session: object) -> Decision:
        return await Enforcer(make_pdp()).require(permission, target, session=session)


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
        audit=privilege_audit,
    ),
    chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug"), ApiKeyResolver()]),
    principal_provider=build_authenticator(config, control_sessions, audit).authenticate,
    container=JdlibContainer(
        session_factory=control_sessions,
        uow_factory=uow_factory,
        enforcer=RequestScopedEnforcer(),
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

(`Invoice` is your application's `TenantBase` + `TenantRouted` model, imported
from your own package as shown; the tenant-scoped snippets below reuse it.)

`install` adds the ASGI middleware, the canonical error envelope
(`install_error_envelope`, which it calls for you), and stores the container on
`app.state`. Every failure answers exactly `code`, `message`, `request_id` and
`correlation_id`: a `JdlibError` maps to its descriptor's status
(401/403/404/409/423/500/503), a malformed body is 422 `VALIDATION_FAILED`, an
unanswered dependency is 503 `DEPENDENCY_UNAVAILABLE`, and `fastapi.HTTPException`
is mapped by status so an application's own rejections keep the same shape. A 401
carries its `WWW-Authenticate` challenge and a 5xx never echoes its own text:
`Retry-After` and `WWW-Authenticate` are the only headers passed through.
`InvalidReference` ("... is deleted") and `CrossTenantReferenceError` both map to
409. Call `install_error_envelope(app)` alone if you build the request edge
yourself; the contract and the edge table are in
[docs/security/error-responses.md](docs/security/error-responses.md). The example uses one shared tenant engine;
hybrid deployments route inside `uow_factory` by `context.strategy` (see
`SessionRouter`).

`DefaultPDP` memoizes through a request-scoped `AuthzCache`: never build one
PDP/cache at import time and share it across requests; the snippet builds a
fresh PDP for each guard evaluation instead.

`require` authorizes in its own unit of work: it opens `uow_factory()`, so the
`RegistryWriteFence` applies to guarded reads too (a guarded read during a
relocation quiesce fails with 423 `TenantNotWritable`). The guard authorizes
once, in that transaction; `get_uow` opens a separate session for the handler
(each `UnitOfWork` gets a new one), so the guard's decision is not re-validated
there: a permission revoked after the check is observed only by a fresh
evaluation in the handler's own session, not by re-checking the guard's
decision (a TOCTOU window between the guard and the handler).

`ContextFactory` takes a `PrivilegeAudit` (operator/system/test context
issuance), not the `PlatformAudit` sink itself; `PrivilegeAuditAdapter` bridges
the two and stamps `actor_type` from the acting principal's kind.

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
jdlib schema lint --rls   # fails when a tenant-plane table is not RLS-eligible (L13)
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

## Development

Python 3.12+ (`requires-python = ">=3.12"`), and Docker for the container-backed
layers.

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"     # POSIX: .venv/bin/pip
```

### Test layers

The layers are selected by **directory**, not by marker (the markers exist, but
most tests carry none):

| Layer | Command | Needs |
|---|---|---|
| Unit | `.venv/Scripts/python -m pytest tests/unit -q -W error` | nothing |
| Integration | `... pytest tests/integration -q -W error` | Docker (testcontainers `postgres:16`), or `JDLIB_TEST_DATABASE_URL` |
| Infra | `... pytest tests/infra -q -W error` | the local harness below; each suite skips cleanly when its service is absent |

`-W error` is the project's own gate flag: warnings fail the suite.

### Gates

```bash
.venv/Scripts/python -m ruff check .
.venv/Scripts/python -m mypy src/jdlib
.venv/Scripts/python -m pytest -q -W error
bash scripts/ci-local.sh     # the complete gate
```

`scripts/ci-local.sh` mirrors `.github/workflows/ci.yml` — `git diff --check`,
ruff, mypy, the whole suite with coverage, `python -m build`, and a clean-venv
install smoke — and is the gate a change is expected to pass before it is pushed;
the hosted workflow is the final verification. Bring the harness up first to
include the infra layer:

```bash
docker compose -f tests/infra/docker-compose.yml up -d cerbos otel-collector zitadel
bash tests/infra/kong/start.sh && . tests/infra/out/kong-credentials.env
bash tests/infra/tyk/start.sh  && . tests/infra/out/tyk-credentials.env
. tests/infra/out/otel.env
export TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1
export JDLIB_INFRA_CERBOS_URL=http://localhost:3592
export JDLIB_INFRA_ZITADEL_ISSUER=http://localhost:8080
export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:8000
export JDLIB_INFRA_TYK_URL=http://127.0.0.1:8081
bash scripts/ci-local.sh
```

The compose file holds the persistence, PDP, identity-provider and collector
services; Kong and Tyk each have their own `start.sh` beside them, and their ports
are overridable (`JDLIB_INFRA_KONG_PROXY_PORT`, `JDLIB_INFRA_KONG_ADMIN_PORT`) for
a machine where 8000/8001 are already taken. Per-service notes, ports and the
skip contract: [`tests/infra/README.md`](tests/infra/README.md).

### Repository layout

```
src/jdlib/           the library, one package per concern (strict mypy, py.typed)
  tenancy/ authz/ authn/ security/ control/ persistence/ data/ query/ resources/
  caching/ credentials/ storage/ reliability/ migrations/ models/ integrations/ testing/
tests/unit/          fast and isolated; no infrastructure
tests/integration/   real HTTP, PostgreSQL and Cerbos, no lab required
tests/infra/         the local harness: compose file, Kong and Tyk harnesses, live suites
docs/                design documents, the security programme, operations, compliance
scripts/ci-local.sh  the complete local gate
knowledge_base/      orientation material for the library as it exists today
```

## CLI

The `jdlib` console script (`jdlib.integrations.cli:main`, Typer; `--json` on every command;
`--database-url` defaults to `JDLIB_CONTROL_DSN`):

| Group | Commands |
|---|---|
| `tenant` | `create`, `provision`, `list` |
| `db` | `upgrade-control`, `upgrade-tenants` |
| `rls` | `install`, `verify` |
| `schema` | `lint` |
| `security` | `posture`, `evidence`, `compliance` |

The CLI registers the `shared` and `schema` strategies. Provisioning a
`database`-placement tenant needs the database strategy (with a
`SecretProvider`) registered programmatically, since the CLI has no secret
provider to resolve target DSNs.

## Security and compliance

Security documentation is indexed in [docs/security/README.md](docs/security/README.md):
authentication, authorization, tenant isolation and row-level security, audit,
observability, gateway trust, error responses, the adversarial review, the CI
security gates and the compliance surface. [SECURITY.md](SECURITY.md) states what
the library is responsible for, what it deliberately leaves to a deployment, and
how to report a vulnerability.

The `security` CLI group reports readiness against the control register
(`pip install "jdlib[cli]"` — typer is an extra):

```bash
jdlib security posture                 # every technical control, with reasons; exit 1 on a failure
jdlib security posture --json --environment production
jdlib security evidence --database-url "$JDLIB_CONTROL_DSN" --schema tenant_acme
jdlib security compliance --framework soc2
```

`posture` assesses the profile you declare, and `--database-url` with `--schema`
adds live observations (row-level security on the catalog, the revision the schema
has applied). **These are technical controls, evidence and readiness — installing
JDLib does not make an organisation certified or compliant**, and the register
records its own gaps (tamper-evident audit storage is a deployment
responsibility; Tyk plugin execution is not infrastructure-verified because the
OSS image has no coprocess runtime, so those tests skip rather than pass).

CI runs the gate plus dependency scanning, full-history secret scanning, static
analysis, an SBOM and a packaging smoke test; `docs/security/ci-security.md` says
what each covers, and which tools were evaluated and rejected.

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
  `CompositeAuditSink`; tenant-scoped events go through `TenantAuditRecorder`,
  and `PrivilegeAuditAdapter` adapts a platform sink to `ContextFactory`.
- **Access control collaborators**: `ScopeLookup` / `ResourceLookup` plug your
  org/team/resource ownership into `AccessControl` validation; `Enforcer` takes
  any `PolicyDecisionPoint`.
- **Errors**: only `JdlibError` subclasses cross module boundaries; adapters are
  expected to map driver exceptions to them.

## Documentation index

| Where | What |
|---|---|
| `docs/jdlib/02`–`07` | the approved design documents: relational schema, isolation invariants, authorization model, tenant lifecycle, strategy matrix, implementation design |
| `docs/jdlib/` (rest) | per-area reference: architecture, authentication, authorization, tenancy, query system, resource management, credentials, connectors, privileged access, security model, production readiness |
| `docs/jdlib/capabilities/` | caching, connectors, credentials, jobs, query, resources, storage |
| `docs/jdlib/successor/` | the successor programme: capability matrix, target architecture, adoption decisions and the roadmap, with per-phase status |
| `docs/security/README.md` | the security-hardening programme: one document per phase, the adversarial review, the CI security gates, the compliance surface |
| `docs/operations/`, `docs/compliance/` | runbooks, and the technical-control register with its own gaps |
| `JDLib-Architecture.md` | the long-form technical reference |
| `knowledge_base/` | orientation: module map, data flow, development guide, testing |
| `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` | contribution rules, what the library is responsible for and how to report a vulnerability, release notes |
