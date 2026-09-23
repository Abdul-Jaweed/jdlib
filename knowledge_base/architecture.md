# Architecture

jdlib separates *control plane* (who tenants are, what they may do, where their
data lives) from *tenant plane* (the tenant's own business rows), and enforces
the boundary in three places: schema (composite keys and composite foreign
keys), session (SQLAlchemy event handlers in `TenantSession`), and query text
(`RawSqlValidator` parsing compiled SQL with `pglast`).

## 1. The two planes

| | Control plane | Tenant plane |
|---|---|---|
| Schema | `jd_control` (`control/base.py:6`) | deployment schema — `public` for shared placement, `t_<slug>` for schema placement, per-tenant DB `public` for database placement |
| Base class | `ControlBase` (`control/base.py:17`) | `TenantBase` (`models/base.py:13`) |
| Tables | 16 tables in `control/models.py` | `organizations`, `teams`, `tenant_settings`, `audit_events` + consumer resources |
| Session wrapper | `ControlPlaneSession` (`control/session.py`) — framework-internal | `TenantSession` (`persistence/session.py`) — fail-closed, context-bound |
| Who may touch it | framework services only (`TenantRegistry`, `AccessControl`, `ControlAccessReader`, authn) | application code through `UnitOfWork`/`TenantSession` |

Invariant L3 (`lint.py`) forbids foreign keys across the two planes; L19 forbids
a control-plane model from inheriting `TenantRouted`; L17 forbids a tenant-plane
model that is not `TenantRouted`. See
[reference/invariants_and_lint.md](reference/invariants_and_lint.md).

## 2. Layering

Verified by reading the static import graph (see §4):

```
integrations/            FastAPI adapters · Typer CLI          (optional deps)
tenancy/  authn/  authz/  control/                             application services
persistence/  models/                                          domain + persistence
context.py  config.py  errors.py  _uuid.py  lint.py            foundation (no I/O)
```

- `context.py`, `config.py`, `errors.py`, `_uuid.py` import nothing from jdlib.
- `persistence/` knows `context`, `errors`, `models`, `migrations.runner`
  (via strategy protocols) — never `integrations`.
- `control/` imports `context`, `errors`, `control.*`, `migrations.runner`, and
  the strategy modules for handle validation.
- `integrations/` and `testing/` are the only modules that import optional
  dependencies (`fastapi`, `typer`, `pytest`).

One deliberate upward edge: `models/base.py` imports
`jdlib.control.base.NAMING_CONVENTION`, and `lint.py` imports both bases — the
naming convention is shared so constraint names are deterministic across planes
(required by the lint rules and by migration diffing).

## 3. Component map

| Component | File(s) | Responsibility |
|---|---|---|
| Config | `config.py` | `TenancyConfig` (pydantic-settings) + resolver/OIDC/API-key/RLS sub-models. |
| Errors | `errors.py` | 27 exception classes rooted at `JdlibError`. |
| UUIDv7 | `_uuid.py` | `uuid7()` — timestamp-ordered UUID primary keys generated in-process. |
| Context | `context.py` | `Principal`, `PrivilegeContext`, `TenantContext`, `TenantRef`, `TenantRecord`, `ContextFactory`, `current_*()` accessors, `scoped_key()`, `EnvelopeCodec`, port protocols. |
| Tenant discovery | `persistence/models.py` | `tenant_table_map()` (reflection over `TenantRouted` subclasses), `WriteFence`, `privileged_bypass()`. |
| Tenant session | `persistence/session.py` | `TenantSession` + the registered event handlers that do scoping/stamping/rejection; `raw_sql` modes. |
| Raw SQL validation | `persistence/rawsql.py` | `RawSqlValidator`, `RawSqlMode`, `CompiledRawSql` — structural proof of tenant boundedness. |
| Unit of work | `persistence/uow.py` | `UnitOfWork` — write-fence check, one session/transaction per scope, commit/rollback. |
| Repository | `persistence/repository.py` | `TenantRepository[ModelT]` — `get/list/add/update/soft_delete/count`, soft-delete-aware. |
| Routing | `persistence/router.py` | `SessionRouter` — strategy dispatch by `TenantRecord.strategy`. |
| Secrets | `persistence/secrets.py` | `SecretProvider` protocol, `MemorySecretProvider`, `EnvSecretProvider`. |
| Strategies | `persistence/strategies/*` | `IsolationStrategy` protocol + shared/schema/database implementations, `DeprovisionMode`, RLS helpers. |
| Control models | `control/models.py` | 16 control-plane ORM models. |
| Control session | `control/session.py` | `ControlPlaneSession` — thin async-session wrapper. |
| Tenant lifecycle | `control/registry.py` | `TenantRegistry` (create/provision/migrate/suspend/resume/archive/deprovision/find/assert_servable/list_for_user) + `RegistryWriteFence`. |
| Tenant purge | `control/purge.py` | `TenantPlanePurger` — child-first privileged deletion of tenant-plane rows. |
| Audit | `control/audit.py`, `models/audit.py`, `models/audit_recorder.py` | `PlatformAudit` protocol, `DatabaseAuditSink`, `CompositeAuditSink`, `RecordingPlatformAudit`, `PrivilegeAuditAdapter`, `TenantAuditRecorder`. |
| Tenancy | `tenancy/resolution.py`, `middleware.py`, `jobs.py` | Request snapshots + resolvers, ASGI middleware, signed-envelope propagation (`ContextPropagator`, `tenant_job`). |
| Authn | `authn/*` | `Authenticator` protocol, OIDC (JWKS/verify/link), API keys, composite, wiring adapters. |
| Authz | `authz/*` | Catalog, resource types, scopes, reader, PDP, cache, `AccessControl`, guards. |
| Migrations | `migrations/runner.py` (+ two Alembic script locations) | `MigrationRunner` — programmatic Alembic. |
| Lint | `lint.py` | `LintIssue`, `lint_metadata()`, `assert_clean()`. |
| Integrations | `integrations/fastapi.py`, `integrations/cli.py` | ASGI middleware install + DI helpers; operator CLI. |
| Test kit | `testing/assertions.py`, `testing/pytest_plugin.py` | Consumer isolation assertions + pytest fixtures. |

## 4. Module dependency graph (verified)

Generated from static imports of `src/jdlib` (64 modules). Edges point from
importer → imported:

```
config, errors, _uuid, control/base, control/enums, control/session, secrets, cache, deprovision
        ▲ (imported by)
context ──▶ config, control.enums, errors
models/base ──▶ control.base            models/org|settings|audit ──▶ models.base, _uuid
lint ──▶ control.base, models.base, errors
persistence/models ──▶ context, models.base
persistence/rawsql ──▶ persistence.models, errors
persistence/session ──▶ context, errors, models.base, persistence.models, persistence.rawsql
persistence/uow ──▶ context, persistence.models, persistence.session
persistence/repository ──▶ persistence.session
persistence/router ──▶ context, control.enums, errors, strategies.base
persistence/strategies/{shared,schema,database} ──▶ context, errors, migrations.runner, secrets, strategies.base
control/audit ──▶ context, control.models, control.session, errors
control/registry ──▶ context, control.{audit,enums,models,purge,session}, errors,
                     migrations.runner, strategies.{base,database,deprovision,schema}
control/purge ──▶ config, context, models.base, persistence.{models,session}
tenancy/resolution ──▶ config, context          tenancy/middleware ──▶ context, errors, tenancy.resolution
tenancy/jobs ──▶ context, errors
authn/* ──▶ context, config, control.{audit,models,session}, errors, tenancy.resolution
authz/* ──▶ context, control.{enums,models,session}, errors, models.org, persistence.session, authz.*
migrations/runner ──▶ control.base, errors
integrations/cli ──▶ control.*, lint, migrations.runner, models.base, strategies.{rls,schema,shared}, errors
integrations/fastapi ──▶ authz.{guards,scopes}, context, errors, persistence.uow, tenancy.{middleware,resolution}
testing/assertions ──▶ context, errors, persistence.session
testing/pytest_plugin ──▶ models.base
jdlib/__init__ ──▶ authz.{access,guards}, config, context, control.registry, errors,
                   persistence.{repository,uow}
```

Cycles: none between top-level packages. `control.registry` reaching into
`persistence.strategies.*` and `models.base` reaching into `control.base` are the
two edges that break a strict "inward only" story; both are explained in §2 and
in [design_decisions.md](design_decisions.md).

## 5. Key abstractions (ports)

| Protocol | Definition | Shipped implementation(s) |
|---|---|---|
| `IsolationStrategy` | `persistence/strategies/base.py` | `SharedSchemaStrategy`, `SchemaPerTenantStrategy`, `DatabasePerTenantStrategy` |
| `WriteFence` | `persistence/models.py` | `RegistryWriteFence` (control), `NullWriteFence` (default for non-lifecycle uses) |
| `Authenticator` | `authn/base.py` | `OidcAuthenticator`, `ApiKeyAuthenticator`, `CompositeAuthenticator` |
| `TenantResolver` | `tenancy/resolution.py` | `JwtClaimResolver`, `SubdomainResolver`, `PathResolver`, `HeaderResolver`, `ApiKeyResolver`, `ResolverChain` |
| `PolicyDecisionPoint` | `authz/pdp.py` | `DefaultPDP` |
| `AccessReader` | `authz/reader.py` | `ControlAccessReader` |
| `PlatformAudit` | `control/audit.py` | `DatabaseAuditSink`, `CompositeAuditSink`, `RecordingPlatformAudit`, `NullPlatformAudit` |
| `RawSqlAuditor` | `persistence/session.py` | (no-op default; consumers supply one) |
| `SecretProvider` | `persistence/secrets.py` | `MemorySecretProvider`, `EnvSecretProvider` |
| `SeedHook` | `control/registry.py` | `_NoopSeedHook` |
| `Clock` | `context.py` | `SystemClock` |
| Context-port protocols | `context.py` (`PrincipalDirectory`, `TenantDirectory`, `ServabilityChecker`, `EntitlementChecker`, `OperatorAuthorizer`, `PrivilegeAudit`) | `authn/wiring.py` adapters + `TenantRegistry` |

## 6. The enforcement core (how isolation actually happens)

`TenantSession.__init__` stores the context in `session.sync_session.info` and
calls `_register_events(session.sync_session)` (`persistence/session.py:272`).
Three handlers then guard every operation:

1. **`do_orm_execute` / SELECT** (`persistence/session.py:117-211`)
   - Refuses to run at all without a context.
   - Rejects `TextClause` / literal SQL fragments *anywhere* in the statement
     tree (`UnscopedRawSql`).
   - Determines which tenant tables the statement genuinely targets (FROM
     entities, mapper tables, bind mapper) and attaches
     `with_loader_criteria(cls, cls.tenant_id == ctx.tenant_id,
     include_aliases=True)` for each trusted mapper — this also covers
     relationship loads and subqueries.
   - Table-level selects on tenant tables, and aliases not derived from an
     entity, are rejected: "aliases of tenant tables must be entity-derived; use
     `aliased(Entity)` or `raw_sql`".
2. **`do_orm_execute` / INSERT-UPDATE-DELETE** (`persistence/session.py:212-224`)
   - Any ORM-enabled bulk DML on a tenant table without the internal
     `jdlib_scoped` / `jdlib_raw_sql` execution option raises
     `UnscopedBulkOperation`, forcing callers through
     `update_where`/`delete_where`/`raw_sql`.
3. **`before_flush`** (`persistence/session.py:226-253`)
   - New `TenantRouted` objects get `tenant_id` stamped from the context; a
     conflicting value raises `CrossTenantReferenceError`.
   - Dirty objects may not change `tenant_id`.
   - Deleting a `SoftDelete` instance without a privileged context raises
     `AuthorizationError` (hard delete requires privilege).

Bulk helpers build scoped statements explicitly
(`sa.update(model).where(model.tenant_id == ctx.tenant_id, *criteria)` with
`execution_options(jdlib_scoped=True)`), and the `before_flush`/`update_where`
code refuses `tenant_id` column updates from non-privileged contexts.
`raw_sql()` compiles the statement with the session's dialect, then parses the
resulting SQL with `pglast` and proves a tenant predicate for every referenced
relation (`persistence/rawsql.py`); privileged modes additionally require a
`PrivilegeContext` capability of `tenant.raw_sql` or `platform.raw_sql`.

## 7. Request and background pipeline

```
HTTP request
  → TenantMiddleware.__call__            (tenancy/middleware.py)
      principal_provider(request)        → Principal | AuthenticationError(401)
      ResolverChain.resolve(...)         → TenantRef   | TenantNotFound(404)
      ContextFactory.for_principal(...)  → TenantContext (entitlement + servability)
      context_scope(context)             → app
  → FastAPI dependencies: get_context / require(...) / get_uow
      require → UnitOfWork(uow_factory) → Enforcer.require → PDP.evaluate

Background job
  → tenant_job(propagator)(envelope, ...)   (tenancy/jobs.py)
      EnvelopeCodec.decode → validate principal/tenant states → context_scope
```

Both paths converge on the same `TenantContext` type, so downstream code
(`UnitOfWork`, `TenantSession`, `AccessControl`) is transport-agnostic.

## 8. Control-plane lifecycle flow

`TenantRegistry` (`control/registry.py`) owns tenant state. Every mutation runs
under a transaction-scoped advisory lock keyed `jdlib:tenant:<id>`
(`hashtextextended`), takes its own `ControlPlaneSession`, writes platform audit
rows in the same transaction, and commits once.

```
create        → tenants(provisioning) + tenant_placements + tenant_migration_states(pending)
provision     → strategy.provision → strategy.migrate → seeder → version check
                → migration state success → tenants(active)  [audit each step]
migrate       → strategy.migrate; on failure: state=failed and an active tenant
                is suspended with reason "migration_failed"
suspend/resume/archive → transition table `_ALLOWED_TENANT_TRANSITIONS`
deprovision   → ARCHIVE: detach children if requested, status=archived
                PURGE/DESTROY: status=deprovisioning → commit → re-lock → re-read
                → verify state → delete access rows → strategy.deprovision
                → (shared) TenantPlanePurger → status=deleted [audit with counts]
```

`assert_servable()` is the single predicate answering "may this tenant serve
traffic?" — status `active` **and** migration `success` **and**
`current_version == desired_version` **and** no relocation in a critical phase.
`RegistryWriteFence.assert_writable()` asks the same question for mutations and
raises `TenantNotWritable`. See [execution_flows.md](execution_flows.md).

## 9. Cross-cutting concerns

- **Audit.** Platform events are transactional with the control-plane mutation
  they describe (`DatabaseAuditSink` reuses the caller's session when given one,
  otherwise opens and commits its own). Tenant-plane events go into the same
  tenant transaction via `TenantAuditRecorder`. Privileged context issuance is
  audited through `PrivilegeAuditAdapter` (`privilege.<kind>` actions).
- **Errors.** Only `JdlibError` subclasses cross module boundaries; the HTTP
  layer maps them through a frozen table (`tenancy/middleware.py:26`). See
  [error_handling.md](error_handling.md).
- **Identity.** Primary keys are UUIDv7 generated in-process (`_uuid.py`), so
  indexes stay roughly insertion-ordered without a database round trip.
- **Accounting for scope.** `scoped_key(namespace, *parts)` mints
  `jdlib:v1:<tenant_id>:<namespace>:<part>...` with every part percent-encoded,
  giving consumers a collision-free key convention for caches, queues, and
  object storage (invariant I8).

## 10. Extension seams

Applications extend jdlib by implementing protocols, not by subclassing internal
services: models via `TenantBase` + mixins, authorization via
`ResourceTypeDefinition`/`Permission`, tenancy resolution via `TenantResolver`,
authentication via `Authenticator`, isolation via `IsolationStrategy`, lifecycle
via `SeedHook`/`SecretProvider`, audit via `PlatformAudit`, and access-control
validation via `ScopeLookup`/`ResourceLookup`. The full table with signatures is
in [api/extension_points.md](api/extension_points.md).
