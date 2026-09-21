# jdlib — Implementation Design (Code Level)

Companion to the foundation design (rev 3) and contracts `02`–`06`. This
document is the blueprint for implementation: architectural style, patterns,
modules, classes, interfaces, and cross-cutting rules. Behavior is owned by the
other documents; this one is about how the code is structured.

## 1. Architectural style

Layered ports-and-adapters:

```
integrations (FastAPI, CLI)          ← adapters
tenancy · authn · audit              ← application services (use cases)
authz · persistence · control        ← domain services and persistence ports
context · models · errors · config   ← foundation (no I/O)
```

Rules:

- Dependencies point inward only. `models`, `context`, `errors`, `config` import
  no framework service.
- Every external concern enters through a `Protocol` port
  (`IsolationStrategy`, `Authenticator`, `TenantResolver`, `PolicyDecisionPoint`,
  `AuditSink`, `SecretProvider`, `ResourceTypeRegistry`, `TenantLifecycleHook`).
- Constructor injection everywhere. No DI container, no service locator, no
  global mutable state. The only module-level state is the `contextvars`
  contextvar, and it is fail-closed.
- Async-first (SQLAlchemy `AsyncSession`, `asyncpg`). Sync code is confined to
  Alembic programmatic invocation and the CLI.
- One concrete implementation per port ships in v1; ports exist because an
  interface was explicitly designed for replacement, not speculatively.

## 2. Patterns used, and patterns rejected

| Pattern | Where | Why |
|---|---|---|
| Ports & Adapters | all extension points | strategy/IdP/engine replacement without touching business code |
| Strategy | `IsolationStrategy` implementations | the core requirement: swap physical tenancy |
| Chain of Responsibility | resolver chain, authenticator chain | layered request identification without branching |
| Factory | `ContextFactory`, `SessionRouter`, strategy registry | the only sanctioned way to create authoritative objects |
| Context Object | `TenantContext` | tenancy as infrastructure; implicit but fail-closed |
| Unit of Work | `UnitOfWork` | one transaction per tenant operation; explicit boundaries |
| Repository / Data Mapper | `TenantRepository` over SQLAlchemy mappings | business code never builds scoped queries by hand |
| Identity Map | SQLAlchemy `AsyncSession` (built in) | no custom implementation |
| Registry | `PermissionCatalog`, `ResourceTypeRegistry` | startup-validated, code-owned metadata |
| Decorator | `@requires`, `@tenant_job` | ergonomic guards without magic internals |
| Composite | `CompositeAuthenticator`, `CompositeAuditSink` | ordered fan-in without an event bus |
| Null Object | `NoopAuditSink`, `StaticResolver` (testing) | tests without branches |

Rejected deliberately: DI framework, event bus/message broker abstraction,
generic query DSL, ORM abstraction layer, Active Record, inheritance-heavy
Template Method hierarchies, cross-request authorization caches (v1).

## 3. File map

```
src/jdlib/
├── __init__.py                 # public API re-exports only
├── config.py                   # TenancyConfig + sub-models
├── errors.py                   # exception hierarchy
├── context.py                  # Principal, TenantContext, PrivilegeContext,
│                               #   ContextFactory, current_*, scoped_key, envelope
├── control/
│   ├── base.py                 # ControlBase (DeclarativeBase, schema="jd_control")
│   ├── models.py               # Tenant, TenantPlacement, TenantMigrationState, TenantRelocation,
│   │                           #   User, IdentityLink, PlatformOperator, ServiceAccount, ApiKey,
│   │                           #   Membership, Invitation, Role, RolePermission,
│   │                           #   RoleBinding, ResourceGrant, PlatformAuditEvent
│   ├── session.py              # ControlPlaneSession (framework-internal)
│   ├── registry.py             # TenantRegistry, DeprovisionMode, MigrationState
│   └── access.py               # AccessControl, ownership validation
├── models/
│   ├── base.py                 # TenantBase + mixins: TenantOwned, TenantRouted,
│   │                           #   Timestamped, SoftDelete, OwnableByOrg, OwnableByTeam
│   ├── org.py                  # Organization, Team
│   ├── settings.py             # TenantSetting
│   └── audit.py                # AuditEvent
├── authn/
│   ├── base.py                 # Authenticator protocol, RequestInfo
│   ├── oidc.py                 # OidcAuthenticator, JwksCache, TokenVerifier,
│   │                           #   ClaimMapper, UserLinker
│   ├── apikey.py               # ApiKeyAuthenticator, KeyParser
│   └── composite.py            # CompositeAuthenticator
├── authz/
│   ├── permissions.py          # Permission, PermissionCatalog, builtin catalog
│   ├── resource_types.py       # ResourceTypeDefinition, ResourceTypeRegistry
│   ├── scopes.py               # ScopeRef, ScopeType, ScopeResolver
│   ├── pdp.py                  # PolicyDecisionPoint, DefaultPDP, Decision, MatchedRule
│   ├── cache.py                # AuthzCache (request-scoped, invalidatable)
│   ├── guards.py               # Enforcer, requires(), authorize()
│   └── ownership.py            # validate_ownership, hierarchy helpers (I12)
├── tenancy/
│   ├── resolution.py           # TenantResolver protocol + 5 built-ins + ResolverChain
│   ├── middleware.py           # pure-ASGI TenantMiddleware, context lifecycle
│   └── jobs.py                 # @tenant_job decorator, ContextPropagator
├── persistence/
│   ├── session.py              # TenantSession (scoping, stamping, guards, raw_sql modes)
│   ├── rawsql.py               # RawSqlMode, RawSqlValidator (pglast structural validation)
│   ├── router.py               # SessionRouter, PoolCache, SecretProvider
│   ├── uow.py                  # UnitOfWork
│   ├── repository.py           # TenantRepository[ModelT]
│   ├── events.py               # SQLAlchemy event registration (do_orm_execute, before_flush)
│   └── strategies/
│       ├── base.py             # IsolationStrategy, StrategyCapabilities, StrategyName
│       ├── shared.py           # SharedSchemaStrategy
│       ├── schema.py           # SchemaPerTenantStrategy, SchemaName validation
│       ├── database.py         # DatabasePerTenantStrategy
│       └── rls.py              # RlsPolicyEmitter, emit_rls_policies(metadata)
├── audit/
│   ├── base.py                 # AuditRecord, AuditSink
│   ├── sinks.py                # DatabaseAuditSink (plane-aware), CompositeAuditSink
│   └── recorder.py             # AuditRecorder (mandatory vs best-effort)
├── migrations/
│   ├── runner.py               # MigrationRunner (programmatic Alembic)
│   └── template/env.py         # consumer Alembic template
├── testing/
│   ├── fixtures.py             # tenants, context, strategy_matrix, rls_on_off
│   ├── fakes.py                # FakePDP, InMemoryAuditSink, StaticResolver, MemorySecretProvider
│   └── assertions.py           # assert_isolation, assert_cross_tenant_rejected, assert_rls_matrix
└── integrations/
    ├── fastapi.py              # middleware wiring, dependencies, exception handlers
    └── cli.py                  # typer commands
```

## 4. Foundation types

```python
class PrincipalKind(StrEnum):
    USER = "user"; SERVICE_ACCOUNT = "service_account"; PLATFORM_OPERATOR = "platform_operator"

@dataclass(frozen=True, slots=True)
class Principal:
    kind: PrincipalKind
    id: uuid.UUID
    user_id: uuid.UUID | None = None
    tenant_id: uuid.UUID | None = None        # pinned for service accounts
    api_key_id: uuid.UUID | None = None
    scopes: frozenset[str] | None = None      # None = no narrowing
    operator_level: OperatorLevel | None = None

@dataclass(frozen=True, slots=True)
class PrivilegeContext:
    kind: PrivilegeKind            # operator | system | test
    capability: str | None
    justification: str | None
    actor: Principal
    issued_at: datetime
    expires_at: datetime | None

@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: uuid.UUID
    tenant_slug: str
    strategy: StrategyName
    principal: Principal
    privilege: PrivilegeContext | None
    request_id: str
    correlation_id: str
    trace_id: str | None

_CTX: ContextVar[TenantContext | None]
def current_tenant() -> TenantContext            # raises MissingTenantContext
def current_principal() -> Principal
def current_privilege() -> PrivilegeContext | None
def scoped_key(namespace: str, *parts: object) -> str   # jdlib:v1:{tenant}:{ns}:{enc parts}
```

`ContextFactory` is the only creator:

```python
class ContextFactory:
    def __init__(self, registry: TenantRegistry, access: AccessControl,
                 config: ContextConfig, clock: Clock = SystemClock()) -> None: ...

    async def for_principal(self, principal: Principal, tenant: TenantRef, *,
                            request_id: str, correlation_id: str | None = None,
                            trace_id: str | None = None) -> TenantContext: ...
    async def for_operator(self, operator: Principal, tenant: TenantRef, capability: str,
                           *, justification: str, ttl: timedelta) -> TenantContext: ...
    def for_system(self, tenant: TenantRef, *, purpose: str) -> TenantContext: ...
    def for_test(self, tenant: TenantRef, *, principal: Principal) -> TenantContext: ...
```

`for_principal` runs the authoritative flow (statuses, membership, tenant
servability) and never trusts caller-supplied state beyond ids.
`for_system`/`for_test` require the internal `_PrivilegeIssuer` instance held by
the factory; their use is audited.

Envelope for async boundaries:

```python
@dataclass(frozen=True, slots=True)
class TenantContextEnvelope:
    tenant_id: uuid.UUID; principal_type: PrincipalKind; principal_id: uuid.UUID
    request_id: str; correlation_id: str; trace_id: str | None
    issued_at: datetime; signature: bytes

class EnvelopeCodec:      # HMAC-SHA256 over canonical fields, TTL-enforced
    def encode(self, ctx: TenantContext) -> str: ...
    def decode(self, token: str, *, now: datetime) -> TenantContextEnvelope: ...

class ContextPropagator:  # rebuilds context: verify → reload statuses → re-authorize
    async def reconstruct(self, token: str) -> TenantContext: ...
```

## 5. Configuration

Pydantic-settings models, environment-prefixed (`JDLIB_`), no defaults for
secrets:

```python
class TenancyConfig(BaseSettings):
    control_dsn: SecretStr
    default_strategy: StrategyName = StrategyName.SHARED
    strategies: StrategiesConfig
    rls: RlsConfig                      # enabled, app_role, owner_role
    pools: PoolConfig                   # max_targets, cap, health_check_interval
    resolvers: list[ResolverName] = [JWT_CLAIM, SUBDOMAIN, PATH, HEADER, API_KEY]
    oidc: OidcConfig                    # issuer, audience, algorithms, jwks_ttl, email_trusted
    api_keys: ApiKeyConfig              # prefix, pepper
    context: ContextConfig              # signing_key, envelope_ttl, operator_ttl
    secrets: SecretProviderConfig
```

Validation happens at startup: unknown strategy, RLS with non-shared placement,
missing signing key, or invalid resource-type definitions raise before the app
serves traffic.

## 6. ORM design

### 6.1 Bases and naming

Two `DeclarativeBase`s (`ControlBase`, `TenantBase`) with one shared naming
convention so constraint names are deterministic for migrations and lint:

```python
convention = {"ix": "ix_%(table_name)s_%(column_0_N_name)s",
              "uq": "uq_%(table_name)s_%(column_0_N_name)s",
              "ck": "ck_%(table_name)s_%(constraint_name)s",
              "fk": "fk_%(table_name)s_%(column_0_N_name)s",
              "pk": "pk_%(table_name)s"}
```

Typed mappings (`Mapped[...]` + `mapped_column`). UUIDv7 via `uuid-utils`,
client-side default. All datetimes timezone-aware UTC.

### 6.2 Mixins (tenant plane)

```python
class TenantOwned:
    tenant_id: Mapped[uuid.UUID] = mapped_column(primary_key=True, nullable=False)

class TenantRouted(TenantOwned):
    """TenantOwned + physical routing/RLS eligibility. Subclass, never a sibling."""

class Timestamped:
    created_at: Mapped[datetime]; updated_at: Mapped[datetime]

class SoftDelete:
    deleted_at: Mapped[datetime | None]

class OwnableByOrg:
    organization_id: Mapped[uuid.UUID | None]

class OwnableByTeam:
    team_id: Mapped[uuid.UUID | None]
    # __table_args__ adds:
    #   CheckConstraint("team_id IS NULL OR organization_id IS NOT NULL")
    #   ForeignKeyConstraint(["tenant_id","team_id","organization_id"],
    #                        ["teams.tenant_id","teams.id","teams.organization_id"])
```

Application models inherit `TenantBase` + `TenantRouted` + mixins; the metadata
lint (L1–L19) runs against the combined metadata at import time in tests and at
startup when `config.strict_schema = true`.

Model inheritance contract (frozen, enforced by L17–L19):

```
                TenantOwned
                /         \
   control-plane            TenantRouted
   tenant-owned             tenant-plane
   (NOT routed)             + application-plane
```

- Every tenant-plane framework model and every application resource inherits
  `TenantRouted` (`TenantRouted ⊂ TenantOwned`).
- Control-plane tenant-owned models (`Membership`, `Role`, `RolePermission`,
  `RoleBinding`, `ResourceGrant`, `Invitation`, `ApiKey`, `ServiceAccount`)
  inherit `TenantOwned` only.
- L17: tenant-plane model without `TenantRouted` → build failure.
  L18: registered application model without `TenantRouted` → build failure.
  L19: control-plane model marked `TenantRouted` → build failure.

```python
class Project(TenantRouted, Timestamped, OwnableByOrg, OwnableByTeam):
    ...
```

### 6.3 Scoping implementation (the enforcement core)

In `persistence/events.py`, registered on every tenant session:

- **Reads** — `do_orm_execute` for ORM SELECTs: when
  `execute_state.is_select` and context has a tenant, attach
  `with_loader_criteria(TenantRouted, lambda cls: cls.tenant_id == ctx.tenant_id)`
  (also applied to relationship loads and subqueries by SQLAlchemy).
- **Bulk writes** — `TenantSession.update_where` / `delete_where` build
  ORM-enabled `update()`/`delete()` with an explicit tenant predicate. A second
  `do_orm_execute` guard inspects ORM-enabled DML against `TenantRouted` and
  raises `UnscopedBulkOperation` if the compiled statement has no `tenant_id`
  criterion. This is a guard, not a substitute for the helpers; both exist.
- **Inserts/updates** — `before_flush`:
  - stamp `tenant_id` from context (new objects); reject a different value;
  - reject mutation of `tenant_id` on dirty objects (L8);
  - run `validate_ownership()` for `OwnableByTeam` objects (I12);
  - maintain `Timestamped` values;
  - translate `session.delete()` on `SoftDelete` models into `deleted_at`
    (hard delete requires a privileged context, audited).
- **Raw SQL** — explicit modes, never a boolean switch:

```python
class RawSqlMode(StrEnum):
    TENANT_BOUND = "tenant_bound"
    PRIVILEGED = "privileged"

@dataclass(frozen=True, slots=True)
class CompiledRawSql:
    sql: str                        # PostgreSQL dialect, $n positional placeholders
    binds: Mapping[int, object]     # bind values by index

class RawSqlValidator:   # persistence/rawsql.py
    def compile(self, statement: TextClause | Executable) -> CompiledRawSql: ...
    def validate_tenant_bound(self, compiled: CompiledRawSql, ctx: TenantContext) -> None: ...
```

  Validation pipeline (frozen): SQLAlchemy statement → PostgreSQL dialect
  compilation (`postgresql.asyncpg` dialect; `$n` placeholders + bind metadata)
  → `pglast` parse → AST validation → execution. Uncompiled SQLAlchemy bind
  syntax (`:name`) is never handed to the parser.

  `TENANT_BOUND` allows **SELECT, INSERT, UPDATE, DELETE** and rejects DDL,
  multiple statements, dynamic SQL, CTEs, transaction control
  (`BEGIN`/`COMMIT`/`ROLLBACK`), `SET`, `COPY`, and administrative commands.
  It must *semantically prove* tenant boundedness, not string-match: every
  referenced relation must resolve to a registered `TenantRouted` table for the
  active target (no control-plane or foreign-schema references, no
  table-valued functions), the WHERE clause must be an AND-conjunction, and
  every relation must carry a conjunct `<relation>.tenant_id = $n` where bind
  `$n` holds the context tenant id; `INSERT` must bind `tenant_id` explicitly.
  `OR`, `NOT`, or nested boolean wrappers around the tenant predicate are
  rejected (`WHERE tenant_id = $1 OR TRUE` cannot pass). Anything unprovable
  raises `UnscopedRawSql`.

  `PRIVILEGED` requires an explicit capability: `tenant.raw_sql` (current
  tenant only; tenant-predicate proof waived, structural rejects still apply)
  or `platform.raw_sql` (cross-tenant/system only, admin-level, mandatory
  justification and `PlatformAuditEvent`). A generic raw-SQL capability is
  never a platform-wide bypass. Every call is logged with tenant and mode.

Serialization of tenant identity is never implicit: sessions hold an immutable
`TenantContext`; there is no setter.

## 7. Persistence services

```python
class UnitOfWork:
    def __init__(self, router: SessionRouter, context: TenantContext,
                 audit: AuditRecorder | None = None) -> None: ...
    async def __aenter__(self) -> TenantSession: ...   # opens session
    async def __aexit__(self, *exc) -> None: ...       # commit clean / rollback dirty

class TenantRepository(Generic[ModelT]):
    def __init__(self, session: TenantSession, model: type[ModelT], *,
                 audited: bool = True) -> None: ...
    async def get(self, entity_id: uuid.UUID) -> ModelT | None: ...
    async def list(self, *criteria, order_by=None, limit=None, offset=None) -> Sequence[ModelT]: ...
    async def add(self, obj: ModelT, *, flush: bool = True) -> ModelT: ...
    async def update(self, obj: ModelT, **changes: object) -> ModelT: ...
    async def soft_delete(self, obj: ModelT) -> None: ...
    async def count(self, *criteria) -> int: ...

class SessionRouter:
    def __init__(self, config: TenancyConfig, control_engine: AsyncEngine,
                 secret_provider: SecretProvider,
                 strategies: Mapping[StrategyName, IsolationStrategy]) -> None: ...
    async def tenant_session(self, ctx: TenantContext) -> TenantSession: ...
    async def control_session(self) -> ControlPlaneSession: ...   # internal
    async def dispose(self) -> None: ...

class SharedSchemaStrategy:  name, capabilities, session, provision, migrate, deprovision
class SchemaPerTenantStrategy: ...  # search_path set on checkout, validated handle
class DatabasePerTenantStrategy: ...  # handle → SecretProvider → pool
```

`SessionRouter` owns the `PoolCache` (LRU, cap, never evicts pools with
checked-out connections) and rejects `context.tenant_id` mismatches before
opening a session.

## 8. Control-plane services

```python
class TenantRegistry:
    async def create(self, *, slug: str, name: str, strategy: StrategyName,
                     target_handle: str, region: str | None = None,
                     parent_tenant_id: uuid.UUID | None = None,
                     actor: Principal) -> Tenant: ...
    async def provision(self, tenant_id: uuid.UUID) -> Tenant: ...      # idempotent/resumable
    async def migrate(self, tenant_id: uuid.UUID) -> MigrationState: ...
    async def suspend(self, tenant_id: uuid.UUID, *, reason: str, actor: Principal) -> Tenant: ...
    async def resume(self, tenant_id: uuid.UUID, *, actor: Principal) -> Tenant: ...
    async def archive(self, tenant_id: uuid.UUID, *, actor: Principal) -> Tenant: ...
    async def deprovision(self, tenant_id: uuid.UUID, *, mode: DeprovisionMode,
                          actor: Principal, detach_children: bool = False) -> None: ...
    async def relocate(self, tenant_id: uuid.UUID, *, to_strategy: StrategyName,
                       to_target_handle: str, to_region: str | None = None,
                       actor: Principal) -> TenantRelocation: ...
    async def resume_relocation(self, tenant_id: uuid.UUID, *, actor: Principal) -> TenantRelocation: ...
    async def rollback_relocation(self, tenant_id: uuid.UUID, *, actor: Principal) -> TenantRelocation: ...
    async def assert_servable(self, tenant: Tenant) -> None: ...
    async def list_for_user(self, user_id: uuid.UUID) -> Sequence[TenantSummary]: ...

class AccessControl:
    async def invite(self, *, tenant_id, email, scope: ScopeRef, role_id, actor) -> Invitation: ...
    async def accept_invitation(self, token: str, principal: Principal) -> Membership: ...
    async def create_role(self, tenant_id, name: str, permissions: Collection[str], actor) -> Role: ...
    async def update_role(self, role: Role, *, permissions: Collection[str], actor) -> Role: ...
    async def delete_role(self, role: Role, *, actor) -> None: ...
    async def bind_role(self, *, tenant_id, role_id, principal: PrincipalRef,
                        scope: ScopeRef, actor) -> RoleBinding: ...
    async def unbind_role(self, binding: RoleBinding, *, actor) -> None: ...
    async def grant_resource(self, *, tenant_id, resource_type: str, resource_id: uuid.UUID,
                             principal: PrincipalRef, permission: str, actor) -> ResourceGrant: ...
    async def revoke_grant(self, grant: ResourceGrant, *, actor) -> None: ...
    async def transfer_resource(self, resource, *, to_org=None, to_team=None,
                                revoke_grants: bool = False, actor) -> None: ...
    async def move_team(self, team: Team, *, to_org: Organization, actor) -> None: ...
```

All methods: run under the lifecycle advisory lock where they mutate lifecycle,
validate every polymorphic reference (I11/L14), enforce scope and namespace
compatibility (L16), write mandatory audit events, invalidate the request-scoped
`AuthzCache` after any authorization-state change (section 10), and never expose
a raw control-plane session.

Relocation record and phases:

```python
class RelocationPhase(StrEnum):
    PENDING = "pending"; PROVISIONING = "provisioning"; COPYING = "copying"
    VERIFYING = "verifying"; FLIPPING = "flipping"
    POST_FLIP_VERIFICATION = "post_flip_verification"
    COMPLETED = "completed"; FAILED = "failed"; ROLLED_BACK = "rolled_back"

@dataclass(frozen=True, slots=True)
class TenantRelocation:
    tenant_id: uuid.UUID; id: uuid.UUID
    from_strategy: StrategyName; from_target_handle: str; from_region: str | None
    to_strategy: StrategyName; to_target_handle: str; to_region: str | None
    phase: RelocationPhase
    started_at: datetime; verified_at: datetime | None
    flipped_at: datetime | None; completed_at: datetime | None
    error: str | None
```

`TenantPlacement` stays the single authoritative placement; `relocate()` only
updates it inside the `FLIPPING` transaction, and the old target is retained
until `COMPLETED` (section 6 of `05-tenant-lifecycle.md`). Phase transitions are
validated against the table in `02` section 3.3.1; invalid moves raise
`RelocationPhaseError`, and only `failed`/`rolled_back → pending` (explicit
retry) or the forward edges are allowed.

Serving gate: `assert_servable()` is the one predicate used by the router,
middleware, and migration runner, and it includes relocation state —
`active AND migration success AND current = desired AND relocation permits
serving`. Relocation permits serving in `pending` and `provisioning`, and
blocks it in `copying`, `verifying`, `flipping`, and
`post_flip_verification`. No adapter reimplements this predicate.

## 9. Authentication

```python
class RequestInfo(NamedTuple):
    headers: Mapping[str, str]; query: Mapping[str, str]; path: str; host: str

class Authenticator(Protocol):
    async def authenticate(self, request: RequestInfo) -> Principal | None: ...

class OidcAuthenticator(Authenticator):
    # JwksCache (TTL + rotation), TokenVerifier (iss/aud/alg/exp/skew),
    # ClaimMapper → (issuer, subject, email, email_verified),
    # UserLinker: IdentityLink match → email link (only if IdP email_trusted) → create

class ApiKeyAuthenticator(Authenticator):
    # KeyParser("prefix.keyid.secret") → lookup by key_prefix (control plane)
    # → Argon2id.verify → ServiceAccount/tenant status → Principal(scopes=...)

class CompositeAuthenticator(Authenticator):
    # first authenticator that returns a Principal wins; all failures audited
```

## 10. Authorization

```python
@dataclass(frozen=True, slots=True)
class Permission:
    code: str; namespace: str; allowed_scopes: frozenset[ScopeType]; description: str

class PermissionCatalog:
    def register(self, permission: Permission) -> None: ...   # duplicate → error
    def validate(self, code: str) -> Permission: ...          # UnknownPermission
    def all(self) -> Collection[Permission]: ...

@dataclass(frozen=True, slots=True)
class ResourceTypeDefinition:
    resource_type: str; model: type; tenant_owned: bool
    tenant_routed: bool; permission_namespace: str
    def __post_init__(self) -> None: ...  # tenant_routed ⇒ tenant_owned

class ScopeRef(NamedTuple):
    type: ScopeType; id: uuid.UUID | None

class ScopeResolver:
    async def chain(self, session: TenantSession, target: ScopeRef) -> tuple[ScopeRef, ...]: ...

class Decision(NamedTuple):
    allowed: bool; reason: str; matched: tuple[MatchedRule, ...]

class PolicyDecisionPoint(Protocol):
    async def evaluate(self, principal: Principal, permission: str,
                       target: ScopeRef, ctx: TenantContext) -> Decision: ...

class DefaultPDP(PolicyDecisionPoint):
    # Precedence chain → bindings → role permissions → grants → API-key scopes
    # Namespace/scope validation for binding/grants lives in AccessControl.
    # Memoization goes through AuthzCache.

class AuthzCache:
    """Request-scoped only. AccessControl calls invalidate() before any
    authorization-state mutation (role, permission, binding, grant, membership,
    ownership transfer, team move), so no stale allow can be reused. A rolled
    back mutation leaves the cache invalidated — fail-safe, no restoration."""
    def invalidate(self) -> None: ...

class Enforcer:
    async def require(self, permission: str, target: ScopeRef) -> Decision: ...  # raises AuthorizationError
```

Declaration and explicit use:

```python
@requires("invoice:approve", target=ResourceScope("invoice"))
async def approve(...): ...

decision = await authorize("invoice:approve", target=ScopeRef.resource("invoice", id))
```

Enforcement points are exactly two: the guard decorator (HTTP) and `authorize`
(jobs/CLI/services). Both call the same `Enforcer`.

## 11. Request pipeline (tenancy)

Pure-ASGI `TenantMiddleware` per request:

```
authenticate (CompositeAuthenticator)      → Principal | 401
resolve tenant (ResolverChain)             → TenantRef   | 404
verify entitlement (AccessControl)         → 404 non-entitled
ContextFactory.for_principal(...)          → TenantContext
install contextvar (fail-closed)           → token
handle request (app)
finally: reset contextvar
```

- Middleware is pure ASGI (no BaseHTTPMiddleware buffering); exception handlers
  map `JdlibError` to HTTP per the fixed table.
- `@tenant_job` wraps worker functions: accepts an envelope, calls
  `ContextPropagator.reconstruct`, installs/clears the context.
- Queue payloads carry envelope fields explicitly; nothing relies on contextvar
  survival.

## 12. Audit

```python
class AuditRecorder:
    async def record(self, *, action: str, target: ScopeRef | None,
                     metadata: Mapping[str, object] | None = None,
                     mandatory: bool = True) -> None: ...
```

- Tenant-routed mutations: `AuditEvent` inserted **in the session transaction**
  by repositories with `audited=True` (or services calling `record`); failure
  rolls the business mutation back too.
- Platform events: `DatabaseAuditSink` via control-plane connection; called even
  when no tenant context exists.
- Transaction ordering is frozen in `05-tenant-lifecycle.md` section 5.1:
  same-transaction on-plane; cross-plane mandatory platform audit is durably
  committed **before** the tenant transaction applies the mutation (a durable
  outbox is the documented future upgrade). No path commits business state and
  then fails a required audit.
- Mandatory events fail the operation closed when no sink can durably record
  them; best-effort events buffer and log.
- `AuditSink` is a port; `CompositeAuditSink` fans out to SIEM adapters in a
  later version.

## 13. Migrations

```python
class MigrationRunner:
    def __init__(self, config: TenancyConfig, strategies: Mapping[...]) -> None: ...
    async def upgrade_control(self, revision: str = "head") -> None: ...
    async def upgrade_tenant(self, tenant: Tenant, revision: str = "head") -> MigrationState: ...
    async def upgrade_all(self, *, concurrency: int = 4) -> Sequence[MigrationState]: ...

def emit_rls_policies(metadata: MetaData, *, only: Collection[str] | None = None) -> None: ...
```

Consumer Alembic env templates import `TenantBase` metadata and call
`emit_rls_policies` after table creation; `ResourceTypeRegistry` supplies the
routed-table set.

## 14. Integrations

FastAPI (`integrations/fastapi.py`):

```python
def install(app: FastAPI, container: JdlibContainer) -> None: ...  # middleware + handlers

async def get_context() -> TenantContext: ...          # dependency
async def get_uow() -> AsyncIterator[UnitOfWork]: ...  # one UoW per request
def require(permission: str, target_factory: Callable[..., ScopeRef] = tenant_target) -> ...: ...
```

CLI (`integrations/cli.py`, typer): `tenant create|provision|suspend|resume|
archive|deprovision|migrate|relocate`, `db upgrade-control|upgrade-tenants`,
`lint schema`, `operator grant`. Every command builds a system/operator context
and audits.

## 15. Testing design

- Unit tests need no database: `FakePDP`, `InMemoryAuditSink`, `StaticResolver`,
  `MemorySecretProvider`, frozen clock.
- Integration tests: one parametrized fixture
  (`strategy_matrix`) yields `(strategy, rls_on)` combinations against
  testcontainers Postgres; the same behavioral tests run everywhere.
- `jdlib.testing` exports `tenants`, `tenant_context`, `strategy_matrix`,
  `assert_isolation`, `assert_cross_tenant_rejected`, `assert_rls_matrix`.
- Lint tests run L1–L19 against the consumer's combined metadata.
- TDD is the implementation workflow: each phase's gate tests are written
  before the phase's code.

## 16. Cross-cutting rules

- Public API is exactly the re-exports in `jdlib/__init__.py`; everything else
  is internal-by-convention with an underscore or module privacy.
- Strict typing (`pyright`/`mypy --strict` for `src/jdlib`); public functions
  carry complete annotations; no `Any` in public signatures.
- Immutable value objects for context/principals/decisions; ORM models are
  mutable by nature and never leave the persistence boundary as DTOs —
  services return explicit DTOs where needed.
- Logging: stdlib `logging` with structured `extra` fields (`tenant_id`,
  `request_id`, `correlation_id`, `action`); no PII, no tokens, no key
  material.
- Errors: only `JdlibError` subclasses cross module boundaries; adapters map
  driver exceptions (`IntegrityError`, `OperationalError`) to framework errors
  at the persistence boundary.
- No silent fallbacks anywhere: missing context, missing placement, missing
  handle, missing audit sink, and missing RLS policy all fail closed.

## 17. Build order (maps to foundation design phase table)

| Phase | Files |
|---|---|
| 0 | doc sign-off; scaffolding (`pyproject`, CI, lint config) |
| 1 | `control/base.py`, `control/models.py` (incl. `TenantRelocation`), `models/*`, baseline migrations |
| 2 | `context.py`, `errors.py`, `config.py`, `tenancy/resolution.py`, `tenancy/middleware.py` |
| 3 | `persistence/events.py`, `session.py`, `rawsql.py`, `uow.py`, `repository.py`, `router.py`, `strategies/base.py`, lint tests |
| 4 | `strategies/shared.py`, control `registry.py` provisioning path, first end-to-end |
| 5 | `authz/*` (incl. `cache.py`), `control/access.py`, registry relocation operations, `authn/base.py` (static principal provider for tests) |
| 6 | `authn/oidc.py`, `authn/apikey.py`, `authn/composite.py` |
| 7 | `strategies/schema.py`, migration distribution |
| 8 | `strategies/database.py`, `SecretProvider` |
| 9 | `strategies/rls.py`, RLS tests |
| 10 | `audit/*`, `testing/*`, `integrations/*`, docs |
