# jdlib — Multi-Tenancy Foundation: Design

Date: 2026-09-21 (rev 2: incorporates external design review)
Status: Approved (design rev 2), pending implementation plan
Package: `jdlib` (Python 3.12+, async-first)
Detail contracts: `docs/jdlib/02-relational-schema.md`, `03-isolation-invariants.md`,
`04-authorization-model.md`, `05-tenant-lifecycle.md`, `06-strategy-matrix.md`

## 1. Purpose

A reusable, production-grade multi-tenancy foundation for SaaS products, services,
and internal platforms. It provides tenant management, tenant context and
resolution, authentication, scoped RBAC authorization, tenant-aware data access,
isolation enforcement, schema/database routing, resource ownership, cross-tenant
access prevention, tenant-aware sessions and transactions, auditing, and
configuration for multiple isolation strategies.

The central property: **tenancy is an infrastructure concern**. The same
application code and the same logical data model run under shared-schema,
schema-per-tenant, or database-per-tenant deployments — or a mix — with no
domain-model changes. Strategy is deployment configuration, not business logic.

### 1.1 Design principles

1. **Single-tenant is multi-tenant with one tenant.** A `Tenant` row is seeded at
   install; every tenant-scoped table carries `tenant_id` from day one. Turning
   multi-tenancy on adds routing and policy, never schema restructuring.
2. **Fail closed.** No tenant context means no tenant data access. No matching
   identity means no request. No allow rule means deny. No active states in the
   precedence chain means deny.
3. **One enforcement point per concern.** Tenant scoping lives in the session
   layer; authorization lives in one evaluator; strategy lives behind one
   interface; lifecycle transitions live in one registry service.
4. **Control plane is not tenant data.** Identity, access control, and deployment
   metadata live in a single platform control plane. It is never routed, never
   moved per tenant, and never foreign-keyed from tenant data.
5. **Composite tenant identity.** Tenant-scoped rows are identified by
   `(tenant_id, id)`; tenant-scoped foreign keys include `tenant_id`, making
   cross-tenant references unrepresentable at the database level.
6. **Additive, allow-only authorization.** Effective permissions are the union of
   applicable bindings and grants; there are no deny rules in v1.
7. **Uniform code paths beat micro-optimization.** `tenant_id` predicates and
   stamps are applied in every strategy, even where a physical boundary makes
   them redundant.
8. **YAGNI with documented seams.** Billing, notifications, policy engines,
   relocation tooling, and sync execution are explicit extension points.

### 1.2 Decisions

| Decision | Choice |
|---|---|
| Persistence foundation | SQLAlchemy 2.0 + Pydantic v2, Postgres-first, repository/UoW boundaries |
| Identity model | Global `User` + `Membership`, both in the control plane |
| Plane split | Control plane: Tenant/placement/migration state, identity, access control. Tenant plane: Organization, Team, TenantSetting, audit, app resources |
| Internal hierarchy | Tenant → Organization(s) (tree) → Team (flat per org) → Resource |
| Authorization | Scoped RBAC + per-resource grants (allow-only) |
| Strategy support | Config-driven adapters, hybrid placement capable; applies to tenant plane only |
| Isolation enforcement | App-layer scoping mandatory + optional Postgres RLS |
| Authentication | External IdP (OIDC/JWT) + API keys; no password storage |
| Principal kinds | `user`, `service_account` only; platform operators are code-mapped levels |
| Email policy | `email` nullable, normalized, partially unique; identity authority is `(issuer, subject)`; linking by email only from `email_trusted` IdPs |
| V1 scope | Async-first, all three strategies, Postgres integration matrix |
| Architecture | Infrastructure-injected tenancy (contextvars) + optional RLS |

## 2. Plane model

### 2.1 Planes

| Plane | Lifetime and routing | Contents |
|---|---|---|
| **Control plane** | One physical location; never moved, never strategy-routed; its own schema/database and `MetaData` | `Tenant`, `TenantPlacement`, `TenantMigrationState`, `User`, `IdentityLink`, `PlatformOperator`, `ServiceAccount`, `ApiKey`, `Membership`, `Invitation`, `Role`, `RolePermission`, `RoleBinding`, `ResourceGrant`, `PlatformAuditEvent` |
| **Tenant plane** | Routed per tenant by the isolation strategy | `Organization`, `Team`, `TenantSetting`, `AuditEvent` |
| **Application plane** | Same routing as tenant plane; owned by consuming applications | Concrete resources (`Invoice`, `Project`, …) built on `TenantOwned` mixins |

### 2.2 Plane interaction rules

1. **No foreign keys cross planes, ever.** `Membership.user_id → User` is a real
   FK (control→control); `AuditEvent.actor_id`, `RoleBinding.scope_id`,
   `ResourceGrant.resource_id` are logical references validated by the framework.
   This is what keeps database-per-tenant possible.
2. **No tenant context is required to read control-plane data**, but only
   framework services may do so. Application code never receives a
   control-plane session.
3. **Tenant-plane access always requires an active `TenantContext`** and is
   scoped by `TenantSession`.
4. **Why access control is control-plane:** login-time tenant discovery
   ("which tenants does this user belong to"), membership verification, API-key
   lookup (which happens before tenant resolution), and role/binding evaluation
   must all work before or across tenant boundaries. Per-tenant access-control
   tables cannot provide this without a mirrored directory.
5. **Scope references are polymorphic by design** (`scope_type` + `scope_id`),
   as accepted in the design review; existence and tenant consistency are
   enforced by the access-control service, not by FKs.
6. **Two session types:** `ControlPlaneSession` (framework-internal only,
   explicit filtering in service code) and `TenantSession` (auto-scoped,
   rule-enforced, provided to application code).

## 3. Control-plane model

| Entity | Why it exists | Identity / constraints |
|---|---|---|
| `Tenant` | Customer/account and isolation boundary. Single-tenant mode seeds exactly one. | `PK(id)`, `UNIQUE(slug)`, self-FK `parent_tenant_id` (reserved: delegation only, never data access) |
| `TenantPlacement` | Where this tenant's data lives. The strategy switch. | `PK(tenant_id)`, `strategy ∈ {shared, schema, database}`, `target_handle` (opaque; resolved via secret provider), `region` |
| `TenantMigrationState` | Per-tenant migration position and health. | `PK(tenant_id)`, `current_version`, `desired_version`, `status` |
| `User` | One row per human; global so one login serves many tenants. | `PK(id)`, `email` nullable/normalized/partial-unique |
| `IdentityLink` | Maps external IdP subject to user; one user may have several. | `PK(id)`, `UNIQUE(issuer, subject)`, `FK(user_id)` |
| `PlatformOperator` | Platform staff, outside all tenants. | `PK(user_id)`, `level ∈ {support, operator, admin}`; capabilities mapped in code |
| `ServiceAccount` | Tenant-owned machine principal referenced by bindings and keys. | `PK(tenant_id, id)`, `UNIQUE(tenant_id, name)` |
| `ApiKey` | Machine credential; verified before tenant resolution. | `PK(tenant_id, id)`, `UNIQUE(key_prefix)`, Argon2id `key_hash`, pinned `(tenant_id, service_account_id)` |
| `Membership` | User joins tenant; tenant-scoped profile and status. | `PK(tenant_id, id)`, `UNIQUE(tenant_id, user_id)`, `FK(user_id)` |
| `Invitation` | Onboarding into tenant/org/team with a role. | `PK(tenant_id, id)`, single-use hashed token, `status ∈ {pending, accepted, expired, revoked}` |
| `Role` | Named permission bundle; built-ins seeded per tenant, custom allowed. | `PK(tenant_id, id)`, `UNIQUE(tenant_id, name)` |
| `RolePermission` | Relational composition of a role. | `PK(tenant_id, role_id, permission_code)`, `FK` to `Role`; code validated against catalog |
| `RoleBinding` | The single authorization link: role → principal at scope. | `PK(tenant_id, id)`, `UNIQUE(tenant_id, role_id, principal_type, principal_id, scope_type, scope_id)`, `principal_type ∈ {user, service_account}`, `scope_type ∈ {tenant, org, team}` |
| `ResourceGrant` | Per-resource exception, allow-only. | `PK(tenant_id, id)`, `UNIQUE(tenant_id, resource_type, resource_id, principal_type, principal_id, permission_code)` |
| `PlatformAuditEvent` | Security/operational audit for pre-transaction events. | `PK(id)`, nullable `tenant_id`, append-only |

The permission catalog itself is code (`resource:action` strings registered at
startup); no `Permission` table is needed.

## 4. Tenant-plane model

| Entity | Why it exists | Identity / constraints |
|---|---|---|
| `Organization` | Business unit tree; scope for authorization. | `PK(tenant_id, id)`, self-FK `(tenant_id, parent_organization_id)`, `UNIQUE(tenant_id, slug)` partial on soft-delete |
| `Team` | Flat collaboration/ownership unit inside one organization. | `PK(tenant_id, id)`, composite FK to organization, `UNIQUE(tenant_id, organization_id, slug)` partial |
| `TenantSetting` | Business configuration and feature flags. Not a JSON dumping ground; platform config lives on the control plane. | `PK(tenant_id, key)`, value `jsonb` |
| `AuditEvent` | Transactional audit written in the same transaction as the mutation. Actor from context, never an argument. | `PK(tenant_id, id)`, indexes on `(tenant_id, occurred_at)` and `(tenant_id, target_type, target_id)` |

Applications define resources with the mixins:

- `TenantOwned` — `tenant_id` in PK and every relationship; mandatory.
- `Timestamped` — `created_at`, `updated_at` (UTC `timestamptz`).
- `SoftDelete` — `deleted_at`; normal queries exclude deleted rows; partial
  unique indexes exclude them.
- `OwnableByOrg` / `OwnableByTeam` — optional composite ownership FKs enabling
  scope-based authorization.
- `created_by` / `updated_by` — logical `User.id` references (cross-plane).

## 5. Tenancy overlay

### 5.1 Tenant context

`TenantContext(tenant_id, strategy, principal, request_id, correlation_id,
trace_id, privileged)` in a `contextvars.ContextVar`.

- **Created only by the framework's `ContextFactory`**, which performs the full
  authoritative flow: authenticated principal → resolved tenant → membership or
  operator validation → context. The constructor is private.
- **Privileged contexts require an internal capability token** held by the
  factory (`operator` after validating `PlatformOperator`; `system` for
  provisioning/migrations; `test`). Application code cannot obtain one through
  public API; any privileged context use produces a platform audit event.
- **Fail closed:** tenant-plane access without a context raises
  `MissingTenantContext`. There is no default tenant.
- **Immutable for the session lifetime**: a session is bound to exactly one
  context; switching tenants requires a new context and session.
- Contextvars are execution state, not a security boundary; the security
  boundary is the factory flow plus session scoping.

### 5.2 Cross-boundary propagation

Every asynchronous boundary (HTTP, background task, queue message, scheduled
job, CLI, worker) is an explicit propagation boundary. The framework serializes
`TenantContextEnvelope` (`tenant_id`, `principal_type`, `principal_id`,
`request_id`, `correlation_id`, `trace_id`, `issued_at`, HMAC signature using a
configured framework secret). On the receiving side the envelope is verified
(signature + TTL), then statuses and bindings are **reloaded**, and authorization
is **re-evaluated at execution time**. Envelopes never carry permissions, and a
context object supplied by a caller is never trusted.

### 5.3 Tenant resolution

Configurable `TenantResolver` chain: JWT claim (`tid`) → subdomain → path prefix
→ header → API-key binding. Resolution is identification only; the factory then
verifies Membership or operator status. Unknown and unauthorized tenants both
return 404 to non-operators; reasons go to logs and audit only.

### 5.4 Ownership and hierarchy

| Relationship | Semantics | Enforcement |
|---|---|---|
| Platform → Tenant | Lifecycle ownership | Operators with `platform.tenant.manage` |
| Tenant → Org → Team → Resource | Authorization inheritance downward, additive | Evaluated against current hierarchy (04) |
| Tenant → Tenant (`parent_tenant_id`) | Delegated administration/billing only | Never grants data access; no query may implement `tenant_id = X OR parent_tenant_id = X` |

### 5.5 Membership lifecycle

Invitation (pending) → acceptance by an authenticated principal whose verified
email matches, or whose `(issuer, subject)` is already linked → `Membership` +
initial `RoleBinding` created atomically in the control plane → audit event.
Suspension at any level denies access without deleting data (precedence chain in
04). Invitation tokens are single-use, short-lived, cryptographically random,
stored hashed, and grant nothing until acceptance.

## 6. Isolation architecture

### 6.1 Strategy interface

```python
class IsolationStrategy(Protocol):
    name: str
    capabilities: StrategyCapabilities
    def session(self, tenant) -> TenantSession
    async def provision(self, tenant) -> None
    async def migrate(self, tenant) -> None
    async def deprovision(self, tenant, mode) -> None
```

Three adapters: `shared` (one schema + `tenant_id` predicate + optional RLS),
`schema` (one database, N schemas, `search_path` set by the framework from the
registry-validated identifier), `database` (per-tenant DSN resolved from an
opaque `target_handle` through the secret provider). Hybrid is per-tenant
placement, never a fourth strategy.

### 6.2 Uniform model and composite identity

One `MetaData` per plane, one migration chain. In every strategy:
`PK(tenant_id, id)` for tenant-scoped tables, composite FKs between them, and a
metadata lint test that fails if any tenant-scoped FK omits `tenant_id`. In
database-per-tenant mode the physical boundary is additional; logical
constraints remain, so code paths and tests are identical. Details and exact
table contracts: `02-relational-schema.md`.

### 6.3 Scoping enforcement

`TenantSession` (the only session application code sees):

- **Reads:** `with_loader_criteria` adds `tenant_id = ctx.tenant_id` to every
  tenant-scoped ORM statement, including relationship loads.
- **Writes:** `before_flush` stamps `tenant_id`, maintains timestamps and
  soft-delete state, and validates composite references; violations raise
  `CrossTenantReferenceError`.
- **Bulk operations:** dedicated scoped helpers (`update_where`, `delete_where`)
  inject the predicate. Arbitrary `session.execute(update/delete/text)` on
  tenant-scoped models is outside the supported API; raw SQL must go through
  `TenantSession.raw_sql(...)`, which requires the statement to reference the
  tenant boundary or a privileged context, and is audited.
- **Control plane:** `ControlPlaneSession` is framework-internal; service code
  applies explicit tenant filters, and cross-tenant paths require operator or
  system authority. Application code never holds one.

### 6.4 Migrations, provisioning, RLS

Programmatic Alembic runner distributes the same chain per target; each target
tracks `alembic_version` locally and the registry tracks
`TenantMigrationState` (`pending → running → success | failed | blocked`). A
tenant becomes `active` only after create → migrate → seed → health check →
invariants pass. Provisioning, migration, seeding, and deprovisioning are
idempotent or safely resumable; lifecycle operations are serialized per tenant
with a Postgres advisory lock. RLS is opt-in, shared-schema only: `FORCE ROW
LEVEL SECURITY`, `NOBYPASSRLS` runtime role, `SET LOCAL app.tenant_id` per
transaction, and pool-leakage tests. Details: `05-tenant-lifecycle.md`,
`06-strategy-matrix.md`.

### 6.5 Strategy-independent vs strategy-specific

| Strategy-independent | Strategy-specific |
|---|---|
| Domain models, mixins, composite identity | Pool management and routing |
| `TenantContext`, resolution, `TenantSession` API | DDL, provisioning, migration distribution |
| AuthN/AuthZ, roles, PDP, auditing | RLS emission and session setting |
| Application services and business logic | Placement decisions, deprovision mode |

## 7. Authentication and authorization

### 7.1 Authentication

- **OIDC/JWT:** JWKS with rotation-aware cache; issuer/audience/algorithm/clock
  skew config. Login linking algorithm: `(issuer, subject)` match → existing
  user; else if the IdP is `email_trusted` and the verified email matches an
  existing user → link; else create a user. No unverified email is ever trusted;
  no silent auto-provisioning outside this algorithm.
- **API keys:** `prefix.keyid.secret`; Argon2id hash at rest; prefix lookup in
  the control plane (works before tenant resolution); optional narrowing scopes;
  `last_used_at`; pinned to one tenant and service account; revocable.
- The package verifies credentials; it never issues passwords or sessions.

### 7.2 Authorization

One evaluator (`PDP`), one traversal algorithm, additive and allow-only:

```
authenticate → Principal (user | service_account | platform operator)
principal + tenant must be active → Membership active (or operator capability)
effective_permissions(principal, target) =
    bindings at target scope and its ancestors (team → org → tenant)
  ∪ resource grants for that exact resource
```

Precedence chain (all must hold): `Principal status → Tenant status →
Membership status → RoleBinding validity → Permission granted`. Exact algorithm,
anti-escalation rule, ownership transfer semantics, and the role × action matrix:
`04-authorization-model.md`.

Platform operator levels are code-mapped capabilities
(`support/operator/admin`), are never a blanket bypass, and tenant data access
by an operator is a separate, time-boxed, audited capability distinct from
tenant administration.

## 8. Package architecture

```
src/jdlib/
├── config.py             # TenancyConfig (pydantic-settings)
├── context.py            # TenantContext, ContextFactory, envelope, fail-closed accessors
├── errors.py             # exception hierarchy
├── control/              # platform control plane (own MetaData, never routed)
│   ├── models.py         # Tenant, TenantPlacement, TenantMigrationState, User, IdentityLink,
│   │                     #   PlatformOperator, ServiceAccount, ApiKey, Membership, Role,
│   │                     #   RolePermission, RoleBinding, ResourceGrant, Invitation, audit
│   ├── session.py        # ControlPlaneSession (framework-internal)
│   ├── registry.py       # TenantRegistry: lifecycle, locks, migration state
│   └── access.py         # AccessControl: invite, bind, grant, revoke, transfer ownership
├── models/               # tenant plane (routed)
│   ├── base.py           # DeclarativeBase + mixins (TenantOwned, Timestamped, SoftDelete, …)
│   ├── org.py            # Organization, Team
│   ├── settings.py       # TenantSetting
│   └── audit.py          # AuditEvent
├── authn/                # Authenticator protocol · oidc.py · apikey.py
├── authz/                # permissions.py · scopes.py · pdp.py · guards.py
├── tenancy/              # resolution.py · middleware.py (ASGI, job/CLI decorators)
├── persistence/
│   ├── session.py        # TenantSession: scoping, stamping, validation, raw_sql
│   ├── router.py         # SessionRouter: target resolution, pool cache and caps
│   ├── uow.py            # UnitOfWork
│   ├── repository.py     # TenantRepository base
│   └── strategies/       # base.py, shared.py, schema.py, database.py, rls.py
├── audit/                # AuditSink protocol + control/tenant sinks
├── migrations/           # programmatic Alembic runner + template env
├── testing/              # pytest fixtures, strategy matrix, isolation assertion kit
└── integrations/         # fastapi.py, cli.py (optional extras)
```

Dependency direction: `config → errors → context → {control, models} → authz →
persistence → authn → tenancy → integrations`. `control` and `models` never
import `persistence`; applications import `models`, the persistence API,
`authz` guards, `context`, and framework services — never a concrete strategy.

Public API: `TenancyConfig`, `TenantContext`, `current_tenant`,
`current_principal`, `UnitOfWork`, `TenantRepository`, `requires`, `authorize`,
`TenantRegistry`, `AccessControl`.

Extension points: `IsolationStrategy`, `TenantResolver`, `Authenticator`,
`PolicyDecisionPoint`, `AuditSink`, `RoleTemplateProvider`,
`PermissionProvider`, `TenantLifecycleHook`, ORM mixins. Dependencies:
SQLAlchemy 2.0, Pydantic v2 + pydantic-settings, Alembic, PyJWT + httpx,
argon2-cffi; extras `[fastapi]`, `[postgres]`, `[cli]`.

## 9. Errors, auditing, external state

Exception hierarchy (one root): `MissingTenantContext`;
`TenantNotFound`/`TenantAccessDenied`/`TenantSuspended`; `CrossTenantReferenceError`;
`AuthenticationError` (`InvalidToken`, `ExpiredToken`, `UnknownPrincipal`);
`AuthorizationError` (`PermissionDenied`, `RoleEscalationBlocked`);
`StrategyCapabilityError`; `ProvisioningError`/`MigrationError`. HTTP mapping:
401 / 403 / 404 / 423 / 409 as before.

Audit splits into **platform audit** (authn failures, resolution failures,
privileged use, operator actions, lifecycle and migration events; written via
`AuditSink`, may precede any transaction) and **tenant transactional audit**
(same transaction as the mutation; actor from context). Both are append-only;
runtime roles hold `INSERT`/`SELECT` only; retention/export is an `AuditSink`
extension.

External state (caches, queues, object storage, search/vector stores) is never
allowed to cross tenants: framework-provided `scoped_key(prefix, *parts)`
produces `{tenant_id}:{...}` keys, events carry the tenant envelope, and the
convention is documented as an invariant (I8).

## 10. Testing strategy

- Unit: context factory and fail-closed behavior, envelope verification,
  resolver chain, catalog validation, PDP truth tables, precedence chain,
  scoping/stamping/composite validation, anti-escalation.
- Integration matrix (dockerized Postgres): `{shared, schema, database} × {rls
  on, off}` executing the same behavioral suite — the proof of
  strategy-independence. Includes connection-pool tenant-leakage tests, bulk-op
  coverage, relationship-loading coverage, and migration-state failure tests.
- `jdlib.testing`: fixtures for consumers to assert I1–I10 against their own
  models under each deployed strategy.

## 11. Out of scope for v1

Password auth, MFA, reset flows; billing/quota/usage and `Subscription`; email
delivery and notification templates; file storage; tenant self-service admin UI;
automated tenant relocation; external policy engines; deny rules; arbitrary
resource trees; multi-region routing; sync SQLAlchemy execution. Each has a
documented seam.

## 12. Implementation phases

| Phase | Delivers | Gate |
|---|---|---|
| 0 | Design contracts (`docs/jdlib/02`–`06`) and revision of this spec | review sign-off |
| 1 | Control-plane and tenant-plane models, mixins, baseline migrations, metadata lint | schema tests; single-tenant usable |
| 2 | `ContextFactory`, fail-closed context, envelope, resolution chain | context and envelope tests |
| 3 | `TenantSession` scoping/stamping/composite validation, router, UoW, repository | isolation unit tests |
| 4 | Shared strategy end-to-end | first working deployment |
| 5 | Authorization: catalog, PDP, guards, `AccessControl`, membership/roles | PDP truth tables; authz matrix |
| 6 | Authentication adapters: OIDC + API keys | auth matrix; linking algorithm tests |
| 7 | Schema-per-tenant adapter, provisioning, migration distribution | strategy matrix: schema |
| 8 | Database-per-tenant adapter, secret-provider handles | strategy matrix: database |
| 9 | RLS adapter and pool-safety tests | strategy matrix: shared × RLS |
| 10 | Audit sinks, `jdlib.testing` kit, FastAPI/CLI integrations, docs | consumer acceptance test |
