# jdlib — Multi-Tenancy Foundation: Design

Date: 2026-09-21
Status: Approved (design), pending implementation plan
Package: `jdlib` (Python 3.12+, async-first)

## 1. Purpose

A reusable, production-grade multi-tenancy foundation that different applications
(SaaS products, services, internal platforms) can build on. It provides tenant
management, tenant context and resolution, authentication, scoped RBAC
authorization, tenant-aware data access, data isolation, schema/database routing,
resource ownership, cross-tenant access prevention, tenant-aware sessions and
transactions, auditing, and configuration for multiple isolation strategies.

The central property: **tenancy is an infrastructure concern**. The same
application code and the same logical data model run under shared-schema,
schema-per-tenant, or database-per-tenant deployments — or a mix — with no
domain-model changes. Strategy is deployment configuration, not business logic.

### 1.1 Design principles

1. **Single-tenant is multi-tenant with one tenant.** A `Tenant` row is seeded at
   install and every tenant-owned table carries `tenant_id` from day one. Turning
   multi-tenancy on adds routing and policy, never schema restructuring.
2. **Fail closed.** No tenant context means no tenant-owned data access. No
   matching identity means no request. No allow rule means deny.
3. **One enforcement point per concern.** Tenant scoping lives in the session
   layer; authorization lives in one evaluator; strategy lives behind one
   interface. Application code cannot forget a filter it never writes.
4. **Additive, allow-only authorization.** Effective permissions are the union of
   applicable bindings and grants; there are no deny rules in v1.
5. **Uniform code paths beat micro-optimization.** `tenant_id` predicates and
   stamps are applied in every strategy, even where a physical boundary makes
   them redundant, so behavior is identical and auditable everywhere.
6. **YAGNI with documented seams.** Billing, notifications, policy engines,
   relocation tooling, and sync execution are explicit extension points, not v1
   code.

### 1.2 Decisions already made

| Decision | Choice |
|---|---|
| Persistence foundation | SQLAlchemy 2.0 + Pydantic v2, Postgres-first, repository/UoW boundaries |
| Identity model | Global `User` + `Membership` per tenant |
| Internal hierarchy | Tenant → Organization(s) → Team → Resource |
| Authorization | Scoped RBAC + per-resource ACL (allow-only) |
| Strategy support | Config-driven adapters, hybrid placement capable |
| Isolation enforcement | App-layer scoping mandatory + optional Postgres RLS |
| Authentication | External IdP (OIDC/JWT) + API keys; no password storage |
| V1 scope | Async-first, all three strategies, Postgres integration matrix |
| Architecture | Infrastructure-injected tenancy (contextvars) + optional RLS |

## 2. Canonical single-tenant model

The model is defined once. Entities split into two planes.

### 2.1 Global plane (tenant-independent)

Identity outlives any tenant; these tables never carry `tenant_id`.

| Entity | Why it exists | Key fields / relations |
|---|---|---|
| `User` | One row per human. Global so one person can belong to several tenants with one login. | `id`, `email` (unique), `display_name`, `status`, `locale`, timestamps |
| `IdentityLink` | Authentication is external; maps an IdP subject to a user. One user may have several links (e.g. Google + Entra). | `issuer`, `subject`, `user_id`; unique `(issuer, subject)` |
| `Permission` | Not a table. A code-defined catalog of `resource:action` strings (`invoice:approve`). Grants reference it; unknown names fail at startup. | constants + registration API |
| `PlatformOperator` | Platform staff, deliberately outside all tenants. | `user_id`, `level` |

### 2.2 Tenant plane (tenant-specific)

Everything that can behave differently per customer carries `tenant_id`.

| Entity | Why it exists | Key fields / relations |
|---|---|---|
| `Tenant` | The customer/account and the isolation boundary. In single-tenant mode exactly one seeded row. Stored in the platform-owned registry. | `id` (UUIDv7), `slug` (unique), `name`, `status`, `placement`, `parent_tenant_id` (reserved), timestamps |
| `Organization` | Business unit / department / subsidiary. Optional tree. | `tenant_id`, `parent_organization_id`, `name` |
| `Team` | Collaboration and ownership unit where resources live; groups people without inventing permissions. | `tenant_id`, `organization_id`, `name` |
| `Membership` | A global user joins a tenant. Tenant-scoped profile/status lives here, not on `User`. | `tenant_id`, `user_id`, `status`, `joined_at`; unique `(tenant_id, user_id)` |
| `Role` | Named permission bundle. Built-in templates seeded per tenant (owner/admin/member/viewer) plus custom roles. | `tenant_id`, `name`, `permissions[]` (catalog-validated) |
| `RoleBinding` | The single authorization link: role granted to a principal at a scope. "Team member" is a binding with `scope=team`. | `tenant_id`, `role_id`, `principal_type`, `principal_id`, `scope_type` (`tenant|org|team`), `scope_id` |
| `Resource` (abstract) | Framework provides mixins; applications define concrete tables (`Invoice`, `Project`, …). | `tenant_id` mandatory; optional `organization_id`, `team_id`; `created_by`, `updated_by` |
| `ResourceGrant` | Per-resource ACL for sharing beyond scope defaults. Allow-only, additive. | `tenant_id`, `resource_type`, `resource_id`, `principal_type`, `principal_id`, `permission` |
| `Invitation` | Onboarding: invite email → user joins tenant/org/team with a role. | `tenant_id`, `email`, `scope_type`, `scope_id`, `role_id`, `token_hash`, `expires_at`, `invited_by` |
| `AuditEvent` | Append-only security trail. Platform events have `tenant_id = NULL` and are visible only to operators. | `tenant_id?`, `actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `metadata`, `ip`, `correlation_id`, `occurred_at` |
| `TenantSetting` | Per-tenant configuration and feature flags. | `tenant_id`, `key`, `value`; unique `(tenant_id, key)` |

### 2.3 Mixins for application models

- `TenantOwned` — adds `tenant_id` (FK to registry, indexed, immutable) and
  participates in automatic scoping/stamping. Mandatory for every app table
  holding customer data.
- `Timestamped` — `created_at`, `updated_at` maintained by session events.
- `SoftDelete` — `deleted_at`; scoped queries exclude soft-deleted rows by default.
- Ownership — optional `organization_id` / `team_id` FKs on resources that need
  hierarchy ownership. Explicit FKs, not polymorphic owners.
- `created_by` / `updated_by` reference the global `User`.

### 2.4 Relationships in one view

```
PlatformOperator ── User ── IdentityLink (issuer, subject)
                     │
                     │ Membership (status, joined_at)
                     ▼
                  Tenant ──────────────── TenantSetting
                     │  role bindings            AuditEvent (tenant or platform)
        ┌────────────┼───────────────┐
        ▼            ▼               ▼
 Organization ──▶ Team ────────▶ Resource (app-defined; tenant_id mandatory)
        │            │               │
   RoleBinding   RoleBinding     ResourceGrant (per-resource exception)
   (scope=org)   (scope=team)         ▲
        └────────── Role ──────────────┘  (Role is tenant-owned data;
                                            permissions come from the code catalog)
ServiceAccount ── ApiKey              Invitation ──▶ Membership + RoleBinding
   (tenant-owned)
```

### 2.5 Boundaries

- Identity (`User`, `IdentityLink`) is global. Everything behaviorally
  tenant-specific is tenant-owned.
- The permission **catalog** is code; role **composition** is data. Tenants can
  customize roles without redeploying; they cannot invent permissions.
- `RoleBinding` replaces parallel membership tables for tenant admins, org
  managers, and team members.
- `AuditEvent` references targets by `(type, id)` and never by FK — the audit log
  does not couple to application schemas.
- The framework owns registry, org/team, membership, roles, bindings, grants,
  invitations, audit, settings. Applications own concrete resources and workflows.

## 3. Tenancy overlay

### 3.1 Tenant entity

The registry is the only platform-owned table about customers. Its `placement`
field is the strategy switch:

```
placement = { strategy: "shared" | "schema" | "database", target: <handle> }
```

- `shared` → single database/schema, target is the default handle.
- `schema` → one database, target is the schema name.
- `database` → target is a connection handle (DSN reference).

Business tables never contain strategy hints. Placement is read by the
`SessionRouter` and the migration runner only.

Lifecycle: `provisioning → active → suspended → archived`. Status gates every
framework operation; suspension rejects all requests into the tenant without
deleting data.

`parent_tenant_id` is reserved and nullable. Its semantics are delegated
**administration, billing, and invitations only** — never data visibility across
the tenant boundary. Enforcement logic is v2; the field exists now so the schema
does not change later.

### 3.2 Tenant context

`TenantContext(tenant_id, strategy, principal, request_meta, privileged)` is held
in a `contextvars.ContextVar`.

- Set by entry points: ASGI middleware, job/worker decorator, CLI wrapper.
  Cleared in `finally`.
- **Fail closed:** any access to tenant-owned models without a context raises
  `MissingTenantContext`. There is no implicit default tenant.
- Privileged (cross-tenant) context requires a `PlatformOperator` principal, an
  explicit system context (provisioning, migrations), or a test context. All
  privileged use is audited.
- Background tasks receive an explicit snapshot of the context; context is never
  assumed to leak into new tasks.

### 3.3 Tenant resolution

A configurable chain of `TenantResolver`s runs at the request boundary:

1. JWT claim (`tid`)
2. Subdomain (`acme.app.example.com`)
3. Path prefix (`/t/{slug}/...`)
4. Header (`X-Tenant-Slug`)
5. API-key binding (service accounts are pinned to one tenant)

Resolution is identification only. The framework then verifies the principal may
act in that tenant (active `Membership`, or `PlatformOperator`) and fails with
`TenantAccessDenied`. New resolvers are registered through the interface.

### 3.4 Ownership and hierarchy

Three distinct relationships, never conflated:

| Relationship | Semantics | Enforcement |
|---|---|---|
| Platform → Tenant | Registry owns lifecycle | Platform operators only |
| Tenant → Org → Team → Resource | Intra-tenant ownership | Bindings at ancestor scope inherit downward, additively; no deny rules in v1 |
| Tenant → Tenant (`parent_tenant_id`) | Delegated administration/billing only | Never grants data access; v2 |

### 3.5 Membership lifecycle

`Invitation` → match existing global `User` by verified email or create one →
`Membership` + `RoleBinding`(s) created atomically in one transaction → audit
event. Suspension at tenant, membership, or user level narrows access without
deleting anything.

### 3.6 Cross-tenant access prevention

Three layers:

1. Resolution must match the principal's memberships or operator status.
2. Reads get automatic tenant predicates; writes are auto-stamped and validated.
   A write referencing another tenant's entity raises `CrossTenantReferenceError`
   (composite constraints in shared/schema modes, context validation in
   database-per-tenant mode).
3. Optional Postgres RLS as a database-enforced wall (shared-schema only).

Unknown tenant and known-but-unauthorized tenant both return 404 to
non-operators; the real reason goes only to logs and audit.

## 4. Isolation architecture

### 4.1 Strategy interface

```python
class IsolationStrategy(Protocol):
    name: str                                # "shared" | "schema" | "database"
    capabilities: StrategyCapabilities       # supports_rls, supports_ddl, ...
    def session(self, tenant) -> TenantSession
    async def provision(self, tenant) -> None
    async def migrate(self, tenant) -> None
    async def deprovision(self, tenant, mode) -> None   # archive | drop | soft
```

### 4.2 Adapters

| | Shared schema | Schema per tenant | Database per tenant |
|---|---|---|---|
| Physical layout | one schema, `tenant_id` predicate | one database, N schemas | N databases |
| `session()` | shared engine, context set | engine + `search_path` | connection routed to tenant DSN |
| `provision()` | registry row + seed | `CREATE SCHEMA` + DDL + seed | `CREATE DATABASE` (+ template) + DDL + seed |
| `migrate()` | once | per schema | per database |
| Isolation | logical (app scoping; optional RLS) | schema boundary | physical boundary |
| Ceiling | noisy neighbors, shared pool | shared server resources | ops cost per tenant |
| Best for | many small tenants, self-serve | mid-market, moderate count | enterprise, compliance, residency |

### 4.3 Routing

```
request → resolve tenant → TenantContext → SessionRouter
                                              │
                              registry.placement{strategy,target}
                                              │
              ┌───────────────┬───────────────┴───────────────┐
              ▼               ▼                               ▼
        shared engine    engine + search_path          tenant DSN pool
        (tenant_id pred) (schema-qualified metadata)   (tenant_id predicate
                                                         still applied)
```

`SessionRouter` caches connection pools per target, creates them lazily, and
enforces a maximum-pool guard so hybrid deployments cannot exhaust connections.
Placement is per-tenant data; moving a tenant is an operational procedure
(`provision` → copy → flip registry record → deprovision old), never an
application change.

### 4.4 Uniform model across strategies

One `MetaData`, one migration chain. Tenant-owned tables carry `tenant_id` in all
modes. Composite constraints `(tenant_id, id)` and composite FKs make
cross-tenant references impossible in shared and schema modes; the physical
boundary plus context validation covers database-per-tenant mode.

### 4.5 Scoping enforcement

Inside `TenantSession`:

- **Reads:** a SQLAlchemy `with_loader_criteria` session event automatically adds
  `tenant_id = ctx.tenant_id` to every tenant-owned SELECT/UPDATE/DELETE.
  Application code never writes the predicate, so it cannot be forgotten.
- **Writes:** a `before_flush` hook stamps `tenant_id` and validates that
  referenced entities belong to the same tenant; violations raise
  `CrossTenantReferenceError`.
- **Escape hatches:** only through a privileged context, and always audited.

### 4.6 Migrations and provisioning

Alembic is invoked programmatically by the migration runner, not as a developer
CLI workflow. The strategy adapter distributes the same chain: once for shared,
per schema for schema mode, per database for database mode. Version tracking
lives naturally per target (`alembic_version` in each schema/database), with
per-tenant migration status recorded in the registry.

`provision()` = create place → run migration chain → seed built-in roles and
default settings → flip status to `active` → run `TenantLifecycleHook`s.

### 4.7 Optional RLS

Shared-schema only, enabled by config. Migrations emit policies
`USING (tenant_id = current_setting('app.tenant_id')::uuid)`; each transaction
begins with `SET LOCAL app.tenant_id` under an application role with
`NOBYPASSRLS`. The integration matrix runs with RLS on and off. Requesting RLS
under a non-shared strategy raises `StrategyCapabilityError` at startup.

### 4.8 Strategy-independent vs strategy-specific

| Strategy-independent (never changes) | Strategy-specific (adapter internals) |
|---|---|
| Domain models and mixins | Connection/pool management and routing |
| `TenantContext`, resolution, `TenantSession` API | DDL, provisioning, migration distribution |
| AuthN/AuthZ, roles, PDP, audit | RLS emission and session setting |
| Application services and business logic | Placement decisions, deprovisioning mode |

## 5. Authentication and authorization integration

### 5.1 Principals

| Principal | Plane | Identity source | Bound to tenant |
|---|---|---|---|
| `User` | global | OIDC `(iss, sub)` → `IdentityLink` → `User` | via `Membership` |
| `ServiceAccount` | tenant | API key | yes, pinned |
| `PlatformOperator` | platform | OIDC + operator flag | no; privileged context |

Authorization evaluates a `Principal`; no downstream component cares which kind.

### 5.2 Authentication (verification, never issuance)

- **OIDC/JWT:** JWKS fetch with rotation-aware cache; configurable issuer,
  audience, algorithms, clock skew; claims resolve to a `User` through
  `IdentityLink`. No link and no pending invitation ⇒ deny. There is no silent
  auto-provisioning; invitations match on the verified email claim.
- **API keys:** format `prefix.keyid.secret`; only an Argon2id hash is stored;
  the prefix enables lookup; optional per-key scopes; `last_used_at` tracked;
  revocation supported; each key is pinned to one tenant and one service account.
- Browser sessions and login UI remain the host application's concern. The
  package authenticates requests; it does not mint or store user credentials.

### 5.3 Authorization

```
authenticate            →  Principal
resolve tenant          →  Tenant (claim | subdomain | path | header | key)
verify principal↔tenant →  Membership? PlatformOperator? else 404
build TenantContext     →  session, strategy, actor
authorize(permission, scope_or_resource)
   ├─ union of RoleBindings at scope and ancestors (team → org → tenant)
   ├─ plus ResourceGrants on that resource
   └─ additive, allow-only; absence of allow = deny
```

- Permission catalog is code: namespaced `resource:action`; modules register
  theirs at startup; unknown names fail fast.
- Roles are tenant-owned data composed from the catalog, so customization cannot
  escalate beyond what the code defines.
- PDP interface: `can(principal, permission, target) → Decision(allowed, reason,
  matched_rules)`. The built-in evaluator is the v1 implementation; decisions
  carry their reasoning for audit. A per-request resolution cache is invalidated
  on role or binding changes.
- Anti-escalation: a non-owner may only assign roles whose permissions they hold;
  owners are bounded by the catalog. Enforced in the evaluator, not per endpoint.
- Enforcement points: declarative `@requires("invoice:approve", scope=resource)`
  for endpoints and explicit `authorize()` for jobs and CLI — one evaluator
  behind both.
- Cross-tenant operations require `PlatformOperator` plus privileged context and
  always write a platform audit event.
- Unknown tenant and unauthorized tenant both return 404 to non-operators.

## 6. Package architecture

`src/` layout, package `jdlib`, Python 3.12+, async-first.

```
src/jdlib/
├── config.py            # TenancyConfig (pydantic-settings)
├── context.py           # TenantContext, contextvar, fail-closed accessors
├── errors.py            # exception hierarchy
├── models/
│   ├── base.py          # DeclarativeBase + mixins (TenantOwned, Timestamped, SoftDelete)
│   ├── registry.py      # Tenant, TenantPlacement, TenantSetting
│   ├── identity.py      # User, IdentityLink, ServiceAccount, ApiKey
│   ├── org.py           # Organization, Team
│   ├── access.py        # Membership, Role, RoleBinding, ResourceGrant, Invitation
│   └── audit.py         # AuditEvent
├── authn/               # Authenticator protocol, oidc.py, apikey.py
├── authz/
│   ├── permissions.py   # code catalog + module registration
│   ├── scopes.py        # scope lookup + ancestor inheritance
│   ├── pdp.py           # PolicyDecisionPoint protocol + built-in evaluator + cache
│   └── guards.py        # requires() / authorize()
├── tenancy/
│   ├── resolution.py    # resolver chain + built-ins
│   ├── registry.py      # TenantRegistry lifecycle service
│   ├── provisioning.py  # provision/deprovision orchestration + lifecycle hooks
│   └── middleware.py    # ASGI middleware, job/CLI decorators
├── persistence/
│   ├── session.py       # TenantSession: scoping events, stamping, validation
│   ├── router.py        # SessionRouter: target resolution, pool cache and caps
│   ├── uow.py           # UnitOfWork transaction boundaries
│   ├── repository.py    # TenantRepository base
│   └── strategies/      # base.py, shared.py, schema.py, database.py, rls.py
├── audit/               # AuditSink protocol + DB sink
├── migrations/          # programmatic Alembic runner + template env
├── testing/             # pytest fixtures, strategy matrix, isolation assertion kit
└── integrations/
    ├── fastapi.py       # middleware + dependencies (optional extra)
    └── cli.py           # ops commands (optional extra)
```

Dependency direction, enforced by imports:

```
config → errors → context → models → authz
                              ↑
        persistence (strategies) → authn → tenancy → integrations
```

`models` imports nothing from `persistence`, `authn`, or `tenancy`. Applications
depend on `models`, the persistence API (session/UoW/repository), `authz` guards,
and `context` — never on a concrete strategy.

Public API (re-exported from `jdlib/__init__.py`): `TenancyConfig`,
`TenantContext`, `current_tenant`, `UnitOfWork`, `TenantRepository`, `requires`,
`authorize`, `TenantRegistry`. Everything else is reachable by module path for
extension authors.

### 6.1 Dependencies

Required: SQLAlchemy 2.0, Pydantic v2 + pydantic-settings, Alembic, PyJWT +
httpx (JWKS), argon2-cffi. Optional extras: `[fastapi]`, `[postgres]`
(asyncpg), `[cli]` (typer). No DI framework, no policy engine, no ORM
abstraction layer; extension points are plain `Protocol`s.

### 6.2 Extension points

| Interface | Default | Replaced when |
|---|---|---|
| `IsolationStrategy` | shared / schema / database | new physical model (sharding, Aurora-per-tenant) |
| `TenantResolver` | claim, subdomain, path, header, key | new channel (mTLS CN, gateway header) |
| `Authenticator` | OIDC/JWT, API key | mTLS, HMAC webhooks, legacy tokens |
| `PolicyDecisionPoint` | built-in evaluator | Casbin/OPA/Cedar escalation |
| `AuditSink` | DB table | SIEM/webhook fan-out |
| `RoleTemplateProvider` | owner/admin/member/viewer | industry-specific seed roles |
| `PermissionProvider` | app registration hook | dynamic module catalogs |
| `TenantLifecycleHook` | none | per-tenant buckets, indexes, caches |
| ORM mixins | `TenantOwned`, ownership FKs | custom ownership columns |

## 7. Errors and auditing

### 7.1 Exception hierarchy

```
JdlibError
├── MissingTenantContext
├── TenantNotFound / TenantAccessDenied / TenantSuspended
├── CrossTenantReferenceError
├── AuthenticationError        # InvalidToken, ExpiredToken, UnknownPrincipal
├── AuthorizationError         # PermissionDenied, RoleEscalationBlocked
├── StrategyCapabilityError
└── ProvisioningError / MigrationError
```

FastAPI integration maps: `AuthenticationError → 401`, `AuthorizationError →
403`, `TenantNotFound`/`TenantAccessDenied → 404`, `TenantSuspended → 423`,
`CrossTenantReferenceError → 409`. Non-HTTP callers receive the typed exceptions.

### 7.2 Auditing rules

- Every mutation writes its `AuditEvent` in the same transaction; if the audit
  write fails, the mutation rolls back.
- The actor is taken from `TenantContext`, never passed as an argument.
- Authentication failures, resolution failures, privileged-context use, role
  binding changes, and membership changes are always audited; platform-scope
  events have `tenant_id = NULL`.
- Append-only: under RLS the runtime role has no `UPDATE`/`DELETE` on the audit
  table. Retention/export is an `AuditSink` extension.

## 8. Testing strategy

- **Unit:** context propagation and fail-closed behavior; resolver chain;
  permission catalog validation; PDP truth tables; stamping and scoping events;
  anti-escalation rules.
- **Integration matrix** (dockerized Postgres):
  `{shared, schema, database} × {rls on, off}` runs the same behavioral suite
  through one parametrized fixture. This suite is the proof of the
  strategy-independence claim.
- **Consumer kit:** `jdlib.testing` ships pytest fixtures that let consuming
  applications assert isolation over their own models: cross-tenant read denial,
  cross-tenant reference rejection, automatic stamping, and 404-on-unauthorized,
  under each deployed strategy.

## 9. Out of scope for v1

Password auth, MFA, password reset; billing/quota/usage metering; email delivery
and notification templates; file storage; tenant self-service admin UI;
automated tenant relocation (documented manual procedure only); external policy
engines; deny-based policies; arbitrary-depth resource trees; multi-region
routing; synchronous SQLAlchemy execution path. The design accommodates each
without structural change.

## 10. Implementation phases

| Phase | Delivers | Gate |
|---|---|---|
| 0 | Scaffold, config, errors, context | context fail-closed tests |
| 1 | Models, mixins, baseline migration, `TenantRegistry` | schema tests; single-tenant usable |
| 2 | `TenantSession` scoping/stamping, router, UoW, repository, strategy interface + shared adapter | isolation unit tests |
| 3 | AuthN (OIDC + API keys), permission catalog, PDP, guards, membership/roles | PDP truth tables; auth matrix |
| 4 | Schema and database adapters, provisioning, migration distribution, RLS | full strategy × RLS integration matrix |
| 5 | Audit, `jdlib.testing` kit, FastAPI/CLI integrations, docs | consumer acceptance test |

Business applications can start on shared-schema after Phase 3 and become
strategy-portable when Phase 4 lands.
