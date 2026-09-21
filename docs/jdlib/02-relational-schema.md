# jdlib — Relational Schema Specification

Companion to the design spec (rev 2). This document is the implementation
contract for Phase 1. Any deviation requires updating this document first.

Conventions:

- PostgreSQL 15+; identifiers snake_case; table names plural.
- All timestamps `timestamptz`, stored UTC.
- `id` columns are UUIDv7 (`jdlib._uuid.uuid7`), application-generated.
- Tenant-scoped tables: `PK (tenant_id, id)`; every FK to another tenant-scoped
  table is composite and includes `tenant_id`.
- Control-plane tables never have FKs to tenant-plane tables; tenant-plane
  tables never have FKs to control-plane tables (logical references only).
- `ON DELETE RESTRICT` is the default. `CASCADE` is used only for pure
  composition rows (child has no meaning without parent). Tenant deletion is
  never a database cascade; it is a lifecycle operation.

## 1. ERD

Control plane (one physical location, never routed):

```
PlatformOperator ──< User >── IdentityLink (issuer, subject)
                      │
                      │ (user_id, logical)
   ┌──────────────────┴───────────────────────────────┐
   │                                                  │
Membership (tenant_id, user_id)                AuditEvent.actor_id (logical)
   │
Tenant ──1:1── TenantPlacement
   │  └──1:1── TenantMigrationState
   │  └──< PlatformAuditEvent.tenant_id (nullable)
   │
   ├──< Role ──< RolePermission (role_id, permission_code)
   │              ▲
   ├──< RoleBinding (role_id, principal, scope_type, scope_id)
   ├──< ResourceGrant (resource_type, resource_id, principal, permission_code)
   ├──< Invitation (role_id, email, scope_type, scope_id)
   ├──< ApiKey >── ServiceAccount (tenant_id, service_account_id)
   └──< Membership
```

Tenant plane (routed by strategy; composite identity throughout):

```
Tenant (from control plane, logical parent)
   │  tenant_id on every row
   ├──< Organization (self-FK parent_organization_id, tree)
   │        └──< Team (flat per organization)
   │                 └──< Application resources (OwnableByTeam)
   ├──< TenantSetting (tenant_id, key)
   └──< AuditEvent (tenant_id, id)
```

## 2. Identifier scopes

| Identifier | Scope | Constraint |
|---|---|---|
| `users.email` | global, optional | partial unique `WHERE email IS NOT NULL` |
| `identity_links.(issuer, subject)` | global | unique |
| `tenants.slug` | global | unique |
| `api_keys.key_prefix` | global | unique |
| `service_accounts.name` | tenant | unique `(tenant_id, name)` |
| `roles.name` | tenant | unique `(tenant_id, name)` |
| `organizations.slug` | tenant | partial unique `(tenant_id, slug) WHERE deleted_at IS NULL` |
| `teams.slug` | tenant + organization | partial unique `(tenant_id, organization_id, slug) WHERE deleted_at IS NULL` |
| `tenant_settings.key` | tenant | PK `(tenant_id, key)` |
| application resource slugs | application-defined, tenant-scoped | partial unique `(tenant_id, slug) WHERE deleted_at IS NULL` |

## 3. Control-plane tables

### 3.1 `tenants`

| Column | Type | Constraints |
|---|---|---|
| `id` | uuid | PK |
| `slug` | text | NOT NULL, UNIQUE, `CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$')`, immutable |
| `name` | text | NOT NULL |
| `status` | text | NOT NULL, `CHECK (status IN ('provisioning','active','suspended','archived','deprovisioning','deleted'))` |
| `suspended_reason` | text | NULL; e.g. `migration_failed`, `operator_action` |
| `parent_tenant_id` | uuid | NULL, FK → `tenants(id)` ON DELETE RESTRICT; delegation metadata only |
| `created_at` / `updated_at` | timestamptz | NOT NULL |
| `suspended_at` / `archived_at` | timestamptz | NULL |

Indexes: `UNIQUE (slug)`, `INDEX (status)`, `INDEX (parent_tenant_id)`.

### 3.2 `tenant_placements`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK, FK → `tenants(id)` ON DELETE RESTRICT |
| `strategy` | text | NOT NULL, `CHECK (strategy IN ('shared','schema','database'))` |
| `target_handle` | text | NOT NULL; opaque key resolved by the secret provider |
| `region` | text | NULL |
| `updated_at` | timestamptz | NOT NULL |

`CHECK (strategy <> 'database' OR target_handle <> 'default')` is intentionally
not enforced at the DB level; the router validates handles per strategy.
`tenant_placements` holds exactly one authoritative row per tenant; relocation
in progress is represented by `tenant_relocations` (section 3.3.1), never by a
second placement row.

### 3.3.1 `tenant_relocations`

Durable operation record for a strategy change; the authoritative placement
stays in `tenant_placements` until the atomic flip.

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `from_strategy` / `to_strategy` | text | NOT NULL, same CHECK as placements |
| `from_target_handle` / `to_target_handle` | text | NOT NULL |
| `from_region` / `to_region` | text | NULL |
| `status` | text | NOT NULL, `CHECK (status IN ('pending','provisioning','copying','verifying','flipping','post_flip_verification','completed','failed','rolled_back'))` |
| `started_at` | timestamptz | NOT NULL |
| `verified_at` / `flipped_at` / `completed_at` | timestamptz | NULL |
| `error` | text | NULL |
| `created_by` | uuid | NULL, logical reference to `users(id)` |

`PRIMARY KEY (tenant_id, id)`;
partial `UNIQUE (tenant_id) WHERE status NOT IN ('completed','failed','rolled_back')`
(at most one in-flight relocation per tenant, DB-enforced);
`INDEX (tenant_id, status)`.
Allowed phase transitions (enforced by `TenantRegistry`, rejected transitions
raise `TenantOperationInProgress` or `RelocationPhaseError`):

```
pending                → provisioning | failed
provisioning           → copying | failed
copying                → verifying | failed
verifying              → flipping | failed
flipping               → post_flip_verification | rolled_back
post_flip_verification → completed | rolled_back
failed                 → pending          # explicit retry only
rolled_back            → pending          # explicit retry only
completed              → terminal
```

Serving gate: the tenant is **not servable** during `copying`, `verifying`,
`flipping`, and `post_flip_verification` (application traffic and writes are
blocked before the snapshot is taken and remain blocked until verification
succeeds). Write fence: the same phases block **every** tenant-plane mutation at
the infrastructure level (`assert_writable` checked by `TenantSession`,
`UnitOfWork`, and tenant job execution) for all writer classes — HTTP, background
jobs, queue consumers, CLI, service-to-service, and privileged tenant writes.
Only explicitly authorized relocation-control operations (system context with
the relocation-manage capability) bypass the fence. The old target is never
deprovisioned before `completed`; `flipping` is a single transaction that
updates `tenant_placements` and sets `post_flip_verification`; because no
application writes can occur after the flip, rollback to the old placement
cannot lose data.

### 3.3 `tenant_migration_states`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK, FK → `tenants(id)` ON DELETE RESTRICT |
| `current_version` | text | NULL (NULL until first successful migration) |
| `desired_version` | text | NOT NULL |
| `status` | text | NOT NULL, `CHECK (status IN ('pending','running','success','failed','blocked'))` |
| `last_error` | text | NULL |
| `updated_at` | timestamptz | NOT NULL |

Servability predicate (single source of truth for the router and the registry):
a tenant is servable **iff** `tenants.status = 'active'` **and**
`tenant_migration_states.status = 'success'` **and**
`current_version = desired_version` **and** no `tenant_relocations` row for the
tenant is in a critical phase (`copying`, `verifying`, `flipping`,
`post_flip_verification`). A `failed` or `blocked` migration on an
active tenant immediately moves it to `suspended`
(`suspended_reason = 'migration_failed'`, audited); an operator resolves the
migration and explicitly resumes.

### 3.4 `users`

| Column | Type | Constraints |
|---|---|---|
| `id` | uuid | PK |
| `email` | citext | NULL, partial `UNIQUE`; never an identity key |
| `display_name` | text | NULL |
| `locale` | text | NULL |
| `status` | text | NOT NULL, `CHECK (status IN ('active','suspended','deleted'))` |
| `created_at` / `updated_at` | timestamptz | NOT NULL |

Uniqueness is enforced with a partial unique index
(`UNIQUE (email) WHERE email IS NOT NULL`). Rationale: deterministic invitation
matching and duplicate-account prevention; authority remains
`identity_links.(issuer, subject)`.

Deleted-user policy: `status='deleted'` rows are retained while any logical
reference exists; `created_by` / `updated_by` / audit `actor_id` values resolve
to `deleted_user` for such rows, and to `unknown_actor(id)` only after an
explicit retention purge. Users are never hard-deleted by cascade, and no
cross-plane FK is ever added to enforce this.

### 3.5 `identity_links`

| Column | Type | Constraints |
|---|---|---|
| `id` | uuid | PK |
| `user_id` | uuid | NOT NULL, FK → `users(id)` ON DELETE CASCADE |
| `issuer` | text | NOT NULL |
| `subject` | text | NOT NULL |
| `created_at` / `last_login_at` | timestamptz | NOT NULL / NULL |

`UNIQUE (issuer, subject)`; `INDEX (user_id)`.
Linking rules: exact `(issuer, subject)` match; otherwise link by verified email
only if the IdP is configured `email_trusted`; otherwise create a new user.

### 3.6 `platform_operators`

| Column | Type | Constraints |
|---|---|---|
| `user_id` | uuid | PK, FK → `users(id)` ON DELETE RESTRICT |
| `level` | text | NOT NULL, `CHECK (level IN ('support','operator','admin'))` |
| `granted_at` | timestamptz | NOT NULL |
| `granted_by_user_id` | uuid | NULL, logical reference |

Capability mapping per level lives in code, not data.

### 3.7 `service_accounts`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `name` | text | NOT NULL |
| `status` | text | NOT NULL, `CHECK (status IN ('active','suspended','deleted'))` |
| `created_at` / `updated_at` | timestamptz | NOT NULL |

`PRIMARY KEY (tenant_id, id)`; `UNIQUE (tenant_id, name)`.

### 3.8 `api_keys`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `service_account_id` | uuid | NOT NULL, composite FK → `service_accounts(tenant_id, id)` ON DELETE CASCADE |
| `key_prefix` | text | NOT NULL, UNIQUE; lookup value, non-secret |
| `key_hash` | text | NOT NULL; Argon2id |
| `scopes` | text[] | NULL; optional narrowing only; effective key permissions = (binding permissions ∪ resource grants) ∩ scopes |
| `status` | text | NOT NULL, `CHECK (status IN ('active','revoked','expired'))` |
| `expires_at` | timestamptz | NULL |
| `last_used_at` | timestamptz | NULL |
| `created_at` / `revoked_at` | timestamptz | NOT NULL / NULL |

`PRIMARY KEY (tenant_id, id)`; `UNIQUE (key_prefix)`;
`INDEX (tenant_id, service_account_id)`.

### 3.9 `memberships`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `user_id` | uuid | NOT NULL, FK → `users(id)` ON DELETE RESTRICT |
| `status` | text | NOT NULL, `CHECK (status IN ('active','suspended','deleted'))` |
| `joined_at` | timestamptz | NOT NULL |
| `suspended_at` | timestamptz | NULL |

`PRIMARY KEY (tenant_id, id)`; `UNIQUE (tenant_id, user_id)`;
`INDEX (user_id)` (login-time tenant discovery). Membership carries **no**
`role_id`; authorization is exclusively `role_bindings`.

### 3.10 `roles`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `name` | text | NOT NULL |
| `description` | text | NULL |
| `is_system` | boolean | NOT NULL default false (seeded templates; not deletable) |
| `created_at` / `updated_at` | timestamptz | NOT NULL |

`PRIMARY KEY (tenant_id, id)`; `UNIQUE (tenant_id, name)`.

### 3.11 `role_permissions`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part |
| `role_id` | uuid | PK part, composite FK → `roles(tenant_id, id)` ON DELETE CASCADE |
| `permission_code` | text | PK part; validated against the code catalog at write time |

`PRIMARY KEY (tenant_id, role_id, permission_code)`;
`INDEX (tenant_id, permission_code)` (reverse lookup during evaluation).

### 3.12 `role_bindings`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `role_id` | uuid | NOT NULL, composite FK → `roles(tenant_id, id)` ON DELETE RESTRICT (roles with bindings cannot be deleted; rule 5 in `04`) |
| `principal_type` | text | NOT NULL, `CHECK (principal_type IN ('user','service_account'))` |
| `principal_id` | uuid | NOT NULL, logical reference (no FK; validated by `AccessControl`) |
| `scope_type` | text | NOT NULL, `CHECK (scope_type IN ('tenant','org','team'))` |
| `scope_id` | uuid | NULL only when `scope_type = 'tenant'`, logical reference |
| `created_at` | timestamptz | NOT NULL |
| `created_by` | uuid | NULL, logical reference to `users(id)` |

`PRIMARY KEY (tenant_id, id)`;
`UNIQUE NULLS NOT DISTINCT (tenant_id, role_id, principal_type, principal_id, scope_type, scope_id)` (PostgreSQL 15+; required because `scope_id` is NULL for tenant scope);
`INDEX (tenant_id, principal_type, principal_id)`;
`INDEX (tenant_id, scope_type, scope_id)`;
`CHECK (scope_type = 'tenant' AND scope_id IS NULL OR scope_type <> 'tenant' AND scope_id IS NOT NULL)`.
Write-time invariant: `principal_id` resolves to a user or service account;
`scope_id` resolves to an organization or team **in the same tenant**; violation
raises `CrossTenantReferenceError`.

### 3.13 `resource_grants`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `resource_type` | text | NOT NULL (application-declared resource name) |
| `resource_id` | uuid | NOT NULL, logical reference |
| `principal_type` | text | NOT NULL, `CHECK (principal_type IN ('user','service_account'))` |
| `principal_id` | uuid | NOT NULL, logical reference |
| `permission_code` | text | NOT NULL; catalog-validated |
| `created_at` | timestamptz | NOT NULL |
| `created_by` | uuid | NULL, logical reference |

`PRIMARY KEY (tenant_id, id)`;
`UNIQUE (tenant_id, resource_type, resource_id, principal_type, principal_id, permission_code)`;
`INDEX (tenant_id, resource_type, resource_id)`;
`INDEX (tenant_id, principal_type, principal_id)`.
Grant creation is idempotent (`ON CONFLICT DO NOTHING`).

### 3.14 `invitations`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part, FK → `tenants(id)` ON DELETE RESTRICT |
| `id` | uuid | PK part |
| `email` | citext | NOT NULL |
| `scope_type` | text | NOT NULL, `CHECK (scope_type IN ('tenant','org','team'))` |
| `scope_id` | uuid | NULL only when `scope_type = 'tenant'` |
| `role_id` | uuid | NOT NULL, composite FK → `roles(tenant_id, id)` ON DELETE RESTRICT |
| `token_id` | text | NOT NULL, UNIQUE; deterministic lookup value (non-secret) |
| `token_hash` | text | NOT NULL; Argon2id verification hash (never a lookup key) |
| `status` | text | NOT NULL, `CHECK (status IN ('pending','accepted','expired','revoked'))` |
| `expires_at` | timestamptz | NOT NULL |
| `accepted_at` / `revoked_at` | timestamptz | NULL |
| `invited_by` | uuid | NULL, logical reference to `users(id)` |
| `created_at` | timestamptz | NOT NULL |

`PRIMARY KEY (tenant_id, id)`;
partial `UNIQUE (tenant_id, email, scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE status = 'pending'`;
`CHECK (scope_type = 'tenant' AND scope_id IS NULL OR scope_type <> 'tenant' AND scope_id IS NOT NULL)`.
An invitation grants nothing until acceptance; acceptance is atomic
(`invitations` update + `memberships` insert + `role_bindings` insert).
Token semantics: raw token = `inv_<token_id>_<secret>`. Lookup is by
`token_id` (deterministic, non-secret); verification is
`Argon2id.verify(secret, token_hash)` — the Argon2id hash is never a lookup
key because its salt makes it non-deterministic. Raw tokens are never stored;
tokens are single-use, expire, and become invalid on acceptance or revocation.

### 3.15 `platform_audit_events`

| Column | Type | Constraints |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | NULL, logical reference (no FK: audit survives tenant deletion) |
| `actor_type` | text | NOT NULL, `CHECK (actor_type IN ('user','service_account','platform_operator','system'))` |
| `actor_id` | uuid | NULL |
| `action` | text | NOT NULL (e.g. `authn.failed`, `tenant.suspended`, `context.privileged_used`) |
| `target_type` / `target_id` | text / uuid | NULL |
| `metadata` | jsonb | NOT NULL default `'{}'` |
| `ip` | inet | NULL |
| `request_id` / `correlation_id` / `trace_id` | text | NULL |
| `severity` | text | NOT NULL, `CHECK (severity IN ('info','warning','critical'))` |
| `occurred_at` | timestamptz | NOT NULL |

Indexes: `INDEX (occurred_at)`, `INDEX (tenant_id, occurred_at)`,
`INDEX (actor_type, actor_id, occurred_at)`, `INDEX (action, occurred_at)`.
Append-only: runtime role holds only `INSERT` and `SELECT`.

## 4. Tenant-plane tables

### 4.1 `organizations`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part |
| `id` | uuid | PK part |
| `parent_organization_id` | uuid | NULL, composite FK → `organizations(tenant_id, id)` ON DELETE RESTRICT |
| `name` | text | NOT NULL |
| `slug` | text | NOT NULL |
| `created_at` / `updated_at` / `deleted_at` | timestamptz | NOT NULL / NOT NULL / NULL |

`PRIMARY KEY (tenant_id, id)`;
partial `UNIQUE (tenant_id, slug) WHERE deleted_at IS NULL`;
`INDEX (tenant_id, parent_organization_id)`.
Tree may be arbitrary depth; ancestry is computed with a recursive CTE in
`authz.scopes` (organizations are low-cardinality per tenant; no materialized
path in v1).

### 4.2 `teams`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part |
| `id` | uuid | PK part |
| `organization_id` | uuid | NOT NULL, composite FK → `organizations(tenant_id, id)` ON DELETE RESTRICT |
| `name` | text | NOT NULL |
| `slug` | text | NOT NULL |
| `created_at` / `updated_at` / `deleted_at` | timestamptz | NOT NULL / NOT NULL / NULL |

`PRIMARY KEY (tenant_id, id)`;
`UNIQUE (tenant_id, id, organization_id)` (FK target that makes resource
ownership hierarchy consistent — see section 5);
partial `UNIQUE (tenant_id, organization_id, slug) WHERE deleted_at IS NULL`;
`INDEX (tenant_id, organization_id)`.
Teams are flat within an organization (no `parent_team_id`). A user is a team
member when at least one valid `role_binding` is scoped to that team; there is
no `team_memberships` table and none may be added.

### 4.3 `tenant_settings`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part |
| `key` | text | PK part; namespaced (`billing.currency`, `features.ai`) |
| `value` | jsonb | NOT NULL |
| `updated_at` | timestamptz | NOT NULL |
| `updated_by` | uuid | NULL, logical reference to `users(id)` |

`PRIMARY KEY (tenant_id, key)`.
Business configuration only. Deployment/security configuration (strategy,
region, IdP bindings) lives on the control plane; credentials live in the
secret provider. Free-form JSON trees are prohibited; keys are declared in code
with defaults.

### 4.4 `audit_events`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK part |
| `id` | uuid | PK part |
| `actor_type` | text | NOT NULL, `CHECK (actor_type IN ('user','service_account','platform_operator','system'))` |
| `actor_id` | uuid | NULL, logical reference |
| `action` | text | NOT NULL |
| `target_type` / `target_id` | text / uuid | NULL |
| `metadata` | jsonb | NOT NULL default `'{}'` |
| `ip` | inet | NULL |
| `request_id` / `correlation_id` / `trace_id` | text | NULL |
| `occurred_at` | timestamptz | NOT NULL |

`PRIMARY KEY (tenant_id, id)`;
`INDEX (tenant_id, occurred_at)`; `INDEX (tenant_id, target_type, target_id)`.
Written in the same transaction as the mutation; actor comes from
`TenantContext`, never from a function argument. No FK to application tables.
Append-only.

## 5. Application resources

Consuming applications define resource tables using the framework mixins. The
required shape:

| Requirement | Rule |
|---|---|
| Primary key | `PRIMARY KEY (tenant_id, id)`, `tenant_id` immutable |
| Tenant-scoped FKs | Composite and include `tenant_id`; targets must have a matching unique/PK |
| Cross-plane FKs | Forbidden; references to `users` are stored as logical `uuid` columns |
| Optional ownership | `organization_id` and/or `team_id` with composite FKs to framework tables |
| Ownership hierarchy | `CHECK (team_id IS NULL OR organization_id IS NOT NULL)`, plus composite FK `(tenant_id, team_id, organization_id) → teams(tenant_id, id, organization_id)`, so a team-owned resource can never point at a team from another organization or tenant |
| Audit columns | `created_by` / `updated_by` logical user references; UTC timestamps |
| Soft delete | `deleted_at`; unique business keys use partial indexes excluding deleted rows |
| Indexes | Every high-volume table indexes `(tenant_id, created_at)` and common filters `(tenant_id, status)` |
| RLS eligibility | Every **tenant-routed** model (framework tenant-plane tables and application resources) is RLS-eligible; when RLS is enabled the standard policy **must** be emitted for it. Control-plane tenant-owned tables are not tenant-plane RLS targets (see `06-strategy-matrix.md` section 6) |

## 6. Enforced invariants (metadata lint and write-path tests)

- `L1` Every tenant-scoped table's PK includes `tenant_id`.
- `L2` Every FK between two tenant-scoped tables includes `tenant_id` on both
  sides, and the target column set is backed by a unique or PK constraint.
- `L3` No FK may exist between a control-plane table and a tenant-plane table in
  either direction.
- `L4` Every tenant-scoped table's primary key leads with `tenant_id`.
- `L5` `tenant_id` is NOT NULL in tenant-scoped tables; only
  `platform_audit_events` (and `tenants.parent_tenant_id`) may carry tenant
  references that are nullable.
- `L6` No table has a DB-level `ON DELETE CASCADE` path starting at `tenants`.
- `L7` (write path, not metadata lint) Every `permission_code` column is
  validated against the code catalog by
  the write path (test asserts an unknown code is rejected).
- `L8` (runtime/mapper) `tenant_id` is immutable after insert; assigning it
  raises.
- `L9` (metadata) `tenant_id` is NOT NULL on every tenant-scoped model.
- `L10` (metadata) Every tenant-scoped FK column set contains `tenant_id`
  (same rule as L2, checked independently per constraint).
- `L11` (metadata, tenant plane) Every tenant-plane model is built on
  `TenantOwned` (no hand-rolled `tenant_id` columns). Control-plane
  tenant-scoped tables declare `tenant_id` explicitly; their identity shape is
  enforced by L1/L4/L9.
- `L12` (metadata) Every unique constraint on a tenant-scoped model includes
  `tenant_id` (business keys are tenant-scoped unless listed as global in
  section 2).
- `L13` (metadata, only when `rls` is enabled) Every **tenant-routed** model —
  framework or application — is RLS-eligible and its policy has been emitted;
  control-plane tenant-owned models are explicitly excluded from tenant-plane
  RLS generation.
- `L14` (write path) Every polymorphic reference (`RoleBinding.scope_id`,
  `ResourceGrant.resource_id`, ownership columns) validates existence, tenant
  match, and allowed state (see I11 in `03-isolation-invariants.md`).
- `L15` (metadata) Every model with a `team_id` ownership column declares the
  `(team_id ⇒ organization_id)` CHECK and the
  `(tenant_id, team_id, organization_id)` composite FK to `teams`
  (see I12 in `03-isolation-invariants.md`).
- `L16` (write path) `RoleBinding` creation validates permission ↔ scope
  compatibility (`RoleScopeMismatch`), and `ResourceGrant` creation validates
  permission ↔ resource-type namespace compatibility
  (`InvalidResourcePermission`) — see `04-authorization-model.md`.
- `L17` (metadata) Every tenant-plane model is `TenantRouted` (a `TenantOwned`
  base without routing is a build failure).
- `L18` (metadata) Every application-plane model registered in the
  `ResourceTypeRegistry` is `TenantRouted`.
- `L19` (metadata) No control-plane model inherits `TenantRouted`
  (`TenantOwned` only).

## 7. Migration artifacts

| Artifact | Scope | Applied |
|---|---|---|
| Control-plane chain | `control@head` | once, at deploy; never per tenant |
| Tenant-plane chain | `tenant@head` | distributed per target: once (`shared`), per schema (`schema`), per database (`database`) |
| Seed migration | built-in roles + `TenantSetting` defaults | idempotent, re-runnable |

Per-target `alembic_version` is authoritative for that target;
`tenant_migration_states` is the platform's view and gate for `active` status.
