# jdlib — Relational Schema Specification

Companion to the design spec (rev 2). This document is the implementation
contract for Phase 1. Any deviation requires updating this document first.

Conventions:

- PostgreSQL 15+; identifiers snake_case; table names plural.
- All timestamps `timestamptz`, stored UTC.
- `id` columns are UUIDv7 (via `uuid-utils`), application-generated.
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

### 3.3 `tenant_migration_states`

| Column | Type | Constraints |
|---|---|---|
| `tenant_id` | uuid | PK, FK → `tenants(id)` ON DELETE RESTRICT |
| `current_version` | text | NULL (NULL until first successful migration) |
| `desired_version` | text | NOT NULL |
| `status` | text | NOT NULL, `CHECK (status IN ('pending','running','success','failed','blocked'))` |
| `last_error` | text | NULL |
| `updated_at` | timestamptz | NOT NULL |

Invariant: a tenant is `active` only if `status = 'success'` and
`current_version = desired_version`.

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
| `scopes` | text[] | NULL; optional narrowing only |
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
| `token_hash` | text | NOT NULL, UNIQUE; Argon2id; token is single-use |
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
| Audit columns | `created_by` / `updated_by` logical user references; UTC timestamps |
| Soft delete | `deleted_at`; unique business keys use partial indexes excluding deleted rows |
| Indexes | Every high-volume table indexes `(tenant_id, created_at)` and common filters `(tenant_id, status)` |

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

## 7. Migration artifacts

| Artifact | Scope | Applied |
|---|---|---|
| Control-plane chain | `control@head` | once, at deploy; never per tenant |
| Tenant-plane chain | `tenant@head` | distributed per target: once (`shared`), per schema (`schema`), per database (`database`) |
| Seed migration | built-in roles + `TenantSetting` defaults | idempotent, re-runnable |

Per-target `alembic_version` is authoritative for that target;
`tenant_migration_states` is the platform's view and gate for `active` status.
