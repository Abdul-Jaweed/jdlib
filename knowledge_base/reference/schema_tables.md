# Schema Tables (generated)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Auto-derived from the SQLAlchemy metadata of `ControlBase` (schema `jd_control`),
`TenantBase` (tenant plane) and the test-support models, compiling each type with
the PostgreSQL dialect — so it cannot drift from the models. Regenerate by
importing the metadata modules, walking `metadata.sorted_tables`, and compiling
`column.type` with `sqlalchemy.dialects.postgresql.dialect()` whenever models
change.

Sections:

1. **Control plane (`jd_control`)** — 16 tables.
2. **Tenant plane (framework)** — 4 tables every tenant schema/database gets.
3. **Test-support models (not shipped)** — `invoices` / `line_items` from
   `tests/support/invoice.py`, shown as a worked example of a consumer resource
   pair.

Reading notes:

- Types are PostgreSQL renderings of the generic types used in the models:
  `sa.Uuid` → `UUID`, `sa.DateTime(timezone=True)` → `TIMESTAMP WITH TIME ZONE`.
  String columns are `TEXT` (no length ceilings); `CITEXT` appears only where
  case-insensitive comparison is required.
- Composite primary keys `(tenant_id, id)` appear wherever a row is tenant-scoped
  in the control plane (`memberships`, `tenant_placements`,
  `tenant_migration_states`, `role_permissions`, `role_bindings`,
  `resource_grants`) — uniqueness is therefore cluster-wide-correct by
  construction.
- FKs are frequently **composite** (`(tenant_id, organization_id)` →
  `organizations (tenant_id, id)`), which is the mechanism that makes a
  cross-tenant reference impossible at the database level, not just in Python.
- Partial unique indexes (`... WHERE ...`) encode "at most one active X per
  tenant" rules (one owner binding, one in-flight relocation, one live email).
- Naming follows `NAMING_CONVENTION` (`control/base.py`): `ix_`, `uq_`, `ck_`,
  `fk_`, `pk_` with `column_0_N_name` expansions.

---

## Control plane (`jd_control`)

### `jd_control.platform_audit_events`

| Column | Type | Flags |
|---|---|---|
| `id` | UUID | PK; not null |
| `tenant_id` | UUID | - |
| `actor_type` | TEXT | not null |
| `actor_id` | UUID | - |
| `action` | TEXT | not null |
| `target_type` | TEXT | - |
| `target_id` | UUID | - |
| `metadata` | JSONB | not null; default: '{}'::jsonb |
| `ip` | INET | - |
| `request_id` | TEXT | - |
| `correlation_id` | TEXT | - |
| `trace_id` | TEXT | - |
| `severity` | TEXT | not null |
| `occurred_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Constraints:

- CHECK `ck_platform_audit_events_actor_type`: `actor_type IN ('user', 'service_account', 'platform_operator', 'system')`
- CHECK `ck_platform_audit_events_severity`: `severity IN ('info', 'warning', 'critical')`

Indexes:

- INDEX `ix_platform_audit_events_occurred_at`: platform_audit_events.occurred_at
- INDEX `ix_platform_audit_events_action_occurred_at`: platform_audit_events.action, platform_audit_events.occurred_at
- INDEX `ix_platform_audit_events_actor_type_actor_id_occurred_at`: platform_audit_events.actor_type, platform_audit_events.actor_id, platform_audit_events.occurred_at
- INDEX `ix_platform_audit_events_tenant_id_occurred_at`: platform_audit_events.tenant_id, platform_audit_events.occurred_at

### `jd_control.tenants`

| Column | Type | Flags |
|---|---|---|
| `id` | UUID | PK; not null |
| `slug` | TEXT | not null; unique |
| `name` | TEXT | not null |
| `status` | TEXT | not null |
| `suspended_reason` | TEXT | - |
| `parent_tenant_id` | UUID | - |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `suspended_at` | TIMESTAMP WITH TIME ZONE | - |
| `archived_at` | TIMESTAMP WITH TIME ZONE | - |

Foreign keys:

- `fk_tenants_parent_tenant_id`: parent_tenant_id → tenants.id

Constraints:

- UNIQUE `uq_tenants_slug`: slug
- CHECK `ck_tenants_status`: `status IN ('provisioning', 'active', 'suspended', 'archived', 'deprovisioning', 'deleted')`
- CHECK `ck_tenants_slug_format`: `slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'`

Indexes:

- INDEX `ix_tenants_status`: tenants.status
- INDEX `ix_tenants_parent_tenant_id`: tenants.parent_tenant_id

### `jd_control.users`

| Column | Type | Flags |
|---|---|---|
| `id` | UUID | PK; not null |
| `email` | CITEXT | - |
| `display_name` | TEXT | - |
| `locale` | TEXT | - |
| `status` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Constraints:

- CHECK `ck_users_status`: `status IN ('active','suspended','deleted')`

Indexes:

- UNIQUE INDEX `uq_users_email`: users.email WHERE email IS NOT NULL

### `jd_control.identity_links`

| Column | Type | Flags |
|---|---|---|
| `id` | UUID | PK; not null |
| `user_id` | UUID | not null |
| `issuer` | TEXT | not null |
| `subject` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `last_login_at` | TIMESTAMP WITH TIME ZONE | - |

Foreign keys:

- `fk_identity_links_user_id`: user_id → users.id

Constraints:

- UNIQUE `uq_identity_links_issuer_subject`: issuer, subject

Indexes:

- INDEX `ix_identity_links_user_id`: identity_links.user_id

### `jd_control.memberships`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `user_id` | UUID | not null |
| `status` | TEXT | not null |
| `joined_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `suspended_at` | TIMESTAMP WITH TIME ZONE | - |

Foreign keys:

- `fk_memberships_tenant_id`: tenant_id → tenants.id
- `fk_memberships_user_id`: user_id → users.id

Constraints:

- UNIQUE `uq_memberships_tenant_id_user_id`: tenant_id, user_id
- CHECK `ck_memberships_status`: `status IN ('active', 'suspended', 'deleted')`

Indexes:

- INDEX `ix_memberships_user_id`: memberships.user_id

### `jd_control.platform_operators`

| Column | Type | Flags |
|---|---|---|
| `user_id` | UUID | PK; not null |
| `level` | TEXT | not null |
| `granted_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `granted_by_user_id` | UUID | - |

Foreign keys:

- `fk_platform_operators_user_id`: user_id → users.id

Constraints:

- CHECK `ck_platform_operators_level`: `level IN ('support', 'operator', 'admin')`

### `jd_control.resource_grants`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `resource_type` | TEXT | not null |
| `resource_id` | UUID | not null |
| `principal_type` | TEXT | not null |
| `principal_id` | UUID | not null |
| `permission_code` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `created_by` | UUID | - |

Foreign keys:

- `fk_resource_grants_tenant_id`: tenant_id → tenants.id

Constraints:

- UNIQUE `uq_resource_grants_tenant_id_resource_type_resource_id_principal_type_principal_id_permission_code`: tenant_id, resource_type, resource_id, principal_type, principal_id, permission_code
- CHECK `ck_resource_grants_principal_type`: `principal_type IN ('user', 'service_account')`

Indexes:

- INDEX `ix_resource_grants_tenant_id_resource_type_resource_id`: resource_grants.tenant_id, resource_grants.resource_type, resource_grants.resource_id
- INDEX `ix_resource_grants_tenant_id_principal_type_principal_id`: resource_grants.tenant_id, resource_grants.principal_type, resource_grants.principal_id

### `jd_control.roles`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `name` | TEXT | not null |
| `description` | TEXT | - |
| `is_system` | BOOLEAN | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Foreign keys:

- `fk_roles_tenant_id`: tenant_id → tenants.id

Constraints:

- UNIQUE `uq_roles_tenant_id_name`: tenant_id, name

### `jd_control.service_accounts`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `name` | TEXT | not null |
| `status` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Foreign keys:

- `fk_service_accounts_tenant_id`: tenant_id → tenants.id

Constraints:

- UNIQUE `uq_service_accounts_tenant_id_name`: tenant_id, name
- CHECK `ck_service_accounts_status`: `status IN ('active','suspended','deleted')`

### `jd_control.tenant_migration_states`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `current_version` | TEXT | - |
| `desired_version` | TEXT | not null |
| `status` | TEXT | not null |
| `last_error` | TEXT | - |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Foreign keys:

- `fk_tenant_migration_states_tenant_id`: tenant_id → tenants.id

Constraints:

- CHECK `ck_tenant_migration_states_status`: `status IN ('pending', 'running', 'success', 'failed', 'blocked')`

### `jd_control.tenant_placements`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `strategy` | TEXT | not null |
| `target_handle` | TEXT | not null |
| `region` | TEXT | - |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Foreign keys:

- `fk_tenant_placements_tenant_id`: tenant_id → tenants.id

Constraints:

- CHECK `ck_tenant_placements_strategy`: `strategy IN ('shared', 'schema', 'database')`

### `jd_control.tenant_relocations`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `from_strategy` | TEXT | not null |
| `from_target_handle` | TEXT | not null |
| `from_region` | TEXT | - |
| `to_strategy` | TEXT | not null |
| `to_target_handle` | TEXT | not null |
| `to_region` | TEXT | - |
| `status` | TEXT | not null |
| `started_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `verified_at` | TIMESTAMP WITH TIME ZONE | - |
| `flipped_at` | TIMESTAMP WITH TIME ZONE | - |
| `completed_at` | TIMESTAMP WITH TIME ZONE | - |
| `error` | TEXT | - |
| `created_by` | UUID | - |

Foreign keys:

- `fk_tenant_relocations_tenant_id`: tenant_id → tenants.id

Constraints:

- CHECK `ck_tenant_relocations_from_strategy`: `from_strategy IN ('shared', 'schema', 'database')`
- CHECK `ck_tenant_relocations_to_strategy`: `to_strategy IN ('shared', 'schema', 'database')`
- CHECK `ck_tenant_relocations_status`: `status IN ('pending', 'provisioning', 'copying', 'verifying', 'flipping', 'post_flip_verification', 'completed', 'failed', 'rolled_back')`

Indexes:

- UNIQUE INDEX `uq_tenant_relocations_active`: tenant_relocations.tenant_id WHERE status NOT IN ('completed', 'failed', 'rolled_back')
- INDEX `ix_tenant_relocations_tenant_id_status`: tenant_relocations.tenant_id, tenant_relocations.status

### `jd_control.api_keys`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `service_account_id` | UUID | not null |
| `key_prefix` | TEXT | not null |
| `key_hash` | TEXT | not null |
| `scopes` | TEXT[] | - |
| `status` | TEXT | not null |
| `expires_at` | TIMESTAMP WITH TIME ZONE | - |
| `last_used_at` | TIMESTAMP WITH TIME ZONE | - |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `revoked_at` | TIMESTAMP WITH TIME ZONE | - |

Foreign keys:

- `fk_api_keys_tenant_id`: tenant_id → tenants.id
- `fk_api_keys_tenant_id_service_account_id`: tenant_id, service_account_id → service_accounts.tenant_id, service_accounts.id

Constraints:

- UNIQUE `uq_api_keys_key_prefix`: key_prefix
- CHECK `ck_api_keys_status`: `status IN ('active', 'revoked', 'expired')`

Indexes:

- INDEX `ix_api_keys_tenant_id_service_account_id`: api_keys.tenant_id, api_keys.service_account_id

### `jd_control.invitations`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `email` | CITEXT | not null |
| `scope_type` | TEXT | not null |
| `scope_id` | UUID | - |
| `role_id` | UUID | not null |
| `token_id` | TEXT | not null; unique |
| `token_hash` | TEXT | not null |
| `status` | TEXT | not null |
| `expires_at` | TIMESTAMP WITH TIME ZONE | not null |
| `accepted_at` | TIMESTAMP WITH TIME ZONE | - |
| `revoked_at` | TIMESTAMP WITH TIME ZONE | - |
| `invited_by` | UUID | - |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Foreign keys:

- `fk_invitations_tenant_id`: tenant_id → tenants.id
- `fk_invitations_tenant_id_role_id`: tenant_id, role_id → roles.tenant_id, roles.id

Constraints:

- UNIQUE `uq_invitations_token_id`: token_id
- CHECK `ck_invitations_status`: `status IN ('pending', 'accepted', 'expired', 'revoked')`
- CHECK `ck_invitations_scope_type`: `scope_type IN ('tenant', 'org', 'team')`
- CHECK `ck_invitations_scope`: `scope_type = 'tenant' AND scope_id IS NULL OR scope_type IN ('org','team') AND scope_id IS NOT NULL`

Indexes:

- UNIQUE INDEX `uq_invitations_pending`: invitations.tenant_id, invitations.email, invitations.scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid) WHERE status = 'pending'

### `jd_control.role_bindings`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `role_id` | UUID | not null |
| `principal_type` | TEXT | not null |
| `principal_id` | UUID | not null |
| `scope_type` | TEXT | not null |
| `scope_id` | UUID | - |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `created_by` | UUID | - |

Foreign keys:

- `fk_role_bindings_tenant_id`: tenant_id → tenants.id
- `fk_role_bindings_tenant_id_role_id`: tenant_id, role_id → roles.tenant_id, roles.id

Constraints:

- UNIQUE `uq_role_bindings_tenant_id_role_id_principal_type_principal_id_scope_type_scope_id`: tenant_id, role_id, principal_type, principal_id, scope_type, scope_id
- CHECK `ck_role_bindings_scope`: `scope_type = 'tenant' AND scope_id IS NULL OR scope_type IN ('org','team') AND scope_id IS NOT NULL`
- CHECK `ck_role_bindings_principal_type`: `principal_type IN ('user', 'service_account')`

Indexes:

- INDEX `ix_role_bindings_tenant_id_scope_type_scope_id`: role_bindings.tenant_id, role_bindings.scope_type, role_bindings.scope_id
- INDEX `ix_role_bindings_tenant_id_principal_type_principal_id`: role_bindings.tenant_id, role_bindings.principal_type, role_bindings.principal_id

### `jd_control.role_permissions`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `role_id` | UUID | PK; not null |
| `permission_code` | TEXT | PK; not null |

Foreign keys:

- `fk_role_permissions_tenant_id_role_id`: tenant_id, role_id → roles.tenant_id, roles.id

Indexes:

- INDEX `ix_role_permissions_tenant_id_permission_code`: role_permissions.tenant_id, role_permissions.permission_code


## Tenant plane (framework)

### `-.audit_events`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `actor_type` | TEXT | not null |
| `actor_id` | UUID | - |
| `action` | TEXT | not null |
| `target_type` | TEXT | - |
| `target_id` | UUID | - |
| `metadata` | JSONB | not null; default: '{}'::jsonb |
| `ip` | INET | - |
| `request_id` | TEXT | - |
| `correlation_id` | TEXT | - |
| `trace_id` | TEXT | - |
| `occurred_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Constraints:

- CHECK `ck_audit_events_actor_type`: `actor_type IN ('user', 'service_account', 'platform_operator', 'system')`

Indexes:

- INDEX `ix_audit_events_tenant_id_target_type_target_id`: audit_events.tenant_id, audit_events.target_type, audit_events.target_id
- INDEX `ix_audit_events_tenant_id_occurred_at`: audit_events.tenant_id, audit_events.occurred_at

### `-.organizations`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `parent_organization_id` | UUID | - |
| `name` | TEXT | not null |
| `slug` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `deleted_at` | TIMESTAMP WITH TIME ZONE | - |

Foreign keys:

- `fk_organizations_tenant_id_parent_organization_id`: tenant_id, parent_organization_id → organizations.tenant_id, organizations.id

Indexes:

- UNIQUE INDEX `uq_organizations_tenant_id_slug`: organizations.tenant_id, organizations.slug WHERE deleted_at IS NULL
- INDEX `ix_organizations_tenant_id_parent_organization_id`: organizations.tenant_id, organizations.parent_organization_id

### `-.tenant_settings`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `key` | TEXT | PK; not null |
| `value` | JSONB | not null |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_by` | UUID | - |

### `-.teams`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `organization_id` | UUID | not null |
| `name` | TEXT | not null |
| `slug` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `deleted_at` | TIMESTAMP WITH TIME ZONE | - |

Foreign keys:

- `fk_teams_tenant_id_organization_id`: tenant_id, organization_id → organizations.tenant_id, organizations.id

Constraints:

- UNIQUE `uq_teams_tenant_id_id_organization_id`: tenant_id, id, organization_id

Indexes:

- UNIQUE INDEX `uq_teams_tenant_id_organization_id_slug`: teams.tenant_id, teams.organization_id, teams.slug WHERE deleted_at IS NULL
- INDEX `ix_teams_tenant_id_organization_id`: teams.tenant_id, teams.organization_id


## Test-support models (not shipped)

### `-.invoices`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `number` | TEXT | not null |
| `status` | TEXT | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `deleted_at` | TIMESTAMP WITH TIME ZONE | - |
| `organization_id` | UUID | - |
| `team_id` | UUID | - |

Foreign keys:

- `organization`: tenant_id, organization_id → organizations.tenant_id, organizations.id
- `team`: tenant_id, team_id, organization_id → teams.tenant_id, teams.id, teams.organization_id

Constraints:

- CHECK `ck_invoices_team_requires_org`: `team_id IS NULL OR organization_id IS NOT NULL`

Indexes:

- UNIQUE INDEX `uq_invoices_tenant_id_number`: invoices.tenant_id, invoices.number WHERE deleted_at IS NULL

### `-.line_items`

| Column | Type | Flags |
|---|---|---|
| `tenant_id` | UUID | PK; not null |
| `id` | UUID | PK; not null |
| `invoice_id` | UUID | not null |
| `amount_cents` | INTEGER | not null |
| `created_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |
| `updated_at` | TIMESTAMP WITH TIME ZONE | not null; default: now() |

Foreign keys:

- `fk_line_items_tenant_id_invoice_id`: tenant_id, invoice_id → invoices.tenant_id, invoices.id
