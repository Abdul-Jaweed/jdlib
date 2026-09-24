# Reference: Schema and Data Model

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Column-by-column tables live in [schema_tables.md](schema_tables.md) (generated
from the ORM metadata). This page is the curated view: what the planes are, the
conventions every table obeys, and how the pieces relate.

## The two planes

| | Control plane | Tenant plane |
|---|---|---|
| Schema | `jd_control` (constant, `control/base.py`) | one schema per tenant (`t_<slug>`), or `public` of a per-tenant database, or the deployment schema for `shared` |
| Base | `ControlBase` | `TenantBase` |
| Migration chain | `src/jdlib/migrations/control/` | `src/jdlib/migrations/tenant/` |
| Tables shipped | 16 | 4 framework tables + your resources |
| Scoping | explicit `tenant_id` columns, never `TenantRouted` | `TenantRouted` mixin (`tenant_id` PK, `sort_order=-1`) |
| Alembic version table | `jd_control.alembic_version` | `<tenant schema>.alembic_version` |

There is no FK between the planes in either direction (rule L3): references from
the control plane to tenant-plane data are **logical** (`uuid` columns such as
`ResourceGrant.resource_id`), validated in Python by `AccessControl`.

## Control-plane tables (`jd_control`)

| Table | Purpose | Key shape |
|---|---|---|
| `tenants` | Identity + lifecycle state of each tenant (`slug` unique, `status` CHECK, `suspended_reason/at`, `archived_at`, optional `parent_tenant_id`). | `id` PK |
| `tenant_placements` | Placement-as-data: `strategy`, `target_handle`, `region`, `desired_version`. One row per tenant. | `(tenant_id, id)` PK |
| `tenant_migration_states` | `current_version`, `desired_version`, `status` (`pending/running/success/failed`) + error text; drives servability. | `(tenant_id, id)` PK |
| `tenant_relocations` | Relocation phases (`planned/copying/verifying/flipping/post_flip_verification/completed/failed/rolled_back`), `from_*`/`to_*` placement coordinates, partial unique index for one in-flight relocation per tenant. **No service uses it.** | `(tenant_id, id)` PK |
| `users` | Global identity: `email` (CITEXT, partial unique when not null), `status`, optional `display_name`/`locale`. | `id` PK |
| `identity_links` | OIDC `(issuer, subject)` → user, with `last_login_at`. | `id` PK, UNIQUE `(issuer, subject)` |
| `platform_operators` | Break-glass operators; `tenant_id` of their `Principal` is the operator's own scope (not a tenant to serve). | `id` PK |
| `service_accounts` | Machine principals, one per tenant (`status`). | `(tenant_id, id)` PK |
| `api_keys` | `key_prefix` (globally unique), `key_hash` (Argon2id), `scopes` (nullable = unrestricted), `status`, `expires_at`, `last_used_at`. | `(tenant_id, id)` PK |
| `memberships` | User ↔ tenant: `status` (`active/suspended/…`), `joined_at`. | `(tenant_id, id)` PK, unique per `(tenant_id, user_id)` |
| `roles` | `name`, `is_system`; system roles are immutable. | `(tenant_id, id)` PK |
| `role_permissions` | Role → permission code rows (validated against the catalog by the write path). | `(tenant_id, role_id, permission_code)` |
| `role_bindings` | role + polymorphic `scope_type`/`scope_id` + principal (`principal_type`, `principal_id`), partial unique index for one active owner binding per tenant. | `(tenant_id, id)` PK |
| `resource_grants` | Exact-resource sharing: `resource_type`, `resource_id`, permission code, principal, optional `expires_at`. Unique per (resource, permission, principal). | `(tenant_id, id)` PK |
| `invitations` | `email`, role, scope (`scope_type`/`scope_id`), `token_id` (unique), `token_hash` (Argon2id), `status`, `expires_at`, `accepted_at`, `revoked_at`, `invited_by`. | `(tenant_id, id)` PK |
| `platform_audit_events` | Append-only audit: `actor_type`/`actor_id`, `action`, `target_type`/`target_id`, `metadata` (JSONB), `severity`, request/correlation/trace ids, `ip`. Its `tenant_id` is a **reference**, and it is the one table exempt from the tenant-scoping rules (L5/L12 whitelisting). | `id` PK |

## Tenant-plane framework tables

Present in every tenant schema/database (all `TenantRouted`):

| Table | Purpose |
|---|---|
| `organizations` | Ownership hierarchy root per tenant: composite FK `(tenant_id, parent_organization_id) → organizations(tenant_id, id)`, `deleted_at`. |
| `teams` | Belongs to an organization; composite FK to it (`team_id ⇒ organization_id`), `deleted_at`. |
| `tenant_settings` | Per-tenant key/value configuration owned by the application. |
| `audit_events` | Tenant-plane audit rows written through `TenantAuditRecorder`. |

## Conventions every table follows

1. **Tenant-scoped tables**: PK includes `tenant_id` and *leads* with it (L1/L4);
   `tenant_id` is `NOT NULL` (L9) and declared by the `TenantOwned` mixin
   (`sort_order=-1`) in the tenant plane (L11/L17).
2. **Tenant-scoped FKs are composite** and include `tenant_id` on both sides
   (L2/L10), pointing at a PK/unique target — e.g.
   `(tenant_id, organization_id) → organizations (tenant_id, id)`. This is what
   makes a cross-tenant reference impossible in the database, not just in Python.
3. **No cross-plane FKs** (L3); logical references to `users` are plain `uuid`
   columns.
4. **Uniques are tenant-scoped** (L12) unless explicitly whitelisted as global
   (`api_keys.uq_api_keys_key_prefix`, `invitations.uq_invitations_token_id`,
   `tenants.uq_tenants_slug`).
5. **No `ON DELETE CASCADE` path from `tenants`** (L6) — lifecycle deletion is an
   explicit operation, not a cascade. Composite FKs from resources to
   organizations/teams use `ON DELETE RESTRICT` (`ownership_constraints()`).
6. **Soft delete via `deleted_at`** with partial unique indexes for live business
   keys; hard delete requires a privileged context.
7. **Ownership columns** `organization_id`/`team_id` are optional but constrained:
   `CHECK (team_id IS NULL OR organization_id IS NOT NULL)` plus the composite FK
   to `teams(tenant_id, id, organization_id)` so a team-owned row cannot point at
   another organization's team (L15, invariant I12).
8. **Timestamps** are `TIMESTAMP WITH TIME ZONE` with `server_default=now()`; ids
   are `UUID`s generated by `uuid7()`.
9. **RLS eligibility**: every `TenantRouted` model is eligible; when RLS is
   enabled the standard policy must exist for each (L13), and control-plane
   tenant-owned tables are explicitly **not** RLS targets.

## RLS policy shape

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON invoices;
CREATE POLICY tenant_isolation ON invoices
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
```

`FORCE` makes the policy apply to the table owner too; `NULLIF(..., '')` turns an
unset GUC into `NULL`, which matches no rows and permits no writes.

## Deletion order (deprovision)

`TenantRegistry.deprovision` deletes control-plane access rows with one `DELETE`
per entry of `_ACCESS_ROW_DELETION_ORDER` (`control/registry.py:60`), recording a
rowcount for each table:

```
api_keys → service_accounts → invitations → role_bindings → resource_grants
→ role_permissions → roles → memberships
```

(the order is child-before-parent; all eight are attempted, and the counts become
`metadata["counts"]` on the `tenant.deprovisioned` audit row).

Tenant-plane rows for a **shared** placement are then deleted by
`TenantPlanePurger.purge`:

```
reversed(TenantBase.metadata.sorted_tables)   # dependency order the metadata already knows
  …then any registered model whose table is missing from that metadata, sorted by name
```

`sorted_tables` puts referenced tables before referencing ones, so reversing it
deletes children first; the second pass is a safety net for models that joined the
metadata after `sorted_tables` was computed in a given process.

## Where to go next

- [schema_tables.md](schema_tables.md) — per-column detail, constraints, indexes.
- [invariants_and_lint.md](invariants_and_lint.md) — the I#/L# rule set and where
  each rule is enforced.
- [../modules/models.md](../modules/models.md) — how to declare your own models.
