# Module: Control Plane (`src/jdlib/control/`)

Everything about *who tenants are, where they live, and what state they are in*.
Control-plane tables live in the `jd_control` schema (`control/base.py:6`), are
built on `ControlBase`, and are only touched by framework services.

| File | Lines | Responsibility |
|---|---|---|
| `base.py` | 21 | `CONTROL_SCHEMA = "jd_control"`, `NAMING_CONVENTION`, `ControlBase`. |
| `enums.py` | 92 | All shared enums + the `sql_in()` CHECK-constraint helper. |
| `models.py` | 487 | The 16 control-plane ORM models. |
| `session.py` | 41 | `ControlPlaneSession` — thin wrapper over `AsyncSession`. |
| `registry.py` | 652 | `TenantRegistry` (lifecycle) and `RegistryWriteFence`. |
| `purge.py` | 61 | `TenantPlanePurger` — privileged, child-first tenant-plane deletion. |
| `audit.py` | 172 | `PlatformAudit` port + shipped sinks and the privilege adapter. |

## Enums (`control/enums.py`)

`TenantStatus` (`provisioning/active/suspended/archived/deprovisioning/deleted`),
`PlacementStrategy` (`shared/schema/database`), `MigrationStatus`
(`pending/running/success/failed/blocked`), `RelocationPhase`
(`pending/provisioning/copying/verifying/flipping/post_flip_verification/
completed/failed/rolled_back`), `OperatorLevel` (`support/operator/admin`),
`PrincipalType` (`user/service_account`), `ScopeType` (`tenant/org/team`),
`MembershipStatus`, `InvitationStatus`, `ApiKeyStatus` (`active/revoked/expired`),
`ActorType` (`user/service_account/platform_operator/system`), `AuditSeverity`
(`info/warning/critical`).

`sql_in(column, enum)` renders `col IN ('a', 'b', ...)` so each table's CHECK
constraint list comes straight from the enum — the DB rejects unknown states
even if application code is wrong.

## The 16 models (`control/models.py`)

| Model | Table | Primary key | Notable constraints |
|---|---|---|---|
| `Tenant` | `tenants` | `id` | unique `slug`, `slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'`, self-FK `parent_tenant_id` `ON DELETE RESTRICT`, `status` CHECK |
| `TenantPlacement` | `tenant_placements` | `tenant_id` | `strategy` CHECK; **the authoritative placement** |
| `TenantMigrationState` | `tenant_migration_states` | `tenant_id` | `status` CHECK, `last_error`, `updated_at` |
| `TenantRelocation` | `tenant_relocations` | `(tenant_id, id)` | phase CHECKs, partial unique index `uq_tenant_relocations_active` on `tenant_id` where `status NOT IN ('completed','failed','rolled_back')` |
| `User` | `users` | `id` | `email CITEXT` with partial unique index when not null; status CHECK |
| `IdentityLink` | `identity_links` | `id` | unique `(issuer, subject)`; FK `user_id` CASCADE |
| `PlatformOperator` | `platform_operators` | `user_id` | `level` CHECK |
| `ServiceAccount` | `service_accounts` | `(tenant_id, id)` | unique `(tenant_id, name)` |
| `ApiKey` | `api_keys` | `(tenant_id, id)` | unique `key_prefix` (global), composite FK to `service_accounts(tenant_id, id)` CASCADE, `scopes TEXT[]`, `key_hash` |
| `Membership` | `memberships` | `(tenant_id, id)` | unique `(tenant_id, user_id)` |
| `Role` | `roles` | `(tenant_id, id)` | unique `(tenant_id, name)`, `is_system` |
| `RolePermission` | `role_permissions` | `(tenant_id, role_id, permission_code)` | composite FK to `roles(tenant_id, id)` CASCADE |
| `RoleBinding` | `role_bindings` | `(tenant_id, id)` | unique over `(tenant_id, role_id, principal_type, principal_id, scope_type, scope_id)` with `NULLS NOT DISTINCT`; CHECK `scope_type='tenant' AND scope_id IS NULL OR scope_type IN ('org','team') AND scope_id IS NOT NULL` |
| `ResourceGrant` | `resource_grants` | `(tenant_id, id)` | unique over `(tenant_id, resource_type, resource_id, principal_type, principal_id, permission_code)` |
| `Invitation` | `invitations` | `(tenant_id, id)` | unique `token_id`; partial unique `uq_invitations_pending` on `(tenant_id, email, scope_type, COALESCE(scope_id, ...0))` where `status='pending'` |
| `PlatformAuditEvent` | `platform_audit_events` | `id` | nullable `tenant_id` **reference** (not a scoped table), `actor_type`/`severity` CHECKs, four indexes (occurred_at, tenant+occurred_at, actor+occurred_at, action+occurred_at) |

All control-plane tenant-scoped tables declare `tenant_id` explicitly and are
**not** `TenantRouted` (lint L19). `platform_audit_events` is in
`TENANT_ID_REFERENCE_ONLY` (`lint.py`), so a nullable `tenant_id` there is not an
L9 violation.

## `ControlPlaneSession` (`control/session.py`)

Async context manager wrapping one `AsyncSession`: `close`, `commit`,
`rollback`, `flush`, `execute(statement)` (any `sa.Executable`), `get(model,
entity_id)`, `add(obj)`, `delete(obj)`. It deliberately exposes no scoping
logic — control-plane code is trusted framework code. `__aexit__` closes the
session (it never commits implicitly).

## `TenantRegistry` (`control/registry.py`)

Constructor (all keyword-only): `session_factory: Callable[[], AsyncSession]`,
`strategies: Mapping[PlacementStrategy, IsolationStrategy]`, `runner:
MigrationRunner`, `audit: PlatformAudit`, `seeder: SeedHook | None = None`,
`desired_version: str = "0001_tenant_baseline"`, `purger: TenantPlanePurger |
None = None`.

### Lifecycle state machine

```
_ALLOWED_TENANT_TRANSITIONS (registry.py:51)
provisioning  → {active, deleted}
active        → {suspended, archived}
suspended     → {active, archived}
archived      → {active, deprovisioning}
deprovisioning→ {deleted, archived}
deleted       → {}          # terminal
```

`_require_transition` raises `TenantOperationInProgress` for anything else;
`_apply_status` maintains `suspended_at`/`suspended_reason`/`archived_at`.

### Concurrency

Every mutating method takes the same transaction-scoped advisory lock —
`SELECT pg_advisory_xact_lock(hashtextextended('jdlib:tenant:<id>', 0))` — before
reading state. Two extra locks exist for creation: `jdlib:tenant-slug:<slug>`
and `jdlib:tenant-handle:<handle>`, so concurrent creates cannot double-book a
slug or a schema/database handle.

### Methods

| Method | Behaviour |
|---|---|
| `get(tenant_id)` | fetch a `Tenant` row or raise `TenantNotFound`. |
| `create(*, slug, name, strategy, target_handle, region=None, parent_tenant_id=None, actor_id=None)` | Normalizes `strategy` via `PlacementStrategy(...)` → `ProvisioningError` on unknown. Validates the handle for the strategy (`validate_schema_name`, `validate_database_handle`, non-empty for shared). Takes slug lock; an existing tenant with the **same** placement/region is returned as-is (idempotent), a different placement raises `ProvisioningError`. For schema/database placements it takes the handle lock and rejects a handle already assigned to another tenant. Inserts `tenants(provisioning)` + `tenant_placements` + `tenant_migration_states(pending, desired_version)`, audits `tenant.created`, commits. |
| `provision(tenant_id)` | Under the tenant lock: `active` ⇒ no-op return; anything but `provisioning` ⇒ `TenantOperationInProgress`. Then `strategy.provision` → state `running` → `strategy.migrate` → `seeder.seed` → read back `runner.tenant_version(strategy.migration_schema(record))` and require it to equal `desired_version` (else `ProvisioningError`). Success ⇒ `current_version = desired`, state `success`, audit `tenant.migration.succeeded`, `tenants.status=active`, audit `tenant.activated`, commit. Any exception ⇒ state `failed` + `last_error`, audit `tenant.migration.failed`, **commit that failure state**, re-raise. |
| `migrate(tenant_id)` | Runs `strategy.migrate` for an existing tenant. Failure ⇒ state `failed`; if the tenant was `active` it is **suspended** with `suspended_reason="migration_failed"`, audited, committed, then re-raised. |
| `suspend(tenant_id, *, reason, actor_id=None)` / `resume` / `archive` | Thin wrappers over `_transition(...)`, which locks, no-ops when already in the target state, validates the transition, applies status, audits (`tenant.suspended`/`tenant.resumed`/`tenant.archived`), commits. |
| `deprovision(tenant_id, *, mode, actor_id=None, detach_children=False)` | See below. |
| `assert_servable(tenant_id)` | Loads tenant + migration state + relocation phase; raises `TenantSuspended(message)` if status ≠ `active`, migration ≠ `success`, `current_version ≠ desired_version`, or a relocation is in a critical phase; raises `ProvisioningError` when the placement row is missing; otherwise returns a `TenantRecord`. |
| `find(ref)` | Lookup by id **or** slug; returns `TenantRecord | None`; a tenant without a placement row returns `None` (documented contrast with `assert_servable`, which raises). |
| `list_for_user(user_id)` | Tenants where an **active** `Membership` exists for the user. |

### Deprovision semantics (`registry.py:465`)

- `DeprovisionMode.ARCHIVE` — status `archived` (idempotent), children detach
  only when `detach_children=True`; a tenant with children and
  `detach_children=False` raises `ProvisioningError`. No storage action.
- `DeprovisionMode.PURGE` / `DESTROY` — requires the tenant to be `archived`
  (transition to `deprovisioning` is validated), commits that status change,
  **re-acquires the lock, re-reads the tenant and re-verifies it is still
  `deprovisioning`** (guards against a concurrent state change while the
  destructive step runs), re-checks children, then deletes control-plane access
  rows in this order: `api_keys`, `service_accounts`, `invitations`,
  `role_bindings`, `resource_grants`, `role_permissions`, `roles`, `memberships`
  (`_ACCESS_ROW_DELETION_ORDER`), calls `strategy.deprovision(record, mode)`,
  and — **only for `shared` placements** — runs `TenantPlanePurger.purge(record)`
  (a shared placement cannot drop a schema, so rows must be deleted; a shared
  placement without a configured purger raises `ProvisioningError` and fails
  closed). Finally `tenants.status=deleted` and one `tenant.deprovisioned` audit
  event carrying `mode`, optional `detach_children`/`detached_children` id lists,
  `counts` (control rows deleted) and `tenant_counts` (purged tenant-plane rows).
- `deleted` is terminal: a second call returns the row without side effects.

### Servability predicate (`_servability_error`, `registry.py:124`)

One function feeds both `assert_servable` (reads/traffic) and
`RegistryWriteFence.assert_writable` (writes). It returns a message when:

1. `tenants.status != 'active'` → `"tenant <slug> is <status>"`,
2. no migration state, or state ≠ `success`, or
   `current_version != desired_version` → `"tenant <slug> migration is not current"`,
3. a `TenantRelocation` exists in a critical phase (`COPYING`, `VERIFYING`,
   `FLIPPING`, `POST_FLIP_VERIFICATION`) → `"tenant <slug> relocation in progress"`.

`assert_servable` raises `TenantSuspended` (→ HTTP 423);
`RegistryWriteFence.assert_writable` raises `TenantNotWritable` (→ HTTP 423);
`assert_writable` also raises `TenantNotWritable` for an unknown tenant.

## `RegistryWriteFence` (`registry.py:636`)

`WriteFence` implementation used by `UnitOfWork`: opens a control-plane session
and applies the same predicate. `UnitOfWork` skips the fence entirely when
`privileged_bypass(context)` is true — i.e. a `SYSTEM` privilege whose
capability is exactly `relocation.manage` (`persistence/models.py:41`).
`NullWriteFence` (the default when no fence is supplied) always allows.

## `PlatformAudit` sinks (`control/audit.py`)

| Sink | Behaviour |
|---|---|
| `DatabaseAuditSink(session_factory)` | Writes a `PlatformAuditEvent`. Reuses `session` when the caller passes one (so the audit row commits atomically with the business change); otherwise opens its own session and commits. Fills `request_id`/`correlation_id`/`trace_id` from the active tenant context when one exists, else leaves them `NULL`. `actor_type` defaults to `"system"` when `actor_id` is `None`, else `"user"`, unless explicitly supplied. Imports `PlatformAuditEvent` lazily to avoid a module cycle. |
| `RecordingPlatformAudit` | In-memory list of dicts — the test double used throughout the unit tests. |
| `CompositeAuditSink(*sinks)` | Fans out in order; forwards `session`; a raised exception propagates (no swallowing → fail closed). |
| `NullPlatformAudit` | Raises `RuntimeError("no platform audit sink is configured")` — a null object that loudly refuses to silently drop audit. |
| `PrivilegeAuditAdapter(sink)` | Adapts `PlatformAudit` to the `PrivilegeAudit` port used by `ContextFactory`; records action `privilege.<kind>` with `capability`/`justification` metadata and `actor_type = actor.kind.value`. |

## `TenantPlanePurger` (`control/purge.py`)

Used by `TenantRegistry.deprovision` for shared placements.

1. Builds a `SYSTEM` privilege context (`for_system(tenant, purpose="tenant.purge",
   issuer=PRIVILEGE_ISSUER)`) — the only way to legitimately hard-delete tenant
   rows (`TenantSession.delete_where` requires a privileged context for
   `SoftDelete` models, and `before_flush` rejects unprivileged hard deletes).
2. If `RlsConfig.enabled`, first sets `app.tenant_id` on the raw session
   (`set_config(..., true)`), so RLS permits the deletes even though the purger
   uses no search-path routing.
3. Opens a `TenantSession` and deletes, for every tenant table in
   `_delete_order()` — reverse `TenantBase.metadata.sorted_tables` order plus any
   table without a mapped model appended alphabetically — returning
   `{table: rowcount}` and committing once.
