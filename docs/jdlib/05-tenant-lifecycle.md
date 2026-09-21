# jdlib — Tenant Lifecycle

Companion to the design spec (rev 2). Freezes tenant states, provisioning and
migration semantics, idempotency, concurrency, deprovisioning, and relocation.

## 1. States

```
provisioning ──▶ active ──▶ suspended ──▶ archived ──▶ deprovisioning ──▶ deleted
                   ▲            │
                   └────────────┘ (resume)
```

| State | Requests admitted | Data | Allowed transitions |
|---|---|---|---|
| `provisioning` | no (404 semantics) | being created | `active`, `deleted` (rollback) |
| `active` | yes | live | `suspended`, `archived` |
| `suspended` | no (`TenantSuspended`, 423) | retained | `active`, `archived` |
| `archived` | no | retained, read-only admin access | `active` (restore), `deprovisioning` |
| `deprovisioning` | no | being removed | `deleted`, back to `archived` on failure |
| `deleted` | no | removed per mode | terminal |

- State changes are explicit lifecycle operations, audited
  (`tenant.created`, `tenant.suspended`, `tenant.resumed`, `tenant.archived`,
  `tenant.deprovisioned`).
- There is **no DB-level cascade from `tenants`**; all removal is explicit and
  ordered (schema lint `L6`).
- Only `active` tenants accept application traffic; control-plane reads
  (registry, operator views) remain available in every state.

## 2. Provisioning pipeline

Ordered steps, executed under a per-tenant advisory lock:

```
1. validate   slug format, uniqueness, requested placement
2. register   tenants(status=provisioning) + tenant_placements + tenant_migration_states(pending)
3. place      strategy.provision: create schema / database (or no-op for shared)
4. migrate    strategy.migrate: run tenant-plane chain; update migration state
5. seed       built-in roles (control plane), default tenant settings (tenant plane)
6. health     connect, SELECT 1, alembic_version == desired, RLS enabled if configured
7. activate   tenants.status=active; emit tenant.created + platform audit
```

Failure: the tenant remains `provisioning` (or moves to `deleted` on explicit
rollback); no partial tenant ever becomes `active`. Step 7 never runs implicitly.

### 2.1 Idempotency and resumability

Every step is safe to retry; provisioning is resumable from the first
incomplete step.

| Step | Retry behavior |
|---|---|
| validate | pure read; safe |
| register | upsert on `tenants.slug`; existing row with same placement is reused, conflicting placement raises `ProvisioningError` |
| place | `CREATE SCHEMA IF NOT EXISTS` / `CREATE DATABASE` guarded by catalog check; existing-and-empty target is reused, existing-and-foreign raises |
| migrate | Alembic is idempotent per target; re-running applies only pending revisions |
| seed | upsert roles by `(tenant_id, name)`; settings upsert by `(tenant_id, key)`; existing custom values are never overwritten |
| health | pure read; safe |
| activate | transition guarded by `WHERE status='provisioning'`; second run is a no-op |

### 2.2 Concurrency

- One lifecycle operation per tenant at a time, enforced with a Postgres
  transaction-scoped advisory lock keyed on the tenant id
  (`pg_advisory_xact_lock(hashtextextended('jdlib:tenant:' || id, 0))`).
- A second concurrent `provision`, `suspend`, or `deprovision` for the same
  tenant waits, then re-reads state and either no-ops (already in the target
  state) or raises `TenantOperationInProgress`.
- Lifecycle operations on different tenants proceed in parallel.

## 3. Migration state machine

```
pending ──▶ running ──▶ success
                │
                ├──▶ failed ──▶ (retry) pending
                └──▶ blocked          # requires operator decision
```

Rules:

- `tenant_migration_states.current_version` changes only after the target's
  `alembic_version` is committed.
- `status='failed'` records `last_error`; the tenant stays on its previous
  version and remains usable unless the operator explicitly suspends it for
  non-backward-compatible changes.
- `blocked` means automated retry is unsafe (divergent schema detected); a
  platform operator must resolve and reset the state to `pending`.
- Activation invariant (`tenant_migration_states.status='success' AND
  current_version = desired_version`) is checked by the health step and by the
  `TenantRegistry.assert_servable(tenant)` gate used by the router.
- A failed migration never silently appears `active`-with-new-version: version
  and status are written in one transaction.

## 4. Suspension

- Suspending sets `tenants.status='suspended'`, `suspended_at`, and immediately
  denies all requests (precedence chain gate 2).
- Suspension does not touch tenant-plane data, bindings, or sessions; it is
  reversible.
- Membership-level and user-level suspension narrow access without deleting
  anything (gates 1 and 3).
- Resumption restores previous state; no re-provisioning is needed.
- Suspension is audited with the operator identity and reason.

## 5. Deprovisioning

Explicit operation with three modes:

| Mode | Effect |
|---|---|
| `archive` | no storage change; records intent; tenant enters `archived` |
| `soft` | logical delete; control-plane rows retained (audit, billing); tenant-plane storage dropped |
| `drop` | full removal: tenant-plane storage dropped, target deallocated, control-plane access rows deleted, audit retained |

Ordering for `soft`/`drop` (under lifecycle lock):

```
1. status=deprovisioning (denies traffic)
2. revoke sessions/keys: api_keys, invitations (control plane, CASCADE-safe)
3. delete access rows: role_bindings, resource_grants, roles (control plane)
4. delete memberships (control plane)
5. strategy.deprovision: drop schema/database per mode (tenant plane)
6. tenants.status=deleted; tenant_placements/migration_states retained for audit
7. platform audit: tenant.deprovisioned with mode and counts
```

- `archived` is reversible; `deleted` is terminal.
- Backups/retention are the deployment's responsibility; the framework emits
  the audit record needed to prove deletion.
- Audit events (`platform_audit_events`) are never removed by tenant deletion;
  tenant-plane `audit_events` are removed with the tenant (mode-dependent).

## 6. Tenant relocation (manual procedure, v1)

Strategy changes for an existing tenant are an operational procedure, not an
application feature:

```
1. provision new target via a new tenant_placements row (same tenant id)
2. copy data (logical export/import or logical replication)
3. verify: row counts, migration version, seed invariants, health checks
4. flip: update tenant_placements (strategy, target_handle) in one transaction
5. deprovision old target
6. audit: tenant.relocated with from/to placement
```

Rollback: the old placement row is kept until step 5; flipping back restores
service. Application code is unaware; ids do not change; logical references
remain valid. Automated relocation is explicitly out of v1 scope.

## 7. Secret and target resolution

- `target_handle` is opaque (`db-tenant-acme`), never a DSN or credential.
- `SecretProvider.resolve(handle) -> ConnectionConfig` is an interface; the
  default implementation reads from environment/secret manager; no credentials
  are ever stored in the database.
- Rotation happens behind the provider; the router caches pools keyed by handle
  and rebuilds them on credential-version change.
- Missing or unresolvable handle fails the router with
  `StrategyCapabilityError` and is never a silent fallback to the shared target.

## 8. Lifecycle test gates

| Test | Asserts |
|---|---|
| provisioning idempotency | `provision` × 3 leaves one target, one role set, one settings set |
| provisioning failure | failure at any step never yields `active` |
| concurrent lifecycle | two parallel provisions for one tenant serialize; different tenants parallelize |
| migration state | failed migration leaves prior version servable; no silent state |
| activation gate | `assert_servable` rejects `current != desired` and non-`success` |
| suspension | suspended tenant denies and resumes without data change |
| deprovision ordering | access rows gone before storage drop; audit retained |
| relocation | flip preserves ids and logical references; rollback restores service |
| secret resolution | missing handle fails closed, no fallback to shared |
