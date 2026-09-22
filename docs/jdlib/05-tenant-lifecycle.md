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
- `failed` and `blocked` on an already-active tenant immediately suspend it:
  `tenants.status='suspended'`, `suspended_reason='migration_failed'`, audited.
  The tenant does not serve on a version mismatch (fail closed); an operator
  resolves the migration and explicitly resumes. There is no
  "failed but usable" state.
- `blocked` means automated retry is unsafe (divergent schema detected); a
  platform operator must resolve and reset the state to `pending`.
- Servability is a single predicate used by the health step, the router, and
  `TenantRegistry.assert_servable(tenant_id) -> TenantRecord`:
  `tenants.status='active' AND migration.status='success' AND
  current_version = desired_version AND relocation permits serving`
  (relocation blocks serving in `copying`, `verifying`, `flipping`,
  `post_flip_verification` — section 6).
- A failed migration never silently appears `active`-with-new-version: version
  and status are written in one transaction; the suspension transition is part
  of the same operation.

## 4. Suspension

- Suspending sets `tenants.status='suspended'`, `suspended_at`,
  `suspended_reason`, and immediately denies all requests (precedence chain
  gate 2).
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
| `purge` | destroys tenant-plane storage; control-plane rows retained (audit, administrative metadata) |
| `destroy` | full removal: tenant-plane storage dropped, target deallocated, control-plane access rows deleted, audit retained |

Ordering for `purge`/`destroy` (under lifecycle lock):

```
1. status=deprovisioning (denies traffic); the lock is released by this commit
   and re-acquired immediately after, with the state re-verified before any
   destructive step
2. revoke credentials: api_keys, service_accounts, invitations (control plane,
   CASCADE-safe)
3. delete access rows: role_bindings, resource_grants, role_permissions, roles
   (control plane)
4. delete memberships (control plane)
5. strategy.deprovision: drop schema/database per mode (tenant plane)
6. tenants.status=deleted; tenant_placements/migration_states retained for audit
7. platform audit: tenant.deprovisioned with mode and counts (plus
   `detach_children`/`detached_children` when children were detached)
```

- `archived` is reversible; `deleted` is terminal.
- **Shared-schema `purge` limitation (tracked):** a shared-schema placement does
  not physically separate the tenant plane, so `strategy.deprovision` is a no-op
  and `purge` (and `destroy`) currently retain the tenant-plane rows.
  Privileged, RLS-scoped tenant-plane deletion arrives with Plan 5; until then
  this is a known compliance limitation. The `tenant.deprovisioned` audit record
  proves the control-plane deletion only.
- Parent/child: deleting a tenant that has `parent_tenant_id` children is
  blocked (`ON DELETE RESTRICT`) while children exist; the operation supports an
  explicit `detach_children=true` that clears their `parent_tenant_id` first
  (audited, including the detached child ids). Cascade deletion of children
  never happens implicitly.
- Backups/retention are the deployment's responsibility; the framework emits
  the audit record needed to prove deletion.
- Audit events (`platform_audit_events`) are never removed by tenant deletion;
  tenant-plane `audit_events` are removed with the tenant (mode-dependent).
- Mandatory platform audit events (lifecycle transitions, migration results,
  access-control changes, privileged use, authentication and resolution
  failures) must be durably recorded before the operation is considered
  complete; if the sink is unavailable the operation fails closed. Informational
  events are best-effort with buffering.

### 5.1 Audit transaction ordering (frozen)

| Operation shares a transaction with its audit? | Ordering |
|---|---|
| Control-plane mutation | **Same transaction**: business row + platform audit commit or roll back together |
| Tenant-routed mutation | **Same transaction** (tenant DB): mutation + `AuditEvent` commit or roll back together |
| Cross-plane (operator/system mutating tenant data) | Mandatory platform audit is durably committed **before** the tenant transaction applies the mutation; the tenant transaction carries its own `AuditEvent`. If the tenant transaction fails, the platform event remains as a record of the attempted operation. A durable outbox is the documented future upgrade if stronger cross-plane atomicity is required |

There is no path where a business commit succeeds and a required audit event
fails afterwards.

## 6. Tenant relocation (manual procedure, v1)

Strategy changes for an existing tenant are an operational procedure, not an
application feature. `tenant_placements` remains the **authoritative current
placement** (exactly one row per tenant); the in-flight operation is recorded as
a `tenant_relocations` row (control plane, `02` section 3.3.1). The placement
row is updated exactly once, at the atomic flip.

```
1. acquire tenant lifecycle/relocation lock
2. create TenantRelocation(status=pending)      # from_* captured from current placement
3. provision destination target; status=provisioning
4. quiesce: status flips to copying in one transaction with the write-fence
   transition
   a. assert_servable → false (new HTTP traffic rejected)
   b. assert_writable → false (every tenant-plane mutation rejected: HTTP,
      jobs, queues, CLI, service-to-service, privileged tenant writes)
   c. drain: wait for all pre-existing tenant transactions to finish
      (bounded by the configured maximum transaction duration + grace)
5. snapshot + copy data (logical export/import or logical replication)
6. verify destination: row counts, migration version, seed invariants, health
   checks; status=verifying        (failure → failed, placement untouched)
7. flip (single transaction): update tenant_placements to to_* + status=flipping
   → post_flip_verification
8. post-flip health check on the new target while serving/writes stay blocked
   ├── success → status=completed; restore serving; deprovision old target
   └── failure → rollback: restore tenant_placements to from_* in one transaction;
                 status=rolled_back; serving/writes stay blocked; retain BOTH targets
9. audit events at each phase (section 6.1)
```

Critical invariant: the snapshot begins only after **all pre-existing tenant
writes have completed and new writes are rejected**. The write fence is checked
at session/transaction start by `TenantSession`, `UnitOfWork`, and tenant job
execution — HTTP middleware is never the only enforcement point. Drain is
bounded: after the fence is set, the relocation runner waits
`relocation_drain_grace` (config; default 2× the configured maximum transaction
duration), so any transaction admitted before the fence must have committed or
aborted. Long-running tenant transactions are therefore bounded by
configuration; exceeding the bound fails the relocation rather than risking a
late write.

Serving gate vs write fence (separate concepts, both in `TenantRegistry`):
`assert_servable()` answers "may this tenant receive normal application
traffic?" and `assert_writable()` answers "may this tenant receive a mutation
right now?". They coincide today (`servable → writable`), and are split so a
future read-only operational state (`servable=true, writable=false`) needs no
redesign. Relocation control operations run under a system context with the
relocation-manage capability and bypass the fence explicitly.

Phase transitions are the table in `02` section 3.3.1; invalid transitions raise
`RelocationPhaseError`, and `failed`/`rolled_back` retry is an explicit
operator action that returns the record to `pending`.

Rules:

- The old target remains fully provisioned and reachable until
  `status='completed'`; deprovisioning it earlier is a contract violation.
- The flip is one transaction over `tenant_placements` + relocation status; no
  observer can see a half-flipped tenant.
- Relocation uses the same per-tenant advisory lock as other lifecycle
  operations; concurrent relocations for one tenant are rejected
  (`TenantOperationInProgress`), and the DB partial unique index is the second
  guard.
- Every phase is idempotent/resumable from the recorded status; re-running a
  completed phase is a no-op.
- Application code is unaware; ids do not change; logical references remain
  valid. Automated relocation is explicitly out of v1 scope.

### 6.1 Relocation audit events (frozen)

`tenant.relocation.started` · `.provisioned` · `.copying` · `.verified` ·
`.flipped` · `.completed` · `.failed` · `.rolled_back`

Each event carries `tenant_id`, `relocation_id`, `from_strategy`,
`from_target`, `to_strategy`, `to_target`, `outcome`, `error`, `actor`,
`request_id`, `correlation_id`. `.failed` and `.rolled_back` are mandatory
platform audit events (fail closed if the sink is unavailable), so an
operational investigation never lacks the trail.

Relocation test names (frozen): `test_relocation_blocks_application_traffic`;
`test_relocation_blocks_writes_during_post_flip_verification`;
`test_relocation_does_not_serve_after_placement_flip_until_verified`;
`test_relocation_rollback_cannot_lose_post_flip_writes`;
`test_relocation_completion_restores_servability`;
`test_relocation_creates_operation_record`;
`test_relocation_preserves_current_placement_until_flip`;
`test_relocation_destination_is_verified_before_flip`;
`test_relocation_flip_updates_authoritative_placement`;
`test_relocation_post_flip_failure_rolls_back`;
`test_relocation_old_target_retained_until_verification`;
`test_relocation_cannot_run_concurrently`;
`test_relocation_is_idempotent`;
`test_relocation_blocks_http_writes`;
`test_relocation_blocks_background_job_writes`;
`test_relocation_blocks_service_to_service_writes`;
`test_relocation_blocks_cli_tenant_writes`;
`test_relocation_blocks_privileged_tenant_writes`;
`test_relocation_allows_relocation_control_operations`;
`test_no_write_can_occur_after_relocation_snapshot` (racing writer admitted
before the fence must commit before snapshot; a writer arriving after the fence
is rejected).

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
| migration state | failed/blocked migration on an active tenant suspends it with `suspended_reason='migration_failed'`; prior version not served |
| activation gate | `assert_servable` accepts only `active AND success AND current=desired`; rejects every other combination |
| suspension | suspended tenant denies and resumes without data change |
| deprovision ordering | access rows gone before storage drop; audit retained |
| parent deletion | parent with children blocked; `detach_children=true` detaches then deletes |
| relocation | operation record created; placement preserved until flip; destination verified before flip; traffic/writes blocked during critical phases; post-flip failure rolls back with no write loss; old target retained until `completed`; serving restored on completion; concurrent relocations rejected; re-runs idempotent |
| invitation tokens | valid accepted; wrong/expired/revoked/already-accepted/tampered/duplicate/nonexistent `token_id` all rejected; Argon2id verify is the only acceptance path |
| mandatory audit | lifecycle operation fails when the audit sink is unavailable |
| secret resolution | missing handle fails closed, no fallback to shared |
