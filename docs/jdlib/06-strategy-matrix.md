# jdlib — Strategy Matrix

Companion to the design spec (rev 2). Freezes per-strategy behavior, routing,
search_path and RLS hardening, pool safety, and failure modes. Hybrid is a
placement configuration, never a fourth strategy.

## 1. Capabilities

| Capability | Shared | Schema | Database |
|---|---|---|---|
| `supports_rls` | ✓ | | |
| `supports_ddl` | per-deploy | ✓ | ✓ |
| `routing_unit` | none | schema name | connection handle |
| `provision_cost` | O(row) | O(schema DDL) | O(database + DDL) |
| `isolation_strength` | logical | namespace | physical |
| `migration_distribution` | once | per schema | per database |
| `pool_model` | one pool | one pool, per-checkout `search_path` | pool per handle, capped |
| `best_for` | many small tenants | mid-market | enterprise/compliance |

The control plane is always a single, unrouted schema with its own pool and
`MetaData`; no strategy applies to it.

## 2. Routing

```
resolve tenant (control plane)
  → TenantContext
  → TenantRegistry.assert_servable(tenant)   # active AND migration success AND current = desired AND relocation permits serving
  → SessionRouter.route(tenant)
       placement.strategy: shared  → control-plane's tenant-plane engine (default handle)
                           schema → engine + SET search_path TO <validated handle>
                           database → pool for SecretProvider.resolve(target_handle)
  → TenantSession(context, connection)
```

- Pools are keyed by `(strategy, target_handle)`; a connection never serves two
  targets.
- `SessionRouter` caches pools lazily with a configurable max-pool cap
  (default: 64) and LRU eviction of idle pools. A hybrid deployment with many
  dedicated tenants cannot exhaust connections silently; cap exhaustion raises
  `PoolCapacityError`.
- Eviction safety: a pool with any checked-out connection is never evicted;
  eviction only closes fully idle pools. When the cap is reached and every
  candidate has checked-out connections, `PoolCapacityError` is raised instead
  of closing a live pool (test: checked-out Pool A must survive cap pressure).
- No strategy ever falls back to another target. Unresolvable placement raises
  `StrategyCapabilityError`.

## 3. Shared schema

- One tenant-plane schema; every tenant-scoped table has `tenant_id` in PK and
  all reads/writes scoped by `TenantSession`.
- Unique business keys are tenant-scoped (`(tenant_id, slug)`), so tenants
  cannot collide.
- Provisioning is a control-plane operation only (no DDL).
- `purge`/`destroy` delete tenant-plane rows through `TenantPlanePurger`
  (child-first, dependency-ordered `delete_where` over the registered
  tenant-plane models in a system-privileged `TenantSession`); per-table counts
  are audited as `tenant_counts` and `archive` deletes nothing.
- RLS optional (section 6); when enabled, the tenant setting is re-asserted on
  every transaction begin (section 6).
- Failure mode: a scoping bug would expose data — this is why I1/I2 tests and
  the metadata lint are phase gates.

## 4. Schema per tenant

- One database; schema name = `tenant_placements.target_handle`, validated at
  registration against `^t_[a-z0-9][a-z0-9_]{0,50}$`.
- `search_path` is re-asserted by the framework on every transaction begin
  (`after_begin` listener): `SET search_path TO <quoted handle>`; identifiers
  are quoted with driver-level quoting (SQLAlchemy's identifier preparer,
  `psycopg.sql.Identifier`, or equivalent), never string interpolation. A
  rollback or commit followed by another statement therefore stays bound to the
  tenant schema, not the connection default.
- Application code never sets or reads `search_path`; control-plane sessions use
  schema-qualified metadata and never share a pool with tenant sessions.
- On checkin, the pool `reset` listener issues `RESET search_path` (server
  default, typically `"$user", public`); even so, correctness does not depend on
  the reset because every transaction begins by setting the tenant schema.
- Migration distribution: run the tenant-plane chain once per schema, bounded
  concurrency (default 4) to protect the primary; each schema keeps its own
  `alembic_version`.
- Failure modes: missing schema → `StrategyCapabilityError` with handle; schema
  exists but migration state diverged → `blocked`; partially created schema is
  resumable by the idempotent provisioner.

## 5. Database per tenant

- `target_handle` maps through `SecretProvider` to a `ConnectionConfig`; no
  credentials in the database (section 7 of `05-tenant-lifecycle.md`).
- The router validates `context.tenant_id` against the placement row before
  returning a session; cross-tenant target access is impossible by construction.
- `tenant_id` predicates and stamps are still applied (uniformity, invariant
  I9); they also protect against misconfigured shared handles.
- `CREATE DATABASE ... TEMPLATE` is an optional fast path; correctness never
  depends on the template. Provisioning runs migrate + seed + health as usual.
- Pool cap and LRU eviction as in section 2; health checks on pool creation.

## 6. RLS (shared schema only)

- Enabled by config `rls: on`; requesting it with `schema`/`database` placement
  raises `StrategyCapabilityError` at startup.
- Coverage contract: **every tenant-routed model is RLS-eligible — framework
  tenant-plane tables and application resources alike**. Control-plane
  tenant-owned tables (`membership`, `role`, `role_binding`, `resource_grant`,
  `invitation`, `api_key`, `service_account`) are **not** tenant-plane RLS
  targets; they are protected by `ControlPlaneSession`, framework-only access,
  and explicit filtering/authorization. `jdlib.persistence.strategies.rls`
  ships the entry points: `rls_eligible_tables(metadata)` and the sync
  `emit_rls_policies(connection, *, metadata, app_role)` for consumer Alembic
  envs, plus the async `install_rls(engine, *, metadata, app_role)` which emits
  policies over a privileged connection and then runs `verify_rls`. Metadata
  lint L13 fails the build if any tenant-routed table lacks a policy when RLS is
  enabled, or if a control-plane table is included in tenant-plane RLS
  emission.
- Per table:

```sql
ALTER TABLE t ENABLE ROW LEVEL SECURITY;
ALTER TABLE t FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON t
  USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
  );
```

- Fail-closed predicate: when `app.tenant_id` is unset (or empty), `NULLIF`
  yields NULL, the comparison yields NULL, and the policy permits nothing —
  zero rows, zero writes. There is no SQL construct in the policy that can turn
  an unset setting into an allow.
- Runtime role: `NOBYPASSRLS`, not the table owner, not superuser; migrations run
  under a separate owner role. The startup self-check
  `verify_rls(engine, app_role, *, metadata)` fails closed unless the role
  exists with `NOBYPASSRLS` and is not superuser, every eligible table has
  `pg_class.relrowsecurity AND relforcerowsecurity` true, and a
  `tenant_isolation` policy exists in `pg_policies`; table names resolve through
  the connection's `search_path` (`to_regclass`), so verification runs against
  the same schema the runtime will use. `install_rls` runs it automatically;
  call it standalone when policies are managed by migrations.
- Every transaction begins with the transaction-local
  `SELECT set_config('app.tenant_id', '<uuid>', true)` (never a session-level
  `SET`); the value comes from `TenantContext`. The shared strategy re-asserts
  it on every transaction begin (`after_begin`), so a rollback or a commit
  followed by further statements stays bound, and the setting is gone after
  close/checkin.
- Tests: pool-leakage (A → checkout → B → checkout), unset setting (zero
  rows/writes), commit-then-continue re-binding and unset-after-close, consumer
  `TenantOwned` table (tenant B invoice invisible to tenant A with RLS on),
  `install_rls` → `verify_rls` self-check plus fail-closed negatives (missing
  policy, `NO FORCE`, bypassing role), and the strategy matrix with RLS on and
  off.

## 7. Hybrid placement

```
tenants: acme → shared      globex → schema t_globex     initech → database db-initech
```

- Placement is data; application code is identical across all three.
- Relocation between strategies is the manual procedure in
  `05-tenant-lifecycle.md` section 6.
- The test matrix runs every isolation test under all three placements in one
  process to prove independence.

## 8. Strategy-independent surface

| Never changes with strategy | Changes only inside adapters |
|---|---|
| `TenantContext`, envelope, resolution | Connection acquisition, pooling, routing |
| `TenantSession` API and scoping | DDL, provisioning, migration distribution |
| Composite identity and metadata lint | RLS emission and session settings |
| AuthN/AuthZ, PDP, `AccessControl` | Placement metadata interpretation |
| Audit sinks, lifecycle service | Target health checks, secret resolution |
| Application models and services | Capacity/eviction behavior |

## 9. Failure modes

| Condition | Behavior |
|---|---|
| Tenant not servable (`provisioning`, `suspended`, migration gate, relocation critical phase) | `TenantSuspended` / 404 semantics before routing |
| Tenant-plane mutation during relocation critical phase (any writer class) | `TenantNotWritable` (423); relocation-control operations exempt |
| Unknown strategy value | startup config validation error |
| Missing/unresolvable `target_handle` | `StrategyCapabilityError`, no fallback |
| Pool cap exceeded | `PoolCapacityError`, bounded latency, alert |
| Eviction candidate has checked-out connections | never evicted; `PoolCapacityError` under pressure |
| Schema missing after placement exists | `StrategyCapabilityError`; reprovision is idempotent |
| `alembic_version` ≠ desired | migration state `failed`/`blocked`; tenant suspended, never served on mismatch |
| RLS requested but role can bypass, table missing, unforced, or lacking `tenant_isolation` | `install_rls`/`verify_rls` fail closed with `StrategyCapabilityError`; no partial RLS deployment |
| RLS enabled and a tenant-routed table lacks a policy (or a control-plane table is wrongly included) | metadata lint L13 fails the build; no partial RLS deployment |
| RLS session setting missing | queries return zero rows (fail closed), never all rows |
| search_path not applied | queries fail with missing relation, never cross-schema read |
