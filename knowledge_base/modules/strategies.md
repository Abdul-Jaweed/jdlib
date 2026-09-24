# Module: Isolation Strategies (`src/jdlib/persistence/strategies/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Placement is data (`tenant_placements.strategy` + `target_handle`); this package
turns that data into a session, a provisioning action, a migration target and a
teardown. All three strategies expose the identical `TenantSession` surface, which
is what makes the strategy matrix tests (`shared`, `shared-rls`, `schema`,
`database`) run the same behavioural suite.

## The protocol (`base.py`)

```python
@dataclass(frozen=True, slots=True)
class StrategyCapabilities:
    supports_rls: bool
    supports_ddl: bool

class IsolationStrategy(Protocol):
    name: str
    capabilities: StrategyCapabilities
    async def session(self, tenant: TenantRecord) -> AsyncSession: ...
    async def provision(self, tenant: TenantRecord) -> None: ...
    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None: ...
    def migration_schema(self, tenant: TenantRecord) -> str: ...
    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None: ...
```

`TenantRecord.target_handle` carries the registry-validated placement handle
(schema name, database handle). Strategies never read the control plane.

| Strategy | `name` | `supports_rls` | `supports_ddl` |
|---|---|---|---|
| `SharedSchemaStrategy` | `shared` | **True** | False |
| `SchemaPerTenantStrategy` | `schema` | False | **True** |
| `DatabasePerTenantStrategy` | `database` | False | **True** |

## `SharedSchemaStrategy` (`shared.py`) — many tenants, one schema

`SharedSchemaStrategy(engine, schema="public", *, rls: RlsConfig | None = None)`

- Validates the schema name against `DEPLOYMENT_SCHEMA_RE`
  (`[a-z_][a-z0-9_]{0,62}` — deployment-configured, so `public` and `jt_test` are
  legal but `t_`-prefixed tenant schemas are not required here) and raises
  `StrategyCapabilityError` otherwise.
- `session()` returns an `AsyncSession`; when `rls.enabled` it registers an
  `after_begin` listener that executes
  `SELECT set_config('app.tenant_id', :tenant_id, true)` on **every**
  transaction (`true` = transaction-local). This is the RLS contract: the
  setting is re-asserted per transaction and disappears on commit/rollback.
  No engine configured ⇒ `StrategyCapabilityError`.
- `provision()` is a no-op; `migrate()` runs the tenant Alembic chain against the
  deployment schema; `deprovision()` is a no-op for **all** modes — a shared
  schema cannot be dropped per tenant (this is why `TenantRegistry` routes shared
  purges through `TenantPlanePurger` and raises when no purger is configured).
- `migration_schema()` returns the configured schema.

## `SchemaPerTenantStrategy` (`schema.py`) — one schema per tenant

`SchemaPerTenantStrategy(engine, runner=None, *, admin_engine=None)`

- Handle validation is strict: `_SCHEMA_RE = ^t_[a-z0-9][a-z0-9_]{0,50}$`
  (`validate_schema_name`). A `None` handle raises `StrategyCapabilityError`.
- Constructor registers a pool `reset` listener on the sync engine
  (`_reset_search_path`): on connection check-in it rolls back, runs
  `RESET search_path`, commits. The listener no-ops when the pool reset state is
  not asyncio-safe or is terminate-only. This is what stops a tenant schema
  leaking to the next borrower of the pooled connection.
- `session()` issues `SET search_path TO <quoted schema>` in an `after_begin`
  listener (quoted with the dialect's identifier preparer). This survives
  transaction and savepoint rollbacks — asserted by
  `tests/integration/test_schema_strategy_db.py`.
- `provision()` runs `CREATE SCHEMA IF NOT EXISTS <quoted>` on `admin_engine` or
  the main engine.
- `migrate()` → `runner.upgrade_tenant(handle)`; `migration_schema()` → handle.
- `deprovision()`: `archive` is a no-op; `purge`/`destroy` run
  `DROP SCHEMA IF EXISTS <quoted> CASCADE`.

## `DatabasePerTenantStrategy` (`database.py`) — one database per tenant

`DatabasePerTenantStrategy(*, admin_dsn, secrets: SecretProvider, runner=None,
max_targets=32)`

- Handle validation: `_HANDLE_RE = [a-z0-9][a-z0-9-]{0,50}` — handles are opaque
  (`db-acme-1`) and must never be DSNs (unit test `test_handle_is_opaque_never_a_dsn`).
  `_resolve()` maps handle → DSN via the `SecretProvider`, converting `KeyError`
  into `StrategyCapabilityError`.
- **Engine cache**: `OrderedDict[handle, AsyncEngine]`, populated lazily by
  `_engine_for()` and used as an LRU. The loop is careful about races:
  resolve → cached? `move_to_end` and return → snapshot `self._generation` →
  `_evict_idle()` → re-check cache → if the generation changed meanwhile,
  restart the loop (an `invalidate()` happened while awaiting) → if
  `len(engines) >= max_targets` raise `PoolCapacityError` → otherwise create the
  engine. `_evict_idle()` only evicts engines whose `pool.checkedout() == 0`.
- **`invalidate(handle)`** is the secret-rotation entry point: bump the
  generation, pop and `dispose()` the cached engine (disposing even with
  checked-out connections — SQLAlchemy closes those as they return; open sessions
  keep using the old DSN until they close), so the next `session()` re-resolves
  the secret. This contract is documented in the class docstring and covered by
  unit and DB tests.
- `provision()` under `AUTOCOMMIT` checks `pg_database` and runs
  `CREATE DATABASE <quoted>` when absent.
- `migrate()` → `runner.upgrade_tenant_url(tenant_dsn, "public")`;
  `migration_schema()` is always `"public"` (per-database layout).
- `deprovision()`: `archive` no-op; otherwise drop the cached engine, terminate
  other backends with `pg_terminate_backend(pid) FROM pg_stat_activity WHERE
  datname = :name AND pid <> pg_backend_pid()`, then `DROP DATABASE IF EXISTS`.
- `dispose()` closes every cached engine plus the admin engine (call it at
  shutdown and in tests).

## `rls.py` — PostgreSQL row-level security for shared placements

Helpers operate on **metadata**, not on a strategy instance, so consumer Alembic
environments can call them directly.

- `rls_eligible_tables(metadata)` — every `TenantRouted` subclass table in that
  metadata, sorted.
- `emit_rls_policies(connection, *, metadata, app_role=None)` — per table:
  `ALTER TABLE … ENABLE ROW LEVEL SECURITY`, `… FORCE ROW LEVEL SECURITY`,
  `DROP POLICY IF EXISTS tenant_isolation`, `CREATE POLICY tenant_isolation`
  with `USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)`
  and the same expression as `WITH CHECK`. With `app_role` it also grants
  `SELECT, INSERT, UPDATE, DELETE`.
- `install_rls(engine, *, metadata, app_role)` — sets `SET LOCAL lock_timeout =
  '5s'`, emits the policies in one transaction, and retries up to 3 attempts
  (0.25 s × attempt backoff) only for `DeadlockDetectedError` /
  `LockNotAvailableError`; then calls `verify_rls`. Emission is idempotent, and
  PostgreSQL's transactional DDL makes a retry safe.
- `verify_rls(engine, app_role, *, metadata)` — fails closed unless the app role
  exists, is neither `BYPASSRLS` nor superuser, and every eligible table has
  `relrowsecurity`, `relforcerowsecurity` and the `tenant_isolation` policy. A
  missing table reports a hint that the engine must be bound to the target schema
  (`search_path`).

The `NULLIF(current_setting('app.tenant_id', true), '')` expression is why an
unset setting yields **zero rows / zero writes** instead of all rows: the
predicate evaluates to `NULL`, which neither passes `USING` nor `WITH CHECK`
(`tests/integration/test_rls_db.py`).

## `deprovision.py`

`DeprovisionMode` — `archive`, `purge`, `destroy`. Consumed by
`TenantRegistry.deprovision` and by each strategy's `deprovision()`. Note that
`purge` and `destroy` currently behave identically at the strategy layer (both
drop/deallocate); the distinction is documentation-level in
`docs/jdlib/05` §5 and is not implemented differently in code — see
[../limitations_and_edge_cases.md](../limitations_and_edge_cases.md).

## Adding a strategy

Implement the five methods, declare `name` + `capabilities`, register it in the
`strategies` mapping passed to `TenantRegistry` and (for request routing) to
`SessionRouter`. `TenantRegistry.create` validates handles through
`validate_schema_name` / `validate_database_handle` / non-empty-for-shared, so a
new strategy with a different handle format needs either a compatible handle or a
change in `_validate_target_handle` (`control/registry.py:81`).
