# Limitations and Edge Cases

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Everything below is verified against the code or the design docs — this page
exists so nobody plans around a capability that is not there.

## 1. Relocation is modelled, not implemented

`RelocationPhase` (enum), `TenantRelocation` (table with phase CHECKs and a
partial unique index), `CRITICAL_RELOCATION_PHASES`, and
`privileged_bypass()`'s `relocation.manage` capability all exist. What does not
exist: any code that creates, drives or completes a relocation. There is no
service, no CLI command, no test that moves a tenant between placements.
`RelocationPhaseError` is defined and never raised.

*Consequence*: a relocation is a manual, out-of-band procedure; the library's
contribution is (a) refusing to serve a tenant whose relocation row is in a
critical phase and (b) letting a `relocation.manage` system context bypass the
write fence while you do it.

## 2. `MigrationError` is never raised

Migration failures surface as `ProvisioningError` (registry) or
`StrategyCapabilityError` (strategy/runner). Do not write `except MigrationError`.

## 3. `purge` and `destroy` behave identically at the strategy layer

`DeprovisionMode.ARCHIVE` is a no-op for schema and database strategies and for
shared. `PURGE` and `DESTROY` both drop the schema/database (or, for shared, both
trigger `TenantPlanePurger.purge`). The only difference between the two modes in
code is documentation and audit metadata. Anything that must differ (e.g. object
storage, external systems) is the application's job.

## 4. Shared-placement purge is row-by-row, and requires a purger

`SharedSchemaStrategy.deprovision()` does nothing. `TenantRegistry.deprovision`
therefore *requires* a `TenantPlanePurger` for a shared tenant and raises
`ProvisioningError` otherwise. The purger deletes per `TenantRouted` table with
`delete_where`, in `reversed(TenantBase.metadata.sorted_tables)` order, with any
table not in the metadata appended alphabetically. Practical limits:

- It issues one DELETE per table — correct and auditable, but not fast for a
  tenant with millions of rows.
- It only touches tables registered in the metadata that the purger's process
  imported. A model class that was never imported is invisible to
  `tenant_table_map()` and therefore **not** purged. Import all model modules
  before lifecycle work (the CLI does this via `_import_framework_models`).
- Rows in tenant tables that live in another database (database placement) are
  handled by the strategy's DROP, not by the purger.

## 5. `TenantSession` scope limits

- `execute()` rejects `TextClause`; there is no `session.connection().execute`
  escape hatch documented for application code (raw SQL goes through `raw_sql`).
- The scoping events are registered **on the session object**. Creating your own
  `AsyncSession` (or using `session.begin()` on one obtained elsewhere) gives you
  an unscoped session; `TenantRepository` requires a `TenantSession` by signature,
  but nothing stops `session.execute(select(...))` on a bare session in your own
  code.
- `with_loader_criteria` covers ORM statements. Core statements built directly on
  `Table` objects inside a `TenantSession` are rejected rather than scoped — by
  design, but it means legacy Core code must migrate to ORM entities.

## 6. Raw SQL: what `PRIVILEGED` does and does not relax

`platform.raw_sql` waives the tenant-predicate proof only. Multi-statement SQL,
CTEs, schema-qualified relations and non-DML statement types are still rejected;
`tenant.raw_sql` keeps the predicate proof as well. There is no mode that accepts
arbitrary DDL — DDL belongs in migrations. Also note the validator compares
**bound values**: a query that passes the same UUID as the context passes, even if
the author intended another tenant, so the guarantee is "this statement touches
only rows the context can already reach", not "the author meant this tenant".

## 7. RLS is opt-in, per deployment, and only for shared placements

- `SchemaPerTenantStrategy`/`DatabasePerTenantStrategy` declare
  `supports_rls=False`; RLS is a shared-placement tool.
- Policies are emitted by `emit_rls_policies`/`install_rls` — the library does not
  install them automatically, and `verify_rls` fails closed when a table is
  missing them, which means a half-migrated deployment refuses to start rather
  than running unprotected.
- `install_rls` uses `lock_timeout = '5s'` and retries deadlocks three times; on a
  very busy table it can exhaust retries.
- The policies require `app.tenant_id` to be set **per transaction**; any code
  path that uses a raw connection from the shared engine without the strategy's
  `after_begin` listener sees zero rows (safe, but confusing when it happens).
- `verify_rls` needs `app_role`; without it there is no verification target.

## 8. Authorization model gaps

- **No cross-request authz cache** (`AuthzCache` is request-scoped and one-way
  invalidated). Multi-process deployments will do the same DB reads per request.
- **`AccessControl` authority is tenant-scope only** — an org- or team-scoped
  `role:manage` binding cannot administer anything (see
  [design_decisions.md](design_decisions.md) D11). This surprises people who bind
  admin roles at org scope; the binding succeeds, the authority does not.
- **No deny rules, no wildcards, no role inheritance.** Permissions must be
  enumerated; a role cannot be "all resource permissions".
- **`Enforcer.require` reads the session from `kwargs["session"]`** — using
  `requires(...)` on a function that takes its session positionally silently
  bypasses the lookup and raises `MissingTenantContext` instead of authorizing.
- **The FastAPI guard/handler TOCTOU window** is documented in
  [api/fastapi.md](api/fastapi.md): the guard authorizes in its own transaction,
  the handler runs in another.
- **`grants_for`/resource grants** attach to one exact resource; there is no
  "all invoices in this team" sharing.
- `ScopeResolver` walks `parent_organization_id` with a cycle guard; a deep
  hierarchy costs one query per level (the chain is memoized per request only).

## 9. Middleware / resolver seams

- `TenantMiddleware._request_info` builds `RequestInfo(..., claims={})`. Nothing
  populates JWT claims for the chain, so `JwtClaimResolver` only works when you
  resolve claims yourself (or bypass the chain). This is the sharpest
  inconsistency between the docstrings' intent and the shipped pipeline.
- One context per request. Multi-tenant requests (one HTTP call touching two
  tenants) are not supported; use a privileged/system path explicitly.
- The error body shape (`{"error", "detail"}`) and the request-id headers are
  fixed; there is no configuration hook for them.

## 10. Lifecycle and control-plane edges

- `TenantRegistry` requires a `PlatformAudit` sink; there is no "disabled audit"
  mode. The CLI supplies a `DatabaseAuditSink`; tests supply a recording sink.
- `create()` is idempotent only for an identical placement slug+strategy+handle+region;
  changing a tenant's strategy means deprovision + recreate (no in-place placement
  change).
- `target_handle` uniqueness applies **only to `schema` and `database`**
  placements (`registry.py:230-250`, guarded by an advisory handle lock): a
  physical target belongs to at most one tenant. `shared` placements are exempt,
  so many shared tenants legitimately carry the same handle (typically
  `default`/the deployment schema) — the exemption is what makes a shared
  deployment expressible.
- Advisory locks (`pg_advisory_xact_lock(hashtext('jdlib.tenant_write'))`) are
  cluster-wide per database: all lifecycle operations serialize on one lock.
- `deprovision` requires the tenant to be `archived` first; `active → deprovisioning`
  is not a legal transition. `mode=archive` is a transition to `archived`
  (idempotent) and refuses to run while the tenant has children unless you pass
  `detach_children=True`, which detaches them.
- There is no fence drain: `RegistryWriteFence` is stateless (its only method is
  `assert_writable`, which re-derives servability per unit of work). A tenant
  being archived/deprovisioned stops accepting writes immediately *for new units
  of work*, but a session opened before the transition keeps its transaction — the
  library does not (and cannot) revoke it.

## 11. Migrations

- Only `0001` baselines exist per plane; they use `create_all`, so a fresh install
  gets the current models but an existing database will **not** pick up new
  columns without a new revision you write yourself.
- `downgrade()` drops all framework tables (`drop_all(checkfirst=True)`) — never
  run it against data you want to keep.
- `MigrationRunner` is synchronous (Alembic + psycopg). Calling it from an async
  request path blocks the event loop; run it at startup/CLI/job time.
- `tenant_version()` returns `None` when the version table is missing, which the
  registry treats as "not migrated" — a tenant whose schema exists but was never
  migrated is therefore not servable (by design).

## 12. Packaging / repo hygiene

- `jdlib/control/` and `jdlib/models/` are **implicit namespace packages** (no
  `__init__.py`), unlike the other subpackages. Imports work, but tools that walk
  packages by `__init__.py` (some import sorters, some coverage configs) will skip
  them.
- Version is `0.1.0` in both `pyproject.toml` and `__init__.py`; there is no
  changelog, no release automation, no published-artifact workflow, and no
  deprecation policy.
- `mypy` is strict **only for `src/jdlib`** (`files = ["src/jdlib"]`); the tests
  are not type-checked. Ruff covers the whole repo.
- There is no coverage measurement in CI, no PostgreSQL version matrix, and no
  Windows/macOS job.
- The repository root contains `JDLib-Architecture.md`, which is **untracked**
  (per `git status`) rather than under `docs/`.

## 13. Small implementation details that bite

- `uuid7()` is a timestamp-prefixed random UUID: version 7 and RFC 9562 **variant**
  bits are set, but there is no monotonic counter, so two ids generated in the same
  millisecond are not orderable relative to each other. Ordering is
  time-bucketed, not strict.
- `TenantRepository.soft_delete` requires the model to have `deleted_at` and
  raises `TypeError` otherwise; `update()` will happily set `deleted_at` directly,
  bypassing the "live rows only" filters on the next query.
- `JwksCache` refetches at most once per second for unknown `kid`s; behind a
  proxy that caches JWKS aggressively, new signing keys are invisible until the
  proxy's TTL expires.
- `OidcAuthenticator` silently ignores tokens whose header is not a JWT with a
  string `kid` — a malformed JWT without `kid` produces 401 with no audit row.
- `ApiKeyAuthenticator` ignores tokens with a different prefix **without auditing**
  (intentional; it is not its credential), so a misconfigured prefix looks like
  "no credentials presented" (401) rather than "invalid key".
- Control-plane sessions built for `UserLinker` must use `expire_on_commit=False`;
  the object it returns is read after its session closes.
- `DatabasePerTenantStrategy.invalidate()` disposes an engine that may have
  checked-out connections: those connections keep working with the old secret
  until they are released. Rotate secrets at a quiet moment or accept a window.
