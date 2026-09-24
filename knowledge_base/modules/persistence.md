# Module: Persistence Core (`src/jdlib/persistence/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

The heart of the library: one data-access API that behaves identically for every
placement, with tenant scoping enforced by SQLAlchemy session events rather than
by developer discipline.

| File | Lines | Responsibility |
|---|---|---|
| `models.py` | 47 | `tenant_table_map()`, `WriteFence`/`NullWriteFence`, `privileged_bypass()`. |
| `session.py` | 363 | `TenantSession` + the three registered event handlers + `raw_sql`. |
| `rawsql.py` | 256 | `RawSqlValidator` / `RawSqlMode` / `CompiledRawSql` (pglast structural proof). |
| `uow.py` | 41 | `UnitOfWork` — write fence, session lifecycle, commit/rollback. |
| `repository.py` | 77 | `TenantRepository[ModelT]`. |
| `router.py` | 23 | `SessionRouter`. |
| `secrets.py` | 31 | `SecretProvider` + memory/env implementations. |

## `persistence/models.py` — discovery and fences

- `tenant_table_map() -> dict[str, type]` — imports `jdlib.models.org|settings|audit`
  and walks `TenantRouted.__subclasses__()` recursively, returning
  `{table_name: model}` for every subclass whose table lives in
  `TenantBase.metadata`. Consumers' models join the map automatically. Called by
  `TenantSession` (per session), `RawSqlValidator` (per instance) and
  `TenantPlanePurger`/`rls_eligible_tables`.
- `WriteFence` protocol: `assert_writable(tenant_id) -> None`.
  `NullWriteFence` allows everything (default when a caller builds a `UnitOfWork`
  outside a lifecycle-managed app).
- `privileged_bypass(context) -> bool`: true only when
  `context.privilege.kind is SYSTEM` **and** `capability == "relocation.manage"`.
  That is the single sanctioned escape from the write fence.

## `TenantSession` (`session.py`) — the enforcement surface

Construction (`session.py:257`) requires a `TenantContext`; a `None` context
raises `MissingTenantContext` immediately (invariant I1 "no context, no tenant
data"). It stores the context under `session.sync_session.info["jdlib_context"]`
and registers the handlers below on that specific session object.

| Method | Notes |
|---|---|
| `execute(statement)` | Rejects `TextClause` outright ("use raw_sql for text statements"); everything else goes through the events. |
| `get(model, entity_id)` | For `TenantRouted` models uses the **composite** key `(tenant_id, entity_id)`; otherwise the plain key. |
| `add(obj)` / `delete(obj)` | Delegate to the ORM; `delete()` on a `SoftDelete` model requires a privileged context (enforced in `before_flush`). |
| `update_where(model, values, *criteria)` | Builds `update(model).where(model.tenant_id == ctx.tenant_id, *criteria)` with `execution_options(jdlib_scoped=True)`; refuses `tenant_id` in `values` without privilege; returns rowcount. |
| `delete_where(model, *criteria)` | Same shape with `delete()`; refuses `SoftDelete` models without privilege. |
| `raw_sql(statement, params=None, *, mode=TENANT_BOUND)` | Compile → validate → execute with `jdlib_raw_sql=True`. |
| `flush/commit/rollback/close` | Direct delegation; `__aenter__/__aexit__` close on exit. |

### Handler 1 — `do_orm_execute`, SELECT path (`session.py:130-211`)

1. No context on the session ⇒ `MissingTenantContext`.
2. `FromStatement` (i.e. `select(...).from_statement(...)`) is rejected with
   `UnscopedRawSql` — ORM selects must be expressed as real ORM selects.
3. Every node in the statement tree is scanned with `visitors.iterate`:
   `TextClause` and SQL literal fragments (`is_literal`, except the `*` of a
   `count(*)`) raise `UnscopedRawSql`.
4. Tenant tables are collected from entities, `_from_obj`, `_setup_joins`, and
   FROM elements. "Trusted" mappers are those whose `local_table` is one of the
   statement's direct FROM tables *and* which subclass `TenantRouted`; the bind
   mapper and entity-derived mappers are added.
5. Any tenant table that is **not** covered by a trusted mapper — i.e. a
   table-level statement, or an alias not derived from an entity — raises
   `UnscopedRawSql` ("aliases of tenant tables must be entity-derived; use
   `aliased(Entity)` or `raw_sql`").
6. `with_loader_criteria(cls, cls.tenant_id == ctx.tenant_id,
   include_aliases=True)` is applied for each trusted mapper, which SQLAlchemy
   propagates into relationship loads, eager loads and subqueries.

### Handler 2 — `do_orm_execute`, bulk DML path (`session.py:212-224`)

Any ORM-enabled INSERT/UPDATE/DELETE against a tenant table that lacks the
internal `jdlib_scoped` / `jdlib_raw_sql` execution option raises
`UnscopedBulkOperation` — the error message points at
`update_where`/`delete_where`/`raw_sql`. `_direct_tables`/`_underlying_table`
unwrap `_Annotated__element` chains to compare real `Table` objects, so
`aliased(Entity)`-style statements remain allowed.

### Handler 3 — `before_flush` (`session.py:226-253`)

- **New** `TenantRouted` objects: a missing `tenant_id` is stamped from the
  context; a different `tenant_id` raises `CrossTenantReferenceError` (I4).
- **Dirty** objects: any change to `tenant_id` raises
  `CrossTenantReferenceError` — it is immutable after insert (I3).
- **Deleted** objects: a `SoftDelete` instance in `session.deleted` without a
  privileged context raises `AuthorizationError` ("hard delete requires a
  privileged context").

## `raw_sql` modes and `RawSqlValidator` (`rawsql.py`)

```python
await session.raw_sql(sa.text("SELECT * FROM invoices WHERE tenant_id = :tid"),
                      {"tid": ctx.tenant_id})                      # TENANT_BOUND (default)

await session.raw_sql(sa.text("DELETE FROM invoices WHERE tenant_id = :tid"),
                      {"tid": ctx.tenant_id}, mode=RawSqlMode.PRIVILEGED)
```

`RawSqlMode.PRIVILEGED` requires a `PrivilegeContext` whose capability is
`tenant.raw_sql` (predicate validation still applies) or `platform.raw_sql`
(predicate waived, structural rejects kept). Both privileged paths record the
statement through the injected `RawSqlAuditor` (no-op by default). A missing
privilege or capability raises `AuthorizationError`.

Pipeline: SQLAlchemy `TextClause` → compile with the session dialect →
`pglast.parse_sql` → AST validation. Bind values are read positionally from the
compiled `positiontup`, so `$n` placeholders are checked against *actual bound
values*, not names.

Rejected in `TENANT_BOUND` (each has a unit test in `tests/unit/test_rawsql.py`):

| Rejection | Reason |
|---|---|
| not exactly one statement / unparseable SQL | `RawSqlValidator._parse` |
| any CTE (`WITH …`) | `_reject_cte` |
| subqueries: `SubLink`, `RangeSubselect` | `_scan_expression_tree`, `_relations` |
| relations outside the FROM clause | `_scan_expression_tree` |
| schema-qualified relations (`other.table`) | `_check_relation` |
| unknown relations (not in `tenant_table_map()`) | `_check_relation` |
| `OR` / `NOT` in the WHERE (any non-AND boolean node) | `_conjuncts` |
| missing `tenant_id = $n` for any referenced relation (joins included) | per-relation check with alias qualifiers |
| `tenant_id` in an UPDATE target list or `ON CONFLICT` set list | `_reject_tenant_id_assignments` |
| `INSERT` without an explicit `tenant_id` column | `_validate_insert` |
| `INSERT` whose bound `tenant_id` ≠ context tenant (per values row) | `_validate_insert` |
| `INSERT … SELECT` | `_validate_insert` |
| statement types other than SELECT/INSERT/UPDATE/DELETE | `validate_tenant_bound` |

`validate_privileged` keeps the single-statement/CTE/DDL rejects and skips the
predicate proof. Note `_column_is_tenant_id` accepts both `tenant_id` and
`alias.tenant_id` forms, and requires the *value* to be the exact context tenant
UUID — `IS DISTINCT FROM`, `ANY`/`ALL` forms, and literal values never satisfy it.

## `UnitOfWork` (`uow.py`)

```python
async with UnitOfWork(session_factory, context, fence=fence, auditor=auditor) as session:
    ...
```

- On enter: unless `privileged_bypass(context)`, call `fence.assert_writable(
  context.tenant_id)` (a suspended tenant or a relocation quiesce raises
  `TenantNotWritable` **before** any session is opened); then create a fresh
  `AsyncSession` and wrap it in `TenantSession`.
- On exit: commit when no exception, roll back when an exception propagates, then
  close — always all three, in that order (`finally`).
- Each `UnitOfWork` gets its own session, so two units of work in one request are
  two transactions (this is why the FastAPI guard and the handler are not
  atomic; see [api/fastapi.md](../api/fastapi.md)).

## `TenantRepository[ModelT]` (`repository.py`)

Soft-delete-aware repository used inside a `TenantSession`:

| Method | Behaviour |
|---|---|
| `get(entity_id)` | Model has `deleted_at` ⇒ `SELECT … WHERE id = :id AND deleted_at IS NULL`; otherwise `session.get`. |
| `list(*criteria, order_by=None, limit=None, offset=None)` | Always adds the live filter; extra criteria are AND-ed. |
| `add(obj)` | add + flush, returns the object. |
| `update(obj, **changes)` | `setattr` loop + flush. |
| `soft_delete(obj)` | Sets `deleted_at = now(UTC)`; raises `TypeError` when the model has no `deleted_at`. |
| `count(*criteria)` | `SELECT count(*)` with the live filter. |

The repository adds **no** tenant predicate of its own — the `TenantSession`
events do that. Running it on a raw `AsyncSession` would therefore be unscoped;
the type signature requires a `TenantSession`.

## `SessionRouter` (`router.py`)

`SessionRouter({PlacementStrategy.SHARED: shared, …}).session(tenant_record)`
looks up the strategy and delegates to `strategy.session(tenant)`; an
unregistered placement raises `StrategyCapabilityError`. Typically driven with
`await registry.assert_servable(tenant_id)` as the `TenantRecord` source, so
routing and servability stay consistent.

## `secrets.py`

`SecretProvider.resolve(handle: str) -> str` (a DSN). Shipped:

- `MemorySecretProvider({"handle": "postgresql+asyncpg://..."})` — raises
  `KeyError("no secret for handle <h>")` on a miss (used by tests).
- `EnvSecretProvider(prefix="JDLIB_TENANT_DB_")` — reads
  `PREFIX + handle.upper().replace("-", "_")` from the environment; missing
  variable ⇒ `KeyError`. `DatabasePerTenantStrategy` converts a `KeyError` into
  `StrategyCapabilityError("no secret for database handle …")`, i.e. fail closed,
  never a fallback to the shared target.
