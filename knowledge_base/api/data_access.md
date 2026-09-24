# API: Tenant-Scoped Data Access

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

The rule that makes this API safe to use: **all tenant scoping happens inside
`TenantSession`**, so any statement issued through it is scoped whether it came
from `TenantRepository`, an ad-hoc `select()`, a relationship load, or a bulk
helper. The corollary is that a raw `AsyncSession` is unscoped — never hand one
to application code.

## `UnitOfWork`

```python
from jdlib import UnitOfWork, current_tenant
from jdlib.control.registry import RegistryWriteFence

write_fence = RegistryWriteFence(session_factory=control_sessions)

async def create_invoice(number: str) -> Invoice:
    context = current_tenant()
    async with UnitOfWork(tenant_sessions, context, fence=write_fence) as session:
        return await TenantRepository(session, Invoice).add(Invoice(number=number))
```

| | Behaviour |
|---|---|
| Constructor | `UnitOfWork(session_factory, context, *, fence, auditor=None)` — `fence` is required (use `NullWriteFence()` to opt out explicitly). |
| `__aenter__` | Skips the fence for `privileged_bypass(context)` (system context with `relocation.manage`), otherwise `await fence.assert_writable(context.tenant_id)` **before** opening a session; then creates one `AsyncSession` and wraps it in `TenantSession`. |
| `__aexit__` | No exception ⇒ `commit()`; exception ⇒ `rollback()`; always `close()`. |
| Scope | One unit of work = one session = one transaction. `TenantSession` is what you get inside the `async with`. |

## `TenantSession`

| Method | Semantics |
|---|---|
| `execute(statement)` | Any ORM/core executable except `TextClause` (that raises `UnscopedRawSql`; use `raw_sql`). Reads are auto-filtered by `tenant_id`; unscoped bulk DML raises `UnscopedBulkOperation`. |
| `get(model, entity_id)` | Composite lookup `(tenant_id, entity_id)` for `TenantRouted` models — another tenant's row returns `None`, it does not raise. |
| `add(obj)` / `delete(obj)` | `add` stamps `tenant_id` from the context (or rejects a conflicting value on flush); `delete` on a `SoftDelete` model needs a privileged context. |
| `update_where(model, values, *criteria)` | Scoped `UPDATE`; returns rowcount; refuses `tenant_id` in `values` without privilege. |
| `delete_where(model, *criteria)` | Scoped `DELETE`; returns rowcount; refuses `SoftDelete` models without privilege. |
| `raw_sql(statement, params=None, *, mode=TENANT_BOUND)` | Compiles + validates + executes; `PRIVILEGED` needs a `tenant.raw_sql`/`platform.raw_sql` capability and is audited. |
| `flush/commit/rollback/close` | Straight delegation. |

**Privileged contexts** (system/test) do **not** disable scoping — reads are still
filtered by the context's tenant. Physical cross-tenant operations are done by
`TenantPlanePurger` (system context) or raw SQL in `platform.raw_sql` mode; there
is no "see everything" session mode.

## `TenantRepository[ModelT]`

```python
repo = TenantRepository(session, Invoice)

await repo.get(invoice_id)                       # soft-delete aware (deleted_at IS NULL)
await repo.list(Invoice.status == "draft", order_by=Invoice.number, limit=100, offset=0)
await repo.add(Invoice(number="INV-1"))          # add + flush
await repo.update(invoice, status="sent")        # setattr loop + flush
await repo.soft_delete(invoice)                  # deleted_at = now(UTC); TypeError if not soft-deletable
await repo.count(Invoice.status == "sent")
```

Because the repository emits ordinary ORM statements, the session events apply:
`list()`/`count()` are tenant-filtered even without an explicit criterion, and a
row from another tenant is simply invisible.

## Raw SQL

```python
from jdlib.persistence.rawsql import RawSqlMode

rows = await session.raw_sql(
    sa.text("SELECT number FROM invoices WHERE tenant_id = :tid AND status = :status"),
    {"tid": context.tenant_id, "status": "draft"},
)

await session.raw_sql(
    sa.text("DELETE FROM invoices WHERE tenant_id = :tid"),
    {"tid": context.tenant_id},
    mode=RawSqlMode.PRIVILEGED,      # requires privilege.capability == "tenant.raw_sql"
)
```

The validator parses the *compiled* PostgreSQL text with `pglast` and proves the
predicate; the value bound to `tenant_id` is compared against
`context.tenant_id`, so a wrong-GUC or wrong-parameter query is rejected rather
than merely filtered. Full rule list:
[../modules/persistence.md](../modules/persistence.md).

## Relationship loading, joins and aliases

- Eager/lazy relationships between `TenantRouted` models are auto-scoped
  (`with_loader_criteria(..., include_aliases=True)` propagates into the loader
  options).
- `aliased(Invoice)` is fine; `sa.alias(invoices_table)` or a table-level select
  on a tenant table raises `UnscopedRawSql` ("use `aliased(Entity)` or `raw_sql`").
- `select(Invoice).from_statement(text(...))` raises `UnscopedRawSql`.
- `select(text("..."))` raises `UnscopedRawSql`.
- Cross-tenant joins are impossible: the criteria are added per mapped entity,
  so the join predicate carries `tenant_id = ctx.tenant_id` on both sides.

## What raises what (data-access quick table)

| Action | Result |
|---|---|
| Using a session with no context | `MissingTenantContext` |
| `session.get(OtherTenantModel, id)` | `None` |
| `sa.update(Model).values(...)` executed directly | `UnscopedBulkOperation` |
| `session.delete(soft_deletable)` without privilege | `AuthorizationError` |
| Flushing a row with a foreign `tenant_id` | `CrossTenantReferenceError` |
| Changing `tenant_id` on a loaded row | `CrossTenantReferenceError` |
| `UPDATE … SET tenant_id = …` via `update_where` | `AuthorizationError` |
| Raw SQL without a provable tenant predicate | `UnscopedRawSql` |
| Raw SQL in `PRIVILEGED` mode without the capability | `AuthorizationError` |
| Truthful raw SQL in `platform.raw_sql` mode | allowed and audited |

## Placement-transparent operation

`SessionRouter` (or your own `uow_factory` that consults
`context.strategy`) is the only place that knows about placement:

```python
record = await registry.assert_servable(tenant_id)
session = await SessionRouter(strategies).session(record)
async with TenantSession(session, context) as scoped:
    ...
# or, more commonly:
uow = UnitOfWork(lambda: router_session_factory(context), context, fence=fence)
```

Application code above that factory is identical for shared, schema and database
placements — that equivalence is what
`tests/integration/test_strategy_matrix.py` proves.
