# Add an endpoint

A route that is guarded by declaration, reads its tenant from the context, and does its work in the
tenant-bound unit of work.

## 1. Declare it

```python
from fastapi import APIRouter

from jdlib.integrations.fastapi import get_uow, require

router = APIRouter()


@router.post("/api/invoices")
@require("invoice:create")
async def create_invoice(body: InvoiceIn, uow=Depends(get_uow)) -> InvoiceOut:
    async with uow.transaction():
        invoice = await uow.repositories.invoices.add(...)
    return InvoiceOut.from_entity(invoice)
```

Three rules are visible in six lines:

* the permission is **declared** (`@require`) rather than checked inside the handler — the guard
  enforces it before the handler is entered, which is what makes a denial non-execution;
* the tenant is **not a parameter** — it comes from the bound context, and the unit of work is
  already tenant-bound;
* the failure path is **not handled here** — a refusal, a conflict and a dependency failure all leave
  as the library's envelope.

## 2. Take the tenant from the context

```python
from jdlib import current_tenant

tenant_slug = current_tenant().slug     # the resolved tenant, never the caller's claim
```

A route that reads a tenant from the path, the query or the body has created a second source for it.
The enterprise example's `test_tenant_isolation.py` exists to fail exactly that.

## 3. Do the work in the unit of work

`get_uow()` returns the request's tenant-bound unit of work. A transaction opened on it is scoped to
the tenant, and the database's policy applies as well.

## 4. Test it

| Test | What it proves |
|---|---|
| a guarded call with an allowing credential | the happy path, through the real guard |
| a call without the permission | `403`, **and the handler did not run** |
| a call with a token claiming another tenant | the tenant in the response is the credential's, not the claim's |
| a call when the policy engine is unreachable | a refusal, not a pass |

The second row is the one that needs care: assert non-execution with a side effect the handler would
have written, and keep an allowing case in the same test so a broken guard cannot make the test pass
by refusing everything.

## What goes wrong

| Symptom | The cause |
|---|---|
| a 500 where a 403 was expected | the handler raised instead of the guard refusing — the permission is not declared |
| the tenant in the response is the caller's claim | the handler read a request field instead of the context |
| a cross-tenant read returns an empty page | a reference resolved to another tenant — expect `409 INVALID_REFERENCE`, and treat an empty page as a bug |
