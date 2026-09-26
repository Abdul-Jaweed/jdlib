# Add a tenant-scoped table

A new table that holds tenant data. Three things have to agree: the model, the migration, and the
isolation policy. Getting two of them right produces a table that *looks* isolated.

## 1. The model

```python
from jdlib.models.base import TenantBase


class Invoice(TenantBase):
    """A tenant's invoice. TenantBase carries the tenant column and its index."""

    __tablename__ = "invoice"
    ...
```

Inherit the tenant base rather than `Base`: it supplies the tenant column, and the session's
tenant-scoping depends on it being there.

## 2. The migration

Add the revision to the tenant plane's migration chain, and make it idempotent — the operator
command that applies it (`jdlib db upgrade-tenants`) is designed to be re-run:

```bash
jdlib db upgrade-tenants            # every registered tenant, to its desired revision
```

The migration runs **per tenant plane**, not once: a schema-per-tenant deployment applies it to each
schema, which is why a migration that assumes it is alone in the database is a defect.

## 3. The isolation policy

The table needs the row-level-security policy for the application role. Installing and verifying it
is an operator step with a command of its own:

```bash
jdlib rls install --database-url "$JDLIB_CONTROL_DSN" --schema tenant_acme
jdlib rls verify  --database-url "$JDLIB_CONTROL_DSN" --schema tenant_acme
```

`rls verify` is the one to run in a deployment check: a table that exists without its policy is
isolated only by the application's discipline, and the command is what tells the two apart.

## 4. The test

```python
async def test_invoice_is_tenant_scoped(session_factory, two_tenants):
    """A query under tenant A returns A's rows and never B's."""
    ...
```

Two assertions, not one: the tenant's own rows are visible, and the other tenant's are not. A test
that only checks the first passes on a table with no isolation at all.

## What goes wrong

| Symptom | The cause |
|---|---|
| the table exists, the policy does not | the migration was applied without `rls install` |
| rows leak between tenants in a *shared-schema* deployment | the model did not inherit `TenantBase`, so there is no tenant column to constrain |
| a schema-per-tenant deployment applies the migration once | the revision was added to the control plane's chain rather than the tenant plane's |
| the policy exists but does not apply | the application connects as the owner role, not `JDLIB_RLS__APP_ROLE` |
