# The tenant flow

How a tenant comes into existence, how its data is placed, and how the binding reaches the database.

## Provisioning (the operator's side)

```
python -m examples.enterprise.app.bootstrap --slug acme --name "Acme Inc"
  └── TenantRegistry.create(...)      the tenant's row in the control plane
  └── TenantRegistry.provision(...)   the tenant's migration, tables and records
  └── (the documented operator step)  install_tenant_rls(...) -- the database's own enforcement
  └── (the serving role's grants)     grant_control_privileges(...) -- what the request path reads
```

`bootstrap.py` is idempotent: running it twice does not create a second tenant, and the operator
steps it performs are the ones the README documents. `dataplane.py` holds them so the tests can run
the same code the operator runs.

## Placement

A tenant's data lives according to its `PlacementStrategy`. The example uses `SHARED` (one schema,
one set of tables, the tenant as a column) because that is the strategy whose failure mode — a
forgotten filter — row-level security exists to close. The strategy is data, not code: the plane is
built with the strategies it supports, and a tenant's row says which one applies.

## The binding, end to end

```
TenantContext (jdlib.context)
├── tenant_id, tenant_slug, strategy
├── principal (kind, id, scopes)
└── request_id, correlation_id
        │
        ├─ context_scope(...)          bound for the request; `current_tenant()` reads it
        ├─ the plane's session         the strategy sets `app.tenant_id` on the connection
        ├─ row-level security          the database filters on that setting
        └─ the audit writer            records the tenant on every row
```

Three consequences worth stating plainly:

* **The tenant is not a parameter.** No route, service or repository in the example takes one; a
  header or query parameter claiming a tenant is ignored, and `tests/security/test_tenant_isolation.py`
  asserts that against the answer.
* **An unbound session reads nothing.** With RLS installed, a session that never set the tenant sees
  no rows — the failure mode is empty, not everything.
* **The graph is bound the same way.** `GraphClient` carries the tenant, and a statement that would
  cross tenants raises `GraphTenantViolationError` rather than returning another tenant's nodes.

## Cross-tenant answers, and why they are not 403

A read for a row that is not this tenant's is answered `409 INVALID_REFERENCE` ("does not exist in
this tenant") — the library's own mapping, which the example deliberately does not re-map. A 403
would confirm that the id exists somewhere; the answer given confirms nothing.
