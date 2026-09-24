---
page: tenancy
sources:
  - src/jdlib/tenancy
  - src/jdlib/control
  - src/jdlib/persistence/strategies
  - docs/jdlib/03-isolation-invariants.md
  - docs/jdlib/06-strategy-matrix.md
---
# Tenancy

## Resolution

A request is resolved to a `TenantContext` by a chain of resolvers (principal, header, or the
application's own), then authenticated and authorized. Resolution is explicit: there is no
"default tenant", and a request that resolves to none fails closed.

## Placement

A tenant is `SHARED` (one schema, RLS-scoped rows), `SCHEMA` (its own schema) or `DEDICATED`
(its own database). The strategy is a property of the tenant record, not of the request, so a
relocation is a control-plane operation with its own bookkeeping (`tenant_placements`,
`tenant_migration_states`, `tenant_relocations`).

## Isolation

Row-level security is installed per tenant schema with `FORCE`, bound to the application role, and
verified by inspection rather than assumed. The constants the tests carry (`SELECT` on
`tenants.id` for the authenticated role) are the ones the invariants document names.

## Lifecycle

`provisioning → active → suspended → archived → deleted`, with explicit transitions
(`TENANT_CREATED`, `TENANT_PROVISIONED`, `TENANT_SUSPENDED`, `TENANT_RESUMED`, `TENANT_ARCHIVED`,
`TENANT_DEPROVISIONED`, `TENANT_PURGED`, `TENANT_RELOCATED`). Suspension is honoured per request:
a suspended tenant is not servable, and a job enqueued before the suspension is refused at
execution ([`jobs.md`](capabilities/jobs.md)).

## Background work

A queued job carries a signed tenant token and a job identity, and the whole chain is revalidated
when the job runs - principal active, tenant present, entitlement held, tenant servable. Authority
is not frozen at enqueue.
