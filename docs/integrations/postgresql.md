# PostgreSQL

PostgreSQL is the one store the library cannot be used without: the control plane and the tenant
plane are both relational, and the isolation guarantee leans on row-level security. There is no extra
to install — the driver is a core dependency.

## Where it appears

| Surface | Module | What it does |
|---|---|---|
| control plane | `jdlib.control.session`, `jdlib.control.registry` | tenants, placements, lifecycle, platform audit |
| migrations | `jdlib.migrations.runner` | control-plane revisions, applied by an operator command |
| tenant plane | `jdlib.persistence.session.TenantSession` | the tenant-bound session, with the RLS policy applied |
| data access | `jdlib.persistence.repository.TenantRepository`, `uow.UnitOfWork` | tenant-bound reads and writes |
| isolation | `jdlib.persistence.strategies.{shared,schema,rls,database,deprovision}` | where a tenant's data lives, and the policy that constrains it |
| connector | `jdlib.data.postgres.PostgresConnector` | the connector framework's PostgreSQL implementation |
| query compilation | `jdlib.query.{compiler,dialect}` | a specification compiled to SQL, with the identifier policy applied |

## The role split

Two roles, and the split is the mechanism rather than a convention:

* the **owner** role owns the tables and runs migrations;
* the **application** role (`JDLIB_RLS__APP_ROLE`) is what the application connects as, and it is the
  role the row-level-security policy applies to.

A deployment that connects as the owner has turned the second layer of isolation off without noticing.
`jdlib rls verify` is the command that checks the policy is present and applies to the role the
application actually uses.

## What it refuses

* A cross-tenant read is a `409 INVALID_REFERENCE` — a refusal, not an empty result, because an empty
  result would confirm that the identifier exists elsewhere.
* A statement that is not tenant-scoped returns nothing once the policy is in place: the
  `TenantSession` sets the tenant, and the policy constrains the rows.
* A migration that has not been applied is a refusal at the point of use, not a silent fallback.

## Where it is tested

`tests/integration/` (against real PostgreSQL, including the raw-SQL auditor), `tests/infra/` (the lab
itself), and both examples' live layers. The strategy matrix in
[`docs/jdlib/06-strategy-matrix.md`](../jdlib/06-strategy-matrix.md) states which strategy is verified
by which suite.
