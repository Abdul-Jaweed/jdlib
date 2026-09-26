# Data architecture

Three planes and one derived store. The separation is the library's oldest decision and the one
everything else leans on: a request cannot reach control-plane state, and a control-plane operation
cannot read tenant data.

```mermaid
flowchart LR
    subgraph control["control plane (one schema, shared)"]
        tenants["tenants<br/>registry + lifecycle"]
        placements["placements<br/>where a tenant lives"]
        paudit["platform audit"]
    end

    subgraph tenantA["tenant plane: acme"]
        rowsA["tenant tables"]
        rlsA["row-level security<br/>app role"]
    end

    subgraph tenantB["tenant plane: beta"]
        rowsB["tenant tables"]
        rlsB["row-level security<br/>app role"]
    end

    subgraph derived["derived plane"]
        neo[("Neo4j<br/>tenant-owned labels")]
    end

    registry["jdlib.control.registry"] --> tenants
    registry --> placements
    provision["jdlib tenant provision"] --> tenantA
    provision --> tenantB
    uow["jdlib.persistence.uow<br/>tenant-bound"] --> rowsA
    uow --> rowsB
    rowsA --- rlsA
    rowsB --- rlsB
    graph["jdlib.graph.repository"] --> neo
    tenants -.->|lifecycle gate| uow
    tenants -.->|lifecycle gate| graph
```

## The control plane

`jdlib.control` holds the registry (`registry`), the lifecycle (`enums`, `base`), the models
(`models`), the platform audit (`audit`) and purge (`purge`). Migrations are
`jdlib.migrations.runner`, run by `jdlib db upgrade-control` — an operator step, deliberately not
part of process start, because a process that migrates while it starts does so on every worker.

A tenant's lifecycle state is the gate the request path consults: `ContextFactory` refuses a request
whose tenant is not active, and the graph plane's `jdlib.graph.tenant` applies the same rule to a
graph session. One state, two enforcers, no second source.

## The placement and isolation strategies

`jdlib.persistence.strategies` is where "where does this tenant's data live" is answered:

| Module | What it does |
|---|---|
| `base` | the strategy interface every placement implements |
| `shared` | shared schema: one set of tables, every row carrying its tenant, enforced by RLS |
| `schema` | schema per tenant: a schema created, migrated and owned per tenant |
| `rls` | the row-level-security policy itself, applied to the application role |
| `database` | a placement per database, for the deployments that need the harder boundary |
| `deprovision` | taking a placement away without taking the tenant's neighbours with it |

The choice is per tenant and recorded in the placement, which is why a deployment can move one
tenant to its own schema without changing a line of application code.

## The data boundary

Two mechanisms, deliberately redundant:

* **The tenant-bound unit of work** — `jdlib.persistence.uow.UnitOfWork` and
  `jdlib.persistence.repository.TenantRepository` carry the context's tenant, so a query is scoped by
  construction.
* **Row-level security** — `jdlib.persistence.session.TenantSession` sets the session's tenant and the
  database's policy constrains the rows. The application role (`JDLIB_RLS__APP_ROLE`) is the role the
  policy applies to, and the owner role is not the role the application connects as.

The redundancy is the point: the first is a programming discipline, the second is enforced by the
database when the first is forgotten. A cross-tenant read is measured in the enterprise example as a
`409 INVALID_REFERENCE` — a refusal, not an empty result — because an empty result would tell the
caller that the identifier exists somewhere else.

## The derived plane

`jdlib.graph` is a *derived* store: it holds relationships the relational plane cannot express
efficiently, and it is rebuilt from the relational plane rather than being its source of truth. Its
tenant rule is enforced twice — `jdlib.graph.tenant` binds the session, and the identity constraint
in `jdlib.graph.query` is applied only to labels the example owns, so the library never rewrites a
query about a model it did not create.

## Storage and cache

`jdlib.storage` (keys, metadata, the S3 backend) and `jdlib.caching` (the protocol, the policy, the
in-process and Redis providers) are both *outside* the tenant boundary by construction: an object key
carries the tenant in its prefix (`jdlib.storage.keys`) and a cache key carries it in the namespace
(`jdlib.caching.keys`), so a shared store cannot become a cross-tenant read. The cache has one
additional rule — it refuses to hold a credential object at all, including inside a container.
