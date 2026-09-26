# The graph flow (Neo4j)

The graph is a **derived** plane: the relational database stays the record of truth, and the graph
exists to answer questions about relationships. Everything here is about keeping that relationship
honest.

## The projection

```
a relational write (a service call)
        │
        ▼
GraphPlane.project_resource(context, resource_id, properties)
        │  the tenant comes from the SecurityContext -- one source, never a parameter
        ▼
GraphRepository (tenant-bound client)
        │  the vocabulary is closed: labels and relationships come from graph/mapping.py
        ▼
MERGE on the identity key          ── an upsert, so a re-projection is safe
        │
        └── a real conflict raises GraphConflictError rather than overwriting
```

The identity constraint (`Resource.id` unique) is declared by the operator step, not assumed: a
projection against a graph without it would create duplicates under concurrency, which is exactly
what the example's mutation check demonstrated before the constraint was added.

## Reading

`GraphQuery` builds statements from the closed vocabulary; `GraphRepository` runs them for one
tenant; `GraphRunner` runs them for a tenant known only at call time — which is what the MCP surface
needs, because a server serving every tenant cannot hold one tenant's client.

## Why it is derived, and what follows

| Because the graph is derived | The consequence |
|---|---|
| the relational plane is authoritative | a graph outage must not fail a request the relational plane can answer — the circuit breaker opens and reads continue |
| a projection can be repeated | writes are idempotent by identity key, and a real conflict is refused |
| the vocabulary is a claim about the model | an undeclared label is refused, so an injected string cannot become a traversal |
| the tenant is bound to the client | a cross-tenant statement raises rather than filters |

## The lab

The example's `docker/docker-compose.yml` brings up its **own** Neo4j on port 7688 with a generated
password (`JDLIB_ENTERPRISE_GRAPH_PASSWORD`), separate from the repository's own instance on 7687 —
so a test that corrupts the example's graph cannot affect the library's infra suite.

## What the tests assert

`tests/integration/test_graph_live.py` (7 tests, against the real instance): the projection lands,
a re-projection is idempotent, the identity constraint exists, the vocabulary refuses an undeclared
label, a cross-tenant read returns nothing, and a tenant's client cannot reach another's nodes.
