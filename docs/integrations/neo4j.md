# Neo4j

```bash
pip install "jdlib[graph]"
```

`jdlib.graph` is the derived graph plane: relationships the relational plane cannot express
efficiently, held in a store that is rebuilt from it rather than being its source of truth.

## The parts

| Module | What it does |
|---|---|
| `client` | `Neo4jClient` behind the `GraphClient`/`GraphRunner` protocols, with a secret resolver |
| `tenant` | binds a session to a tenant, and applies the same lifecycle gate the request path uses |
| `query` | the closed query vocabulary, and the identity constraint on labels the library owns |
| `repository` | `GraphRepository`: typed reads and writes over that vocabulary |
| `transaction` | transaction scope, so a multi-statement write is one unit |
| `policy` | what the plane will and will not execute |
| `mapping` | rows to models |
| `config`, `errors`, `models` | configuration, the error vocabulary, the types |

## The rules

1. **A session always has a tenant.** `jdlib.graph.tenant` refuses a session without one, so a graph
   query cannot run tenantless.
2. **Identifiers are values, never query text.** A string in an identifier position is refused —
   the defect that made the rule explicit is recorded in the CHANGELOG, and the constraint is applied
   in `jdlib.graph.query`.
3. **The library constrains what it owns.** The identity constraint is applied only to the labels the
   example owns, so a query about a model the library did not create is not rewritten.
4. **The graph is derived.** Nothing in the request path treats a graph read as the authoritative
   answer for tenant data; the relational plane is.

## Configuration

The client takes a URI, credentials and a secret resolver rather than reading the environment itself,
so a deployment can source the password from its own provider chain
(`jdlib.credentials`). The example lab runs Neo4j on `bolt://127.0.0.1:7688` with
`JDLIB_ENTERPRISE_GRAPH_PASSWORD` as the credential handle.

## Where it is tested

`tests/integration/` against a real Neo4j, `tests/unit/` for the vocabulary and the identifier rule,
and the enterprise example's graph slice — including the cross-tenant case, which is a refusal.
