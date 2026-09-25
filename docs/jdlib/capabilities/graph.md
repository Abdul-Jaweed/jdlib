---
capability: graph
namespace: jdlib.graph
errors_module: jdlib.graph.errors
modules:
  - src/jdlib/graph/__init__.py
  - src/jdlib/graph/client.py
  - src/jdlib/graph/config.py
  - src/jdlib/graph/errors.py
  - src/jdlib/graph/mapping.py
  - src/jdlib/graph/models.py
  - src/jdlib/graph/policy.py
  - src/jdlib/graph/query.py
  - src/jdlib/graph/repository.py
  - src/jdlib/graph/tenant.py
  - src/jdlib/graph/transaction.py
exports:
  - GraphCircuitBreaker
  - GraphClient
  - GraphConfig
  - GraphPolicy
  - GraphQuery
  - GraphRepository
  - GraphRunner
  - GraphTransaction
  - GraphVocabulary
  - Label
  - Neo4jClient
  - PropertyKey
  - RelationshipType
  - TransactionOutcome
  - node_create
  - node_match
  - relationship_create
refusals:
  - GraphAuthorizationError
  - GraphCircuitOpenError
  - GraphConflictError
  - GraphError
  - GraphNotFoundError
  - GraphQueryError
  - GraphTenantViolationError
  - GraphTimeoutError
  - GraphUnavailableError
  - GraphValidationError
test_files:
  - tests/unit/test_graph_adversarial.py
  - tests/unit/test_graph_client.py
  - tests/unit/test_graph_config.py
  - tests/unit/test_graph_errors.py
  - tests/unit/test_graph_observability.py
  - tests/unit/test_graph_query.py
  - tests/unit/test_graph_reliability.py
  - tests/unit/test_graph_repository.py
  - tests/unit/test_graph_transaction.py
  - tests/unit/test_graph_vocabulary.py
  - tests/infra/test_neo4j_infra.py
test_functions: 126
---

# The graph plane: Neo4j as a data plane, not a driver wrapper

## What it is

A deployment declares which labels, relationship types and property keys exist; a caller
builds a statement from that vocabulary and runs it under the tenant it is authenticated
for. The driver is an optional extra (`graph`) imported inside `open`, so the library
imports and type-checks without it.

```python
vocabulary = GraphVocabulary(
    labels=frozenset({"User"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"name"}),
)
client = Neo4jClient(GraphConfig(uri="neo4j+s://graph:7687", database="acme",
                                 auth=SecretRef(handle="graph/password")),
                     provider=provider, policy=GraphPolicy())
await client.open(context=context)          # binds the tenant this client serves
await client.run(query=node_create(vocabulary.label("User"), tenant=str(tenant),
                                   node_id="u1",
                                   properties={vocabulary.property_key("name"): "Ada"}),
                 context=context)
```

`GraphRepository` is the surface an application should prefer: its methods take no tenant
at all — the scope is read from the context, and a statement that does not carry it is
refused before a connection is opened. `GraphTransaction` is the multi-statement form:
one ending, `retryable()` as a fact rather than an assumption, and a commit failure that
lands in `UNCERTAIN` rather than `PENDING`.

## The security properties, and where each one is proven

- **An identifier is validated where it is interpolated.** `Label`, `RelationshipType`
  and `PropertyKey` validate at construction, and every builder re-checks the type at the
  position — because an annotation enforces nothing, and a plain string in that position
  becomes Cypher. `tests/unit/test_graph_adversarial.py` attacks each position with
  twelve hostile spellings; the RED run that motivated the guard failed 106 of 111 cases.
- **A value is never statement text.** The statement is a function of identifiers alone:
  the same query with a hostile and a benign value produces byte-identical text, and the
  value travels in the parameters.
- **The tenant is a parameter, not a filter**, and the check lives in exactly one place
  (`graph/tenant.py`), called by the client and by the transaction. A statement for
  another tenant is refused *before* the driver is touched — the refusal tests assert the
  driver recorded zero calls.
- **A refusal is recorded before it is raised**, with the actor the call was made for:
  the event fills its actor from the ambient context, so the statement runs inside the
  context scope, and the vocabulary is the existing `CROSS_TENANT_ACCESS_REJECTED` rather
  than a second name for the same fact.
- **A retry never repeats a committed write.** The reliability composition reuses the
  library's classifier, backoff, shared budget and breaker; the retry loop asks the
  transaction's own `retryable()`, which is false after a commit and after a failed one.
- **Telemetry cannot become the failure.** Spans and events go through the existing
  seams: an audit outage does not change the caller's outcome, and nothing exported
  carries a tenant id or a statement.

## Limits, stated rather than implied

- **Schema DDL has no path through this client.** A statement with no tenant parameter is
  refused — which is the point — so constraints and indexes are an operator's job,
  declared out of band. The live suite creates its constraint with the driver directly,
  the way a migration would, and then proves the library's own statements meet it.
- **`GraphQuery` is the low-level seam.** It carries text and parameters, so code that
  builds one by hand chooses its own Cypher. What it cannot do is run unscoped: the tenant
  check applies to it like any other statement. Prefer the builders, or
  `GraphRepository`.
- **Tenant isolation is the statement's scope, not the engine's.** Neo4j has no row-level
  security; what the library guarantees is that every statement it builds filters on the
  tenant parameter it bound from the context, and that a statement which does not is
  refused.

## Running the live layer

```bash
docker compose -f tests/infra/docker-compose.yml up -d neo4j
export JDLIB_INFRA_NEO4J_URL=bolt://127.0.0.1:7687
export JDLIB_INFRA_NEO4J_PASSWORD=jdliblab
.venv/Scripts/python.exe -m pytest tests/infra/test_neo4j_infra.py -q -W error
```

Without `JDLIB_INFRA_NEO4J_URL` the suite skips with that variable named in the reason.
The live layer proves what unit tests cannot: that the builders produce Cypher a real
server accepts, that the parameter they bind is what it filters on, that the driver's own
exception classes land on the right taxonomy, and that a hostile value is stored as data.
