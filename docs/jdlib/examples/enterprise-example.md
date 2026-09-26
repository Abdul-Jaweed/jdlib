# The enterprise example

The same library across every surface it has: HTTP and MCP, PostgreSQL and Neo4j, a real policy
engine, an audit trail, and the reliability primitives.

## Run it

```bash
# 1. the lab: PostgreSQL (two roles), Cerbos, Neo4j
docker compose -f examples/enterprise/docker/docker-compose.yml up -d

# 2. the environment
export JDLIB_EXAMPLE_LIVE_DSN=postgresql://jdlib_app:...@127.0.0.1:45432/jdlib_enterprise
export JDLIB_EXAMPLE_LIVE_MIGRATION_DSN=postgresql://jdlib:...@127.0.0.1:45432/jdlib_enterprise
export JDLIB_EXAMPLE_CERBOS_ENDPOINT=http://127.0.0.1:4592
export JDLIB_EXAMPLE_GRAPH_URI=bolt://127.0.0.1:7688
export JDLIB_ENTERPRISE_GRAPH_PASSWORD=...

# 3. the operator steps, then the app
python -m examples.enterprise.app.bootstrap --slug acme --name "Acme Inc"
uvicorn examples.enterprise.app.asgi:app --host 127.0.0.1 --port 8000
python -m examples.enterprise.app.mcp.asgi        # the MCP surface, streamable HTTP
```

`examples/enterprise/README.md` is the authority for the exact commands, the operator steps and the
test layout; this page is the map.

## The shape

```
app/
├── configuration/    settings, marked required or optional; no secrets in files
├── security/         authentication, authorization, roles, audit, context
├── api/              the routers, each route declaring its permission
├── services/         the operations: the transaction boundary and the audit of a write
├── repositories/     the statements, through the library's repository
├── models/           the tables the application owns
├── mcp/              the tool declarations, the boundary over the same collaborators
├── graph.py          the derived plane: the projection, the vocabulary, the runner
├── dataplane.py      the tenant plane, RLS, the operator grants
├── bootstrap.py      the operator steps
└── asgi.py           the entry point
config/cerbos/        the policies, and the engine's own tests for them
docker/               the lab: PostgreSQL with two roles, Cerbos, Neo4j
tests/                unit / integration / security / e2e, over tests/support/
```

## The four test layers

| Layer | Count | Question |
|---|---|---|
| `unit/` | 24 | what is declared, and how it is wired (no services) |
| `integration/` | 29 | does the real infrastructure answer (PostgreSQL, Cerbos, Neo4j, MCP) |
| `security/` | 16 | isolation, denial non-execution, and what a failure may say |
| `e2e/` | 8 | does the documented command work as a *process* |

## What writing it found

The example exists to be run, and running it found things a description would not:

* **the runtime role could not reach the control plane at all** — the operator step granted
  privileges inside the tenant schema and nowhere else, and a serving process authenticates, resolves
  a tenant, reads roles and writes the trail, all of which are control-plane rows;
* **the MCP chain asks its authorization question about the tenant scope**, so a policy set written
  only against route targets refuses every tool call (the policy set now carries the capabilities,
  and the engine's own tests grew from 29 to 44);
* **an unreachable row is answered `409 INVALID_REFERENCE`**, not 404 — the library's mapping, which
  the example deliberately does not re-map;
* **a denied MCP call writes three audit events** where HTTP writes one;
* and one suspicion was **disproved**: the MCP boundary was assumed to bind only a security context,
  a probe showed it binds both scopes, and the change was reverted with the probe kept as a test.
