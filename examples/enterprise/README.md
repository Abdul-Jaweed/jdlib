# The enterprise example

The full JDLib capability set, wired the way a production application would wire it: a gateway in
front, Cerbos as the policy engine, PostgreSQL for the control and tenant planes, Neo4j for the
graph, an audit trail that is written with the operation it describes, and an MCP surface that
reuses the same security chain as HTTP.

Read it if you want to know **where each collaborator plugs in**. The minimal example answers "what
is the least I must do"; this one answers "what does the whole thing look like, and which part is
whose job".

## What is here, and what arrives next

| Layer | State |
| --- | --- |
| `app/configuration/` — settings from the environment, marked required/optional, secret/non-secret | **here** |
| `app/security/` — authentication, the Cerbos bridge, the context factory, the operator directory, the container, the audit sink | **here** |
| `app/api/` — the tenant routes, each declaring its permission | **here** |
| `app/bootstrap.py` — the operator step (migrate, create, provision) | **here** |
| `config/.env.example` — every variable, marked, with no values | **here** |
| `config/cerbos/` — the policy set, with the engine's own tests beside it | **here** — 21 policy tests, run by `cerbos compile` |
| `docker/` — the lab (PostgreSQL, Cerbos, Neo4j) | **here** — the collector arrives with the telemetry layer |
| `tests/test_authorization.py`, `tests/test_authorization_live.py` — the bridge's mapping, and the engine's answers over the wire | **here** — 5 unit, 4 live |
| `app/services/`, `app/repositories/` — the tenant plane | **here** |
| `app/graph.py` — the tenant-bound graph plane and the projection | **here** — 7 live tests against Neo4j |
| `app/mcp/` — the MCP surface (tools, the boundary over the same collaborators, the graph runner) | **here** — 8 unit, 6 live |
| `tests/{integration,security,e2e}` — the matrix the directive asks for | next |

The order is deliberate and dependency-forced: the policy files and the container lab land with the
routes that need them, so that every artifact this example ships has been run rather than only
written. This README is corrected in the same commit as each layer.

## The layers

| Module | Owns |
| --- | --- |
| `app/configuration/settings.py` | what the environment supplies that the library does not already own |
| `app/security/authentication.py` | the library's authenticator chain, as the middleware's principal provider |
| `app/security/authorization.py` | the bridge: Cerbos answers, the library's guard asks |
| `app/graph.py` | the graph's URI, its credential handle, the vocabulary, and the projection the resource plane drives |
| `app/security/roles.py` | the roles a principal holds in a tenant, from the control plane |
| `app/security/context.py` | the library's `ContextFactory`, and the operator directory it leaves to the application |
| `app/security/container.py` | the collaborators `require(...)` reads from `app.state` |
| `app/security/audit.py` | security events into the control plane's audit trail |
| `app/api/router.py` | the tenant routes, each declaring the permission it needs |
| `config/cerbos/policies/tenant_scope.yaml` | the policy set, written against `resource_for`'s names |
| `config/cerbos/policies/tenant_scope_test.yaml` | the same properties, asserted to the engine's compiler |

## Prerequisites

- Python 3.12+
- PostgreSQL 16 (the control plane)
- Cerbos (the policy engine) — `JDLIB_EXAMPLE_CERBOS_ENDPOINT`, https outside localhost

## Configure

Every variable is documented in [`config/.env.example`](config/.env.example) with its marking.
Nothing in this repository carries a value: a deployment supplies them from its own secret store.

```bash
export JDLIB_CONTROL_DSN="postgresql://jdlib:...@127.0.0.1:5432/jdlib_enterprise"
export JDLIB_CONTEXT__SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export JDLIB_OIDC__ISSUER="https://your-issuer.example/"
export JDLIB_OIDC__AUDIENCE="jdlib-enterprise"
export JDLIB_EXAMPLE_CERBOS_ENDPOINT="http://127.0.0.1:3592"
```

The DSN is normalised per role by `app/dsn.py`: `psycopg` for migrations, `asyncpg` for everything
that serves a request — psycopg's async mode refuses Windows' default event loop, so one
`postgresql+psycopg` DSN for both roles works on Linux and fails on Windows.

## Provision, then serve

```bash
python -m examples.enterprise.app.bootstrap --slug acme --name "Acme Inc"   # once
uvicorn examples.enterprise.app.asgi:app --host 127.0.0.1 --port 8000       # then
```

## The routes

| Route | Answers |
| --- | --- |
| `GET /healthz` | Liveness: the process is serving. No credentials, no dependency checks. |
| `GET /readyz` | Readiness: the control plane answers. An unreachable database is `503 DEPENDENCY_UNAVAILABLE` from the library's envelope. |
| `GET /api/whoami` | The caller's tenant, principal and scopes — from the resolved context. Requires `tenant:read`. |
| `GET /api/tenants/current` | The tenant this request is scoped to, and how its data is placed. Requires `tenant:read`. |

A request to `/api/...` with no credentials answers the canonical envelope; a request whose
principal the policy engine denies answers `403 PERMISSION_DENIED` with no handler output, and one
the engine cannot answer at all answers `503` — a degraded decision is never an allow.

## Verifying the policies

Two halves, and both run without the application:

```bash
# Static: the engine's own compiler runs the policy tests beside the policies.
docker run --rm -v "$PWD:/repo:ro" ghcr.io/cerbos/cerbos:0.54.0 \
    compile /repo/examples/enterprise/config/cerbos/policies

# Live: the query the bridge builds, answered by the engine over the wire.
export JDLIB_ENTERPRISE_POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
docker compose -f docker/docker-compose.yml up -d cerbos
export JDLIB_EXAMPLE_CERBOS_ENDPOINT=http://127.0.0.1:4592
pytest examples/enterprise/tests/test_authorization_live.py -q -W error
```

With `JDLIB_EXAMPLE_CERBOS_ENDPOINT` unset the live file skips with that reason, so a missing lab
shows as a skip rather than a failure.

Mount the policy directory at a destination other than `/cerbos`: the image's entrypoint *is* the
binary at that path, and a directory mounted there fails with `not a directory` before the container
starts.

## The tenant plane

The layers below the API: `app/models/` are the tenant-routed tables, `app/repositories/` reads and
writes them, `app/services/` is what a route calls, and `app/dataplane.py` owns the engines, the
provisioning and the row-level policies. The library owns the schema, the policies and the write
fence; the example owns the DSN, the engine's connect arguments and the privileges — the library
deliberately grants none, because a role with no `SELECT` is not protected by a policy, it is locked
out.

**Two roles, and the split is a security property.** The application connects as `jdlib_app` — no
superuser, no `BYPASSRLS`, no DDL — while the owner migrates, provisions and installs the policies.
Row-level security does not constrain a superuser, and the library refuses to install policies for a
role that can bypass them (`StrategyCapabilityError`), so a single-DSN lab would install policies
that apply to nobody. The lab creates the second role when its volume is first initialised:

```bash
export JDLIB_ENTERPRISE_POSTGRES_PASSWORD=...   # the owner role
export JDLIB_ENTERPRISE_APP_PASSWORD=...        # the runtime role
docker compose -f docker/docker-compose.yml up -d
```

The owner's DSN is needed by the **operator step** and by nothing else: the request path reads the
library's own `JDLIB_CONTROL_DSN`, which is the runtime role, and `JDLIB_EXAMPLE_MIGRATION_DSN` is
optional in the settings. The bootstrap refuses, naming the variable, when it is absent.

**Three controls, and each is measured on its own.** A query is scoped by the session's predicate
(the tenant-bound session adds `tenant_id = ...`), by the policy (`app.tenant_id`, bound at connect
time), and by the composite foreign key that refuses a cross-tenant reference even from a caller who
reaches past both. The live tests say which one each is measuring — a mutation that disabled
row-level security left the service-level test green, which is how the policy's own test came to
exist.

```bash
export JDLIB_EXAMPLE_MIGRATION_DSN="postgresql://jdlib:${JDLIB_ENTERPRISE_POSTGRES_PASSWORD}@127.0.0.1:45432/jdlib_enterprise"
export JDLIB_EXAMPLE_LIVE_DSN="postgresql://jdlib_app:${JDLIB_ENTERPRISE_APP_PASSWORD}@127.0.0.1:45432/jdlib_enterprise"
python -m examples.enterprise.app.bootstrap --slug acme --name "Acme Inc"
pytest examples/enterprise/tests/test_tenant_plane_live.py -q -W error
```

## The graph plane

`app/graph.py` is the second data plane, and it is a plane rather than a second kind of access:
the relational plane is the *record*, the graph is derived from it, and the security model is the
same one. Three properties, each measured against a live server:

**The tenant comes from the context, never from an argument.** `Neo4jClient.open` binds a client to
the tenant it was opened for, and every statement is checked against that binding, so the plane keeps
one client per tenant and passes each call's context to the statement. A client opened for one tenant
**refuses** another tenant's statement — that is a different control from a scope the caller could
forget, and `test_a_statement_for_another_tenant_is_refused_by_the_client` measures the refusal with a
statement that is perfectly well-formed for the tenant it names.

**The vocabulary is declared, not inferred.** `VOCABULARY` lists the labels, relationship types and
property keys this deployment may contain; the repository resolves a caller's name through it, so an
undeclared label never reaches a statement. A graph that accepts whatever a caller spells is a graph
whose schema is decided by its callers.

**Schema is the operator's job, and it is why `bootstrap` has a graph step.** A constraint has no
tenant to be scoped to, so it cannot go through the client at all: `ensure_graph_constraints` uses the
driver directly, with the operator's credentials, before the application serves. Without it a second
projection of the same row is a *second node* rather than a conflict — the mutation that turned the
upsert into a create succeeded at the database, which is what a missing constraint looks like.

The lab's Neo4j is the example's own instance (bolt `7688`, HTTP `7475`), like the database above it:
a lab that shares an engine with another stack is a lab whose tests can pass on the other stack's
data. The password is **one variable for both sides** — `JDLIB_ENTERPRISE_GRAPH_PASSWORD`
initialises the server and is what the credential handle `graph-password` resolves:

```bash
export JDLIB_ENTERPRISE_GRAPH_PASSWORD=...      # the lab and the application read the same name
docker compose -f docker/docker-compose.yml up -d neo4j
export JDLIB_EXAMPLE_GRAPH_URI=bolt://127.0.0.1:7688
pytest examples/enterprise/tests/test_graph_live.py -q -W error
```

## The MCP surface

`app/mcp/` is the same application over a second protocol. Nothing about the security model is
restated: `build_collaborators` builds the collaborators **once**, `create_app` and
`build_example_mcp_server` are both handed them, and the unit tests assert the *identity* of those
objects — an MCP surface that built its own authenticator, resolver chain or enforcer would be a
second place for a decision to drift, and no test would notice.

Three properties are the surface's own, and each is checked:

**The inventory is the declarations.** No tool exists that is not declared, every declaration
carries the capability its authorization is asked against (the registry refuses one that does not),
and no schema has a slot for an identity or a statement — checked by walking the properties, because
"there is no `tenant_id` in the schema" is exactly the claim a reader gets wrong.

**The chain is the HTTP path's, and it runs live.** A bearer API key is minted by the test and
hashed into the control plane; the library's own authenticator verifies it, the resolver chain
decides the tenant, the context factory checks the service account is active and entitled, and the
capability is put to the live policy engine before any handler runs. A forged key is refused, which
is the negative control that stops every other assertion from passing on a boundary that
authenticated nothing.

**The graph tools get a runner, not a client.** A graph client *is* a tenant binding, so a surface
serving every tenant cannot hold one: `TenantGraphRunner` opens the calling tenant's client per
statement, and the tenant still comes from the context.

```bash
python -m examples.enterprise.app.mcp.asgi       # MCP over streamable HTTP
pytest examples/enterprise/tests/test_mcp_surface.py -q -W error    # no lab needed
pytest examples/enterprise/tests/test_mcp_live.py -q -W error       # with the lab up
```

## Tests

```bash
pytest examples/enterprise/tests -q -W error     # from the repository root
```

The structural slice: the ops routes answer without credentials, every tenant route declares a
permission, an unauthenticated request answers the canonical envelope, and a plaintext policy
endpoint is refused. The authorization slice: the bridge's mapping (unit, no engine), and the
engine's own answers — allow, deny, and an administrator of another tenant denied (live). The
operator step: the settings a serving process needs (and the owner's DSN it must not need), and the
refusals that name their variable. The tenant plane (live): read-back over a fresh connection,
ordering, isolation at both layers, the composite foreign key, unscoped statements refused beside
the scoped form, rollback, and a suspended tenant that cannot write.

The graph plane (live): a projected node read back over a fresh client, the upsert, cross-tenant
invisibility, the client's refusal of another tenant's statement, the closed vocabulary, and the
identity constraint the operator step declares.

The MCP surface: the inventory, the capabilities, the closed schemas and the identity of the
collaborators (unit, no engine); and through the whole chain — authentication by a real key, tenant
resolution, the live policy engine's answer, a denial measured at the data, an undeclared argument
refused, cross-tenant invisibility, and the graph tools over the real Neo4j (live).

The behavioural matrix over HTTP — denial non-execution, tenant isolation end to end, the whole chain
through the gateway — arrives with the layers it tests.
