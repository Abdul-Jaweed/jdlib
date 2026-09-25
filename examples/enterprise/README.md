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
| `config/cerbos/` — the policy files, compiled and tested against a live engine | next |
| `app/services/`, `app/repositories/`, `app/graph/`, `app/mcp/` | next |
| `docker/` — the lab (PostgreSQL, Cerbos, Neo4j, collector) | next |
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
| `app/security/roles.py` | the roles a principal holds in a tenant, from the control plane |
| `app/security/context.py` | the library's `ContextFactory`, and the operator directory it leaves to the application |
| `app/security/container.py` | the collaborators `require(...)` reads from `app.state` |
| `app/security/audit.py` | security events into the control plane's audit trail |
| `app/api/router.py` | the tenant routes, each declaring the permission it needs |

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

## Tests

```bash
pytest examples/enterprise/tests -q -W error     # from the repository root
```

This slice's tests are structural: the ops routes answer without credentials, every tenant route
declares a permission, an unauthenticated request answers the canonical envelope, and a plaintext
policy endpoint is refused. The behavioural matrix — denial non-execution, tenant isolation, the
end-to-end chain — arrives with the layers it tests.
