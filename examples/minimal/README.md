# The minimal example

The smallest application that is still secure: two routes, one guard, one tenant, and no security
mechanism of its own. Everything that decides whether a request may run — authentication, tenant
resolution, authorization, the error envelope — comes from `jdlib.integrations.fastapi`, so this
example is configuration rather than security code.

Read it if you want to know **what the minimum is**: which collaborators an application has to
build, which of them fail closed when they are missing, and which parts are deliberately not the
application's business.

## What it demonstrates

| Claim | Where to see it |
| --- | --- |
| Ops routes answer without credentials, tenant routes never do | `app/main.py` — two ASGI apps, `TENANT_PREFIX` |
| Every tenant route is guarded by the library's own `require(...)` | `tests/test_app.py` — the route walk |
| The tenant comes from the resolved context, never from a parameter | `app/main.py` `/me`, pinned by `tests/test_app.py` |
| One envelope shape for every failure, including a 503 readiness answer | `app/main.py`, `tests/test_app.py` |
| A denial is `403 PERMISSION_DENIED`, and the handler does not run | `tests/test_denial_live.py` — with an allowing control beside it |
| Tenants resolve in the order the operator configured | `app/main.py` uses the library's `build_chain`, not a hand-listed resolver |
| Provisioning is an operator step, separate from serving | `app/bootstrap.py` |
| The application has no configuration of its own | no settings module: the library's `JDLIB_*` contract is the whole surface |

## Prerequisites

- Python 3.12+
- PostgreSQL 16 (the control plane; the example needs no other service)

## Configure

Everything comes from the library's own environment contract — there is no settings file here.

```bash
export JDLIB_CONTROL_DSN="postgresql://jdlib:...@127.0.0.1:5432/jdlib_example"
export JDLIB_CONTEXT__SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export JDLIB_OIDC__ISSUER="https://your-issuer.example/"
export JDLIB_OIDC__AUDIENCE="jdlib-example"
```

Write the DSN in any common spelling. The example normalises the driver per role
(`app/dsn.py`): **sync** work (migrations, DDL) runs on `psycopg`, **async** work on `asyncpg`.
That is not a preference — psycopg's async mode refuses Windows' default event loop, so a single
`postgresql+psycopg` DSN for both roles works on Linux and fails on Windows.

## Provision, then serve

Provisioning is a separate entry point on purpose: an application that migrates and provisions
while it starts does both on every worker, and a half-applied provisioning that a restart retries
is the failure this split avoids.

```bash
python -m examples.minimal.app.bootstrap --slug acme --name "Acme Inc"   # once
uvicorn examples.minimal.app.asgi:app --host 127.0.0.1 --port 8000       # then
```

## The routes

| Route | Answers |
| --- | --- |
| `GET /healthz` | Liveness: the process is serving. No credentials, no dependency checks. |
| `GET /readyz` | Readiness: `SELECT 1` against the control plane. An unreachable database is `503 DEPENDENCY_UNAVAILABLE` — the library's envelope maps it, so this file carries no readiness-specific handling. |
| `GET /api/me` | The caller's tenant slug, from the resolved context. Requires a verified principal **and** a resolvable tenant. |

The tenant comes from the resolver chain in `JDLIB_RESOLVERS__ORDER` — a JWT claim, a subdomain, a
path segment, a header, or an API key — and never from a parameter a caller could set.

A request to `/api/me` with no credentials answers the canonical envelope:

```json
{"code": "AUTHENTICATION_REQUIRED", "message": "...", "request_id": "...", "correlation_id": "..."}
```

The same shape carries a denial: `403` with `"code": "PERMISSION_DENIED"`, and no handler output in
the body.

## Tests

```bash
pytest examples/minimal/tests -q -W error     # from the repository root
```

| Test file | Needs | Proves |
| --- | --- | --- |
| `test_app.py` | the interpreter | the route walk, the parameter rule, the envelope, readiness answering 503 when its database is down, and a startup refusal without a DSN |
| `test_bootstrap_live.py` | PostgreSQL | the operator step provisions a tenant, read back from the database |
| `test_denial_live.py` | PostgreSQL | an allowed request answers 200 with the tenant; a denied one answers 403 and runs no handler |

The live tests need PostgreSQL: each uses
`JDLIB_EXAMPLE_DATABASE_URL` when you set one (a lab), otherwise a throwaway `postgres:16`
container, and it **skips with that reason** when neither is available — never a silent pass. It
reads the tenant back out of the database rather than trusting the value the call returned,
because a provisioning path that answers success and stores nothing is exactly what a return-value
assertion misses.

## What it leaves out, on purpose

One tenant shape (shared schema), one resolver (a header), one placement strategy, no queues, no
cache, no graph. Each omission is a decision the [enterprise example](../enterprise/README.md)
makes the other way, with the same library — and every one of them is documented under
[`docs/jdlib/`](../../docs/jdlib/README.md).
