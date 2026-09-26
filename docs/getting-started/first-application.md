# Your first application

The smallest application that is *correct*: two routes, one guard, one tenant, and no security
mechanism of its own. This page is the shape; [`examples/minimal`](https://github.com/Abdul-Jaweed/jdlib/tree/main/examples/minimal)
is the code, and it is run by its own tests.

## The shape

```
app/
├── asgi.py        uvicorn examples.minimal.app.asgi:app
├── bootstrap.py   the operator step: create and provision one tenant
└── main.py        install(...), two ops routes, one guarded route
```

Three files, because there are exactly three jobs: serve, provision, and compose. An application
that mixes provisioning into serving does both on every worker.

## 1. Compose the library

```python
from jdlib import ContextFactory, TenancyConfig
from jdlib.authn.wiring import build_authenticator
from jdlib.integrations.fastapi import install
from jdlib.tenancy.resolution import build_chain

config = TenancyConfig()
authenticator = build_authenticator(config)          # API keys and OIDC, from the config
chain = build_chain(config)                          # the resolver order is configuration, not code
factory = ContextFactory(...)                        # verifies the tenant's lifecycle state
app = install(app, authenticator=authenticator, chain=chain, factory=factory, ...)
```

`install(...)` is the whole integration: the middleware that gives the request its ids, the guard
that resolves identity and tenant, and the error envelope that answers every failure. The example
carries no middleware of its own, and its tests assert that by walking the routes.

## 2. Declare what each route needs

```python
from jdlib import current_tenant
from jdlib.integrations.fastapi import require


@app.get("/api/me")
@require("tenant:read")
async def me() -> dict[str, str]:
    """The caller's tenant, from the resolved context - never from a parameter."""
    return {"tenant": current_tenant().slug}
```

The permission is *declared*, not checked inside the handler. That is the difference between a
control and a code path: a declared permission is enforced by the guard before the handler is
entered, and the route walk in `tests/test_app.py` fails when a tenant route has no declaration.

## 3. Keep the probes outside the guarded plane

```python
@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is serving. No credentials, no dependency checks."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, str]:
    """Readiness: SELECT 1 against the control plane. An unreachable database is 503."""
    await control_sessions.execute(text("SELECT 1"))
    return {"status": "ready"}
```

A probe that needs a token fails during an identity-provider outage and gets the process restarted
for it. `readyz` answers `503 DEPENDENCY_UNAVAILABLE` through the library's envelope, so the route
carries no readiness-specific handling.

## 4. Provision, then serve

```bash
export JDLIB_CONTROL_DSN="postgresql://jdlib:***@127.0.0.1:5432/jdlib_example"
export JDLIB_CONTEXT__SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export JDLIB_OIDC__ISSUER="https://your-issuer.example/"
export JDLIB_OIDC__AUDIENCE="jdlib-example"

python -m examples.minimal.app.bootstrap --slug acme --name "Acme Inc"   # once
uvicorn examples.minimal.app.asgi:app --host 127.0.0.1 --port 8000       # then
```

## 5. Read what the tests prove

```bash
pytest examples/minimal/tests -q -W error
```

| Test file | Needs | Proves |
|---|---|---|
| `test_app.py` | the interpreter | the route walk, the parameter rule, the envelope, readiness answering 503 when its database is down, and a startup refusal without a DSN |
| `test_bootstrap_live.py` | PostgreSQL | the operator step provisions a tenant, read back from the database |
| `test_denial_live.py` | PostgreSQL | an allowed request answers 200 with the tenant; a denied one answers 403 and runs no handler |

That last row is the one worth copying into your own application: a denial is measured as
**non-execution**, with an allowing control beside it so the test cannot pass by refusing everything.

## Where to go next

* [Enterprise example](../jdlib/examples/enterprise-example.md) — the same library across HTTP and
  MCP, PostgreSQL and Neo4j, a real policy engine and the reliability primitives.
* [Tenancy](../jdlib/features/tenancy.md) and [Authorization](../jdlib/features/authorization.md) —
  the two mechanisms a first application gets wrong most often.
