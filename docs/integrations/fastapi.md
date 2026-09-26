# FastAPI

```bash
pip install "jdlib[fastapi]"
```

`jdlib.integrations.fastapi` is the HTTP edge. It is one call plus one decorator.

## Install the chain

```python
from fastapi import FastAPI

from jdlib import ContextFactory, TenancyConfig
from jdlib.authn.wiring import build_authenticator
from jdlib.integrations.fastapi import install
from jdlib.tenancy.resolution import build_chain

app = FastAPI()
config = TenancyConfig()

app = install(
    app,
    authenticator=build_authenticator(config),
    chain=build_chain(config),
    factory=ContextFactory(...),
    ...
)
```

`install(...)` puts the library's middleware on the application: request ids, the deadline, the
security headers, the guard that resolves identity and tenant, and the error envelope. The
application does not add its own middleware for any of those, and the minimal example asserts that by
walking the routes.

## Declare what a route needs

```python
from jdlib import current_tenant
from jdlib.integrations.fastapi import require


@app.get("/api/me")
@require("tenant:read")
async def me() -> dict[str, str]:
    return {"tenant": current_tenant().slug}
```

`require(...)` is the declaration the guard enforces *before* the handler runs. A tenant-scoped route
without a declaration is a defect the example's route walk fails on.

## Read the request's context and unit of work

| Helper | Returns | Use it for |
|---|---|---|
| `get_context()` | the bound `SecurityContext` | the principal, the tenant, the request ids |
| `get_uow()` | the tenant-bound unit of work | repositories and transactions |
| `current_tenant()` | the tenant from the context | the common case, without a parameter |

None of them takes a tenant argument, because a route that could pass one could pass the wrong one.

## Failures

Every failure leaves as the library's envelope — the same shape the MCP surface produces:

| Status | Code | When |
|---|---|---|
| 401 | `UNAUTHENTICATED` | the credential is missing or unverifiable |
| 403 | `AUTHORIZATION_DENIED` | the decision was deny, or the engine was unreachable |
| 403 / 404 | `TENANT_SUSPENDED` / `NOT_FOUND` | the tenant's lifecycle state refuses the request |
| 409 | `INVALID_REFERENCE` | a reference crosses a boundary — a cross-tenant read is a refusal, not an empty page |
| 429 | `RATE_LIMITED` | the concurrency gate refused the work |
| 503 | `DEPENDENCY_UNAVAILABLE` | a dependency is down; readiness answers the same way |

A 5xx never echoes its own exception text: the envelope carries a stable code and a request id, and
the detail is in the log and the span.

## Where it is tested

`examples/minimal/tests/test_app.py` (the route walk, the parameter rule, the envelope, readiness),
`examples/enterprise/tests/` (the composed chain against live PostgreSQL, Cerbos and Neo4j), and the
library's own `tests/unit/` for the middleware's ordering rules.
