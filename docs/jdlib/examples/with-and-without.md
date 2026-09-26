# With and without JDLib

What the library is doing for you, side by side with the code you would otherwise write.

> **The "without" snippets are illustrative.** They are marked as such deliberately, and they are
> **never runnable production paths**: the directive forbids shipping deliberately vulnerable code
> as an example, so nothing here is importable and no test executes it. They exist to make the
> difference legible, not to be copied. The "with JDLib" column names the seam that does the work —
> every entry is a real module, and the feature guides link to the page that owns it.

## Authenticating a caller

**Without** — the shape a hand-written app drifts into:

```python
# ILLUSTRATIVE, NOT RUNNABLE: parses a credential, compares it in a request handler,
# and trusts whatever the comparison says.
token = request.headers["authorization"].removeprefix("Bearer ")
row = db.execute("SELECT * FROM api_keys WHERE prefix = %s", (token.split(".")[0],)).fetchone()
if row and row["secret"] == token.split(".")[-1]:   # a plaintext comparison
    tenant = request.headers.get("x-tenant")        # a claim the caller controls
```

**With JDLib** — `jdlib.authn` + `jdlib.tenancy`: `build_authenticator` verifies the credential
against its hash, the `ResolverChain` decides the tenant, and the `ContextFactory` builds a
`TenantContext` that no request field can influence.

## Authorizing an operation

**Without** — a check inside the handler, or a role read from the request:

```python
# ILLUSTRATIVE, NOT RUNNABLE: the check is a code path someone can forget to take,
# and it runs after the operation has started.
if "admin" in request.headers.get("x-roles", ""):
    do_the_write()
```

**With JDLib** — `require("resource:write")` (`jdlib.integrations.fastapi`) declares the permission
on the route; `AuthorizationPEP` asks the engine before the handler is entered, refuses a degraded
answer, and the refusal is the canonical envelope.

## Isolating tenants

**Without** — a filter per query, remembered at every call site:

```python
# ILLUSTRATIVE, NOT RUNNABLE: one forgotten `WHERE tenant_id = ...` is a cross-tenant read.
rows = db.execute("SELECT * FROM resources WHERE kind = %s", (kind,)).fetchall()
```

**With JDLib** — `jdlib.persistence.TenantRepository` opens a tenant-bound session,
`install_rls` puts the same rule in the database, and an unbound session reads nothing.

## Answering a failure

**Without** — every layer inventing a shape:

```python
# ILLUSTRATIVE, NOT RUNNABLE: the client gets a traceback, a table name, or both.
except Exception as error:
    return JSONResponse({"error": str(error)}, status_code=500)
```

**With JDLib** — `install_error_envelope`: one envelope (four keys), 4xx messages are the error's own
text made printable and capped, 5xx never echoes its own text, and a 401 carries the RFC 6750
challenge.

## Reaching a graph

**Without** — a driver in a handler, a label from input:

```python
# ILLUSTRATIVE, NOT RUNNABLE: the tenant is a parameter, the label is interpolated,
# and the driver is the application's problem forever.
session.run(f"MATCH (n:{label} {{tenant: '{tenant_id}'}}) RETURN n")
```

**With JDLib** — `jdlib.graph.GraphRepository` (tenant-bound), a closed vocabulary from
`graph/mapping.py`, and `GraphTenantViolationError` for a statement that would cross tenants.

## Exposing a tool surface

**Without** — a second entry point with its own shortcuts:

```python
# ILLUSTRATIVE, NOT RUNNABLE: the tool trusts an argument for identity and never asks policy.
@tool
def get_resource(tenant_id: str, resource_id: str) -> dict:
    return db.fetch_resource(tenant_id, resource_id)
```

**With JDLib** — `McpTool` declarations with a required capability, `McpSecurityBoundary` turning the
credential into a `SecurityContext`, and the same engine answering the same question the HTTP route
asks.

## The honest summary

| Concern | What the library provides | What remains yours |
|---|---|---|
| identity | verification, the context, the failure vocabulary | choosing the methods, the directory, the issuer |
| authorization | the guard, the query, the PEP, fail-closed | writing the policies, and testing them |
| tenancy | resolution, the bound session, RLS | choosing placement, provisioning tenants |
| errors | one envelope, no internals | mapping your own domain errors to it |
| audit | the vocabulary and the writers | the action names, and where the trail lives |
| reliability | breaker, budget, gate, shutdown | the thresholds, and what may degrade |

The library does not decide your policies, your placement or your thresholds — those are deployment
decisions. What it does is make the *mechanism* the same everywhere, so a decision cannot differ by
protocol, by surface, or by whoever wrote the route.
