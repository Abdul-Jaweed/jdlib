# Quickstart

The shortest path from an empty environment to a guarded request. This is the README's quickstart,
with the reasoning the README has no room for.

## 1. Configure

`TenancyConfig` is a pydantic-settings model: every field is settable through `JDLIB_*` environment
variables, `__` nests, and secrets stay wrapped in `SecretStr` so they cannot be logged by accident.

```bash
export JDLIB_CONTROL_DSN="postgresql+psycopg://jd:secret@localhost:5432/app"
export JDLIB_CONTEXT__SIGNING_KEY="$(openssl rand -hex 32)"
export JDLIB_OIDC__ISSUER="https://login.example.com/"
export JDLIB_OIDC__AUDIENCE="my-api"
```

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from jdlib import TenancyConfig

config = TenancyConfig()  # fails fast when JDLIB_CONTEXT__SIGNING_KEY is missing
engine = create_async_engine(config.control_dsn.get_secret_value())
control_sessions = async_sessionmaker(engine, expire_on_commit=False)
```

The signing key is not optional and has no default: it signs the context envelope a job or a
delegation carries, and a default would be a shared secret every deployment had.

## 2. Migrate and provision

Two operator steps, deliberately separate from serving: a process that migrates while it starts does
both on every worker, and a half-applied provisioning that a restart retries is the failure this
split avoids.

```bash
jdlib db upgrade-control --database-url "$JDLIB_CONTROL_DSN"
jdlib tenant create --slug acme --name "Acme Inc" --strategy shared --target-handle default
jdlib tenant provision <tenant-id>   # provisions the placement plane, migrates, activates
```

Programmatically: `MigrationRunner(url).upgrade_control()`, then
`TenantRegistry(...).create(...)` and `.provision(tenant.id)`.

## 3. Wire FastAPI

`install(...)` puts the library's middleware, guard and error envelope on your application; the
routes declare what they need rather than checking it.

```python
from fastapi import FastAPI

from jdlib.integrations.fastapi import install, require

app = FastAPI()


@app.get("/api/me")
@require("tenant:read")
async def me() -> dict[str, str]:
    return {"tenant": current_tenant().slug}
```

The full wiring — the authenticator, the resolver chain, the context factory, the policy decision
point, the audit sink and the strategies — is the [first application](first-application.md), and the
[README's quickstart](https://github.com/Abdul-Jaweed/jdlib#60-second-quickstart) is the long form of
this page with every collaborator named.

## What just happened

1. The credential was verified by the library's authenticator, not by your code.
2. The tenant was decided by the resolver chain — a JWT claim, a subdomain, a path segment, a header
   or an API key, in the order `JDLIB_RESOLVERS__ORDER` sets.
3. `require("tenant:read")` was put to the policy engine **before** the handler ran, and a refusal
   would have answered the canonical envelope without executing it.
4. The context was bound for the request, so `current_tenant()` reads the tenant the *credential*
   resolved rather than anything the caller sent.

## Next

* [First application](first-application.md) — the same thing as a complete, tested application.
* [Features](../jdlib/features/README.md) — one guide per mechanism.
* [Configuration](configuration.md) — every setting, what it does, and what happens without it.
