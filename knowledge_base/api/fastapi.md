# API: FastAPI Integration

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Requires `pip install "jdlib[fastapi]"`. Internals (why it is implemented this
way) are in [../modules/integrations.md](../modules/integrations.md); this page
is the usage contract.

## Install the middleware, handlers and DI container

```python
from fastapi import Depends, FastAPI

from jdlib import ContextFactory, TenancyConfig, TenantContext
from jdlib.authn.wiring import (EntitlementAdapter, PrincipalDirectoryAdapter,
                                TenantDirectoryAdapter, build_authenticator)
from jdlib.authz.guards import Enforcer
from jdlib.authz.pdp import Decision, DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.authz.scopes import ScopeResolver, Target
from jdlib.control.audit import DatabaseAuditSink, PrivilegeAuditAdapter
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.integrations.fastapi import JdlibContainer, get_context, get_uow, install, require

app = FastAPI()

def make_pdp() -> DefaultPDP:                      # request-scoped cache only!
    return DefaultPDP(catalog=catalog, reader=reader,
                      scopes=ScopeResolver(resource_types))

class RequestScopedEnforcer(Enforcer):
    async def require(self, permission: str, target: Target, *, session: object) -> Decision:
        return await Enforcer(make_pdp()).require(permission, target, session=session)

def uow_factory():
    context = current_tenant()
    return UnitOfWork(tenant_sessions, context,
                      fence=RegistryWriteFence(session_factory=control_sessions))

install(
    app,
    factory=ContextFactory(config=config.context, principals=…, tenants=…,
                           servability=registry, entitlements=…, operators=…,
                           audit=PrivilegeAuditAdapter(audit)),
    chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug"), ApiKeyResolver()]),
    principal_provider=build_authenticator(config, control_sessions, audit).authenticate,
    container=JdlibContainer(session_factory=control_sessions,
                             uow_factory=uow_factory,
                             enforcer=RequestScopedEnforcer()),
)
```

`install` = `app.state.jdlib_container = container` + `TenantMiddleware` +
`exception_handler(JdlibError)`. A complete runnable version of this snippet is
in the repository `README.md` (steps 1–3) and in
[../examples.md](../examples.md).

## Dependencies

| Dependency | Type | Use |
|---|---|---|
| `Depends(get_context)` | `TenantContext` | read `context.tenant_id` / `tenant_slug` / `principal`. |
| `Depends(require("resource:read"))` | `None` (raises on denial) | route-level guard on the tenant scope. |
| `Depends(require("resource:update", target_factory=lambda request: ResourceRef("invoice", uuid.UUID(request.path_params["invoice_id"]))))` | `None` | resource-scoped guard. |
| `Depends(get_uow)` | `UnitOfWork` | open it in the handler: `async with uow as session: …`. |

```python
@app.get("/invoices", dependencies=[Depends(require("resource:read"))])
async def list_invoices(uow: UnitOfWork = Depends(get_uow)) -> list[str]:
    async with uow as session:
        return [i.number for i in await TenantRepository(session, Invoice).list()]
```

## Behaviour contract

1. **Order of failure.** Missing/invalid credentials ⇒ 401; unresolvable tenant ⇒
   404; unentitled principal ⇒ 404 (existence is not disclosed); suspended tenant
   for an entitled principal ⇒ 423; cross-tenant reference ⇒ 409. The mapping is
   the frozen table in [../modules/tenancy.md](../modules/tenancy.md).
2. **Error body.** `{"error": "<ExceptionClassName>", "detail": "<message>"}` for
   anything raised inside the middleware *and* for handlers (via the registered
   `JdlibError` handler). Non-`JdlibError` exceptions keep FastAPI's default
   500 behaviour.
3. **Guard vs handler transactions.** The guard authorizes in its own
   `UnitOfWork` (so the write fence applies to guarded reads: 423 during a
   relocation quiesce); the handler's `get_uow` opens a *separate* transaction and
   the guard's decision is not re-validated there. If revocation latency matters,
   call `authorize(...)` again inside the handler.
4. **The context is request-scoped.** It is installed before the app is called and
   reset afterwards, even on exceptions; never cache `get_context()`'s result
   across requests, and never build one `DefaultPDP`/`AuthzCache` at import time
   and share it.
5. **`require` needs the container.** Calling it on an app installed without a
   container raises `RuntimeError("jdlib container is not installed on the app")`.

## Tests to copy

`tests/integration/test_fastapi_integration.py` covers: 401 without credentials,
404 when an API key pinned to tenant A presents tenant B's header, tenant
resolution from an API key, `require` denial ⇒ 403 JSON, container dependencies
yield a working `UnitOfWork`, a handler-raised `JdlibError` maps through the
handler, and a grant against a soft-deleted resource ⇒ 409.
