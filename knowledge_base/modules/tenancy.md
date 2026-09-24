# Module: Tenancy (`src/jdlib/tenancy/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Bridges the outside world (HTTP requests, background jobs) to the context
machinery in `context.py`. Three files, one job each: identify the tenant from a
request, install the context for the request, and carry the context across an
async boundary.

## `resolution.py` — where does the tenant come from?

```python
class RequestInfo(NamedTuple):
    headers: Mapping[str, str]   # lowercase keys (ASGI convention)
    query: Mapping[str, str]
    path: str
    host: str
    claims: Mapping[str, object] = {}
```

Resolvers (each `async def resolve(request, principal) -> TenantRef | None`):

| Resolver | Source | Behaviour |
|---|---|---|
| `JwtClaimResolver(claim="tid")` | `request.claims[claim]` | Non-string claim ⇒ `None`. |
| `SubdomainResolver(base_domain=…)` | `request.host` | Strips the `.<base_domain>` suffix; a single-label prefix is accepted, multi-label or empty ⇒ `None`. Case-insensitive, trailing dot tolerated. |
| `PathResolver(prefix="/t/")` | `request.path` | First segment after the prefix. |
| `HeaderResolver(name="X-Tenant-Slug")` | header (case-insensitive) | Direct value. |
| `ApiKeyResolver()` | the authenticated principal | Only for `SERVICE_ACCOUNT` principals with a pinned `tenant_id`; returns `TenantRef(id=…)`. |

All slug/uuid values flow through `_slug_ref()`: it lowercases and strips the
input, tries `uuid.UUID(...)` first (so a UUID is treated as an id), then matches
`^[a-z0-9][a-z0-9-]{1,62}$` for a slug, and rejects anything else — the same
pattern enforced by the `tenants.slug` CHECK constraint.

`ResolverChain(resolvers)` returns the first non-`None` result — the chain is
ordered and deterministic; nothing merges. `build_chain(config: ResolverConfig)`
constructs the chain from the configured `order`, and silently omits the
subdomain resolver when `base_domain` is unset.

Security note: each resolver independently maps to a **reference**, never to a
context. Authorization always happens afterwards in `ContextFactory`.

## `middleware.py` — the ASGI pipeline

`TenantMiddleware(app, *, factory: ContextFactory, chain: ResolverChain,
principal_provider: PrincipalProvider)` — pure ASGI (no `BaseHTTPMiddleware`
buffering). For `scope["type"] != "http"` it passes straight through.

```
1. principal = await principal_provider(request)     → None ⇒ AuthenticationError("no credentials presented")
2. tenant_ref = await chain.resolve(request, principal) → None ⇒ TenantNotFound("tenant could not be resolved")
3. request_id / correlation_id / trace_id = _request_ids(headers)
4. context = await factory.for_principal(principal, tenant_ref, request_id=…, correlation_id=…, trace_id=…)
5. with context_scope(context): await self.app(scope, receive, send)
```

- `_request_ids`: `request_id = uuid4().hex` (always fresh);
  `correlation_id = header x-correlation-id` or the request id;
  `trace_id` extracted from a W3C `traceparent` header, but only when the second
  segment matches `[0-9a-f]{32}` (a non-hex or absent value yields `None` rather
  than a bogus id).
- Every `JdlibError` raised in steps 1–4 is converted to a JSON response by
  `_send_error` with the status from the frozen table below; the `contextvar` is
  installed only after the context exists, and `context_scope` guarantees it is
  reset even when the app raises.
- Non-`JdlibError` exceptions propagate unchanged — the middleware never hides
  programming errors behind a 500 body it invented.

### Frozen HTTP mapping (`http_status_for`, `middleware.py:26`)

| Error (first match wins — order matters) | Status |
|---|---|
| `AuthenticationError` | 401 |
| `AuthorizationError` | 403 |
| `TenantNotFound` | 404 |
| `TenantAccessDenied` | 404 |
| `TenantSuspended` | 423 |
| `TenantNotWritable` | 423 |
| `CrossTenantReferenceError` | 409 |
| `InvalidReference` | 409 |
| anything else (`JdlibError` or not) | 500 |

Because `PermissionDenied`/`RoleEscalationBlocked` subclass `AuthorizationError`
they map to 403; because `TenantAccessDenied` is checked after `TenantNotFound`
but before suspension, an unentitled principal on a suspended tenant sees **404**,
not 423 (`tests/unit/test_middleware.py::test_unentitled_principal_on_suspended_tenant_is_404_not_423`).
Response body: `{"error": "<ClassName>", "detail": "<message>"}`.

## `jobs.py` — crossing the async boundary

```python
class ContextPropagator:
    def __init__(self, *, codec: EnvelopeCodec, principals: PrincipalDirectory,
                 tenants: TenantDirectory, servability: ServabilityChecker,
                 entitlements: EntitlementChecker): ...

    async def reconstruct(self, token: str) -> TenantContext: ...

def tenant_job(propagator: ContextPropagator) -> Callable[[F], F]: ...
```

`reconstruct` deliberately re-derives everything instead of trusting the token:

1. `codec.decode(token)` verifies the HMAC and TTL (`InvalidToken`/`ExpiredToken`).
2. Rebuilds a `Principal` from the envelope; for `SERVICE_ACCOUNT` it re-pins
   `tenant_id` to `envelope.tenant_id` so the pin check can never be bypassed.
3. `principals.is_active` ⇒ `UnknownPrincipal`.
4. `tenants.get(TenantRef(id=envelope.tenant_id))` ⇒ `TenantNotFound`.
5. `entitlements.can_act` ⇒ `TenantAccessDenied`.
6. `servability.assert_servable` ⇒ `TenantSuspended` for suspended tenants or
   tenants mid-relocation.
7. Returns a `TenantContext` with `privilege=None` (privileged contexts are never
   propagated; a job gets an ordinary principal context or nothing).

`tenant_job(propagator)` decorates an async function whose **first positional
parameter is the envelope string**:

```python
@tenant_job(propagator)
async def send_digest(envelope: str, user_id: UUID) -> None:
    context = current_tenant()      # installed for the duration of the call
    ...
```

The wrapper reconstructs, installs the context with `context_scope`, calls the
function, and guarantees the contextvar is cleared even on exception
(`tests/unit/test_jobs.py`).

### Why an envelope and not a serialized context

`TenantContextEnvelope` carries tenant id, principal type/id, request ids and
`issued_at` only (`context.py`). The design notes
(`docs/jdlib/03` I7, `docs/jdlib/07` §4) are explicit that this is intentional:
permissions and privileges must be *re-derived* at execution time, because a
queued job may run after a revocation. The tests assert that a permission-looking
field smuggled into the payload has no effect
(`tests/unit/test_envelope.py::test_token_does_not_contain_permissions_or_scopes`).

## Practical wiring notes

- The middleware needs a callable `principal_provider`;
  `build_authenticator(...).authenticate` is the shipped implementation
  (`authn/wiring.py`). Passing a bound method is fine — the port is
  `async def __call__(request) -> Principal | None`.
- `RequestInfo` is constructed by the middleware with `claims={}`; supply the JWT
  claims yourself if you use `JwtClaimResolver` (the shipped `OidcAuthenticator`
  verifies tokens but does not write claims into `RequestInfo` — the resolver is
  for deployments that decode claims earlier in their own pipeline). This is a
  real seam worth knowing about; see
  [../limitations_and_edge_cases.md](../limitations_and_edge_cases.md).
