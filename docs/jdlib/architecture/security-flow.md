# The security flow, step by step

What happens between a request arriving and a handler running, and where each decision is recorded.
The paths below are the real ones; every step is covered by a test named at the end.

## A request over HTTP

```
1. TenantMiddleware                RequestInfo(headers, path, host, query)
2. PrincipalProvider / authenticator   credential → SecurityContext
      · API key: parse_api_key → hash_api_key_secret → compare with the stored hash
      · OIDC:    verify the token against the JWKS (cached)
      · failure → 401 in the canonical envelope; recorded as a security event
3. ResolverChain                   which tenant: JwtClaimResolver → Subdomain → Path → Header → ApiKey
4. ContextFactory                  TenantContext + the factory's checks
      · the service account is active, the tenant is not suspended
      · failure → 403/404 per the mapping, recorded
5. context_scope(...)              the tenant context is bound for this request only
6. require("resource:write")       AuthorizationQuery(principal, tenant, target, action, roles)
7. AuthorizationPEP.require        the engine answers; a denial or a *degraded* answer raises
      · denial → PermissionDenied → 403 PERMISSION_DENIED, the handler never runs
      · degraded → AuthorizationUnavailable → 503
8. the handler                     the service, the repository, the database -- bound to the tenant
9. the envelope / the response     exactly one error contract for every failure
```

## The same chain over MCP

```
1. McpSecurityBoundary             the request's credential → SecurityContext  (the same authenticator)
2. ResolverChain + ContextFactory  the same resolution, the same checks
3. the invocation binds both scopes: security_context_scope(...) and context_scope(context.require_tenant())
4. the declared capability is put to the same engine, against the caller's *tenant scope*
      · the tool has no resource id to be asked about before it runs -- the question is about the tenant
5. the handler                     the same services, the same repository, the same database
6. audit                           three events on a refusal: mcp.request, the engine's decision, the refusal
```

## Where the answers are recorded

| Event | Where it lands | Who can read it |
|---|---|---|
| authentication failure | security event → the platform trail | an operator with `audit:read` |
| authorization allow/deny | `security.AUTHZ_*.{SUCCESS,DENIED}` in the trail | same |
| privileged access | the trail, with the operator's identity | same, and it is the point |
| every request | a span with allow-listed attributes | the tracer's collector |
| failures | the canonical envelope, with request and correlation ids | the caller |

## What the tests assert

* a denied call executes nothing — measured at the row, read as the **owner** (`tests/security/test_denial_non_execution.py`);
* another tenant's row is unreachable by any path — over both surfaces (`tests/security/test_tenant_isolation.py`);
* no failure leaks an internal — a deny-list over every probe (`tests/security/test_error_surface.py`);
* the whole chain over a real socket, in a real process (`tests/e2e/test_http_chain.py`);
* the MCP chain's own three events, and a forged key refused (`tests/integration/test_mcp_live.py`).
