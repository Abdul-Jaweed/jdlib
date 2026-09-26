---
guide: authentication
authority: docs/jdlib/authentication.md
modules:
  - src/jdlib/authn/base.py
  - src/jdlib/authn/wiring.py
  - src/jdlib/authn/apikey.py
  - src/jdlib/authn/oidc.py
  - src/jdlib/authn/composite.py
  - src/jdlib/security/context.py
exports:
  - Authenticator
  - build_authenticator
  - ApiKeyAuthenticator
  - OidcAuthenticator
  - CompositeAuthenticator
  - SecurityContext
  - AuthMethod
  - bearer_token
example:
  - examples/enterprise/app/security/authentication.py
test_files:
  - tests/unit/test_authn_wiring.py
  - tests/integration/test_apikey_auth.py
  - tests/unit/test_oidc_authenticator.py
  - tests/integration/test_authn_composite.py
  - tests/unit/security/test_security_context.py
---
# Authentication

> **Design authority:** [`docs/jdlib/authentication.md`](../authentication.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

Turning a credential a caller presents -- a bearer API key or an OIDC token -- into a verified `SecurityContext`: a principal, a method, the token's claims, and the request's ids.

## Why it exists

Every later decision (which tenant, which roles, what may be done) is only as trustworthy as the identity it starts from. Doing this once, in the library, is what stops each route from growing its own header parsing.

## When to use it

Always, for anything reachable by a caller outside the process. Also for in-process callers whose authority matters: the `Authenticator` interface takes a `RequestInfo`, not an HTTP request, so a job or a tool call presents a credential the same way a route does.

## When not to use it

For probes (`/healthz`) and static content, which must answer during an identity-provider outage -- a probe that needs a token gets the process restarted for it. And never for authorization: authentication says *who*, never *what may be done*.

## How it works

`build_authenticator(config, ...)` composes the configured methods (`ApiKeyAuthenticator`, `OidcAuthenticator`) into a `CompositeAuthenticator`. Each parses its credential form, verifies it (`verify_api_key_secret` against the stored hash, or the OIDC verifier against the JWKS), and returns a `SecurityContext` -- or raises, which the middleware maps to 401 in the canonical envelope.

## Architecture

`security/context.py` holds the context and its scope (`security_context_scope`); `authn/base.py` holds the interface and the failure recorder; `authn/wiring.py` builds the authenticator from `jdlib.config`; the middleware calls it once per request and binds the result. Nothing downstream re-reads a header.

## Example

`examples/enterprise/app/security/authentication.py` builds the principal provider the middleware uses; the example's live layer mints an API key, hashes it into the control plane, and drives a request through the library's own authenticator -- with a forged key refused as the control.

## Security

A credential is verified against stored material, never trusted: an API key is compared by hash (`hash_api_key_secret`), a token by signature. Failures are recorded (`record_authn_failure`) so an outage is visible rather than silent. The context is a value bound per request by `security_context_scope`, so no code can substitute an identity mid-request.

## Reliability

Verification depends on the identity provider: the OIDC path caches the JWKS and reports a degraded state rather than hanging, and the composite tries its methods in order. A credential failure is a 401, not a 500 -- an outage is a different answer from a bad token, and the two are distinguishable in the trail.

## Observability

The request and correlation ids are created at this boundary (`new_request_ids`) and carried in the context, so every later span, audit event and error envelope names the same request. Authentication decisions emit `SecurityAuditEvent`s.

## Audit

`AuthMethod` records how the caller was authenticated, and every failure is an audit event -- the trail answers 'was this credential refused, and why' without reading application logs.

## Configuration

`JDLIB_OIDC__ISSUER`, `JDLIB_OIDC__AUDIENCE` and the API-key prefix under `jdlib.config`; `JDLIB_CONTEXT__SIGNING_KEY` signs context material. Configuration is validated at startup: a process that cannot authenticate refuses to start.

## Testing

The library covers the wiring, the API-key path, the OIDC path and the composite; the example's live layer drives a real key that is really in the control plane, plus the negative control.

## Common mistakes

Reading a header instead of using the context; treating 401 as 403; making a probe require a token; assuming a verified identity implies an authorization decision.

## Production checklist

Serve `/healthz` without credentials and `/readyz` with the dependency checks; keep the JWKS cache warm; make sure the process refuses to start with an incomplete environment; keep authentication failures in the trail.
