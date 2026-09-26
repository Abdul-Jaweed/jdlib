---
guide: aws
authority: docs/security/gateway-hardening.md
modules: []
exports: []
test_files: []
---

# Amazon API Gateway: the edge, not the boundary

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md),
> [the research sources](research-sources.md), and the library's own
> [gateway hardening](../../security/gateway-hardening.md)
> page. API Gateway is classified **INFRASTRUCTURE_ONLY**: it is an edge control, and this page
> exists so that no reader mistakes it for a JDLib abstraction.

## What it is

A managed HTTP edge: TLS, routing, throttling, request validation, WAF integration, and authorizers
that decide whether a request reaches the backend at all.

## Why there is no adapter for it

The library already has gateway adapters — `KongGatewayAdapter`, `TykGatewayAdapter` — and they do
something specific: they verify a **signature over the identity claims** a gateway injects as
headers. `_canonical(subject, tenant, scopes, issued, expires)` is the exact byte string a gateway
signs, and `NoGatewayAdapter` exists for deployments where identity may never come from a header at
all.

API Gateway has no equivalent contract. It does not inject a signed identity envelope that a backend
can verify; a JWT authorizer validates a token and lets the request through, and a Lambda
authorizer's context reaches the backend as a plain map. Neither is something JDLib can verify, so
there is nothing to adapt. Inventing a third gateway adapter here would mean inventing a trust
contract that AWS does not offer — which is precisely the kind of interface section 29 forbids.

## The three integrations that are correct

### 1. JWT authorizer with pass-through (recommended)

API Gateway validates the token at the edge and forwards it; the application validates it again.

```text
client --Bearer token--> API Gateway (JWT authorizer: issuer, audience, scopes)
                              |  forwards the Authorization header
                              v
                         JDLib (CognitoAuthenticator validates it for real)
```

The edge check is a fast reject, not the security decision. JDLib still verifies signature, issuer,
audience and expiry — with the [Cognito adapter](authentication-cognito.md) when the pool is Cognito
— because the application must not depend on a header a caller could have supplied directly if the
edge were bypassed, misconfigured, or fronted by another path.

### 2. Lambda authorizer: treat its context as a hint, never as identity

A Lambda authorizer can return a context map that API Gateway passes to the backend. That map is
**not verifiable** by the application: it is plain data from a component the application cannot
authenticate. Use it for routing or logging if it is useful; do not build a `Principal` from it.
The documented authorizer cache (300 seconds by default) also means a decision can outlive the
credential that produced it.

### 3. IAM authorization (SigV4) for service-to-service

When the caller is an AWS principal rather than a user, IAM authorization is the right edge control:
it authenticates the AWS identity and the request's signature. That identity is an AWS principal —
it says nothing about a JDLib tenant or permission, so the application still maps it to a principal
and asks its own decision point.

## What API Gateway must not be trusted for

| Not this | Because |
| --- | --- |
| Application authorization | No policy language, no resource-level decisions, no tenancy model. A JWT authorizer checks a token's claims; it cannot decide whether *this* principal may read *that* tenant's document. |
| Tenant isolation | Scopes and claims are not tenancy. Tenant scoping is the application's and the policy store's job. |
| The identity of a caller to the application | Unless the application verified it itself. Edge validation is an optimisation. |
| Request-body semantics | Request validation checks shapes and sizes, not permissions. |

## What it is genuinely good for

* **Throttling and quotas** at the edge, so a burst reaches the application as a controlled rate
  rather than as load. (The application's own limits still exist; the edge is not a substitute.)
* **WAF** in front of the API, before any application code runs.
* **Request validation** — body shape, parameter types, payload size — cheaply rejected.
* **Private APIs** and VPC endpoints, so the application is not reachable from the public internet at
  all.
* **Usage plans and API keys** for partner-facing quotas. Note what an API key is *not*: it is not
  authentication, and the library never treats it as such.

## Operational notes worth knowing

* A REST API integration timeout is 29 seconds. Long-running work must not be behind a synchronous
  integration; queue it or make it asynchronous.
* Authorizer results are cached (300 seconds by default for REST APIs), so revocation and permission
  changes are visible only after the cache expires. Short token lifetimes and application-side
  validation bound the exposure; the edge cache does not.
* Payload limits (10 MB for REST) mean large uploads go directly to S3 with a presigned URL rather
  than through the API — which is also why the library's S3 capability is a separate concern.

## Where this leaves the architecture

The edge rejects cheaply and loudly. The application authenticates and authorizes for real. The
decision point never moves to the edge, which is the same conclusion
[the gateway comparison](gateway-comparison.md) reaches for Kong and Tyk.
