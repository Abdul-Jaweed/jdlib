---
page: authentication
sources:
  - src/jdlib/security/authn
  - src/jdlib/security/context.py
  - tests/unit/security
---
# Authentication

## Authenticators

JWT and OIDC verification (JWKS-backed, cached), a gateway identity path for a deployment behind
Kong, an API-key path for machines, and a service-authn path where one service acts for a tenant.
Each produces the same thing: a `Principal` with a kind, an id and - for service accounts - the
tenant it is pinned to.

`AuthMethod` records which path authenticated the request (`GATEWAY`, `JWT`, `SERVICE`, ...), and
that value reaches the audit record.

## Machine identities

Service accounts are pinned and registered: the entitlement adapter requires the principal's
tenant to be the target tenant *and* the account to be registered for it. An api key is a
credential like any other - hashed at rest, revocable, and subject to the same audit path.

## Failure semantics

| Case | Outcome |
|---|---|
| Invalid or expired token | Refusal (`InvalidToken` / `ExpiredToken`) |
| Identity provider unreachable | 503 (`AuthenticationUnavailable`), never a bypass |
| Token without roles or scopes | 401/403 at the authorization layer, not silently anonymous |
| Gateway mode where the gateway is absent | Configuration error at startup, not at request time |

## What authentication does not do

It does not decide authorization, and it does not read a tenant or role claim and trust it as
authority. `ClaimMapper` maps no tenant claim; tenancy comes from the control plane. A token that
carries a tenant claim is not a tenant binding - that is why the resolution chain and the access
reader exist.
