# Authentication Hardening (Phase 2)

Status: **PARTIAL** — JWKS hardening and the JWT validator are implemented and
verified; token provider, ZITADEL adapter and service-identity formalisation
remain (see §5).

Source: `src/jdlib/authn/oidc.py` (hardened in place),
`src/jdlib/security/authn/` (new)
Tests: `tests/unit/security/test_jwks_hardening.py` (21),
`tests/unit/security/test_jwt_validator.py` (20)

---

## 1. JWKS cache hardening (spec #9)

`JwksCache` keeps its public signature and gains:

| Property | Behaviour |
|---|---|
| **Thundering-herd protection** | concurrent lookups share one refresh under an `asyncio.Lock`; 25 concurrent lookups for an unknown `kid` cause exactly **one** fetch (test) |
| **Stale-if-available** | a refresh failure or refresh timeout never discards usable key material; a cached `kid` keeps validating |
| **Cause surfaced** | when no usable key exists *and* the refresh failed, the original failure is re-raised (e.g. `RuntimeError`, `TimeoutError`) instead of being masked as "unknown key" — the audit trail distinguishes an identity-provider outage from a rotated-away key, while callers still fail closed |
| **Rate-limited retries** | a failed refresh is not retried before `min_refresh_interval`, so an IdP outage cannot become a request storm |
| **Explicit timeout** | every fetch is bounded by `timeout` (default 5s) via `asyncio.wait_for`; a hanging IdP cannot hang a request (test asserts it completes in <1s) |
| **Readiness** | `ready()` reports whether key material is loaded (spec #51) |
| **Safe introspection** | `__repr__` shows url, key count, staleness and last failure — never key material (test asserts the RSA modulus never appears) |

Behaviour change note (spec #90): the previous cache let fetch exceptions
propagate on every lookup. The hardened version degrades to cache and only
re-raises when nothing usable can be served. The existing regression test
`test_authenticator_fails_closed_when_jwks_fetch_raises` (which asserts the
audited failure reason is the underlying `RuntimeError`) still passes, so the
observability of an IdP outage is preserved.

## 2. Algorithm policy (spec #9, #10)

`assert_safe_algorithms()` — used by the validator at construction:

* `none` (any casing) is rejected,
* symmetric `HS*` algorithms are rejected for JWKS-based validation: a
  published verification key must never validate an HMAC token,
* an empty algorithm list is rejected (an allowlist, never a default),
* anything outside the explicit asymmetric allowlist (RS/PS/ES/EdDSA) is
  rejected.

Algorithms are never taken from the token itself.

## 3. JWT validator (spec #7, #10, #56)

`JwtTokenValidator` implements the core `TokenValidator` port (structural
conformance is asserted with the runtime protocol check).

* Signature, `iss`, `aud` and time claims are validated by the **existing**
  production `TokenVerifier` — one implementation, not two.
* Claim mapping is explicit (`JwtClaimMapping`): issuer, audience, algorithms,
  `subject_claim`, `scope_claims` (default `scope`, `scp`),
  `client_id_claims` (default `client_id`, `azp`).
* **Arbitrary claims never become privileges**: `roles`, `permissions`,
  `groups`, `ent`, `is_admin` in a token produce no scopes (test).
* Results carry `TokenMetadata` only — never the raw token; `repr` and `str` of
  the result and its metadata are asserted not to contain the token.
* Failures are typed and fail closed: expired → `ExpiredToken`; future `nbf`
  or `iat`, wrong issuer, wrong audience, missing subject, unknown `kid`,
  malformed token, invalid signature, `alg=none`, wrong algorithm
  (`HS256` against a public key) → `InvalidToken`.
* Key-source failures (e.g. an IdP outage surfacing from the JWKS cache) are
  wrapped as `InvalidToken` with the cause chained — 401 semantics with the
  cause preserved for logs/audit.
* `ready()` delegates to the key source (spec #51).

## 4. Tests added

Negative/adversarial cases per spec #56: invalid signature, expired token,
future `nbf`, future `iat`, wrong issuer, wrong audience, missing subject,
unsupported algorithm, `alg=none`, symmetric forgery, unknown `kid`, malformed
token; plus concurrency (single-flight), timeout, stale-if-available and
claim-hygiene tests.

## 5. Remaining Phase 2 work

* **TokenProvider** (outbound service credentials: client credentials /
  `private_key_jwt`, expiry-aware caching, single-flight refresh, `invalidate`,
  `OutboundToken` with `SecretStr`) — NOT IMPLEMENTED.
* **ZITADEL adapter** (config: issuer, audience, JWKS URI, allowed algorithms,
  client id, client auth method, scopes, timeouts, cache TTL; factory wiring
  `ZitadelTokenValidator` / `ZitadelTokenProvider`) — NOT IMPLEMENTED.
* **Service identity formalisation** (spec #39: service account vs user vs
  operator vs system vs anonymous) — PARTIAL: `PrincipalKind.SERVICE_ACCOUNT`
  and `ANONYMOUS` exist, entitlement checks for services exist in
  `EntitlementAdapter`; a dedicated service-identity module and its tests are
  pending.
* Wiring `JwtTokenValidator` into `build_authenticator` so the application
  path uses the hardened validator — pending (avoids a behaviour change
  without its own tests; the existing `OidcAuthenticator` path is untouched).
