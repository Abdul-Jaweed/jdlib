# Authentication Hardening (Phase 2)

Status: **COMPLETE** — inbound validation, outbound credentials, the ZITADEL
adapter and service-identity formalisation are implemented and verified, over
three layers (unit, real-HTTP integration, real-ZITADEL infra).

Source: `src/jdlib/authn/oidc.py` (hardened in place),
`src/jdlib/security/authn/` (new), `src/jdlib/security/identity.py` (new)
Tests: `tests/unit/security/` (unit), `tests/integration/test_authn_http_integration.py`
(real HTTP), `tests/infra/test_zitadel_infra.py` (real ZITADEL)

| Evidence | Result |
|---|---|
| Unit (security) | 165 passed |
| Integration (real HTTP over TCP, real RSA) | 11 passed |
| Infra (real ZITADEL 4.19.1) | 4 passed (skipped without `JDLIB_INFRA_ZITADEL_ISSUER`) |
| Full suite (`pytest -q -W error`) | **744 passed** |
| `ruff check .` | clean |
| `mypy src/jdlib` | clean (76 files) |

---

## 1. JWKS cache hardening (spec #9)

`JwksCache` keeps its public signature and gains:

| Property | Behaviour |
|---|---|
| **Thundering-herd protection** | concurrent lookups share one refresh under an `asyncio.Lock`; 25 concurrent lookups for an unknown `kid` cause exactly **one** fetch (test) |
| **Stale-if-available** | a refresh failure or refresh timeout never discards usable key material; a cached `kid` keeps validating |
| **Cause surfaced** | when no usable key exists *and* the refresh failed, the original failure is re-raised (e.g. `RuntimeError`, `TimeoutError`) instead of being masked as "unknown key" — the audit trail distinguishes an identity-provider outage from a rotated-away key, while callers still fail closed |
| **Rate-limited retries** | a failed refresh is not retried before `min_refresh_interval` (default 1s, configurable), so an IdP outage cannot become a request storm |
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
* `ready()` delegates to the key source (spec #51); `keys` and `mapping` are
  read-only diagnostics used by the adapter and health wiring.

## 4. Token provider (spec #7, #59, #76, #78)

`ClientCredentialsTokenProvider` issues outbound service credentials.

| Requirement | Behaviour |
|---|---|
| Grant | `grant_type=client_credentials`; `audience` and `scope` are sent when configured |
| Client authentication | `client_secret_post`, `client_secret_basic` (credential delivered in the transport's `Authorization` header, never as a form field) and `private_key_jwt` (signed JWT assertion: `iss`/`sub` = client id, `aud` = token endpoint, `iat`/`exp`/`jti`) |
| Credential handling | the only value ever handed to a caller is `OutboundToken.value` (`SecretStr`); `repr` of provider, config and token contain no secret (test) |
| Caching | per `(audience, scopes)` with LRU bound `max_cache_entries`; a token is reused while `now < expires_at - expiry_skew` |
| Single flight | 100 concurrent callers trigger exactly **one** token request (test) |
| Invalidation | `invalidate()` empties the cache; expiry, invalidation and cache bounds are all tested |
| Transient failures | retried with exponential full-jitter backoff under a per-attempt timeout, then fail closed with `TokenEndpointUnavailable` |
| Permanent failures | 4xx credential rejections are never retried and never cached (an `invalid_client` must not be hammered) |
| Response hygiene | a response without a usable `expires_in` is rejected — an unbounded token is never cached |

## 5. ZITADEL adapter (spec #8)

Configuration and wiring only — vendor specifics do not leak into the core:

* endpoints are derived from the issuer (`/oauth/v2/keys`,
  `/oauth/v2/token`) with explicit overrides available,
* `build_zitadel_token_validator()` and `build_zitadel_token_provider()`
  return the generic, already-tested validator and provider,
* `zitadel_provider_config()` translates settings and fails closed when the
  credentials required by the chosen client-auth method are missing,
* the issuer must be `https` (localhost/`127.0.0.1` allowed for development),
* secrets are `SecretStr`; `repr`, `model_dump()` and `model_dump_json()`
  never contain them (regression-tested).

Verified against a real ZITADEL 4.19.1 container (`tests/infra/`): the derived
JWKS URI and token endpoint are exactly the ones ZITADEL advertises in its
discovery document, and the JWKS document it serves is fetched and parsed.

## 6. Service identity formalisation (directive §13, spec #39)

`IdentityKind` keeps human users, service accounts, operator identities, system
identities and anonymous principals distinct; unknown principal kinds fail
closed rather than defaulting to a permitted kind. `ServiceIdentity` is
tenant-bound, scope-limited, time-bounded and revocable:
`assert_service_may_act()` rejects human/operator/anonymous principals,
rejects expired or revoked service identities, and rejects any attempt by a
service identity to act in another tenant.

## 7. Transports and test layers

`src/jdlib/security/authn/transports.py` (requires the `http` extra, never
imported by `jdlib.security.authn`) performs the real HTTP calls:

* explicit timeout on every request,
* classification: timeouts, connection failures, 5xx/429 are transient
  (`TokenEndpointUnavailable`, retryable); other 4xx are permanent
  (`TokenAcquisitionError`, never retried),
* response bodies never enter exceptions or logs, since error responses can
  echo credentials.

Test layers (registered in `pyproject.toml`, selected with `-m`):

| Layer | What runs | Infrastructure |
|---|---|---|
| `unit` | the bulk of the suite | none |
| `integration` | `tests/integration/test_authn_http_integration.py` | real HTTP server on a real socket, real RSA keys, real JWKS rotation, real outage and recovery |
| `infra` | `tests/infra/test_zitadel_infra.py` | real ZITADEL (`docker compose -f tests/infra/docker-compose.yml up -d zitadel`) |

Behaviour verified over the wire: validation and JWKS caching (one fetch for
repeated validations), key rotation pickup, forged-signature/expired/wrong-
audience rejection, token acquisition with caching and invalidation,
`private_key_jwt` assertions **verified by the server** (signature checked
against the registered public key), 401 → single attempt and no cached
credential, endpoint outage → fail closed with no credential issued, bounded
retries and recovery once the endpoint returns.

## 8. Deferred (explicitly not implemented)

* `build_authenticator` still constructs the pre-existing `OidcAuthenticator`;
  the hardened validator is not yet wired into the application path. Doing so
  changes request-path behaviour and needs its own tests plus a migration note,
  so it is scheduled with the gateway phase rather than smuggled into this one.
* The full ZITADEL end-to-end **token** flow (creating an org/project/service
  user and exercising `client_credentials` against the live instance) is not
  automated: it needs Management-API provisioning and credentials that must not
  live in the repository. The hermetic integration layer covers the same
  provider code path, and the infra layer covers the live endpoint derivation.
* `knowledge_base/` documentation refresh for the `jdlib.security` package is
  deferred to the documentation sweep phase, as agreed, to avoid patching the
  knowledge base piecemeal.
