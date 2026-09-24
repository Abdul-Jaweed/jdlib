# Module: Authentication (`src/jdlib/authn/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Turns credentials into a `Principal`. Two authenticators ship (OIDC, API keys)
behind one protocol, plus wiring that adapts them to `ContextFactory`'s ports.

## The protocol (`base.py`)

```python
class Authenticator(Protocol):
    async def authenticate(self, request: RequestInfo) -> Principal | None: ...
```

Returning `None` means "not my credential / no credential" — the chain moves on.
Raising is reserved for genuine failures inside a scheme the authenticator owns.

Helpers:

- `bearer_token(request)` — parses `Authorization: Bearer <token>`; scheme match
  is case-insensitive, the value is stripped, empty values are rejected.
- `record_authn_failure(audit, reason)` — writes a platform audit event
  `authn.failed` with `tenant_id=None`, `actor_id=None`, `metadata={"reason": reason}`.
  The `reason` is always a class name or a short tag (`invalid_api_key`,
  `unlinked_identity`) — **never token material**.

## API keys (`apikey.py`)

Token format: `<prefix>.<key_id>.<secret>`, e.g. `jd.9f2c…<32 hex>.…<64 hex>`,
where `prefix` is `ApiKeyConfig.prefix` (default `jd`) and `key_prefix` (the
database column, globally unique) is `"<prefix>.<key_id>"`.

| Function | Behaviour |
|---|---|
| `parse_api_key(token)` | Splits on `.`; requires exactly 3 non-empty parts; returns `ParsedApiKey(key_prefix, secret)`; raises `InvalidToken("malformed api key")`. |
| `hash_api_key_secret(secret)` | Argon2id via `argon2.PasswordHasher()` (the default parameters of the installed `argon2-cffi`). |
| `verify_api_key_secret(secret, stored_hash)` | `PasswordHasher.verify`; `VerificationError`/`InvalidHashError` ⇒ `False` (never raises). |

`ApiKeyAuthenticator(session_factory=…, audit=…, config=None, clock=None)`:

1. `bearer_token` first; a token whose first `.`-segment is not the configured
   prefix is ignored **silently and without audit** (it is not this scheme's
   credential). `tests/integration/test_apikey_auth.py::test_configured_prefix_gates_auditing`
   pins this.
2. `parse_api_key` + `_resolve()`; any exception ⇒ audit `authn.failed` with the
   exception class name and return `None` (fail closed, no material logged).
3. Lookup by unique `api_keys.key_prefix`; require `status == "active"` and
   `expires_at` in the future (using the injected `Clock`).
4. `verify_api_key_secret(secret, key.key_hash)` — Argon2id verification.
5. Load the owning `ServiceAccount` by composite key `(tenant_id,
   service_account_id)`; require `status == "active"`.
6. Build `Principal(kind=SERVICE_ACCOUNT, id=account.id, tenant_id=key.tenant_id,
   api_key_id=key.id, scopes=frozenset(key.scopes) if key.scopes is not None else None)`.
7. Stamp `last_used_at` and commit.

Denial paths audit the exact reason (`invalid_api_key` for every resolution
failure), which the integration tests assert case by case.

## OIDC (`oidc.py`)

Four collaborating objects plus the authenticator.

### `JwksCache(*, url, ttl, fetcher, clock=None, min_refresh_interval=1s)`

- `_refresh()` fetches the JWKS document via the injected
  `JwksFetcher` callable and indexes keys by `kid`.
- `signing_key(kid)` refreshes when the cache is stale **or** the `kid` is
  unknown, but never more often than `min_refresh_interval` — this floors the
  refetch rate so an attacker cannot use unknown-`kid` tokens to hammer the IdP
  (unit test `test_jwks_cache_unknown_kid_refetch_is_floored`).
- Returns `pyjwt.PyJWK.from_dict(jwk).key`, or `None` for a malformed key.
- `wiring.fetch_jwks` is the default fetcher (`httpx.AsyncClient` + `raise_for_status`).

### `TokenVerifier(config, clock=None)`

- `pyjwt.decode` with `algorithms=config.algorithms`, `audience`, `issuer`,
  `leeway`, and **`verify_exp/nbf/iat` disabled** — time claims are validated by
  `_validate_times` afterwards so that expiry produces `ExpiredToken` rather than
  a generic JWT error. `PyJWTError` ⇒ `InvalidToken("token verification failed: <ExcName>")`.
- `_validate_times`: `exp <= now - leeway` ⇒ `ExpiredToken`;
  `nbf > now + leeway` or `iat > now + leeway` ⇒ `InvalidToken`; non-integer
  timestamps ⇒ `InvalidToken("invalid <claim> claim")`.

### `ClaimMapper(config).map(claims) -> IdentityClaims(issuer, subject, email, email_verified)`

Requires `sub`; `iss` falls back to the configured issuer; non-string emails are
dropped; `email_verified` is only trusted when it is a real boolean.

### `UserLinker(session_factory, config).link(claims) -> User | None`

Resolution order (each step is a documented rule):

1. Existing `IdentityLink(issuer, subject)` ⇒ its `User`, provided the user is
   `active`; updates `last_login_at` and commits.
2. If `config.email_trusted` **and** `claims.email_verified` **and** an email is
   present: an active `User` with that email (`lower()` comparison) is reused.
3. Otherwise a new `User` is created; the email is stored **only when verified**.
4. An `IdentityLink` is inserted. A uniqueness race (`IntegrityError`) rolls back
   and re-reads the winner, so concurrent first logins converge on one user.
5. `link` returns a `User` after its session closed ⇒ **the control-plane session
   factory must use `expire_on_commit=False`** (documented in `docs/jdlib/07` §9;
   the README's example does this).

### `OidcAuthenticator(*, config, cache, verifier, mapper, linker, audit)`

1. No bearer token ⇒ `None` (not this scheme).
2. `_kid(token)` via `pyjwt.get_unverified_header`; malformed header ⇒ `None`
   silently (again: not this scheme's credential); missing/non-string `kid` ⇒
   `None`.
3. `cache.signing_key(kid)`; unknown key ⇒ `InvalidToken("unknown signing key")`.
4. `verifier.verify` ⇒ `mapper.map` ⇒ `linker.link`.
5. Any exception in step 3–4 is audited as `authn.failed` with the exception
   class name and returns `None` (fail closed — a JWKS fetch outage denies, it
   never allows).
6. `user is None` ⇒ audit `unlinked_identity`; otherwise
   `Principal(kind=USER, id=user.id, user_id=user.id)`.

## Composition and wiring

`CompositeAuthenticator([oidc, apikey])` returns the first non-`None` principal.
`build_authenticator(config, session_factory, audit)` assembles exactly that
order, adding OIDC only when `config.oidc is not None` (unit-tested). Both
authenticators are cheap to try in sequence because each ignores tokens that do
not match its own scheme; the integration tests assert that a valid JWT through
an "api-key-first" composite audits nothing, and vice versa.

`wiring.py` also provides the `ContextFactory` adapters — **translation only, no
policy**:

| Adapter | Port | Behaviour |
|---|---|---|
| `PrincipalDirectoryAdapter(reader)` | `PrincipalDirectory` | `is_active` → `reader.principal_active`. |
| `TenantDirectoryAdapter(registry)` | `TenantDirectory` | `get(ref)` → `registry.find(ref)`. |
| `EntitlementAdapter(reader)` | `EntitlementChecker` | `SERVICE_ACCOUNT`: pin equality **and** `reader.service_account_active(tenant_id, id)`. `USER`: `principal_active` **and** `membership_active`. `PLATFORM_OPERATOR`: always `False` — operators are never tenant PDP principals. |

### Password/key hashing summary

| Secret | Algorithm | Where |
|---|---|---|
| API key secret | Argon2id (`argon2.PasswordHasher()` default params) | `apikey.hash_api_key_secret` |
| Invitation secret | Argon2id (same hasher) | `authz/access.py::hash_invitation_secret` |
| Context envelope | HMAC-SHA256 over canonical JSON | `context.EnvelopeCodec` |
| OIDC tokens | RS256 (configurable) via PyJWT + JWKS | `authn/oidc.py` |
