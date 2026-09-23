# Configuration

One settings object, `TenancyConfig` (`src/jdlib/config.py`), built on
`pydantic-settings`:

```python
model_config = SettingsConfigDict(env_prefix="JDLIB_", env_nested_delimiter="__")
```

So every field is settable as `JDLIB_<SECTION>__<FIELD>`; the process environment
is the only source. `TenancyConfig()` **fails fast** when a required nested field
is missing (`context`, and inside it `signing_key`), which is deliberate — the
library refuses to start without an envelope signing key.

## Full tree

| Field | Type | Default | Env var | Notes |
|---|---|---|---|---|
| `control_dsn` | `SecretStr \| None` | `None` | `JDLIB_CONTROL_DSN` | Control-plane DSN. Optional in the model; the CLI requires it (or `--database-url`). |
| `context` | `ContextConfig` | **required** | — | |
| `context.signing_key` | `SecretStr` | **required** | `JDLIB_CONTEXT__SIGNING_KEY` | HMAC key for `EnvelopeCodec`; ≥ 32 random bytes recommended. Never logged (it is a `SecretStr`). |
| `context.envelope_ttl` | `timedelta` | 5 minutes | `JDLIB_CONTEXT__ENVELOPE_TTL` | Job-envelope lifetime; expired envelopes ⇒ `ExpiredToken`. |
| `context.operator_ttl` | `timedelta` | 30 minutes | `JDLIB_CONTEXT__OPERATOR_TTL` | Default TTL for `for_operator`; the request's `ttl` is clamped to `[ttl_min, ttl_max]`. |
| `context.allow_test_contexts` | `bool` | `False` | `JDLIB_CONTEXT__ALLOW_TEST_CONTEXTS` | Gate for `ContextFactory.for_test`. Must stay `False` in production. |
| `resolvers.order` | `list[ResolverName]` | `[jwt_claim, subdomain, path, header, api_key]` | `JDLIB_RESOLVERS__ORDER` | JSON list, e.g. `'["header","api_key"]'`. |
| `resolvers.base_domain` | `str \| None` | `None` | `JDLIB_RESOLVERS__BASE_DOMAIN` | Required for `SubdomainResolver`; the resolver is dropped from the chain when unset. |
| `resolvers.path_prefix` | `str` | `"/t/"` | `JDLIB_RESOLVERS__PATH_PREFIX` | Validated: non-empty and must start with `/`. |
| `resolvers.header_name` | `str` | `"X-Tenant-Slug"` | `JDLIB_RESOLVERS__HEADER_NAME` | Header lookup is case-insensitive. |
| `resolvers.jwt_claim` | `str` | `"tid"` | `JDLIB_RESOLVERS__JWT_CLAIM` | Claim read by `JwtClaimResolver`. |
| `oidc` | `OidcConfig \| None` | `None` | — | `None` disables the OIDC authenticator (`build_authenticator` skips it). |
| `oidc.issuer` | `str` | **required** (when `oidc` is set) | `JDLIB_OIDC__ISSUER` | Also the fallback `iss` and the base of the JWKS URL. |
| `oidc.audience` | `str` | **required** (when set) | `JDLIB_OIDC__AUDIENCE` | Passed to `pyjwt.decode`. |
| `oidc.algorithms` | `list[str]` | `["RS256"]` | `JDLIB_OIDC__ALGORITHMS` | JSON list; must not include `none`. |
| `oidc.jwks_url` | `str \| None` | `None` | `JDLIB_OIDC__JWKS_URL` | `resolved_jwks_url()` falls back to `<issuer without trailing />` + `/.well-known/jwks.json`. |
| `oidc.jwks_ttl` | `timedelta` | 1 hour | `JDLIB_OIDC__JWKS_TTL` | JWKS cache lifetime (stale ⇒ refetch on next use, floored at 1 s). |
| `oidc.leeway` | `timedelta` | 60 seconds | `JDLIB_OIDC__LEEWAY` | Clock-skew allowance for `exp`/`nbf`/`iat`. |
| `oidc.email_trusted` | `bool` | `False` | `JDLIB_OIDC__EMAIL_TRUSTED` | Enables linking an unverified-by-us email to an existing user (only with `email_verified: true` in the token). |
| `api_keys` | `ApiKeyConfig` | `ApiKeyConfig()` | — | |
| `api_keys.prefix` | `str` | `"jd"` | `JDLIB_API_KEYS__PREFIX` | Tokens are `<prefix>.<key_id>.<secret>`; tokens with another prefix are ignored by the authenticator. |
| `rls` | `RlsConfig` | `RlsConfig()` | — | |
| `rls.enabled` | `bool` | `False` | `JDLIB_RLS__ENABLED` | Enables the shared strategy's `app.tenant_id` per-transaction `set_config`. |
| `rls.app_role` | `str \| None` | `None` | `JDLIB_RLS__APP_ROLE` | App role used by `emit_rls_policies` (grants) and required by `verify_rls`. |

`ResolverName` is a `StrEnum`: `jwt_claim`, `subdomain`, `path`, `header`,
`api_key`.

`timedelta` fields accept seconds as an integer (`JDLIB_OIDC__LEEWAY=30`) or an
ISO-8601 duration string (`"PT30S"`), which is standard pydantic v2 behaviour.

## Example `.env` / process environment

```bash
JDLIB_CONTROL_DSN="postgresql+asyncpg://jd:…@localhost:5432/app"
JDLIB_CONTEXT__SIGNING_KEY="<32+ bytes of random base64>"
JDLIB_CONTEXT__ENVELOPE_TTL=PT10M
JDLIB_RESOLVERS__ORDER='["jwt_claim","subdomain"]'
JDLIB_RESOLVERS__BASE_DOMAIN=example.com
JDLIB_OIDC__ISSUER=https://auth.example.com
JDLIB_OIDC__AUDIENCE=my-app
JDLIB_OIDC__EMAIL_TRUSTED=true
JDLIB_API_KEYS__PREFIX=acme
JDLIB_RLS__ENABLED=true
JDLIB_RLS__APP_ROLE=acme_app
```

## Configuration the library deliberately does *not* own

| Concern | Where it lives instead |
|---|---|
| Pool sizes, timeouts, `statement_cache_size` | your `create_async_engine(...)` — strategies take an engine or a DSN, never pool knobs. |
| Tenant-DB secrets | `SecretProvider` implementations (env-var naming convention is `EnvSecretProvider`'s business, not `TenancyConfig`'s). |
| Schema-name conventions for deployment | `DEPLOYMENT_SCHEMA_RE` / `_TENANT_SCHEMA_RE` (module constants, not settings). |
| Feature flags, rate limits, HTTP hardening | your application. |
| Observability | `context.request_id`/`correlation_id`/`trace_id` are propagated; emitting logs/metrics is the app's job. |

## Gotchas

- `TenancyConfig` reads the environment **at construction**; there is no reload
  and no `Config.from_file`. Construct it once per process.
- `SecretStr` values must be unwrapped explicitly
  (`.get_secret_value()`) — useful for accidental-log protection, and the reason
  `str(config.context.signing_key)` yields `**********`.
- `api_keys.prefix` is a compatibility boundary: rotating it invalidates parsing
  of already-issued tokens (their `key_prefix` column still matches, but the
  authenticator will no longer consider them its own scheme).
- `allow_test_contexts=true` in production would let any caller holding the
  framework issuer token mint a tenant context in tests' stead — treat it as a
  test-only switch, and note that `for_test` is additionally protected by the
  internal `PRIVILEGE_ISSUER` token, which is not importable-by-accident
  (underscore-prefixed, private module attribute).
