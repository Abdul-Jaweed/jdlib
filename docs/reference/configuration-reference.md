# Configuration reference

Every setting the library reads, with its default and what it does. The model is
`jdlib.TenancyConfig` in [`src/jdlib/config.py`](https://github.com/Abdul-Jaweed/jdlib/blob/main/src/jdlib/config.py);
the environment variable is `JDLIB_` plus the field's path, upper-cased, with `__` between levels.

## Top level

| Field | Env | Type | Default | What it does |
|---|---|---|---|---|
| `control_dsn` | `JDLIB_CONTROL_DSN` | `SecretStr \| None` | `None` | the control-plane connection string; wrapped, so it cannot be logged by accident |
| `context` | `JDLIB_CONTEXT__…` | `ContextConfig` | required | the context envelope (below) |
| `resolvers` | `JDLIB_RESOLVERS__…` | `ResolverConfig` | defaults | where the tenant may come from |
| `oidc` | `JDLIB_OIDC__…` | `OidcConfig \| None` | `None` | OIDC verification; absent means OIDC is not configured |
| `api_keys` | `JDLIB_API_KEYS__…` | `ApiKeyConfig` | defaults | the API-key surface |
| `rls` | `JDLIB_RLS__…` | `RlsConfig` | defaults | row-level security |

## `context`

| Field | Env | Default | What it does |
|---|---|---|---|
| `signing_key` | `JDLIB_CONTEXT__SIGNING_KEY` | **required** | signs the context envelope a job or delegation carries; there is no default because a default would be a shared secret |
| `envelope_ttl` | `JDLIB_CONTEXT__ENVELOPE_TTL` | 5 minutes | how long a signed envelope is valid |
| `operator_ttl` | `JDLIB_CONTEXT__OPERATOR_TTL` | 30 minutes | the lifetime of an operator context |
| `allow_test_contexts` | `JDLIB_CONTEXT__ALLOW_TEST_CONTEXTS` | `False` | allows a hand-built context; for tests, and it must stay off in a deployment |

## `resolvers`

| Field | Env | Default | What it does |
|---|---|---|---|
| `order` | `JDLIB_RESOLVERS__ORDER` | the library's default order | the resolvers tried, in order |
| `base_domain` | `JDLIB_RESOLVERS__BASE_DOMAIN` | `None` | the suffix the `subdomain` resolver strips |
| `path_prefix` | `JDLIB_RESOLVERS__PATH_PREFIX` | `/t/` | the prefix the `path` resolver reads after |
| `header_name` | `JDLIB_RESOLVERS__HEADER_NAME` | `X-Tenant-Slug` | the header the `header` resolver reads — only meaningful behind a gateway that sets it |
| `jwt_claim` | `JDLIB_RESOLVERS__JWT_CLAIM` | `tid` | the claim the `jwt` resolver reads |

## `oidc`

| Field | Env | Default | What it does |
|---|---|---|---|
| `issuer` | `JDLIB_OIDC__ISSUER` | **required** when configured | the expected `iss` |
| `audience` | `JDLIB_OIDC__AUDIENCE` | **required** when configured | the expected `aud` |
| `algorithms` | `JDLIB_OIDC__ALGORITHMS` | `["RS256"]` | the accepted signing algorithms — an allow-list, not a preference |
| `jwks_url` | `JDLIB_OIDC__JWKS_URL` | discovered from the issuer | where the keys come from |
| `jwks_ttl` | `JDLIB_OIDC__JWKS_TTL` | 1 hour | how long a fetched key set is used before a refresh |
| `leeway` | `JDLIB_OIDC__LEEWAY` | 60 seconds | the clock skew tolerated on `exp`/`nbf` |
| `email_trusted` | `JDLIB_OIDC__EMAIL_TRUSTED` | `False` | whether the `email` claim may be used as an identity attribute |

## `api_keys` and `rls`

| Field | Env | Default | What it does |
|---|---|---|---|
| `api_keys.prefix` | `JDLIB_API_KEYS__PREFIX` | `jd` | the prefix the library expects on a key it will parse |
| `rls.enabled` | `JDLIB_RLS__ENABLED` | `False` | whether the library manages the row-level-security policy; a deployment that relies on the database's policy sets it to `True` |
| `rls.app_role` | `JDLIB_RLS__APP_ROLE` | `None` | the role the policy applies to — the role the application connects as, not the owner |

## What fails at startup

`TenancyConfig()` raises when `JDLIB_CONTEXT__SIGNING_KEY` is missing, and when `oidc` is configured
without `issuer` or `audience`. Failing at construction is the point: a process that starts with a
missing security setting and refuses at the first request has already accepted traffic.

## What is not configurable

Three things are code, because they are claims about the process rather than settings for it: the
span attribute allow-list, the error envelope's shape, and the permission catalog.
