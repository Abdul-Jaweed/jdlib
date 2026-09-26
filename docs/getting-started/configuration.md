# Configuration

Configuration comes from the environment through one model, `jdlib.TenancyConfig` (a
pydantic-settings `BaseSettings`). There is no configuration file: a library that reads files has to
answer where the file is, and every deployment answers differently.

## The model

| Field | Type | Default | What it is |
|---|---|---|---|
| `control_dsn` | `SecretStr \| None` | `None` | the control-plane connection string; wrapped, so it cannot be logged by accident |
| `context` | `ContextConfig` | required | the context envelope: `signing_key` (required, no default), `envelope_ttl`, `operator_ttl`, `allow_test_contexts` |
| `resolvers` | `ResolverConfig` | `ResolverConfig()` | `order`, `base_domain`, `path_prefix`, `header_name`, `jwt_claim` |
| `oidc` | `OidcConfig \| None` | `None` | `issuer`, `audience`, `algorithms`, `jwks_url`, `jwks_ttl`, `leeway`, `email_trusted` |
| `api_keys` | `ApiKeyConfig` | `ApiKeyConfig()` | `prefix` — the shape of an API key the library will parse |
| `rls` | `RlsConfig` | `RlsConfig()` | `enabled`, `app_role` — the row-level-security policy and the role it applies to |

Every field is settable as an environment variable with the `JDLIB_` prefix; `__` nests:

```bash
JDLIB_CONTROL_DSN=postgresql+psycopg://jd:secret@localhost:5432/app
JDLIB_CONTEXT__SIGNING_KEY=<32 bytes of hex>
JDLIB_CONTEXT__ENVELOPE_TTL=900
JDLIB_RESOLVERS__ORDER=jwt,subdomain,path,header,api_key
JDLIB_RESOLVERS__BASE_DOMAIN=example.com
JDLIB_RESOLVERS__JWT_CLAIM=tenant
JDLIB_OIDC__ISSUER=https://login.example.com/
JDLIB_OIDC__AUDIENCE=my-api
JDLIB_OIDC__ALGORITHMS=RS256,ES256
JDLIB_RLS__ENABLED=true
JDLIB_RLS__APP_ROLE=jdlib_app
```

## What fails fast, and why

`TenancyConfig()` raises at construction when `JDLIB_CONTEXT__SIGNING_KEY` is missing. That is
deliberate: the key signs the envelope a job or a delegation carries, and a default would be a
shared secret across every deployment that forgot to set one. The minimal example has no settings
module at all — the library's `JDLIB_*` contract is the entire surface — and one of its tests asserts
that a process started without a DSN refuses to start rather than serving unconfigured.

## The resolver order

`JDLIB_RESOLVERS__ORDER` is the list of places the tenant may come from, in the order they are
tried. Each name is a resolver the library ships:

| Name | Reads | Notes |
|---|---|---|
| `jwt` | the configured claim in a verified token | the claim name is `JDLIB_RESOLVERS__JWT_CLAIM` |
| `subdomain` | the host, against `JDLIB_RESOLVERS__BASE_DOMAIN` | `acme.example.com` → `acme` |
| `path` | the first segment after `JDLIB_RESOLVERS__PATH_PREFIX` | useful for `/t/{slug}/…` APIs |
| `header` | `JDLIB_RESOLVERS__HEADER_NAME` | **only meaningful behind a gateway that sets it**; a client can send any header, which is why it is not first by default |
| `api_key` | the tenant an API key belongs to | resolved from the control plane, not from the key's text |

The order is configuration because it is a deployment decision; the *rule* is not: the resolved
tenant is the only source, and a request field that claims one is ignored — asserted by
`examples/enterprise/tests/security/test_tenant_isolation.py`.

## Secrets

Secrets arrive as `SecretStr` and are unwrapped at the point of use, never logged, never placed in a
span attribute (the tracing allow-list drops them), and never cached — `jdlib.caching` refuses a
credential object outright, including inside a container. Where a secret *comes from* is a provider
chain: the environment, a file, or your own provider, composed in order.

## Configuration that is not environment

Three things are deliberately code rather than configuration, because they are claims about the
process rather than settings for it:

* the **span attribute allow-list** (`SPAN_ATTRIBUTE_ALLOWLIST`) — what may leave the process;
* the **error envelope's** shape — one contract for every failure;
* the **capability** each route or tool declares — a permission is a decision, not a knob.

## Reference

The model itself, including every validator and default, is
[`src/jdlib/config.py`](https://github.com/Abdul-Jaweed/jdlib/blob/main/src/jdlib/config.py): the table above is that file
read at this commit, and the generated API reference covers the same surface.
