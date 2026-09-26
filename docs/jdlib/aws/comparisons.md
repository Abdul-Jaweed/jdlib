---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Comparisons: the choices this programme made, and the alternatives

> **Design authority:** [the capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Directive section 35. Each row links the page that
> argues it; this page is the index, not a second argument.

## Policy engines

| | Cerbos (self-hosted) | Amazon Verified Permissions |
| --- | --- | --- |
| Policy language | Cerbos policies: roles, derived roles, CEL conditions | Cedar |
| Roles | first-class, with derived roles computed at evaluation time | no role construct — roles become entities or attributes |
| Deny semantics | deny overrides allow per role; principal policies are final overrides | any satisfied `forbid` overrides every `permit`, globally |
| Conditions | CEL with Cerbos extensions; a runtime error means the rule does not match | Cedar expressions; an erroring policy is skipped with diagnostics |
| Principal source | the caller supplies it per request | the caller supplies it, or AVP derives it from a token (`WithToken`) |
| Operations | you run it; no per-request limits to design around | managed, with documented quotas and throttling |
| In this library | `security/authz/cerbos.py` | [`security/authz/verified_permissions.py`](authorization-verified-permissions.md) |

The differences that cannot be mapped are enumerated on
[the Verified Permissions page](authorization-verified-permissions.md#differences-that-an-adapter-must-not-paper-over)
rather than smoothed over, because a migration that assumes equivalence will change authorization
behaviour.

## Gateways

Kong, Tyk and API Gateway are compared in full on
[the gateway comparison page](gateway-comparison.md). The one-line version: Kong and Tyk sign an
identity envelope a backend can verify (which is why both have adapters), API Gateway does not
(which is why it has none), and none of the three decides application authorization.

## Secrets and configuration

| | Secrets Manager | SSM Parameter Store |
| --- | --- | --- |
| For | sensitive material: credentials, keys, connection strings | configuration: endpoints, feature flags, non-sensitive settings |
| Rotation | built in (Lambda rotation) | not automatic — a `SecureString` is encrypted, not rotated |
| Cost model | per secret per month plus per API call | standard parameters free, advanced charged |
| In this library | [`SecretsManagerSecretProvider`](secrets-manager.md) | [deliberately not adapted](parameter-store.md) — no `ConfigurationProvider` exists |

The two are kept apart on purpose: a `SecureString` would work through the secret protocol, and
doing that would teach every caller that configuration and secrets are the same thing.

## Data planes

| | In the library | On AWS | Verdict |
| --- | --- | --- | --- |
| Relational | SQLAlchemy async + asyncpg | RDS / Aurora PostgreSQL | [ADOPT](rds-aurora.md) — a deployment target, not an adapter |
| Cache | `RedisCache` | ElastiCache (Redis, Valkey) | [ADOPT](elasticache.md) — with cluster mode and IAM auth named as limits |
| Object storage | `S3ObjectStorage` | S3 | [ADOPT](s3.md) — omit `endpoint_url` |
| Graph | `Neo4jClient` over Bolt | Neptune (openCypher subset) | [DEFER](neptune.md) — feasible, and the subset is the reason |
| Messaging | *(none)* | SQS, SNS, EventBridge | [NOT_APPLICABLE](messaging.md) — nothing to adapt |

## Identity

| | Cognito | ZITADEL (the existing adapter) |
| --- | --- | --- |
| Issuer | `https://cognito-idp.{region}.amazonaws.com/{poolId}` | the deployment's own domain |
| Keys | two pairs per pool, one JWKS | one JWKS |
| Access token audience | `client_id` (plus `aud` only with a resource binding) | `aud` |
| Clock-skew tolerance | none documented for user-pool validation | the library defaults to a minute |
| In this library | [`CognitoConfig`](authentication-cognito.md) | `security/authn/zitadel.py` |

Both are wired the same way — discovery into the generic `JwtTokenValidator` — and the differences
live in configuration, which is what the seam is for.
