---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules:
  - src/jdlib/persistence/secrets_manager.py
exports:
  - SecretsManagerConfig
  - SecretsManagerSecretProvider
  - SecretsManagerClient
test_files:
  - tests/unit/test_aws_secrets_manager.py
---

# Secret resolution with AWS Secrets Manager

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md).

## What it is

A `SecretProvider` backed by AWS Secrets Manager — the third implementation beside
`MemorySecretProvider` and `EnvSecretProvider`, with the same one-method protocol
(`resolve(handle) -> str`). The application resolves a handle the same way wherever the secret
lives; what changes is rotation, caching and failure behaviour.

## Why it exists

Because the library already has the seam and a managed secret store is the deployment's natural
choice. It is also the one AWS service in this programme that maps onto an existing abstraction
with no semantic mismatch at all: a handle goes in, a secret comes out.

## When to use it

When tenant credentials, signing keys or database passwords live in Secrets Manager. When they live
in environment variables, `EnvSecretProvider` already covers it.

## When not to use it

Do not use it for **configuration**. Secrets Manager is for sensitive material; non-sensitive
configuration belongs in Parameter Store, and the two are deliberately not merged here — see
[the Parameter Store verdict](parameter-store.md). Do not use it as a general cache or as a
feature store: this adapter caches only what it resolves, and only for a bounded TTL.

## Rotation

| Mechanism | What this adapter does |
| --- | --- |
| Secrets Manager rotates the value (Lambda rotation) | Nothing special: the cache entry expires after `cache_ttl` and the next resolution reads the new version. Rotation needs no restart. |
| A rotation is known to have happened | `invalidate(handle)` drops that handle, or `invalidate()` drops everything, so the next resolution is immediate. |
| The application needs the version | It does not: `resolve` returns the current value, and a deployment that needs version pinning should read the API itself. |

The cache is bounded by `cache_ttl` (default five minutes) rather than by a version id. A version-aware
cache would need the version to be visible to the caller, and the protocol returns a string.

## Trust boundaries

* **AWS is trusted to keep the secret.** This adapter does not encrypt, and does not re-encrypt.
* **The client is trusted to be authenticated.** Credentials, IAM policy and SigV4 signing belong to
  the injected client — the library never holds an AWS access key.
* **A resolved secret is trusted as the value.** There is no verification that the value is well
  formed; a caller that needs a DSN to parse will find out when it parses it.
* **Handles are not authorization.** Anyone who can call `resolve` can read what the client can read;
  which tenant gets which handle is the application's decision, not this adapter's.

## Failure behaviour

| Condition | Result |
| --- | --- |
| Secret does not exist | `KeyError` naming the handle and the client exception class |
| Access denied by IAM | `KeyError`, same shape |
| Throttled or unavailable | `KeyError`, same shape — a secret that cannot be read is never an empty string |
| Binary secret (`SecretBinary`) | `KeyError` — this protocol returns `str`, so a binary secret is unsupported rather than guessed at |
| Empty handle | `SecurityConfigurationError`, and no AWS call is made |
| Cache expired | Re-read; the old value is not served past its TTL |

The client's exception **message is dropped and the class is kept**: an SDK error can echo the secret
value back, so the message and the cause chain would put secret material in a traceback. The class
survives because `ResourceNotFoundException` and `AccessDeniedException` need different fixes.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| `prefix` | `""` | namespaces handles, so one deployment separates environments without changing callers |
| `region` | `None` | the injected client's business, but recorded for documentation |
| `endpoint_url` | `None` | https only; useful for a VPC endpoint or a local emulator |
| `cache_ttl` | 5 minutes | must be positive; the bound on how stale a resolved secret can be |

Timeouts are **not** configured here. Botocore's client configuration owns connect and read
timeouts, and an adapter that pretended to enforce its own would be lying.

## Limits worth designing around

Secrets Manager's own limits apply and are documented upstream: request rate per region, 64 KB per
secret, and a cost per secret per month plus per API call — which is the real argument for the
cache. The cache is per-process, so a fleet of N processes resolves N times per TTL, not once.

## Testing

Thirteen tests in `tests/unit/test_aws_secrets_manager.py` with an injected duck-typed client: the
caching contract (one call for two resolutions), TTL expiry picking up a rotated value, both
`invalidate` forms, the failure shapes, the binary-secret refusal, and two leak tests — a repr and
an exception message must never carry a value. No AWS account is involved, so the live path is
`NOT RUN — AWS credentials unavailable`.
