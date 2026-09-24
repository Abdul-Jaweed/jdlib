---
page: credentials
sources:
  - src/jdlib/credentials
  - src/jdlib/persistence/secrets.py
  - docs/jdlib/capabilities/credentials.md
---
# Credentials

A secret is addressed by **handle**, optionally pinned to a **version**, and resolved through a
provider chain that reports which generation it produced. Full page:
[`capabilities/credentials.md`](capabilities/credentials.md).

## Where credentials are used

| Consumer | What it receives |
|---|---|
| Resource hydration | A resolved target string, plus the version that produced it |
| The connector | A `ConnectionConfig`; the engine is built from it, never from a stored DSN |
| The CLI | Nothing by default: tokens are written to files, not printed |
| Storage and cache | Nothing: values must not reach either, and both refuse authoritatively |

## Rules

- `SecretRef` carries no value and cannot render one; `ResolvedSecret` is the only way to obtain
  the value, and its `repr` shows metadata only.
- A pinned reference to a retired version fails closed with `CredentialVersionRetiredError`.
- `current_version` establishes the version on demand, because version-aware caching must ask
  *before* deciding to use a cache entry.
- Rotation is a declaration; the vault call, if the application has one, is the application's.

## The chain

`CompositeSecretProvider` composes providers in order; `VersionedSecretProvider` adds generations
and rotation on top of any `SecretProvider`. The application chooses the backend - the reference
application seeds a memory provider from configuration and says so, because that is the one place
it is weaker than a deployment.
