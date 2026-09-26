---
guide: credentials
authority: docs/jdlib/credentials.md
modules:
  - src/jdlib/credentials/__init__.py
  - src/jdlib/credentials/composite.py
  - src/jdlib/credentials/errors.py
  - src/jdlib/credentials/redaction.py
  - src/jdlib/credentials/refs.py
  - src/jdlib/credentials/rotation.py
  - src/jdlib/persistence/secrets.py
exports:
  - CompositeSecretProvider
  - SecretRef
  - SecretVersion
  - VersionedSecretProvider
  - ResolvedSecret
  - redact
  - INITIAL_VERSION
example:
  - examples/enterprise/app/dsn.py
test_files:
  - tests/unit/test_credentials_providers.py
---
# Credentials

> **Design authority:** [`docs/jdlib/credentials.md`](../credentials.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

Resolving a stored reference into a usable secret -- a password, a token, a key -- with versions, rotation and redaction built in, so the secret itself never lands in a log or a value's `repr`.

## Why it exists

Secrets are the one input that must never be printed, cached or compared by accident. A type that refuses to render itself, plus a resolver that is the only way to get the plaintext, is what makes that a property of the code rather than of reviewer attention.

## When to use it

Whenever an application needs a credential it did not receive from its own environment: a per-tenant database password, a connector's token, a key rotated on a schedule.

## When not to use it

For the process's own bootstrap secrets (its DSN, its signing key), which come from configuration; and for anything a caller supplies per request, which is authentication's business, not the credential store's.

## How it works

A `SecretRef` names a secret and a version; `VersionedSecretProvider` resolves it to a `ResolvedSecret`; `CompositeSecretProvider` chains providers (environment, then a store) so a deployment can move one secret at a time. `redact` and `REDACTED` make the value's textual form useless to an attacker reading a log, and a retired version raises `CredentialVersionRetiredError` rather than silently serving stale material.

## Architecture

`credentials/refs.py` (references and versions), `credentials/composite.py` (the chain), `credentials/rotation.py` (version lifecycle), `credentials/redaction.py` (safe rendering); `jdlib.persistence.secrets` is where a resolved secret becomes a connection parameter.

## Example

`examples/enterprise/app/dsn.py` is the example's use of the seam: the DSN's password is a resolved secret, so it is never a literal in a settings object or a log line.

## Security

Plaintext exists only inside a `ResolvedSecret`, which does not render it; the resolution path is synchronous and explicit, so there is no ambient 'current secret' to leak. A retired version is refused, which is what makes rotation safe to do during business hours.

## Reliability

Provider failures are typed (`CredentialUnavailableError`), so an application can distinguish 'the store is down' from 'the secret is wrong' -- the first is a 503, the second a misconfiguration. Resolution does not retry silently, because a retry storm against a secret store is its own outage.

## Observability

Spans record the reference and the version, never the value; the redaction helpers are what make that safe to log even if a value is passed by mistake.

## Audit

Reading a privileged secret is an auditable act: the library's audit vocabulary records privileged access, and the version recorded is what makes 'which credential was in use at the time' answerable.

## Configuration

The provider chain is configuration; the secrets themselves live where the deployment keeps them (a store, a mounted file, the environment for the bootstrap case).

## Testing

`tests/unit/test_credentials_providers.py` covers the providers, versions and redaction; a deployment's own rotation should be rehearsed against a non-production store.

## Common mistakes

Logging a resolved secret (or a settings object that contains one); caching plaintext in a long-lived object; comparing versions by string equality instead of the version type; rotating without a retired-version policy.

## Production checklist

Rotate on a schedule and rehearse it; keep plaintext out of process arguments and logs; give each tenant its own credential where the placement strategy allows it; and alert on resolution failures -- they are usually the first symptom of a rotated-away version.
