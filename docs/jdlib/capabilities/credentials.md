---
capability: credentials
namespace: jdlib.credentials
errors_module: jdlib.credentials.errors
modules:
  - src/jdlib/credentials/composite.py
  - src/jdlib/credentials/errors.py
  - src/jdlib/credentials/redaction.py
  - src/jdlib/credentials/refs.py
  - src/jdlib/credentials/rotation.py
exports:
  - CompositeSecretProvider
  - ResolvedSecret
  - SecretRef
  - SecretVersion
  - VersionedSecretProvider
  - redact
refusals:
  - CredentialUnavailableError
  - CredentialVersionRetiredError
test_files:
  - tests/unit/test_credentials_providers.py
test_functions: 18
---
# Credentials: versioned resolution and rotation

## What it is

A credential is addressed by a **handle**, optionally pinned to a **version**, and every
resolution reports which generation it produced. `SecretRef` carries no value and cannot render
one; `ResolvedSecret` is the only way to obtain the value, and its `repr` shows metadata only.

```python
ref = SecretRef(handle="db/reports")              # current version
pinned = SecretRef(handle="db/reports", version=SecretVersion("v1"))

provider = VersionedSecretProvider(EnvSecretProvider(), emitter=sink)
resolved = provider.resolve(ref)                  # -> ResolvedSecret(version=..., value=...)
```

## The decisions that carry weight

**`current_version` establishes the version on demand.** Version-aware caching has to ask
*before* deciding to use a cache entry; reading the inner provider is the cheap half, and
connecting is the expensive half. A handle nobody holds still reports `None`, and callers fail
closed on that rather than guessing.

**Rotation retires the previous generation.** A pinned reference to a retired version is refused
(`CredentialVersionRetiredError`) instead of quietly resolving the current value. Rotating a
handle that was never resolved *establishes* the version when the inner provider holds it, and a
handle nobody holds still fails closed.

**Values are never text.** `redact()` and `REDACTED` exist so that a value that reaches a log
line arrives already marked, and the composite provider can only return what its members return.

## Evidence

18 test functions across `tests/unit/test_credentials_providers.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_credentials_providers.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

## Limits

The provider chain is the application's to compose; the library ships the versioned wrapper and
the composition, not a secret-manager client. Rotation is a *declaration* - the library records
the new generation and lets the inner provider serve it - so an application that rotates in a
vault still owns the vault call.
