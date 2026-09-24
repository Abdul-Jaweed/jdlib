---
capability: caching
namespace: jdlib.caching
errors_module: jdlib.caching.errors
modules:
  - src/jdlib/caching/errors.py
  - src/jdlib/caching/keys.py
  - src/jdlib/caching/local.py
  - src/jdlib/caching/policy.py
  - src/jdlib/caching/protocol.py
  - src/jdlib/caching/redis.py
exports:
  - CacheKeyError
  - CachePolicy
  - CacheProvider
  - LocalCache
  - RedisCache
  - ScopedKeyFactory
  - contains_credential
refusals:
  - CacheKeyError
  - CachePolicyError
  - CacheSerializationError
  - CredentialCacheRefusedError
test_files:
  - tests/unit/test_scoped_cache.py
  - tests/integration/test_redis_cache.py
test_functions: 28
---
# Caching: tenant-scoped keys and a credential guard

## What it is

Two implementations of one protocol - `LocalCache` for a process and `RedisCache` for a fleet -
over keys built in exactly one place:

```python
keys = ScopedKeyFactory()
cache = LocalCache(keys=keys, clock=clock)

cache.set(tenant=str(tenant_id), namespace="resources", resource="db/reports",
          identifier=version, value=config, ttl=300)
```

Every key carries the tenant. A value written for one tenant is invisible to another, and that
is asserted as `None` rather than as an error message.

## The credential guard (ADR-2)

`set` refuses a credential-shaped value - an object whose type is a credential, a dict, a list or
a tuple - with `CredentialCacheRefusedError`, and the refusal **names the namespace, not the
value**. The design intent is written into the code rather than into a comment: because
`ResolvedSecret` is the only way to obtain a secret, flattening one to a plain string to get it
past this check is a deliberate act, not an accident.

## Evidence

28 test functions across `tests/unit/test_scoped_cache.py` and `tests/integration/test_redis_cache.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_scoped_cache.py -q
.venv/Scripts/python.exe -m pytest tests/integration/test_redis_cache.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

The Redis suite runs against a real Redis container (`testcontainers.community.redis`) and its
fixture flushes the throwaway instance's own database; the production class has no `flush`, and
a test asserts that.

## Limits

No distributed invalidation: entries expire by TTL, and `invalidate_namespace` is local to the
provider that holds the keys. A fleet that needs cross-node invalidation needs a pub/sub the
library deliberately does not invent.
