---
guide: caching
authority: docs/jdlib/capabilities/caching.md
modules:
  - src/jdlib/caching/__init__.py
  - src/jdlib/caching/errors.py
  - src/jdlib/caching/keys.py
  - src/jdlib/caching/local.py
  - src/jdlib/caching/policy.py
  - src/jdlib/caching/protocol.py
  - src/jdlib/caching/redis.py
exports:
  - CachePolicy
  - CacheProvider
  - LocalCache
  - RedisCache
  - ScopedKeyFactory
  - contains_credential
  - CredentialCacheRefusedError
  - SCHEMA_VERSION
example:
  - examples/enterprise/app/configuration/settings.py
test_files:
  - tests/unit/test_scoped_cache.py
  - tests/integration/test_redis_cache.py
---
# Caching

> **Design authority:** [`docs/jdlib/capabilities/caching.md`](../capabilities/caching.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

A cache seam with tenant-scoped keys, an explicit policy, and one refusal that matters: a credential is not a cacheable value.

## Why it exists

A cache is a second copy of the truth, and in a multi-tenant system a key that is not tenant-scoped is a cross-tenant leak with a TTL. Naming the scope in the key factory is what makes that structural.

## When to use it

For values that are expensive to compute and safe to serve slightly stale: a policy decision's inputs, a tenant's settings, a lookup table. Use it where a miss is cheap and a stale hit is acceptable.

## When not to use it

For anything a caller's authorization depends on being current, for credentials, and for data whose staleness is a correctness bug (a balance, a lock, a job's state).

## How it works

`CachePolicy` describes the entry (scope, TTL, serialization version); `ScopedKeyFactory` builds the key from the policy's scope so a tenant is part of it by construction; `LocalCache` and `RedisCache` are the two providers. `SCHEMA_VERSION` is part of the key, so a changed value shape invalidates old entries instead of mis-reading them.

## Architecture

`caching/policy.py` (what may be cached, for how long), `caching/keys.py` (the scoped key), `caching/protocol.py` (the provider interface), `caching/local.py` and `caching/redis.py` (the implementations).

## Example

The example configures its cache through settings (`examples/enterprise/app/configuration/settings.py`); the caching capability's own tests are the reference for the seam, because the example's data path is deliberately uncached.

## Security

`contains_credential` refuses a value that looks like key material, and `CredentialCacheRefusedError` is raised rather than logged -- the cache is the last place a secret should ever be copied to. Keys carry the tenant, so a shared Redis is not a shared view.

## Reliability

A provider failure is a miss, not an error: the application serves from the source of truth. TTLs are part of the policy rather than a call-site argument, so an outage does not turn into a stampede with no ceiling.

## Observability

Hit/miss is recorded per policy, which is what tells you whether the cache earns its complexity; the key's scope (not its value) is what a span records.

## Audit

Caching itself is not audited -- the decision to serve a cached value is not a security event -- but a refused credential cache attempt is.

## Configuration

The provider and its endpoint are configuration; the TTLs live in the policies beside the code that owns the value.

## Testing

`tests/unit/test_scoped_cache.py` covers the key factory and the policy; `tests/integration/test_redis_cache.py` covers the shared provider against a real Redis.

## Common mistakes

Caching an authorization decision; building a key from a string that a caller influences; caching a value whose shape changed without bumping the schema version; treating a cache failure as an application failure.

## Production checklist

Give each tenant's keys their own namespace; set a TTL you would be comfortable serving after a deploy; watch the miss rate; and keep credentials out of the cache entirely.
