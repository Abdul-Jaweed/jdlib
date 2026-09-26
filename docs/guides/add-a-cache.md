# Add a cache

A cache provider implements the protocol; the policy decides what may be cached and the keys decide
where it lands.

## 1. Implement the protocol

```python
from jdlib.caching.protocol import CacheProvider
```

Two rules come with the protocol and are not optional:

* **the tenant is in the key** — `jdlib.caching.keys` builds the namespace from the context, so two
  tenants cannot collide on a shared store;
* **a credential is never cached** — `jdlib.caching.policy` refuses a credential object outright,
  including one inside a container. A cache that can hold a secret is a secret store with no access
  control.

## 2. Wire it

```python
from jdlib.caching.redis import RedisCache

cache = RedisCache(url="redis://127.0.0.1:6379/0")
```

The provider takes its connection from the caller, not the environment, so the deployment keeps
control of where the connection string comes from.

## 3. Test it

| Test | What it proves |
|---|---|
| a hit returns the stored value | the provider works at all |
| two tenants' keys do not collide | the namespace rule holds |
| storing a credential raises | the guard is enforced by the policy, not by convention |
| a miss is a miss | the cache is not a second source of truth |

## What goes wrong

| Symptom | The cause |
|---|---|
| a tenant sees another tenant's cached value | the key was built from the caller's claim rather than the context |
| a rotated secret keeps working | the old value is still cached — the guard was bypassed |
| a stale value outlives its correctness | no TTL in the policy: caching is a decision about time, not only about space |
