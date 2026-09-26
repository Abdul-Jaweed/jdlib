# Redis

```bash
pip install "jdlib[redis]"
```

`jdlib.caching.redis.RedisCache` is the shared cache provider. The library's caching has three parts,
and the provider is only the third:

| Module | What it is |
|---|---|
| `protocol` | the cache protocol a provider implements |
| `policy` | what may be cached, for how long, and under which key |
| `keys` | key construction — the tenant is part of the namespace, never an afterthought |
| `local` | the in-process provider, for a single worker or a test |
| `redis` | `RedisCache`, for a fleet that must share a cache |
| `errors` | the refusals |

## The rules the policy enforces

* **A credential is never cached.** The policy refuses a credential object outright, including one
  inside a container — a cache that can hold a secret is a secret store with no access control.
* **The tenant is in the key.** `jdlib.caching.keys` builds the namespace from the context, so two
  tenants cannot collide on a shared Redis.
* **A miss is a miss.** The cache never becomes a second source of truth: a value that is not there
  is recomputed from the store that owns it.

## Wiring it

```python
from jdlib.caching.redis import RedisCache

cache = RedisCache(url="redis://127.0.0.1:6379/0")
```

The provider takes its connection from the caller rather than the environment, so a deployment can
source it from its own configuration or credential chain.

## Where it is tested

`tests/integration/` against a real Redis (including the credential refusal and the tenant-namespaced
keys) and `tests/unit/` for the policy and key construction. The feature guide is
[`features/caching`](../jdlib/features/caching.md).
