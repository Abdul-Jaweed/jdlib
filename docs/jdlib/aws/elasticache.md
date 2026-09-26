---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# ElastiCache: adopt the existing Redis cache

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **ADOPT**: the library's `RedisCache` is
> the adapter, and it is already written against the protocol ElastiCache speaks.

## The verdict

`RedisCache(url=..., keys=..., prefix=...)` works against ElastiCache unchanged, because
ElastiCache speaks Redis — and, for new clusters, **Valkey**, which is the same protocol. The cache
contract is already the right one: keys are tenant- and namespace-scoped, and there is deliberately
no `flush` — invalidation is scoped to a namespace or a tenant, never `FLUSHALL`.

## What changes in a deployment

| Concern | What to do |
| --- | --- |
| TLS | use `rediss://` in the URL; ElastiCache supports in-transit encryption |
| Authentication | a Redis AUTH token in the URL (`redis://:token@host:6379/0`); for IAM auth, see the caveat below |
| Endpoint | the cluster's primary endpoint for writes, reader endpoints for reads |
| Eviction | set a policy that matches the cache's role; the library sets TTLs and expects the store to honour them |

## Two honest caveats

**Cluster mode is not supported by the current adapter.** `RedisCache` builds a `redis.asyncio.Redis`
client from a URL, and that client is not cluster-aware: it talks to one node. A cluster-mode
ElastiCache deployment needs a cluster-aware client (`redis.asyncio.cluster.RedisCluster`), which is
a code change in the adapter, not a configuration change. Single-node and non-cluster-mode
replication groups are unaffected.

**IAM authentication is not a URL.** ElastiCache's IAM auth uses a SigV4-signed token as the
password, regenerated periodically. The adapter takes a URL, so a deployment using IAM auth would
need the token injected at connect time — another small change, and another reason to state the
limitation rather than imply support.

## What the library deliberately does not do

No ElastiCache API calls, no cluster discovery, no failover orchestration. The cache is a cache: if
it is unavailable, the library's cache contract decides what happens, and that behaviour is
unchanged by the store being managed.

## Testing

The existing cache tests run against a real Redis server; the enterprise lab uses one. A live
ElastiCache run is `NOT RUN — AWS credentials unavailable`.
