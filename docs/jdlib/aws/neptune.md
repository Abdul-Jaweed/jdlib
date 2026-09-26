---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Amazon Neptune: evaluated, and not adapted

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **DEFER** with the evaluation recorded —
> the directive asks for Neptune to be evaluated and adapted *if justified*, and the justification
> does not hold.

## What Neptune actually offers

Neptune Database speaks openCypher **over Bolt** — the same wire protocol the library's graph layer
already uses — so a connection is not the obstacle. The obstacle is the language:

| Neo4j feature the library's graph layer may use | Neptune |
| --- | --- |
| openCypher query language | supported, as a documented subset |
| Bolt protocol | supported |
| APOC procedures | not available |
| `CALL` subqueries and procedures | not available |
| `shortestPath` / `allShortestPaths` | not available |
| Dynamic property access (`node[expr]`) | not available |
| Multiple databases in one cluster | one graph per cluster |
| IAM authentication | supported |
| Gremlin | supported, but a different language |

## The one thing that does *not* block it

Tenancy. It is worth being precise here, because it is the usual objection and it is wrong for this
library: `Neo4jClient` opens **for one tenant** and checks every statement against the authenticated
tenant before it reaches the driver (`require_open_tenant`, `require_scope`), so tenant isolation is
enforced in the client and expressed in the data — not delegated to Neo4j's multi-database feature.
A single-graph Neptune cluster therefore does not break the tenancy model; it changes where the
tenant predicate lives, which the library already controls.

## Why the verdict is still DEFER

Because an adapter would have to do more than translate an endpoint: it would have to **refuse**
constructs Neptune cannot execute, and a capability profile that refuses queries is a meaningful
piece of design — worth building when a deployment needs Neptune, not speculatively. Shipping an
adapter that silently fails on `CALL` or `shortestPath` would be worse than not shipping one, and
shipping one that pretends the two engines are equivalent is exactly what this programme forbids.

## The graph strategy, stated for both engines

The directive asks for the Neo4j-and-AWS graph strategy to be documented, and the strategy is the
same sentence in both directions: **the query vocabulary is the portability boundary, and the client
enforces tenancy.**

* **Today (Neo4j).** The graph layer speaks a closed query vocabulary; `Neo4jClient` opens for one
  tenant and checks every statement against it before the driver sees it, so isolation does not
  depend on the database's features.
* **On AWS (Neptune, if it is ever adopted).** The same client shape works over Bolt with openCypher,
  and the same client-side tenant check applies. What changes is the subset of Cypher that will
  execute, which is why the verdict above is DEFER rather than ADOPT.
* **What makes it portable.** Keeping the vocabulary closed — no APOC, no procedures, no
  shortest-path functions, no dynamic property access — is what would make the two engines
  interchangeable. That is a discipline the library can hold deliberately, and the reason this page
  records the constraint rather than hiding it.
* **What is not portable at all.** Neptune Analytics is a different engine for analytical workloads
  with a different connection model; a strategy that assumes one adapter covers both would be wrong.

## What would change the verdict

* A deployment that needs Neptune **and** a graph layer restricted to the portable subset — at which
  point the capability profile is a requirement with a user, not a guess.
* A decision to keep the library's Cypher portable by construction (no APOC, no procedures, no
  shortest-path functions anywhere), which would make the two engines genuinely interchangeable and
  the adapter nearly free.

## Notes for that future work

Neptune **Analytics** is a different engine again — it is for analytical workloads, its
connection model differs from Neptune Database's, and it should not be conflated with the
transactional database in any adapter design.
