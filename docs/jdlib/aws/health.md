---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Health and dependency checks

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **ADOPT** (documentation): the library's
> health surfaces do not change on AWS, but what a probe should mean does.

## The distinction that matters

| Probe | Question | Must depend on |
| --- | --- | --- |
| Liveness | is this process alive, or should it be restarted? | nothing outside the process |
| Readiness | should this process receive traffic right now? | only what a request needs to succeed |

A liveness probe that checks the database is a self-inflicted outage: the database has a bad minute,
every instance reports unhealthy, and the orchestrator restarts a fleet that was fine. A readiness
probe that checks nothing sends traffic to an instance that cannot serve it.

## Checking each dependency

| Dependency | Readiness? | Why |
| --- | --- | --- |
| Database (RDS/Aurora) | yes | no request can be served without it |
| Cache (ElastiCache) | usually no | a cache outage is a performance event; if the library's cache contract degrades, readiness should not flip |
| Graph (Neo4j/Neptune) | only if every request needs it | otherwise it belongs in a feature-level check |
| Policy decision point | **no** | see below — a PDP outage produces degraded decisions, which are denials, not unavailability of the whole service |
| Secret resolution | at startup, not per request | a secret that resolved once is cached; failing readiness on a per-request secret read makes the secret store a single point of failure for traffic |
| Object store (S3) | only for endpoints that use it | S3's own availability is not the application's |

## The PDP case, in full

The library's policy decision points return a **degraded denial** when the engine is unavailable or
throttled — the decision type refuses to construct an allowed degraded decision. So a PDP outage
means requests are *denied*, not that the service is *down*. Reporting unready would take the whole
service out of rotation for a condition the library already handles per request, and it would turn a
policy outage into a total outage. Readiness stays up; metrics and alerts carry the signal (see
[the observability page](observability.md)).

## Timeouts and caching

A health check that hangs is worse than one that fails: it consumes the probe's own timeout and
delays the orchestrator's decision. Every dependency check needs a short timeout, and a check that
is expensive (a database round trip on every probe) should be cached for a second or two. AWS load
balancers and ECS both have their own probe timeouts and healthy/unhealthy thresholds; the
application's checks must fit inside them rather than competing with them.

## What the library does not do

It does not call AWS health APIs, does not know about target groups or ECS task health, and does not
implement a `/healthz` for you. It exposes the dependency state a deployment needs, and the
deployment wires it to whichever probe mechanism it runs.
