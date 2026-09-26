---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# RDS and Aurora PostgreSQL: a deployment target, not an adapter

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **ADOPT**: the library's existing
> PostgreSQL support is the adapter, and RDS/Aurora are where it runs.

## The verdict

No new code. The library speaks PostgreSQL through SQLAlchemy's async engine with an asyncpg driver,
takes a DSN, and has no PostgreSQL-version or vendor-specific behaviour that a managed service
changes. RDS and Aurora PostgreSQL are the same protocol at a different address, so the correct
outcome is a documented deployment story rather than an adapter nobody needs.

## What changes in a deployment

| Concern | What to do | Why it matters |
| --- | --- | --- |
| DSN | `postgresql+asyncpg://user:pass@host:5432/dbname` with the cluster endpoint | the library takes a DSN; the endpoint name is the stable address |
| TLS | require it — RDS and Aurora accept TLS and the driver must be told to use it | an unencrypted connection to a managed database is a finding in any review |
| Credentials | Secrets Manager, resolved through [the provider](secrets-manager.md) | rotation without a redeploy; the cache TTL bounds staleness |
| IAM database authentication | possible, with a per-connection token | the token is short-lived (about 15 minutes) and generated per connection, so a pooled connection cannot outlive it |
| Connection pooling | consider RDS Proxy, which multiplexes connections and can authenticate with IAM | serverless and bursty workloads exhaust direct connections |
| Failover | nothing to write: multi-AZ failover keeps the endpoint name and closes open connections | the pool must re-establish, which is ordinary connection-loss handling, not RDS-specific code |
| Read scaling | Aurora reader endpoints for read-only work | the library's read paths can be pointed at a reader endpoint; write paths must not be |

## What the library deliberately does not do

* **No RDS API calls.** Nothing in the library creates, modifies or inspects a database; that is
  infrastructure as code, and a library that tried would need AWS credentials it should not hold.
* **No IAM token generation.** A deployment that uses IAM database authentication generates the token
  in its composition root and hands the library a DSN. The library's `SecretProvider` protocol
  returns a string; it does not sign SigV4 requests.
* **No automatic reader routing.** Sending a read to a reader endpoint is a deployment decision, and
  guessing it in the library would be a correctness bug waiting for a replica lag.

## Testing

Nothing new is needed: the existing PostgreSQL tests run against a real PostgreSQL server, and the
enterprise example lab uses one on a port. A live RDS or Aurora run is
`NOT RUN — AWS credentials unavailable`, and this page does not claim otherwise.
