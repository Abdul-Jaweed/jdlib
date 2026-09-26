# Failure modes

What each dependency being down looks like from outside. Every row is a behaviour the library has, or
a boundary it deliberately leaves to the deployment.

| The dependency | The library's behaviour | The client sees | Where it is enforced |
|---|---|---|---|
| PostgreSQL (control plane) | the request is refused; `/readyz` answers `503 DEPENDENCY_UNAVAILABLE` | a refusal with a stable code, and a readiness probe that tells the truth | `jdlib.integrations.fastapi`, `jdlib.persistence.session` |
| PostgreSQL (tenant plane) | the tenant-bound statement fails; the envelope is the canonical error | `503`-class refusal, never a partial page | `jdlib.persistence.repository` |
| the policy engine | the decision is **degraded**, and a degraded decision is a refusal | `403 AUTHORIZATION_DENIED`, audited as a decision, not an outage | `jdlib.security.authz.pep` |
| the identity provider (JWKS) | verification fails; the credential is refused | `401 UNAUTHENTICATED` | `jdlib.authn.oidc` |
| Neo4j (graph plane) | the graph operation is refused; the relational path is unaffected | a refusal on the graph operation only | `jdlib.graph.client` |
| Redis (cache) | a miss is a miss: the value is recomputed from its owner | normal latency, no error | `jdlib.caching.policy` |
| S3 | the object operation is refused | a refusal with a stable code | `jdlib.storage.s3` |
| the audit sink | the write fails and is counted; the request's outcome is unchanged | no client-visible change | `jdlib.security.audit.emitters` |
| the OTel collector | spans and metrics are dropped by the exporter; the request is unaffected | no client-visible change | the deployment's exporter |
| a dependency that is slow | the breaker opens after its threshold; later calls fail fast | fast refusals instead of waiting for timeouts | `jdlib.reliability.breaker` |

## The two rules behind the table

1. **A dependency that cannot answer does not become a permission.** The policy engine and the JWKS
   are the two places where "unavailable" could have meant "allow"; both refuse.
2. **Telemetry failure is not request failure.** An unreachable collector or audit sink degrades the
   evidence, not the request — and the degradation is counted, so it is visible rather than silent.

## What is the deployment's

* the **queue** behind a job: `jdlib.tenancy.job_envelope` gives work authority and a lifetime;
  delivery, retries and the dead-letter store are the queue's;
* the **gateway's** rate limiting and connection handling;
* **fleet-wide** state for the breaker and the budget, which are per process by design.
