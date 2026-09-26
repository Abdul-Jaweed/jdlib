# Production checklist

Every line is a claim someone should be able to answer "yes" to, with evidence. The evidence column
is the point: a checklist without it is a list of intentions.

## Isolation

| Check | Evidence |
|---|---|
| the application connects as `JDLIB_RLS__APP_ROLE` | the deployment's connection string; the role's grants |
| the policy is installed on every tenant schema | `jdlib rls verify` per schema |
| every tenant-scoped table inherits the tenant base | the models; a query returning nothing under a second tenant |
| cross-tenant references refuse rather than return empty | a test asserting `409 INVALID_REFERENCE` |
| the graph session always carries a tenant | `jdlib.graph.tenant`; a test with a tenantless session |

## Identity and authorization

| Check | Evidence |
|---|---|
| the signing key is set per deployment and rotated | `JDLIB_CONTEXT__SIGNING_KEY`; the rotation record |
| every guarded route and tool declares its permission | the route walk in the example's tests, adapted to your app |
| a denial is measured as non-execution | the security layer's tests |
| a degraded decision is a refusal | a test pointing the engine at a dead port |
| the permission catalog is checked at startup | the process fails to start on an unknown permission |

## Data and stores

| Check | Evidence |
|---|---|
| migrations run as an operator step, not at process start | the deploy procedure |
| a migration is idempotent | applying it twice in a test |
| the cache keys carry the tenant | the key construction; a two-tenant test |
| a credential is never cached | the policy's refusal, asserted |
| object keys carry the tenant prefix | the key construction; a two-tenant test |

## Reliability

| Check | Evidence |
|---|---|
| breakers have chosen thresholds | the configuration, and the transition metric |
| the retry budget has a value | the configuration, and the exhaustion metric |
| the concurrency gate has a value | the configuration, and the refusal metric |
| `/healthz` and `/readyz` are on different probes | the orchestrator's configuration |
| readiness flips before the drain | the `ShutdownReport` from a deploy |

## Evidence

| Check | Evidence |
|---|---|
| the audit sink is reachable and monitored | its failure metric |
| span attributes are allow-listed | `jdlib.security.tracing`; a review of what the collector receives |
| the compliance posture is recorded | the [compliance surface](../compliance/README.md) |
| the refusal codes in the dashboards match the library's | the [error codes](../reference/error-codes.md) |
| the docs build passes on the deployed revision | `mkdocs build --strict` in the gate |
