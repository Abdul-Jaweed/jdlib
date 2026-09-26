# Troubleshooting

Symptom first. Each row names the cause that is most often behind it, and the evidence that
distinguishes it from the others.

| Symptom | The likely cause | Where to look |
|---|---|---|
| every request is `401` | the credential is not verifiable: a wrong audience, a stale JWKS, a clock skew beyond the leeway | the audit event's method and code; the JWKS cache's refresh behaviour |
| every request is `403` | the policy engine is unreachable, so every decision is degraded — and degraded is a refusal | the decision audit events; the engine's own logs |
| one route is `403` for everyone | the permission is declared but absent from the policy | the engine's decision log for that permission |
| a route is reachable by anyone | the permission is missing from the catalog, so the declaration did not take | the catalog at startup; the route walk in the example's tests |
| `404` for a tenant that exists | the resolver chain did not find it: check the order, the base domain, the claim name | `JDLIB_RESOLVERS__*`, and the resolver named in the span |
| `403 TENANT_SUSPENDED` | the tenant's lifecycle state refuses the request — this is the gate working | the tenant's state in the control plane |
| a cross-tenant read returns an empty page | a reference resolved outside the tenant — this should be `409 INVALID_REFERENCE` | the resource type's resolver |
| rows are visible that should not be | the application connects as the owner role, or the policy is not installed | `jdlib rls verify`; `JDLIB_RLS__APP_ROLE` |
| `503` on readiness but the app serves | the control plane is unreachable from this process | the DSN, the network policy, the database's own health |
| fast refusals after a dependency recovers | the breaker is open: it is doing its job until its cooldown probes | the breaker's transition metric |
| retries are not happening | the retry budget is spent — by design, so a struggling dependency is not amplified | the budget's exhaustion metric |
| `429` under load | the concurrency gate refused the work | the gate's refusal metric; the limit is per process |
| a deploy dropped requests | readiness did not flip before the drain | the `ShutdownReport` |
| a denial has no audit event | the sink is unreachable, or the surface's boundary is not wired | the sink's failure metric |
| traces are missing attributes | the attribute is not on the allow-list | `jdlib.security.tracing` |
| a graph query is refused | the session has no tenant, or an identifier was passed as query text | `jdlib.graph.tenant`, `jdlib.graph.query` |
| an MCP tool's arguments are rejected | the client sent what the tool advertises but not what it enforces | the tool's input model |
| the docs build fails in CI | a page is unlisted, a link is broken, or a generated page is stale | `mkdocs build --strict`; `scripts/docs-inventory.py --check` |

## The first three moves for any incident

1. **Read the audit trail**, not the logs: it records the decision, the tenant and the request
   identity for allows *and* refusals.
2. **Check `/readyz`** rather than assuming a dependency is healthy — and check which dependency it
   names.
3. **Check the refusal's code**, not its message: the codes are stable
   ([error codes](../reference/error-codes.md)), and each one narrows the layer.
