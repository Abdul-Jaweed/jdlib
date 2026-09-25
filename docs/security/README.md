# Security documentation

The security work in this repository is documented one phase per document, plus
two reference documents (the adversarial review and the CI gates). Every
document below describes what the code does at the commit it was written on,
what it deliberately does not do, and the tests behind each claim. Each one
carries its own `Status:` line — read the status in the document itself rather
than in this index, which is a map and not a summary.

## Documents

| Document | What it covers |
|---|---|
| [`security-core.md`](security-core.md) | Phase 1 — the foundation: request-scoped `SecurityContext`, strongly typed security configuration, the stable machine-readable error model, and the ports (`GatewayAdapter`, `Authenticator`, rate limiting) that adapters implement. |
| [`authentication-hardening.md`](authentication-hardening.md) | Phase 2 — inbound token validation (JWKS caching and rotation, algorithm policy, expiry and audience), outbound credentials, the ZITADEL adapter, and service-identity formalisation. |
| [`authorization-hardening.md`](authorization-hardening.md) | Phase 3 — the decision model, the PDP port, the Cerbos adapter and the enforcement point (`AuthorizationPEP`), with the fail-closed rules. One paragraph is superseded by Phase 5 (a decision that could not be taken is a `503 AuthorizationUnavailable`, not a 403). |
| [`gateway-hardening.md`](gateway-hardening.md) | Phase 4 — gateway-derived identity: the adapters, the fail-closed rules each with its test, the end-to-end Kong 3.6 verification, and the Tyk live harness, now **verified**: all six tests pass (§6 records the five fixture defects that were fixed). |
| [`error-responses.md`](error-responses.md) | Phase 5 — the stable error codes and their HTTP mapping, the safe response envelope, `WWW-Authenticate` behaviour, and the declared behaviour changes (including the 503 for a degraded policy decision). |
| [`audit-hardening.md`](audit-hardening.md) | Phase 6 — the audit event vocabulary and envelope, metadata safety (no secret can reach the trail), transaction semantics, audit access capabilities, deterministic export, and the integrity evaluation with its residual risk (§7). |
| [`observability-hardening.md`](observability-hardening.md) | Phase 7 — structured logs, bounded metric labels, telemetry failure isolation, OpenTelemetry spans and trace propagation, and the Docker collector stack verified against a real collector. |
| [`adversarial-review.md`](adversarial-review.md) | Phase 8 — the attacks run against the built controls, the two genuine findings that were fixed, the attacks with no finding (and the evidence), and what was considered and deliberately not implemented. |
| [`compliance-evidence.md`](compliance-evidence.md) | Phase 9 — the control register, the control model, the evidence record and its collectors, the posture layer, and the `jdlib security` CLI. Readiness, not certification. |
| [`ci-security.md`](ci-security.md) | Phase 10 — the five gates in the `security` CI job with their pinned tool versions, the reviewed exception list, what is deliberately not covered (§7), and the tools that were evaluated and rejected (§8). |

Companion documents outside this directory: [`SECURITY.md`](../../SECURITY.md)
(what the library is responsible for, what it leaves to a deployment, known
limitations, how to report a vulnerability), [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
(gate commands, test layers, contribution rules),
[`docs/operations/README.md`](../operations/README.md) (running the posture and
evidence commands, CI artifacts, operator responsibilities) and
[`docs/compliance/README.md`](../compliance/README.md) (the assessor-facing view
of the register, the evidence and the posture outcomes).

## Topic map

| If you are working on… | Start here |
|---|---|
| Authentication — inbound tokens, JWKS, algorithms, service identity | [`authentication-hardening.md`](authentication-hardening.md), [`security-core.md`](security-core.md) §4 (the ports) |
| Authorization — decisions, the PDP, Cerbos, the enforcement point | [`authorization-hardening.md`](authorization-hardening.md); design contract in [`docs/jdlib/04-authorization-model.md`](../jdlib/04-authorization-model.md) |
| Tenant isolation — resolution, bound context, RLS, raw SQL | [`docs/jdlib/03-isolation-invariants.md`](../jdlib/03-isolation-invariants.md) (the invariants are the security contract), [`docs/jdlib/02-relational-schema.md`](../jdlib/02-relational-schema.md) (schema and composite keys), [`docs/jdlib/06-strategy-matrix.md`](../jdlib/06-strategy-matrix.md) (per-strategy RLS and pool rules) |
| Privilege liveness — an expired privilege must not authorize work | [`authorization-hardening.md`](authorization-hardening.md), [`adversarial-review.md`](adversarial-review.md) §1.1 (the finding and its fix) |
| Audit — vocabulary, trail, reads, export, integrity | [`audit-hardening.md`](audit-hardening.md) |
| Observability and telemetry safety — logs, metrics, spans | [`observability-hardening.md`](observability-hardening.md) |
| Gateway trust — Kong, Tyk, identity assertions | [`gateway-hardening.md`](gateway-hardening.md) |
| Error responses — codes, envelope, status mapping | [`error-responses.md`](error-responses.md) |
| Compliance and evidence — register, collectors, posture | [`compliance-evidence.md`](compliance-evidence.md), then [`docs/compliance/README.md`](../compliance/README.md) |
| CI security — dependency, secret, SAST, SBOM and packaging gates | [`ci-security.md`](ci-security.md) |
| Adversarial review — attacking the controls | [`adversarial-review.md`](adversarial-review.md) |
| Running the checks in a deployment | [`docs/operations/README.md`](../operations/README.md) |
| Tenant lifecycle, deprovisioning, retention semantics | [`docs/jdlib/05-tenant-lifecycle.md`](../jdlib/05-tenant-lifecycle.md) |
| Implementation structure and extension points | [`docs/jdlib/07-implementation-design.md`](../jdlib/07-implementation-design.md), [`README.md`](../../README.md) |
