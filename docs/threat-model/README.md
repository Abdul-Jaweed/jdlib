# Threat model

Scope: JDLib as a library, the boundaries it defends, and the residual risk it
leaves to the deployment. This is a working model, not a risk register: every row
names the control that addresses the threat and the test that holds the control
in place. Where a threat is not eliminated, the *Owner* column says who has to
close it — a library cannot decide whether a deployment's database is backed up.

The model describes the code at the commit this file was written on. The
per-topic evidence lives in the documents indexed in
[../security/README.md](../security/README.md).

## Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Tenant data (rows in the tenant schema) | Disclosure or cross-tenant mutation is the failure that ends the relationship | PostgreSQL, per tenant schema (or database) |
| Tenant identity binding (who the request acts as) | Every authorization and isolation decision derives from it | Request-scoped `SecurityContext`, `TenantContext` |
| Authorization decisions | A wrong ALLOW is a breach; a wrong DENY is an outage | PDP (Cerbos / `DefaultPDP`) + `AuthorizationPEP` |
| Audit trail | The record of who did what, and the evidence during an incident | Audit sinks (database, logs, telemetry) |
| Gateway identity assertions | The only thing standing between an arbitrary client and a trusted principal | Kong / Tyk, verified by the gateway adapters |
| Credentials and secrets | Tokens, client secrets, DSNs, keys | Environment, `SecretProvider`; never in the library's own output |
| Compliance evidence | Claims an operator or an assessor reads | `jdlib.security.compliance` snapshots |

## Actors and trust boundaries

```text
untrusted client
  │  ①  no identity, arbitrary headers, arbitrary payloads
  ▼
gateway (Kong 3.6 verified; Tyk adapter unit-tested)      ← boundary ①
  │  ②  a signed identity envelope (algorithm, audience, tenant, expiry, nonce)
  ▼
consumer application (FastAPI)                            ← boundary ②
  │  ③  credentials on the request; tenant from the envelope, never from the body
  ▼
JDLib authentication → Principal → tenant resolution → SecurityContext
  │  ④  decision request (principal, tenant, resource, action, attributes)
  ▼
policy engine (Cerbos)                                    ← boundary ③
  │  ⑤  ALLOW / DENY / cannot decide
  ▼
JDLib PEP → TenantSession                                 ← boundary ④
  │  ⑥  parameterised, tenant-bound SQL or refused raw SQL
  ▼
PostgreSQL with row-level security                        ← boundary ⑤
```

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| ① gateway → app | It performed transport authentication and signed the identity envelope | Anything the client claims directly: headers are re-verified, never believed |
| ② app → JDLib | It passes the credentials and the declared tenant | Choosing the tenant for a key pinned elsewhere, or bypassing the PEP |
| ③ JDLib → PDP | An ALLOW/DENY answer for a complete request | Availability: an unreachable or slow engine must not become an ALLOW |
| ④ JDLib → database | The transaction and the bound role | Trusting the caller's SQL: raw SQL is gated, privileged operations need a live privilege |
| ⑤ database → rows | RLS policies and composite keys | Application-level filters alone — with RLS disabled, a wrong query returns other tenants' rows |

## Threat table

| # | Threat | Control | Evidence | Residual risk / Owner |
|---|---|---|---|---|
| T1 | Forged, expired or wrong-audience token accepted | Token validation against issuer, audience, algorithm, expiry, with JWKS caching and rotation | `tests/integration/test_authn_http_integration.py` (forged signature, expired, wrong audience, rotation, outage), `tests/infra/test_zitadel_infra.py` | IdP misconfiguration → **deployment** |
| T2 | Forged gateway identity envelope | Signature verification, replay window, audience and tenant checks per adapter | `tests/unit/security/test_gateway_adapters.py`, `tests/infra/test_kong_infra.py` | Tyk plugin path unverified (OSS image has no coprocess runtime) → **documented limitation**, see `../security/gateway-hardening.md` |
| T3 | Cross-tenant read or write | Tenant binding from the verified envelope, RLS in PostgreSQL, composite foreign keys | `tests/integration/test_session_isolation.py`, `tests/integration/test_rls_db.py`, `tests/integration/test_adversarial_tenant_isolation.py` | Direct database access outside the library → **deployment** (roles, network) |
| T4 | Bulk operation escapes the tenant filter | Tenant-bound `update_where`/`delete_where`; tenant id required | `tests/unit/test_persistence_models.py`, `tests/integration/test_adversarial_tenant_isolation.py` | — |
| T5 | Raw SQL used to bypass the session's tenant filter | Raw SQL is refused unless the operation carries a live privilege | `tests/integration/test_adversarial_raw_sql.py`, `tests/integration/test_audit_raw_sql_refusal.py` | An operator granting a privilege for the wrong work → **deployment policy**, refusal is audited |
| T6 | Expired privilege still authorizes work | Privilege liveness checked at every gate (`TenantContext.live_privilege`) | `tests/unit/security/test_adversarial_privilege.py` | — |
| T7 | Policy engine unavailable or slow → request allowed | Fail closed: no decision becomes a refusal (503 `AuthorizationUnavailable`) | `tests/infra/test_cerbos_infra.py` (`test_unavailable_cerbos_never_allows`, `test_timing_out_cerbos_never_allows`), `tests/unit/security/test_authz_pep.py` | Availability: a Cerbos outage is a denial of service by design → **deployment** (run the PDP highly available) |
| T8 | IdP outage silently downgrades to anonymous | Authentication fails closed; no anonymous principal is fabricated | `tests/integration/test_authn_http_integration.py` (`test_endpoint_outage_fails_closed_and_recovers`) | — |
| T9 | Telemetry pipeline outage breaks or weakens the request path | Telemetry failures are isolated: spans/metrics/logs drop, the request proceeds unchanged | `tests/infra/test_otel_infra.py`, `tests/unit/security/test_telemetry.py` | Blind spots during an outage → **deployment** (collector monitoring) |
| T10 | Audit event with no actor, or back-dated | Fail-closed attribution and timestamp corroboration (`MAX_TIMESTAMP_SKEW`) | `tests/unit/security/test_adversarial_audit_integrity.py`, `tests/integration/test_security_audit_persistence.py` | — |
| T11 | Audit trail read or exported by an unauthorized principal | Separate capabilities for writing, reading and exporting; reads are tenant-scoped | `tests/integration/test_audit_isolation_export.py` | — |
| T12 | A secret reaches a log, span, error or audit metadata | One redaction path (`redact_text`/`redact_mapping`) used by all sinks | `tests/unit/security/test_telemetry.py`, `tests/unit/security/test_tracing.py`, `tests/unit/security/test_error_responses.py`, `tests/integration/test_audit_sinks.py` | Pattern-based, not a proof: do not put secret material into library fields → **consumer app** |
| T13 | Audit history rewritten by someone with database access | *Not provided.* The trail is written atomically and attribution is enforced, but the library does not make storage tamper-evident | `../security/audit-hardening.md` §7 | **Deployment**: append-only storage, external shipping, or signed/WORM audit storage |
| T14 | Stolen bearer token replayed inside its lifetime | Token lifetime and audience checks bound it; no server-side session is kept | `tests/unit/security/test_jwt_validator.py`, `tests/unit/security/test_jwks_hardening.py` | Accepted and recorded as not applicable in the register; shorten token lifetime → **IdP configuration** |
| T15 | Service account acts outside its tenant | Service identity is formalised: envelope tenant and entitlement must both contain the account | `tests/integration/test_auth_wiring.py`, `tests/unit/security/test_adversarial_service_identity.py` | — |
| T16 | The request-scoped authorization memo is shared between requests, so one principal's status/bindings/grants answer another's query | `AuthzCache` is request-scoped by contract — `DefaultPDP` memoizes status gates, scope chains, bindings, per-role permissions and grants under per-call keys, `invalidate()` clears the memo and does not re-enable it, and there is no cross-request authorization cache in v1 | `tests/unit/test_pdp.py` (`test_cache_memoizes_until_invalidated`, `test_cache_invalidate_forces_refetch`), class docstring in `src/jdlib/authz/pdp.py` | A consumer that injects **one** cache instance into many requests breaks the contract; the library documents the requirement and cannot enforce it → **consumer app** |
| T17 | Partial cross-tenant mutation when the database fails mid-work | One transaction per unit of work; composite foreign keys; no partial commits | `tests/unit/test_uow.py`, `tests/unit/test_session.py`, `tests/integration/test_session_isolation.py` | — |
| T18 | Context leaks between concurrent requests | Request-scoped contexts; background work requires an explicit context | `tests/unit/security/test_security_context.py`, `tests/unit/security/test_adversarial.py` | → **consumer app** when it spawns its own tasks |
| T19 | Compliance claim overstated | The register records `implemented` / `partial` / `not_implemented` / `not_applicable` with reasons, and posture reports FAIL for a missing control | `tests/unit/security/test_compliance_controls.py`, `tests/unit/security/test_compliance_posture.py`, `../security/compliance-evidence.md` | Readiness is not certification → **organisation** |
| T20 | A gate is silently weakened in CI | The security job fails the build; suppressions require a documented reason | `.github/workflows/ci.yml`, `../security/ci-security.md` | — |

## What the model deliberately excludes

* **Consumer application logic.** JDLib cannot protect a route the application
  never wires to the PEP, or data the application chooses to log.
* **Deployment topology and operations.** Network boundaries, database roles,
  backups, retention, key management and secrets handling belong to the operator;
  `../operations/README.md` lists the obligations the library does not take on.
* **The gateways, the IdP, the PDP and PostgreSQL themselves.** Their
  vulnerabilities are theirs; JDLib's obligation is to verify what they assert and
  to fail safely when they are unavailable — which is what T7, T8 and T9 assert.
* **Compliance certification.** See T19 and `../compliance/README.md`.
