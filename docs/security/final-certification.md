# Final certification (phase 12)

Status: **COMPLETE**

This document records the phase 12 enterprise validation: the eight checks the
directive asks for, the exact output of each, what is verified and what is not.
Every number here was produced by running the command shown, on the development
host (Windows, git-bash, Docker Desktop), with the local infrastructure stack up
(Cerbos 0.37.0, Kong 3.6, ZITADEL, PostgreSQL 16, an OpenTelemetry collector
0.110.0 and Tyk 5.3.1). Nothing is estimated or rounded.

## 12.1 Full pytest

```bash
export TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1
set -a; . tests/infra/out/kong-credentials.env; set +a
.venv/Scripts/python.exe -m pytest -q -W error
```

```text
1217 passed, 6 skipped in 73.03s
```

The six skips are the documented Tyk coprocess limitation (§ Tyk below). With the
infrastructure variables unset the same suite reports `1192 passed, 31 skipped` —
the difference is exactly the infrastructure layer (Kong 9, Cerbos 12, ZITADEL 4,
Tyk 6), each skip naming the variable it wants. Nothing is skipped silently.

## 12.2 Lint

```bash
.venv/Scripts/python.exe -m ruff check .
```

```text
All checks passed!
```

## 12.3 Type checking

```bash
.venv/Scripts/python.exe -m mypy src/jdlib
```

```text
Success: no issues found in 101 source files
```

## 12.4 Package build and clean install

Built with `python -m build` (hatchling): `jdlib-0.1.0.tar.gz` and
`jdlib-0.1.0-py3-none-any.whl`. Installed into a fresh virtual environment with
only the wheel and the optional `cli` extra (`typer`), then:

```text
import jdlib                                        → ok
import jdlib.security                               → ok
import jdlib.security.compliance                    → ok, CONTROL_REGISTRY holds 19 controls
.../smoke/bin/jdlib security posture --json         → exit 0, 19 findings, keys
                                                      counts/environment/findings/
                                                      generated_at/is_ready/outcome
```

(There is no `__main__.py`, so `python -m jdlib.integrations.cli` imports the
module and exits without running anything — the console script is the supported
entry point.)

The console-script check is the phase 12 review's finding: the package declared
no `[project.scripts]` and had no `__main__.py`, so the `jdlib …` commands every
document recommended did not exist for an installed package. Fixed in the review
commit (`pyproject.toml` declares `jdlib = "jdlib.integrations.cli:main"`, the
callable was added, two tests pin it, and the CI smoke step now runs the installed
script) — the certification would be dishonest without this step.

## 12.5 Infrastructure E2E

```bash
.venv/Scripts/python.exe -m pytest -q tests/infra -rs
```

```text
29 passed, 6 skipped in 10.92s
```

Against the real components:

| Component | Verified by | State |
|---|---|---|
| PostgreSQL 16 | Testcontainers in the integration suite, plus the RLS harness on a raw connection (`tests/integration/test_rls_db.py`) | verified |
| Redis 7 | Used by Tyk and ZITADEL inside the harness; **the library itself keeps no state in Redis** (only `RateLimiter` names it as an adapter example, `src/jdlib/security/interfaces.py:5,142`) | not applicable to the library |
| ZITADEL | `tests/infra/test_zitadel_infra.py` — issuer, discovery, token endpoint | verified |
| Cerbos 0.37.0 | `tests/infra/test_cerbos_infra.py` — ALLOW and four DENY paths, all-actions rule, plus outage and timeout | verified |
| Kong 3.6 | `tests/infra/test_kong_infra.py` — identity envelope end to end | verified |
| OpenTelemetry collector 0.110.0 | `tests/infra/test_otel_infra.py` — a security span is stored, a secret never reaches the collector, metrics are collected | verified |
| Tyk 5.3.1 (OSS) | `tests/infra/test_tyk_infra.py` — six tests skip | **not verified**: the OSS image has no JavaScript/coprocess runtime |

## 12.6 Security E2E — the complete path

No single test walks the whole chain; each link is verified, and this is the map
so a reader can check every claim:

| Link | Verified by |
|---|---|
| authentication | `tests/integration/test_authn_http_integration.py` (real HTTP: forged signature, expired, wrong audience, JWKS rotation, outage, 5xx retry), `tests/infra/test_zitadel_infra.py` |
| principal | `tests/integration/test_auth_wiring.py`, `tests/unit/test_authn_wiring.py` |
| tenant resolution | `tests/integration/test_auth_wiring.py` (a key pinned to tenant A presenting tenant B gets 404), `tests/unit/test_resolution.py` |
| SecurityContext | `tests/unit/security/test_security_context.py`, `tests/integration/test_session_isolation.py` |
| authorization (PEP) | `tests/unit/security/test_authz_pep.py`, `tests/integration/test_fastapi_integration.py` (403/404/409 JSON) |
| Cerbos (PDP) | `tests/infra/test_cerbos_infra.py` — **ALLOW** from a real policy, **DENY** for wrong action, wrong role, wrong tenant and missing attribute |
| TenantSession | `tests/integration/test_session_isolation.py`, `tests/unit/test_session.py` |
| RLS | `tests/integration/test_rls_db.py` (unset role sees nothing; cross-tenant inserts refused), `tests/integration/test_adversarial_tenant_isolation.py` |
| PostgreSQL | the Testcontainers `postgres:16` instances those tests run against |
| audit | `tests/integration/test_security_audit_persistence.py`, `tests/integration/test_audit_sinks.py`, `tests/integration/test_audit_isolation_export.py` |
| telemetry | `tests/infra/test_otel_infra.py` (real collector), `tests/unit/security/test_tracing.py` |

Both ALLOW and DENY are asserted at the decision point against the live engine and
at the enforcement point in the integration tests. The honest gap: the DENY path
is asserted against Cerbos with the harness's own policies, not with a consumer's
production policy set.

## 12.7 Failure injection

| Injected failure | Required behaviour | Evidence | Result |
|---|---|---|---|
| Cerbos unavailable | authorization fails closed | `test_cerbos_infra.py::test_unavailable_cerbos_never_allows` | verified |
| Cerbos slow | no allow on timeout | `test_cerbos_infra.py::test_timing_out_cerbos_never_allows` | verified |
| IdP unavailable | authentication does not become anonymous | `test_authn_http_integration.py::test_endpoint_outage_fails_closed_and_recovers` | verified |
| Telemetry collector unavailable | security does not fail open | `test_telemetry.py::test_a_broken_metric_sink_cannot_break_an_authorization_decision`, `::test_a_failing_emitter_is_swallowed_and_reported` | verified |
| PostgreSQL failure mid-transaction | no partial cross-tenant mutation | `tests/unit/test_uow.py::test_rollback_on_exception`, `tests/integration/test_audit_sinks.py::test_tenant_audit_recorder_commits_and_rolls_back`, composite foreign keys proven on a raw connection (`tests/integration/test_adversarial_tenant_isolation.py`) | verified |
| Redis unavailable | security-sensitive state does not become permissive | not applicable: the library holds no security state in Redis (see §12.5). Rate limiting is a port the consumer implements — an adapter that fails open under a Redis outage is the consumer's decision and is recorded as such | boundary, documented |
| Gateway unavailable | no request is trusted without an identity assertion | the library makes no outbound call to a gateway; the adapters verify assertions and are infrastructure-verified against Kong 3.6 and unit-tested for each refusal. A gateway outage means no traffic reaches the application | boundary, documented |

## 12.8 Final adversarial review

Areas attacked in this final pass, and what happened:

| Area | Attack | Result |
|---|---|---|
| CLI | does any command echo a credential it was given? Ran `security evidence --database-url "postgresql+psycopg://app:…@…"` and `security posture --json`, grepped the output for the password | no leak (2 probes, 0 hits) |
| CLI | does the documented command exist at all? | **finding**: no console script, no `__main__.py`. Fixed with tests; the CI smoke step now runs the installed script |
| Compliance surface | can a declared profile hide a failure? `--environment development` and hostile `JDLIB_SECURITY*` environment overrides | outcomes follow the declared profile and the register's own statuses; a live observation still overrides a configuration claim (posture rules in `src/jdlib/security/compliance/posture.py`) |
| Compliance surface | can the register overclaim? | `tests/unit/security/test_compliance_controls.py` (no gap without a reason; every cited evidence path must exist) and the register's own `not_implemented`/`partial` statuses |
| Documentation / CI | do the documents describe what exists? | **findings**: the `e2e` marker is declared but collects nothing (CONTRIBUTING now says so); `JdlibError` subclasses were described as 28 when 31 exist package-wide; the threat model's cache row described a cross-request cache that does not exist (corrected). Every relative link in the nine reviewed documents resolves; no credential-shaped value appears |
| Everything else | the phase 8 adversarial suites (privilege liveness, audit attribution and integrity, tenant isolation, service identity, raw SQL) | re-run green in the full suite; no new finding |

No new security vulnerability was found in this pass. The genuine defect it did
find — the missing console script, with documents describing a command that did
not exist — was fixed with regression tests rather than documented as a
limitation, because it is not a limitation: it was a gap.

## Residual risks, by owner

| Residual risk | Owner |
|---|---|
| Tamper-evident audit storage (an actor with database access can rewrite history) | deployment |
| IdP, PDP, gateway and collector availability (the library fails safely, it cannot make them available) | deployment |
| Redis-backed or gateway rate limiting failing open | consumer / deployment |
| Sharing one `AuthzCache` across requests (documented contract, not enforceable) | consumer |
| Secret material placed into library fields by the application | consumer |
| Tyk plugin execution (OSS image has no coprocess runtime) | vendor limitation, documented |
| Compliance certification | organisation |

## Final state

```text
Phase 0  COMPLETE      Phase 6  COMPLETE      Phase 11 COMPLETE
Phase 1  COMPLETE      Phase 7  COMPLETE      Phase 12 COMPLETE
Phase 2  COMPLETE      Phase 8  COMPLETE
Phase 3  COMPLETE      Phase 9  COMPLETE
Phase 4  COMPLETE      Phase 10 COMPLETE
Phase 5  COMPLETE
```

What is *not* verified, stated plainly: GitHub Actions runner semantics (the
workflow's steps were reproduced locally, not on a runner — except that CI itself
runs them); the Tyk plugin path; and the behaviour of a consumer's own policy set
against Cerbos. Everything else above is a command's output.
