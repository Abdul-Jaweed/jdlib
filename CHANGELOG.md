# Changelog

Notable changes to `jdlib`, derived from the commit history of `main` and from
the phase documents under `docs/security/`.

**Unreleased — the project has not published a release.** There are no version
tags, no published distributions and no released artifact of any kind;
`pyproject.toml` carries the development version `0.1.0`, and `main` is the only
line that exists. Every entry below is therefore part of the current,
unreleased development line: the security-hardening programme, recorded phase by
phase in the order it landed.

How to read an entry:

* the **commit SHA(s)** are short hashes on `main`; `git show <sha>` is the
  authoritative record of what changed and why,
* the **phase document** (`docs/security/<name>.md`) is the evidence behind the
  phase's claims — what it verified, what it deliberately did not do, and the
  gaps it records,
* the phase numbers are the security programme's own (phases 1–11). They are
  unrelated to the multi-tenancy foundation phases in
  `docs/superpowers/plans/`.

---

## Unreleased

### Phase 0 — Baseline and directive

No commit in this repository is attributable to this phase. The hardening
directive is referenced by clause throughout `docs/security/*.md` (for example
§4, §5, §6, §9.1–§9.5, §13, §16–§20, §96) but is not itself part of the tree.

* The programme's pre-hardening baseline is commit `a30601d`
  (`chore: final completion sweep`), 568 tests passing
  (`docs/security/security-core.md`: "Baseline: 568 tests → 640 tests").

### Phase 1 — Security core

Commit: `c379f0e` (`feat(security): add security core (context, config, errors, interfaces)`)

* Added `src/jdlib/security/`: `context.py` (request-scoped `SecurityContext`,
  `RequestIds`, `AuthMethod`, `TokenMetadata`, contextvar binding),
  `config.py` (strongly typed `SecurityConfig` and its sections, fail-fast
  posture validation, `assert_strong_signing_key`), `errors.py` (stable
  machine-readable `SecurityCode` descriptors) and `interfaces.py`
  (authentication, gateway and rate-limiting ports).
* `src/jdlib/context.py` gained one additive enum member
  (`PrincipalKind.ANONYMOUS`); no existing member or value changed and
  `jdlib.__all__` is unchanged.
* Tests: 72 in `tests/unit/security/`; suite baseline 568 → 640
  (`docs/security/security-core.md`).

### Phase 2 — Authentication hardening

Commits: `b6c97cd`, `067b6a3`, `cbbd855`, `32c818b`, `c9ff598`, `7fa1da6`, `4fcfe0d`

* `JwksCache` hardened in place (`src/jdlib/authn/oidc.py`): an `asyncio.Lock`
  collapses concurrent refreshes for an unknown `kid` into one fetch, a failed
  or timed-out refresh never discards usable key material, and every fetch is
  bounded by a timeout.
* Added `src/jdlib/security/authn/`: the algorithm allow-list policy, the
  inbound `JwtTokenValidator`, the outbound `ClientCredentialsTokenProvider`
  (`client_credentials` and `private_key_jwt`), the ZITADEL adapter, and the
  HTTP transports (the `http` extra).
* Added `src/jdlib/security/identity.py` — service-identity formalisation
  (directive §13).
* Verification layers: unit; real-HTTP integration
  (`tests/integration/test_authn_http_integration.py`); real ZITADEL 4.19.1
  (`tests/infra/test_zitadel_infra.py`); plus the shared local infrastructure
  stack under `tests/infra/`.
* Gate recorded at certification: 744 passed
  (`docs/security/authentication-hardening.md`).
* Also landed in this window, belonging to no security phase: `f0f8747` added
  `knowledge_base/` (36 tracked files) and `JDLib-Architecture.md`.

### Phase 3 — Authorization hardening

Commits: `4d09859`, `e573420`, `7f8349d`, `04e797a`, `3b1fc03`

* Added `src/jdlib/security/authz/`: the vendor-neutral decision model
  (`decision.py`), the `PolicyDecisionPoint` port (`interfaces.py`), the
  fail-closed Cerbos adapter (`cerbos.py`), the enforcement point
  `AuthorizationPEP` (`pep.py`) and the HTTP transport (`transports.py`,
  `http` extra).
* Verified against a real Cerbos 0.37.0 engine
  (`tests/infra/test_cerbos_infra.py`) with policies under
  `tests/infra/cerbos/policies/`.
* Unit security layer total at certification: 218 passed
  (`docs/security/authorization-hardening.md`).

### Phase 4 — Gateway hardening

Commits: `2964ff5`, `0bcfafa`, `09f3a24`, `b34d74b`

* Added `src/jdlib/security/gateway/`: `NoGatewayAdapter`, `KongGatewayAdapter`,
  `TykGatewayAdapter`, `GatewayConfig`/`GatewayMode`. Identity asserted by an
  edge is trusted only when the channel it arrived on is authenticated; every
  fail-closed rule has a test.
* Verified end to end against real Kong 3.6 (9 infrastructure tests,
  `tests/infra/test_kong_infra.py`).
* Tyk: the adapter is unit-tested and a live harness ships
  (`tests/infra/tyk/`), but it is **not** infrastructure-verified — the stock
  Tyk 5.3.1 OSS image has no JavaScript/coprocess runtime, so the six tests in
  `tests/infra/test_tyk_infra.py` skip. `docs/security/gateway-hardening.md` §6
  records the blocker and the secondary route-matching observation.
* 27 unit tests for the adapters.

### Phase 5 — Security error responses

Commits: `3b513f0`, `47da713`, `586bf74`, `cfe9b63`

* Added the stable security codes and descriptors with their HTTP mapping, the
  safe response envelope and `WWW-Authenticate` emission
  (`src/jdlib/security/errors.py`, `src/jdlib/security/responses.py`).
* Declared behaviour change: a decision that could not be taken (policy engine
  unavailable) is reported as `503 AuthorizationUnavailable` — still a denial,
  now distinguishable from a policy denial — rather than a 403
  (`docs/security/error-responses.md` §4).
* Sensitive values are redacted from client-visible error messages; the leak
  corpus and its tests are recorded in the phase document.
* Gate recorded at certification: 876 passed, 6 skipped.

### Phase 6 — Audit hardening

Commits: `8abe224`, `a6341b1`, `8094dd4`, `4fcccb2`, `7146ff4`, `4a84607`, `a313537`

* Added `src/jdlib/security/audit/`: the `SecurityEventType` vocabulary (the 34
  directive names plus the two audit-access names), the `SecurityAuditEvent`
  envelope (identifiers default from the ambient security context; `repr`
  prints metadata keys, never values), metadata safety through the shared
  redaction path, emitters for authorization decisions, audit-access
  capabilities, tenant-scoped reads and deterministic export, and adapters that
  give the existing privilege, raw-SQL and control-plane seams producers.
* `TenantAuditRecorder.record_security` persists a security event in the
  caller's transaction; the schema change ships as
  `src/jdlib/migrations/tenant/versions/0002_security_audit_columns.py`.
* Integrity evaluation, its threat model and residual risk:
  `docs/security/audit-hardening.md` §7.
* Gate recorded at certification: 1025 passed, 6 skipped.

### Phase 7 — Observability hardening

Commits: `be0fb5b`, `f1cbba5`, `a5d21a7`

* Added `src/jdlib/security/telemetry.py`: `security_log_record` (fixed field
  order, redaction-enforced, identifiers filled from the ambient security
  context), `SecurityMetrics` with a bounded label allow-list, and `safe_emit`
  so a telemetry failure can never disable security.
* Added `src/jdlib/security/tracing.py`: strict `traceparent` parsing and
  formatting and security spans, duck-typed against the OpenTelemetry API
  rather than importing it.
* The telemetry pipeline was verified against a real collector via the Docker
  stack; `docs/security/observability-hardening.md` §5 records what the
  collector stored.

### Phase 8 — Adversarial review

Commits: `39ccdc9` (the review's tests), `f3feec8` (the fixes)

* A labelled verdict for every directive review item, 55 attacks across six
  test modules — `docs/security/adversarial-review.md`.
* **Fixed:** an expired (or not-yet-valid) privilege still authorized privileged
  work at every enforcement gate. `PrivilegeContext.is_live`,
  `TenantContext.live_privilege` and the shared `_privilege_refusal` helper in
  `src/jdlib/persistence/session.py` now refuse a lapsed privilege exactly like
  a missing one, on every path that consumes a privilege.
* **Fixed:** audit attribution is fail-closed and time is corroborated —
  `TenantAuditRecorder.record_security` refuses an event naming another tenant
  or actor than the ambient one, and requires `occurred_at` to sit within
  `MAX_TIMESTAMP_SKEW` (one minute) of the recorder's clock, so request-derived
  data cannot backdate, postdate or replay an entry
  (`src/jdlib/models/audit_recorder.py`).
* **Fixed:** a test-level order dependence found by the review.

### Phase 9 — Compliance evidence and posture

Commits: `9e3b901` (§9.1, §9.2), `0c54aae` (§9.3), `d9ca6c2` (§9.4, §9.5), `ca138ec` (CLI test fix)

* Added `src/jdlib/security/compliance/`: `controls.py` (the `CONTROL_REGISTRY`,
  19 controls mapped onto seven framework families — SOC 2, ISO/IEC 27001,
  NIST CSF, NIST SP 800-53, OWASP ASVS, OWASP API Security Top 10, CIS),
  `evidence.py` (`SecurityEvidence` and the checkout-side collectors),
  `posture.py` (`PostureOutcome`, `Severity`, `PostureFinding`, `PostureReport`,
  `evaluate_posture`, `POSTURE_RULES`) and `session.py` (the two collectors that
  read a live schema).
* The namespace is additive by construction (the security core's public surface
  is pinned by an exact-equality test); it imports no optional dependency and
  nothing from the persistence layer — the session-backed collectors live in
  `compliance/session.py`, which the CLI imports explicitly.
* `verify_rls` was refactored onto a shared catalogue inspection,
  `RlsInspection` / `inspect_rls` (`src/jdlib/persistence/strategies/rls.py`),
  which the isolation evidence collector shares, so the guard that raises and
  the evidence that reports cannot disagree.
* Added the `security` CLI group (`jdlib security posture|evidence|compliance`)
  beside the existing `tenant`, `db`, `rls` and `schema` groups; `posture`
  exits non-zero when a control fails, so it can gate a pipeline.
* Gate recorded at certification: 1215 passed, 6 skipped; six live-collector
  tests run against real PostgreSQL
  (`tests/integration/test_compliance_live_collectors.py`).

### Phase 10 — CI security gates

Commit: `4d113e5` (`feat(ci): security gates - dependencies, secrets, SAST, SBOM, packaging (phase 10)`)

* `.github/workflows/ci.yml` gained a second job, `security`; the existing
  `test` job is unchanged by design and the two run in parallel.
* Five gates, every one of them able to fail the build (no `continue-on-error`,
  no `|| true`): `pip-audit` 2.10.1 over the frozen installed set; `gitleaks`
  v8.30.1 over the **full git history** (pinned container, `--redact`,
  reviewed allowlist in `.gitleaks.toml`); `bandit` 1.9.4 at medium+ severity;
  a CycloneDX SBOM (`cyclonedx-bom` 7.4.0); and `python -m build` plus a
  clean-venv install smoke test that imports `jdlib`, `jdlib.security` and
  `jdlib.security.compliance` and prints the register size.
* Workflow-level `permissions: contents: read`; scanners run from a throwaway
  venv or a pinned container and are **not** project dependencies.
* Coverage, the reviewed exception list, what is deliberately not covered and
  the tools evaluated and rejected: `docs/security/ci-security.md`. §9 records
  what was verified locally and states that the first run on a real GitHub
  runner is the remaining verification step.

### Phase 11 — Documentation sweep

Commit: `6125558` (`docs(security): documentation and knowledge base in line with the code (phase 11)`)

* Added `SECURITY.md` (what the library is responsible for, what it leaves to a
  deployment, known limitations, how to report a vulnerability),
  `CONTRIBUTING.md`, and `CHANGELOG.md` (this file).
* Added the documentation set around the phase documents: an index at
  `docs/security/README.md`, an assessor-facing view at
  `docs/compliance/README.md`, an operator-facing view at
  `docs/operations/README.md`, and `docs/threat-model/README.md`.
* `README.md` gained a security-and-compliance section naming the `security`
  CLI group and pointing at the documents above.
* `JDLib-Architecture.md` was synchronised with the programme: the compliance
  package, the `security` CLI group, `RlsInspection`/`inspect_rls`, the phase 8
  enforcement fixes, the CI security job and the `docs/security/` set.
* **Uncommitted at the time of writing**, and therefore not part of `6125558`:
  the completion of the architecture synchronisation (§19 test totals, §26–§27
  and the §26.6 notes), the knowledge-base refresh (all 36 files carry a
  "refreshed in phase 11" banner pointing at `docs/security/`), a `jdlib`
  console script (`integrations/cli.py:main`, `[project.scripts]` in
  `pyproject.toml`, the test in `tests/unit/test_cli_security.py`, and the CI
  smoke test now running `jdlib security posture --json`), and small edits to
  `README.md` and `docs/operations/README.md`.

### Suite status at this revision

Verified on the development host (Windows, Docker), with the phase-11 documents
committed in `6125558` and the console-script and knowledge-base work in
`2bc22e3`:

* `pytest -q -W error` → **1,217 passed, 6 skipped** (71.48 s), with the local
  Kong/Cerbos/ZITADEL stack up and its `JDLIB_INFRA_*` variables exported; the
  six skips are the documented Tyk ones (§ Phase 4 above). The phase-9
  certification gate recorded 1,215 counted before the two console-script tests
  landed in the working tree.
* The same suite without those variables reports 1,192 passed, 31 skipped — the
  31 skips are Kong (9), Cerbos (12), ZITADEL (4) and Tyk (6), each naming the
  variable it wants.
* `tests/infra` selected on its own against the running stack: 29 passed,
  6 skipped (Tyk).
* The four security-compliance modules together
  (`test_compliance_controls.py`, `test_compliance_evidence.py`,
  `test_compliance_posture.py`, `tests/unit/test_cli_security.py`): 67 passed;
  `CONTROL_REGISTRY` holds 19 controls over 7 framework families, 15 of them
  `implemented`, 2 `partial`, 1 `not_implemented`, 1 `not_applicable`.
