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

---

## Consumer-driven fixes

Not hardening phases: defects found by consuming the library from outside it, in
the private reference application (`jdlib-reference-app`), where the evidence is
what a real caller observes rather than what JDLib's own tests assert. Each entry
names the commit that fixed it.

### A degraded authorization decision left the middleware as 403 — `c062a09`

* **Symptom.** A request whose authorization could not be decided — the policy
  engine unreachable, timing out, or answering unparsably — was answered
  `403 Forbidden` instead of `503 Service Unavailable`, although
  `AuthorizationPEP` raises `AuthorizationUnavailable`, that error's own
  descriptor is `SecurityDescriptor(SecurityCode.POLICY_UNAVAILABLE, 503,
  retryable=True)` (`security/errors.py`), and the operator-facing documentation
  said 503 (`docs/operations/README.md`).
* **Cause.** `tenancy/middleware._STATUS_MAP` resolves a failure by
  `isinstance` in list order and matched the generic `(AuthorizationError, 403)`
  first. `AuthorizationUnavailable` is an `AuthorizationError` and had no entry
  of its own, so its 503 never reached a caller passing through the middleware —
  the one path a real client takes.
* **Fix.** `(AuthorizationUnavailable, 503)` now precedes
  `(AuthorizationError, 403)`, with the ordering rule stated where the table is
  defined.
* **Why the library's tests missed it.** They cover the enforcement point (which
  raises the right error) and the error descriptors (which declare the right
  status) separately; nothing asserted the status the middleware derives for that
  class.
* **Now.** Two tests: the specific mapping, and a class-level test that every
  concrete error class maps to the status its own descriptor declares — all 28
  concrete classes agree at this revision, so the middleware's table and the
  descriptors cannot drift apart again without a failure naming the class that
  drifted. Mutation-checked: both fail with the entry removed.
* **Found by** the reference application's request-path suite, which asserts the
  status code a caller receives rather than the exception the library raises.
  `tests/unit -q -W error` → 859 passed at this revision.

### A principal with no roles was reported as an authorization outage — 1ccdf2c

* **Symptom.** A request whose principal carries no roles in the tenant came back
  as `503 Service Unavailable` — "the policy engine could not answer" — when the
  truth is a denial. Nothing grants permission to a principal with no roles, and
  the caller is not facing an unavailable decision.
* **Cause.** Cerbos rejects such a principal at the API boundary (400,
  `principal.roles: value is required`). `CerbosPDP.decide` sends the query, the
  transport reports the client error as a failure, and every failure becomes a
  *degraded* decision. A request the library should never have built was
  indistinguishable from an engine outage.
* **Fix.** `security/authz/cerbos.py` answers a role-less query locally: a denied,
  non-degraded decision with `reason="no_roles"`, and no call to the engine. The
  question is not asked because the engine will not answer it and no role-based
  policy can grant anything to a principal that carries no roles at all.
* **Now.** One test in `tests/unit/security/test_cerbos_pdp.py` asserting both the
  decision and that the transport was never called. Mutation-checked: fails with
  the guard removed (`if not query.roles:` → `if False:`). One existing test had
  to be corrected while doing this: `test_request_carries_a_request_id_when_the_query_has_one`
  built a query with no roles, so it was silently exercising the failure path —
  a query that can never reach the engine. It now carries a role, which is what
  that test always meant. `tests/unit -q -W error` → **860 passed** at this
  revision (859 before).
* **Found by** the reference application's request path, where a member with no
  role binding but an active membership reached the enforcement point and got a
  503 for what is a denial. The application refuses that case itself before
  asking, but the library was still misreporting it for every other consumer.

### The transactional audit sink dropped every event written through an async session — e1e2435

* **Symptom.** `TransactionAuditSink` — the sink the documentation tells consumers
  to use so that an audit row is written with the operation it describes —
  persisted nothing when the caller's session was JDLib's own async
  `TenantSession`. The operation succeeded, the trail stayed empty, and the only
  trace was a `RuntimeWarning: coroutine 'TenantSession.add' was never awaited`
  that a deployment not running under `-W error` never sees.
* **Cause.** `TenantAuditRecorder` is synchronous and stages rows with
  `self._session.add(row)`. On an async session that call returns a coroutine;
  discarding it means the row is never added. The `# type: ignore[attr-defined]`
  on that line kept the type checker from reporting the discarded awaitable, and
  the sync-only signature hid it from callers: `TransactionAuditSink.emit` is
  `async`, but it reached the recorder through a synchronous method.
* **Fix.** `models/audit_recorder.py` gains `arecord` and `arecord_security` for
  awaitable sessions, which await the session's `add`. The synchronous methods now
  *refuse* an awaitable session (`TypeError`) instead of silently dropping the
  row — an audit trail with silent holes is worse than an operation that refuses
  to run — and close the coroutine they abandon, so the refusal is the only signal
  raised. `security/audit/emitters.py` awaits the async entry point.
* **Now.** Two tests in `tests/unit/security/test_adversarial_audit_integrity.py`:
  one asserts the row is staged on an awaitable session, one asserts the sync path
  refuses rather than drops. Mutation-checked: removing the `await` in
  `arecord_security` fails the first. `tests/unit/security/test_adversarial_audit_integrity.py`
  + `tests/integration/test_audit_sinks.py` → 17 passed under `-W error`. Reported
  by the reference application, whose operator surface emitted a privileged
  `SECURITY_CONFIGURATION_CHANGED` event through this sink and watched the trail
  stay empty.

### An identity-provider outage was reported as a credential failure — 1cc27ea

* **Symptom.** With no usable key cached and the key set unreachable, every request
  that carried a token answered `401 no credentials presented`. A refused
  connection to the identity provider was indistinguishable from a bad credential,
  so an operator watching authentication failures saw an outage as user error.
* **Cause.** `JwksCache.signing_key` does its part — with no usable key material it
  re-raises the underlying refresh failure rather than pretending the `kid` was
  unknown, and its own tests pin that ("surface the real cause so callers can audit
  and alert on it"). One level up, `OidcAuthenticator.authenticate` caught every
  failure of the lookup in a blanket `except Exception`, recorded it, and returned
  `None`; the middleware reports `None` as `401`. The distinction the key set was
  built to preserve was discarded one line later, and no consumer could recover it.
* **Fix.** `AuthenticationUnavailable` (`errors.py`), raised by the authenticator
  when the key lookup fails, with the underlying cause chained. `_STATUS_MAP` lists
  it before `AuthenticationError` — an outage is `503` and retryable, a rejection is
  `401` — exactly as `AuthorizationUnavailable` precedes `AuthorizationError`. The
  error model gained the descriptor and code every public error is required to have
  (`AUTHENTICATION_UNAVAILABLE`, 503, retryable, classification `authentication`).
  The key set itself is untouched: stale-if-available, rate-limited retries and the
  surfaced cause all still hold, its tests unchanged.
* **Now.** `tests/unit/security/test_adversarial_authn_outage.py` (5 tests): the
  outage travels with its cause, an unknown key against a healthy key set is still
  `None` (`401` — the guard against over-blocking), a provider that answered is
  never reported unavailable, and the mapping order is pinned. Mutation-checked:
  restoring the swallow fails two of them. The existing fail-closed test in
  `test_oidc_authenticator.py` now asserts the outage instead of `None`; the
  security property it guards — nothing is authenticated when the key set cannot be
  read — is unchanged. `tests/unit -q -W error` → **867 passed** at this revision
  (862 before).
* **Docs.** `docs/security/authentication-hardening.md` corrected (it described an
  `InvalidToken` wrapping the code never performed) and `docs/security/error-responses.md`
  carries the new code.
* **Found by** the reference application asking what an unreachable identity
  provider should answer. The honest answer — `503` — was unreachable from any
  consumer, which is why the fix is here and not in the application.
