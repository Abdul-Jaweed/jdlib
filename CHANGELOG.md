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

### Audit identifiers were dropped when the writer ran on its own task — 790a615

* **Symptom.** A consumer that drains its control-plane trail from a worker task -
  the shape an audit writer wants, so a slow database cannot back-pressure a
  request - found every identifier column `NULL`, although the events it was
  writing carried the identifiers the request had bound. Measured on the reference
  application's lab: 5 of 5 rows with `NULL` request and correlation ids, no way to
  join a decision to the request that caused it.
* **Cause.** `DatabaseAuditSink.record` took the identifiers from the ambient tenant
  context only (`_trace_ids()`), and `PlatformAudit.record` had no parameter for
  them. A task created earlier has its own context - contextvars are copied at task
  creation, not shared - so the ambient lookup found nothing and the columns were
  written `NULL`. Binding a security context per request, which is what the
  reference application was doing when it found this, cannot fix a writer that runs
  outside the request.
* **Fix.** `PlatformAudit.record` and all of its implementations
  (`DatabaseAuditSink`, `NullPlatformAudit`, `RecordingPlatformAudit`,
  `CompositeAuditSink`, which forwards them) accept `request_id`, `correlation_id`
  and `trace_id`. Explicit values win over the ambient lookup; the ambient fallback
  is unchanged, so existing callers behave exactly as before and a caller with no
  context stores `NULL` rather than an invented identifier.
* **Now.** Two tests in `tests/unit/test_platform_audit_sinks.py`: the caller's
  identifiers win, and the ambient fallback still works. Mutation-checked: forcing
  the ambient lookup fails the first. One existing test corrected
  (`test_privilege_audit_adapter_delegates_to_platform_sink` asserts the whole
  recorded entry, which now carries the three fields). `tests/unit -q -W error` →
  **869 passed** at this revision (867 before).
* **Found by** the reference application wiring the security context, and finding
  that the binding alone changed nothing: identifiers must travel with the event.

### The envelope's fourth shape — a framework's own `HTTPException` — `27b8e63`, `42c26d0`

* **Symptom.** A route that raised `fastapi.HTTPException` (or Starlette's, from a
  dependency) answered the framework's default `{"detail": ...}` body while every
  other failure answered the documented four-key envelope — an application's own
  rejections, the ones it writes deliberately, were the ones that escaped it.
* **Cause.** The request edge installed handlers for `JdlibError` and
  `RequestValidationError` but never took over Starlette's default
  `HTTPException` handler, so that path bypassed the envelope entirely.
* **Fix.** `install_error_envelope` maps `HTTPException` by status, adds the
  RFC 6750 challenge to a 401, and never lets a 5xx echo its own text
  (`security/responses.py`, `integrations/fastapi.py`). `install` calls it, so a
  consumer that installed the library gets the canonical envelope without a
  second step.
* **Now.** `tests/integration/test_error_envelope_contract.py` pins the shape, the
  status mapping, the challenge and the 5xx rule, including the framework-handler
  edges.
* **Found by** the reference application asserting the envelope on a route that
  raises its own `HTTPException`.

### The policy engine recorded a request id the caller never sent — `3d0c26c`

* **Symptom.** Cerbos' own decision log carried a freshly minted `request_id`, so
  the engine's record of *why* a request was allowed was the one record that could
  not be joined to the gateway's log, the application's log or the audit trail.
* **Cause.** `CerbosPDP.decide` sent no `requestId` and no `traceparent`; the
  engine therefore generated its own.
* **Fix.** The caller's correlation id now travels as the request's `requestId`
  with a W3C `traceparent` beside it (`security/authz/cerbos.py`). A live
  experiment — not the documentation — established what Cerbos 0.54 records: it
  keeps `requestId` and none of the headers, and it *rejects* the `metadata` field
  an earlier attempt sent (`400`, `proto: unknown field "metadata"`).
* **Now.** `tests/unit/security/test_cerbos_pdp.py` asserts the id travels and pins
  the absence of `metadata`; the reference application's walkthrough asserts the
  engine's own log line.
* **Found by** the reference application trying to join one request across three
  systems.

### The statement that stores a request's evidence carried no request identity — `f6cc973`

* **Symptom.** PostgreSQL's own log showed the audit INSERT with no way to say
  which request it belonged to: the transaction that stores the evidence was
  anonymous at the database's own edge.
* **Cause.** `ControlPlaneSession.execute` had no way to set a session parameter,
  so the audit sink could not name its transaction.
* **Fix.** `ControlPlaneSession.execute(..., session_settings=...)` — an additive
  keyword — and the audit sink sets `application_name` per transaction via
  `set_config(..., true)` (`control/session.py`, `control/audit.py`).
* **Now.** The reference application's lab shows the same id on the `set_config`,
  the INSERT and the gateway's response: three independent records of one request.
* **Found by** the reference application asking what its own audit trail looks like
  from the database's side.

### A string in an identifier position was Cypher — `afd71d7`

* **Symptom.** None, until the graph plane's adversarial pass wrote the attack: the
  suite's first run failed 106 of 111 cases against a tree that every gate called green.
* **Cause.** The query builders annotated their identifiers as `Label`,
  `RelationshipType` and `PropertyKey`, and those types validate at construction — but
  an annotation enforces nothing. A plain string in that position was interpolated
  straight into the statement, so
  `node_match("User) DETACH DELETE n //", tenant=..., node_id=...)` produced
  `MATCH (n:User) DETACH DELETE n //) WHERE n.tenant_id = $jdlib_scope_tenant ...`:
  caller text as Cypher, the trailing comment swallowing the tenant predicate, and
  every tenant check passing because the parameters and the scope predicate were all
  present in the text.
* **Fix.** `_label` and `_relationship_type` check the type at each interpolated
  position, and all seven builders route their label, relationship type and both
  endpoint labels through them (`graph/query.py`).
* **Now.** Each identifier position is attacked with twelve hostile spellings (a
  backtick, a second label, a label expression, a variable-length marker, a property
  map, a trailing space, a newline, a NUL, a homoglyph, the wrong case, the empty
  string, a whole statement) in `tests/unit/test_graph_adversarial.py`.
* **Found by** the graph plane's own red-team slice, which exists because the same
  programme's earlier phases kept finding that a validated *type* is not a validated
  *call site*.

### A refusal was recorded without the actor who made it — `f174849`

* **Symptom.** The graph tenant refusal emitted its audit event with `principal_id`
  and `tenant_id` empty — a record of a refused cross-tenant statement that named
  nobody.
* **Cause.** The refusal helper ran before the call established the security context
  scope, and the event fills its actor from the ambient context by design.
* **Fix.** `run`, `begin` and the transaction's `run` establish the scope first, so
  anything written on that path is attributed to the caller (`graph/client.py`,
  `graph/transaction.py`).
* **Now.** A test asserts the refusal event's actor is the caller's principal, and
  that the event is written *before* the refusal is raised.
* **Found by** the graph plane's observability slice, which asked who a refusal
  belongs to rather than whether it was recorded.

### The MCP surface — a second entry point into the same chain (directive §18–§28)

* **What landed.** `jdlib.integrations.mcp`: a tool registry whose declarations cannot exist
  without naming a capability (or saying `public=True`), a security boundary that reuses the HTTP
  edge's own authentication, principal and tenant-resolution steps, an invocation chain
  (declared arguments → authorization → handler → audit) that runs inside both scopes, seven graph
  tools with no identity and no statement slot in any schema, read-only tenant/schema/health
  resources, a bounded concurrency gate added to `jdlib.reliability`, and a server factory behind
  a new optional `mcp` extra. Commits `6a9e631` … `9e59db3`.
* **Why it is a capability, not a wrapper.** Every step of the chain is a collaborator the HTTP
  surface already takes, handed to the same code — and a test asserts the reuse **by identity**
  (the chain sees the provider's own principal object) rather than by resemblance.
* **The rule the surface keeps.** A refusal is proven by non-execution: the handler's call count,
  not the exception's type. The adversarial slice runs that as a table over seven refusal paths.
* **Capability page:** `docs/jdlib/capabilities/mcp.md` — 8 modules, 16 exports, 7 refusals and 89
  test functions, all machine-checked against the tree.

### A tool's advertised schema was not the schema the library enforced — `819b6a8`

* **Symptom.** A probe of fastmcp 4.0.10 built a tool with an explicit `parameters` schema and
  called it with an argument the schema does not declare: the call reached the handler.
* **Cause.** FastMCP advertises a `Tool`'s `parameters` and does not validate arguments against it,
  so `additionalProperties: false` — the property the graph-tool declarations exist to state — was
  decoration on the wire.
* **Fix.** The invocation chain validates the arguments against the tool's own declaration before
  authorization and before anything runs, records the refusal as `MCP_ERROR` by class name, and
  raises `McpArgumentsRefusedError` (`integrations/mcp/invocation.py`).
* **Now.** An undeclared argument — including an injected `tenant_id` on every one of the seven
  tools — is refused with the handler's call count at zero.
* **Found by** the server-factory slice, by probing the library's own dependency instead of
  assuming the directive's "FastMCP validates tool schema" was already true.

### An unregistered resource URI crashed where the surface owes a refusal — `9e59db3`

* **Symptom.** Reading a resource whose URI nobody registered raised
  `AttributeError: 'NoneType' object has no attribute 'capability'`.
* **Cause.** The lookup was `self._resources.get(uri)` and the next line read an attribute off the
  answer, which is `None` for an unknown URI — a caller-supplied string reaching an attribute
  access rather than a refusal.
* **Fix.** A named lookup raises `McpResourceDefinitionError`, the same error the registry already
  raises for an unknown tool (`integrations/mcp/invocation.py`).
* **Now.** An unknown URI fails the same way an unknown tool name does, and the RED run that found
  it is the mutation evidence.
* **Found by** the MCP adversarial slice, which attacks the resource path rather than only the
  tool path.
### The example application — the minimal example (directive §18)

* **What landed.** `examples/minimal/`: a real FastAPI application that installs the library and
  serves one tenant-scoped route through `require(...)`. Two ASGI applications, deliberately — the
  ops routes answer `/healthz` and `/readyz` without credentials, and the tenant plane is mounted
  at `/api`, where nothing is reachable without a verified principal and a resolved tenant. It has
  no configuration of its own: the library's `JDLIB_*` contract is the whole surface, and the
  resolver order is the operator's (`build_chain`), not a hand-listed resolver.
* **Why it exists.** A library's claims are only as good as a consumer's first run: this one found
  two defects (below) before it served a single request, and its route walk is the check a reader
  copies — every route under the mount must declare a permission.
* **Evidence.** `examples/minimal/tests`: 11 tests over three files, including the operator step
  and the denial path against a real PostgreSQL (lab URL or a throwaway container, skipped with a
  reason when neither is available). The tests are part of the repository's own gate.

### A database that is down answered 500 over the async driver

* **Symptom.** Readiness against an unreachable database answered an unhandled 500 — and the same
  outage over `psycopg` answered 503 `DEPENDENCY_UNAVAILABLE`.
* **Cause.** The edge's descriptor table maps SQLAlchemy's connection-level errors
  (`OperationalError`, `InterfaceError`, `TimeoutError`), but a pool connect the database *refuses*
  arrives as the driver's own `ConnectionRefusedError` — an `OSError`, never wrapped — which is
  exactly the asyncpg path the library's consumers run on.
* **Fix.** One row, `ConnectionError`, in `integrations/fastapi.py`. A database that is down is now
  the 503 that invites a retry, whichever driver is installed; a statement the database *rejected*
  keeps the 500 that says it is a defect here.
* **Found by** the minimal example's readiness probe, whose first version passed for the wrong
  reason: it was asserting the psycopg error, not an unreachable database.

### A guard could not say what it enforced

* **Symptom.** An application walking its own routes could not tell a guarded route from an
  unguarded one: deleting `require(...)` from a route left the test green.
* **Cause.** `require(...)` returned a closure with no marker, and `get_context` — the context
  accessor — lives in the same module, so "the dependency came from `jdlib.integrations.fastapi`"
  was true of both.
* **Fix.** The returned callable carries `jdlib_permission`, the requirement it enforces. The
  example's walk asserts every tenant route declares one, and the mutation that previously escaped
  now fails it.
* **Found by** a mutation check of the example's own guard test — the RED that proved the test was
  decoration.

### The example application — the enterprise example (directive §18)

* **What landed.** `examples/enterprise/`: the layers a production application wires, each one a
  place a collaborator is plugged in rather than a mechanism the example implements — settings
  marked required/optional and secret/non-secret, the library's authenticator chain as the
  principal provider, the bridge between the Cerbos PDP and the route guard, an operator directory
  backed by the control plane's `platform_operators` record, the context factory, the container,
  the security-event sink, and two tenant routes that declare their permissions. Committed in
  `9359301`; its own entry lands here, one commit later, because that commit omitted it.
* **Why it exists.** The minimal example answers "what is the least I must do"; this one answers
  "what does the whole thing look like, and which part is whose job" — including the adapters a
  deployment must write itself.

### The example application — the tenant plane, against real PostgreSQL (directive §18)

* **What landed.** `examples/enterprise/`: `app/models/`, `app/repositories/`, `app/services/` (the
  tenant-routed tables and the service that owns them), `app/dataplane.py` (the per-tenant engines,
  the provisioning, the RLS installation and the privilege grant), `app/api/resources.py` (the
  resource routes, each declaring its permission), `app/asgi.py`, and `docker/initdb/` — the lab's
  **second role**, without which every policy would apply to nobody. `tests/test_tenant_plane_live.py`
  drives the service against a real database; `tests/test_bootstrap.py` covers the operator step
  without one.
* **Why it exists.** The layers above the API are where a tenant boundary is either real or
  decorative, and only a live database can say which: the session's predicate, the row-level policy
  and the composite foreign key are three separate controls, and a test that cannot tell them apart
  is measuring one of them by accident.
* **Evidence.** 11 live tests pass against the lab's PostgreSQL (`docker compose -f
  examples/enterprise/docker/docker-compose.yml up -d`); 5 unit tests for the operator step; the
  full example suite is 31 tests with both labs up. Mutations **3/3**: with the policy not installed
  (installer disabled *and* the policy dropped, since the installer is idempotent and the database
  keeps the previous run's policy) **9 of 11 fail**; with the composite foreign key dropped, exactly
  the database-level test fails (`DID NOT RAISE IntegrityError`) while the session-level one still
  passes; with the bootstrap's guard removed, its two refusal tests fail. With either DSN unset the
  live file skips with the bring-up command as the reason (11 skipped).
* **Found by** the live run: a **single superuser DSN cannot be the application role** — row-level
  security does not constrain a superuser, and the library refuses to install policies for a role
  that can bypass them (`StrategyCapabilityError`), so the example runs two roles and its lab creates
  the second one.
* **Found by** the mutation that did not bite: with row-level security disabled on the table, the
  suite stayed green — the service-level isolation test was measuring the *session's* predicate, not
  the policy. The policy now has its own test, on a statement the session never filtered, and both
  layers are named in the tests that measure them.
* **Found by** the first live caller of ordering: `TenantRepository.list`'s `order_by` annotation
  accepted no idiomatic SQLAlchemy argument (`ColumnElement` rejects an `InstrumentedAttribute`;
  `ColumnOperators` rejects `desc(...)`), so no caller in the library or in the reference
  application had ever ordered a page. The parameter is now `Any` with the reason recorded at the
  annotation, and the example's live test is the type-level proof the gate runs.
* **Found by** the operator step's own imports: `bootstrap` referenced the settings class and the RLS
  installer without importing either, and nothing called the function — a `NameError` that would have
  surfaced in an operator's hands. Its new test calls the entry point, which is what exercises them.
* **Found by** the lab's own init script: it is executed by the container's shell as it sits on disk,
  and a CRLF shebang is `/bin/bash\r`, which the kernel reports as "required file not found". Git's
  autocrlf would hand every Windows checkout CRLF, so `.gitattributes` now pins `*.sh` to LF.

### The example application — the authorization slice, verified against a live engine (directive §18)

* **What landed.** `examples/enterprise/config/cerbos/policies/`: the policy set the bridge's
  mapping is written against (`scope` / `tenant` / the permission strings the routes declare), plus
  `tenant_scope_test.yaml` — 21 assertions executed by the engine's own compiler. `docker/` brings
  up the lab (PostgreSQL and Cerbos on their own ports). `tests/test_authorization.py` pins the
  mapping without an engine (5 tests); `tests/test_authorization_live.py` has the engine answer the
  query the bridge builds over the wire (4 tests: allow, deny, the administrator's lifecycle
  actions, and an administrator of another tenant denied).
* **Why it exists.** A policy that has never been compiled is a claim, and a mapping that has never
  been sent is a guess: the two halves are verified separately, and the live half is what makes the
  cross-tenant rule a control rather than an intention.
* **Evidence.** `cerbos compile` → 21 tests executed, 21 OK. Live: 4 passed against
  `ghcr.io/cerbos/cerbos:0.54.0`; mutations 2/2 (the policy stops comparing tenants → the
  cross-tenant test fails; the resource stops carrying its tenant → the allow tests fail). With the
  endpoint unset the live file skips with its bring-up command as the reason.
* **Found by** the lab: the image's entrypoint *is* the binary at `/cerbos`, so mounting the policy
  directory there fails with `not a directory` before the container starts — mount it anywhere else.
* **Found by** the live run's first shape: `HttpCerbosTransport(timeout=…)` takes a `timedelta`, and
  a float fails only when the request is made, where the adapter reports it as a *degraded* decision
  — every case answered DENY/degraded, which reads like a policy denial and is an outage.

### The example application — the graph plane, against real Neo4j (directive §18)

* **What landed.** `examples/enterprise/app/graph.py`: the tenant-bound graph plane (a client per
  tenant, opened *for* that tenant), the declared `VOCABULARY`, the projection as an upsert inside one
  transaction, and `ensure_graph_constraints` — the schema declaration, which `bootstrap` runs the way
  it runs the migration. The example's lab gains its own Neo4j (`docker/docker-compose.yml`, bolt on
  7688), and `tests/test_graph_live.py` drives all of it against the server: 7 live tests.
* **Why it exists.** The relational plane is the record and the graph is derived from it. Two controls
  make the derivation safe — the client's tenant binding and the closed vocabulary — and neither is
  visible without a server: a scope that is a parameter and a scope that is enforced look identical in
  a unit test.
* **Evidence.** 7 live tests pass against the example's own Neo4j (`docker compose -f
  examples/enterprise/docker/docker-compose.yml up -d neo4j`): read-back over a *fresh client* (the
  positive path), the upsert, the node invisible to the other tenant, the client refusing another
  tenant's well-formed statement, an undeclared label refused before any statement, the projection
  carrying the row's own id, and the identity constraint (a duplicate create is a conflict; the same id
  in another tenant is not). Mutations **2/2**: with the upsert turned into a create, exactly the upsert
  test fails; with `Invoice` added to the vocabulary, exactly the undeclared-label test fails.
* **Found by** the mutation that bit *at the database and not at the code*: with the upsert turned into
  a create, the create **succeeded** — the lab carried no identity constraint, so "project twice" was a
  second node and the projection's idempotence held only because nothing else wrote at the same moment.
  `ensure_graph_constraints` declares `(tenant_id, id)` unique per label, and the operator step refuses
  over data that violates it, naming the offending nodes.
* **Found by** one secret with two names: the application resolved `JDLIB_EXAMPLE_GRAPH_PASSWORD` while
  the lab's compose file initialised the server from `JDLIB_ENTERPRISE_GRAPH_PASSWORD`, so the first
  live run failed with `CredentialUnavailableError` on a password that was exported. The handle is now
  `graph-password` under the `JDLIB_ENTERPRISE_` prefix — one variable, one rotation.
* **Found by** running the suite the way the README documents it: with the owner's DSN exported, the
  operator step's three tests failed — they assert a process that serves without it, and the fixture
  only *set* variables, so the shell decided the premise. The fixture now removes the variable
  (`monkeypatch.delenv`), because a test whose premise the environment can supply is not measuring the
  code — and it had passed before only because every earlier run of this file happened to be on a bare
  environment.

### The example application — the MCP surface, over the same chain (directive §18)

* **What landed.** `examples/enterprise/app/mcp/`: `tools.py` (three declarations — `resource_get`,
  `resource_list`, `resource_archive` — each carrying the capability the HTTP routes declare and a
  closed schema with no slot for an identity or a statement), `server.py` (the registry, the
  library's `McpSecurityBoundary` built from the *HTTP path's own collaborators*, the per-tenant
  graph runner, the library's async-sink emitter) and `asgi.py`
  (`python -m examples.enterprise.app.mcp.asgi`). `main.py` gained `Collaborators` and
  `build_collaborators` so both surfaces are one composition, and `dataplane.py` gained
  `grant_control_privileges`. Tests: `tests/test_mcp_surface.py` (8, no lab) and
  `tests/test_mcp_live.py` (6, against the lab).
* **Why it exists.** A second surface is where a security model is either reused or quietly
  re-implemented. Every collaborator here is the object `create_app` built — asserted by *identity*,
  not by shape — so the chain that authenticates an HTTP request authenticates a tool call.
* **Evidence.** 8 unit tests (the inventory, the capabilities, the closed schemas, the identity of
  the collaborators, and the enforcer's tenant source). 6 live tests through the whole chain: a
  bearer API key minted in the test and hashed into the control plane is authenticated by the
  library's own authenticator, the tenant is resolved, the context factory's checks run, the
  capability is put to the **live policy engine**, and only then does the handler reach the service
  and PostgreSQL — plus `graph_get` through the surface to the real Neo4j. The denial is measured at
  the data (the row is still `active`), the refusal's *reason* is asserted (`authorization denied`,
  not merely "some `ToolError`"), and a forged key is refused as the negative control. Mutations
  **2/2**: with the archive tool declaring the read capability, the denial test and the capability
  test fail; with the enforcer reading a context the MCP invocation does not bind, the MCP-shape test
  fails.
* **Found by** the first live call: **the runtime role could not reach the control plane at all.**
  The operator step granted privileges inside the tenant schema and nowhere else, so a serving
  process failed its first request with `permission denied for schema jd_control` — it authenticates,
  resolves a tenant, reads roles and writes the audit trail, and every one of those is a control-plane
  row. `grant_control_privileges` now grants exactly what the request path reads and appends:
  `SELECT`, `INSERT` on the audit trail, and — measured rather than guessed — `UPDATE` on the key's
  own `last_used_at`, which the authenticator writes and whose refusal the library reports as "no
  credentials presented", an authentication failure wearing a denial's clothes.
* **Found by** the live authorization answer: **the MCP chain asks about the tenant scope.** A tool
  declares a capability and the invocation puts it to the engine with the caller's *tenant* as the
  target — a tool call has no resource id to be asked about before it runs — so a policy set written
  only against route targets answered `no_allow` for every tool. The scope policy now carries the
  capabilities (`resource:read`, `graph:read`, `resource:write`, `graph:write`), the engine's own
  tests grew to **44** (from 29), and the tenant comparison is the same one the route rules use.
* **Corrected** a suspicion this slice started with: the MCP boundary was assumed to bind only a
  security context, which would have made the enforcer's `current_tenant()` read fail closed on every
  MCP call, and the enforcer was changed for it. A probe through the live path showed the invocation
  binds **both** scopes (`jdlib/integrations/mcp/invocation.py`), so the change was reverted and the
  probe kept as a test: a claim about which context is bound is measured here, not read off the
  source and trusted.

### The example application — the four test layers (directive §18)

* **What landed.** `examples/enterprise/tests/` is now the directive's four layers: `unit/` (24),
  `integration/` (29), `security/` (16) and `e2e/` (8), with `tests/support/` as the harness they
  share — the lab's environment, the provisioning (tenants, callers, roles, and API keys that are
  really in the control plane), and a chain that builds the application's own composition with an
  HTTP client and a tool caller over it. The two earlier live files gave up their duplicated helpers
  to it (`wait_for_database`, `mint_key`).
* **The security layer** asks three questions the earlier layers did not: can a caller reach another
  tenant's data **by any path**, does a denial execute nothing, and does any failure leak an
  internal. Isolation is asked over **both surfaces** with credentials that really are in the control
  plane and with both callers holding the *same* role, so every difference is a difference the
  tenant made; the denial is measured three ways (the answer, the row read as the *owner*, and the
  audit trail); the error surface is probed with the requests an attacker sends first — no
  credential, a malformed one, an unknown route inside and outside the mount, a malformed body, an
  absent row, another tenant's row — and every answer is checked against a deny-list of internals
  (drivers, schemas, module paths, DSNs, SQL, stack-trace shapes).
* **The e2e layer** runs the documented command — `uvicorn examples.enterprise.app.asgi:app` — as a
  subprocess and drives it over TCP: the liveness probe without credentials, the readiness probe
  asking the real dependencies, an allowed request through the whole chain, a denial, a 401, a
  cross-tenant read, a refusal to start without its environment, and a `SIGTERM` stop asserted to
  exit 0.
* **Evidence.** 77 tests in the example (76 passed, 1 skipped) with the lab up; the whole example
  suite green in the repository gate. Mutations **2/2**: with the archive route declaring the weaker
  permission, the denial test fails *and shows the write happening* (the row becomes `archived`);
  with the outer error envelope removed, the unknown-route probe answers `{"detail": "Not Found"}`.
* **Found by writing them**, and each corrected rather than asserted around:
  * the library answers an unreachable row **`409 INVALID_REFERENCE`** ("does not exist in this
    tenant"), not 404 — the example deliberately does not re-map it, and the test now asserts the
    library's own answer and the part that matters (the message names the caller's id and nothing
    about whether the row exists elsewhere);
  * a **denied MCP call writes three audit events** where HTTP writes one — the boundary's
    `mcp.request`, the engine's decision, and the chain's own refusal — so the trail evidence is
    per-surface rather than one shape imposed on both;
  * a failure **inside** a tool handler is answered generically ("the tool could not complete")
    while a *schema* refusal is precise ("does not declare: extra"): the library cannot know which
    part of a driver's exception is safe to repeat, and a malformed uuid reaching the service is
    that case;
  * the audit events name the target the **question** was about — the tenant scope — not the row the
    handler would have touched, so "which event did this call produce" is answered by a before/after
    delta and not by a filter on an id that is never in the row;
  * a harness that **invented** a tenant slug passed every assertion that compared it with itself and
    failed the one that compared it with the application's answer; the fixture now carries the slug
    the registry created;
  * Windows has no `SIGTERM` — `Popen.send_signal` terminates the process — so the graceful-shutdown
    assertion is POSIX-only and **says so** in the test, rather than asserting something weaker
    everywhere and calling it the same thing.

### The example application — the feature guides (directive §18, E5)

* **What landed.** `docs/jdlib/features/`: **14 guides**, one per feature a developer consumes —
  authentication, authorization, tenancy, resource-management, query-system, credentials, caching,
  storage, connectors, graph, mcp, jobs, audit, observability — each carrying the directive's
  template (what / why / when / when not / how / architecture / example / security / reliability /
  observability / audit / configuration / testing / common mistakes / production checklist), each
  linking to its **design authority** page and saying so, and each with machine-read front-matter
  (`guide`, `authority`, `modules`, `exports`, `example`, `test_files`).
* **Every citation is verified before it lands.** The front-matter is generated against the working
  tree and asserted: every module path exists, every exported symbol resolves in the modules the
  guide names, every test file exists, and every authority page is real. The first attempt cited 17
  paths and symbols that did not exist (a test in `tests/unit/` that lives in `tests/integration/`,
  `CerbosPDP` in a module that does not define it, and so on) — the check caught all of them before
  a single file was written, which is the difference between a guide that is true and one that reads
  as if it were.
* **Where the fourteen come from, recorded rather than implied.** The directive names the set; this
  list is the library's own surfaces, because a guide for a feature the library does not have is the
  failure this programme exists to remove. Where the example application does not use a feature —
  **background jobs** — the guide says so in its own Example section instead of inventing one, and
  points at the library's suites as the evidence. Privileged access and the error envelope are
  cross-cutting and are documented where they live (the authorization guide and every guide's
  security section respectively), with the README naming both.
* **The index** (`docs/jdlib/features/README.md`) states the rule the set rests on: these guides are
  not the design authority, they link to it, and where the two disagree the authority page and the
  code win. It also names the test that will keep them honest (`tests/unit/test_example_docs.py`,
  E7) — the same treatment the capability pages already get.

### The example application — architecture pages and example documentation (directive §18, E6)

* **What landed.** `docs/jdlib/architecture/` (**6 pages**): `example-architecture` (the layers and
  what each may decide, one composition over two surfaces), `security-flow` (the request, step by
  step, over HTTP *and* MCP), `tenant-flow` (provisioning, placement, and the binding end to end),
  `neo4j-flow` (why the graph is derived, and what follows), `mcp-flow` (the chain, and why the
  authorization question is about the tenant scope), `observability-flow` (the ids, the allow-list,
  and degrading rather than failing). `docs/jdlib/examples/` (**5 pages**): `overview`,
  `minimal-example`, `enterprise-example`, `with-and-without`, `developer-journey`.
* **`with-and-without`** is the §25 comparison, and it obeys the directive's constraint: the
  "without" snippets are marked **illustrative, not runnable** in the first line of every block, and
  a test asserts that — unmarked illustrative code is indistinguishable from recommended code. Each
  "with JDLib" cell names the seam that does the work.
* **The example's findings are recorded where a reader meets them**: the enterprise page lists the
  runtime-role grant, the MCP tenant-scope policy gap, the `409 INVALID_REFERENCE` mapping, the
  three-event MCP denial, and the suspicion that was disproved.

### The example application — the documentation is checked, and the matrices are generated (E7)

* **`tests/unit/test_example_docs.py`** (115 checks): the guide set is exactly the fourteen named;
  every guide carries every template heading; every guide names its design authority and links it;
  every cited module, export, test file and example path resolves; every path cited in the
  architecture and example pages exists (resolved against the repository root **or** the example it
  documents, a rule stated in the test); and the with-and-without snippets are marked.
* **It found real problems immediately**: the first run failed on five pages citing paths relative
  to `examples/enterprise/` (`tests/security/…`) that the test was resolving against the repository
  root — which is how the two-root rule came to be written down instead of assumed.
* **`scripts/feature-matrix.py` generates both matrices** — `docs/jdlib/examples/feature-matrix.md`
  (69 rows: the seam's definition site, the first use in `examples/`, the test function that names
  it) and `coverage-matrix.md` (the layers, their files, their test-function counts, what each needs
  and what it answers). Line numbers are read from the tree, not typed.
* **The gate keeps them generated**: `scripts/ci-local.sh` runs the generator with `--check` and
  fails when a page would change — because a hand-written table of line numbers is wrong the first
  time someone edits the file above it. Line endings are normalised in the comparison, so the check
  means the same thing on Windows and on the runner.
* **A cell says exactly what was measured**: *library-only* (the guide declares no example path — the
  example does not use the feature at all) versus *not named directly* (the example uses the feature
  through another seam, so this symbol never appears under `examples/`). Conflating the two would
  have been the easy lie.

### The example application — the security review, the report, and the phase closes (directive §18, E8)

* **The security review** (`docs/jdlib/examples/security-review.md`): nine sections — identity,
  authorization, tenancy, the graph plane, the error surface, the audit trail, operational, build
  and supply chain, and **what the review does not claim**. Every row names the control, the
  evidence (a test at its line, or a command) and what it showed. The last section is not decoration:
  no penetration test, no coverage-guided fuzzing, one database vendor, a lab that is not hardened,
  and the Windows `SIGTERM` skip recorded as a skip.
* **The report** (`docs/jdlib/successor/06-example-report.md`): what landed per slice with its
  commit, the **nine findings** that came from running the example rather than describing it, what
  was verified, and what remains open. The findings include the two library defects the minimal
  example found, the CI extras gap, and **a suspicion a live probe disproved** — recorded because a
  review that lists only confirmations is not a review.
* **The review's own citations are checked.** Three rows cited a file without a line, which made them
  the only claims in the page a reader had to take on trust; they now carry the test and its line,
  and a check asserts that every `file:line` cell in the review lands on a test function. Writing it
  found a real error: the database row claimed an unscoped statement "returns nothing", while the
  test asserts it is **refused** — the stronger claim, and the one the test makes.
* **The phase is closed**: the roadmap's §18 slice table carries E1–E8 and the status line records
  the whole phase with its commits. The example composes §16's graph plane and §17's MCP surface over
  §4–§12's mechanisms, and the documentation that describes it is checked by the same suite that
  describes it — 201 checks in `tests/unit/test_example_docs.py`, the matrices regenerated and
  compared by both `scripts/ci-local.sh` and the runner, and the full local gate green
  (**2226 passed, 39 skipped**, clean-venv install and console-script smoke included).

### The documentation portal — the site builds, and the audit says what is missing (documentation directive §2–§5)

Commit: `4a82eca` (`docs(portal): the site builds, and the audit says what is missing`)

* **The site exists.** `mkdocs.yml` puts MkDocs Material over the existing `docs/` tree: search,
  Mermaid through `pymdownx.superfences`, admonitions, tabbed code and permalinked headings, with
  `validation` configured so a broken link, a missing page, an unlisted page or a missing anchor is
  a warning — and `mkdocs build --strict` turns every one of them into a failure.
* **`docs/index.md`** is the portal's home: what the library is, the reading paths for five
  audiences, and the request path as a Mermaid diagram that follows the real chain.
* **`docs/getting-started/`** — six pages: introduction, installation, quickstart, your first
  application, configuration, project structure. The configuration table is `TenancyConfig` read at
  this commit, the commands are the ones the repository runs, and the example commands match
  `examples/minimal/README.md` rather than paraphrasing it.
* **The long-form reference is published with its status.** `JDLib-Architecture.md` moved to
  `docs/architecture/long-form-reference.md` under a banner that states the revision it describes
  (`6125558`) and which phase documents supersede it for the packages that arrived afterwards.
* **The audit is generated.** `scripts/docs-inventory.py` writes
  `docs/development/documentation-inventory.md` from the tree: **34 namespaces**, every package under
  `src/jdlib` — including the seven that declare no `__all__` and whose surface is per-module
  (`jdlib.tenancy`, `jdlib.persistence`, `jdlib.authn`, `jdlib.authz`, `jdlib.migrations`,
  `jdlib.integrations`, `jdlib.persistence.strategies`) — each with its public surface, its
  classification, the pages that document it and the number of test files that hold it.
  Namespaces documented under a page named after the capability rather than the package are mapped
  by an alias table, because a false gap sends someone to write a page that already exists.
* **The judgement rows are judgements.** EXPERIMENTAL, DEPRECATED, IMPLEMENTED BUT INTERNAL and
  NOT IMPLEMENTED cannot be inferred from a grep, so they are recorded with their reason and a
  citation that `tests/unit/test_docs_portal.py` checks against the tree. The three real gaps the
  audit reports — `jdlib.reliability`, `jdlib.testing` and the sections that do not exist yet — are
  the portal's remaining work, not an omission nobody noticed.
* **`tests/unit/test_docs_portal.py`** — 275 checks: every navigation entry resolves, every
  published page is reachable from the navigation, every relative link resolves to a file that
  exists, every Mermaid fence names a diagram type the renderer draws, every page has a title and a
  body, and the inventory is regenerated rather than edited.
* **Both gates carry the site.** `mkdocs build --strict` and `scripts/docs-inventory.py --check` are
  steps in `scripts/ci-local.sh` and in `.github/workflows/ci.yml`; the `docs` extra carries
  `mkdocs-material`, and the gate fails with the install command when it is missing rather than
  skipping the build.
* **Nineteen real warnings were fixed to reach a strict build**, none of them by widening the
  configuration: files that live outside `docs_dir` (`SECURITY.md`, `CONTRIBUTING.md`, `README.md`,
  `tests/infra/README.md` and the two example directories) are linked by URL, four links written
  from the repository root became docs-relative, two directory links became links to the file they
  resolve to, and the long-form reference's own table-of-contents anchor carried a double hyphen
  where the real slug collapses it.

### The documentation portal — the architecture and integration sections (documentation directive §6–§8)

Commit: `c9a0e4c` (`docs(portal): the architecture and the edges, in eighteen pages`)

* **`docs/architecture/`** — eight pages over the existing flow pages: an overview that states the
  four planes and the dependency rule, a high-level view (the request path, the stores, the operator
  path) as a Mermaid flowchart, a component view that names every module in every package, a request
  lifecycle with two sequence diagrams (HTTP and MCP) and the steps that *stop*, and four
  plane-specific pages: data (control / placement / tenant / derived), security (the trust
  boundaries and the enforcement points), reliability (the failure domains and the primitives) and
  observability (the signals and the allow-list).
* **`docs/integrations/`** — ten pages for the edges and the stores: FastAPI, MCP, the CLI, the pytest
  kit, PostgreSQL, Neo4j, Redis, S3 and Cerbos, plus an overview that states the rule every
  integration follows (it composes, it does not decide).
* **The CLI page documents the surface that exists**, not the part of it the README mentions:
  `tenant create|provision|list`, `db upgrade-control|upgrade-tenants`, `rls install|verify` and
  `schema lint`, each with the command's own docstring behind the description.
* **The claims are grounded.** The configuration table is `TenancyConfig` at this commit, the module
  lists are the tree, the CLI table is the Typer commands, and the class names
  (`PostgresConnector`, `S3ObjectStorage`, `RedisCache`, `CerbosPDP`, `Neo4jClient`, `GraphRepository`,
  `RetryBudget`, `ConcurrencyGate`, `ShutdownCoordinator`, `SecurityMetrics`, `SecuritySpan`) are the
  names in the source.
* **`tests/unit/test_docs_portal.py` is now 329 checks**, and `mkdocs build --strict` passes with zero
  warnings over the enlarged tree — the navigation, the links, the Mermaid fence types and the
  regenerated inventory all hold.

### The documentation portal — guides, operations, reference, and the generated API (documentation directive §9–§26)

Commit: `699cc56` (`docs(portal): the guides, the operational pages, and the reference the source writes`)

* **`docs/guides/`** — ten task-shaped walkthroughs (add a tenant-scoped table, an endpoint, a
  permission, a resource type, an MCP tool, a connector, a cache, a migration; test your
  integration). Each shows the change **and the test that proves it**, and each ends with a
  symptom-to-cause table, because in this library a change without a test is a claim rather than a
  control.
* **`docs/reliability/`** — timeouts and deadlines, retries and budgets, circuit breakers, rate
  limiting versus admission, shutdown and draining, and a failure-modes table that says what each
  dependency being down looks like from outside.
* **`docs/observability/`** — logging, metrics, tracing and audit events, each with the rule that
  makes it safe: the redaction floor, the bounded-label rule, the span allow-list, and the audit
  vocabulary that records decisions rather than traffic.
* **`docs/operations/`** — deployment, health and readiness, troubleshooting (an eighteen-row
  symptom table), incident response, and a production checklist whose every line names its evidence.
* **`docs/development/`** — testing (the layers, the gate, the generated pages) and the architecture
  decisions (ten decisions with their reasoning and where each is recorded).
* **`docs/reference/`** — the configuration reference (every field, its default and its effect, read
  from `TenancyConfig`), the error codes, the CLI reference, the extension points, and the **public
  API reference, generated** by `scripts/api-reference.py` from the source: 24 namespaces, 257
  exported names, their signatures and their own docstrings. `--check` runs in both gates, and two
  unit tests fail when the page is stale or a namespace is missing from it.
* **Two rules the generator learned the hard way, and keeps**: `inspect.getdoc` walks the MRO, so a
  class with no docstring of its own was credited with its base's — the reference reads `__doc__`
  now; and the namespace walk is rooted at `src/jdlib`, not `src`, which is the difference between a
  reference of the surface and a reference of one package named `jdlib.jdlib`.
* **`tests/unit/test_docs_portal.py` is now 433 checks**, and the strict build passes with zero
  warnings over 49 pages of new material.

### The documentation portal, closed: the matrix, the review, and the report (documentation directive §34–§40)

Commit: `8af98b0` (`docs(portal): the matrix, the review, and the report`)

* **`docs/development/documentation-test-matrix.md`** - the directive's section 36 table, but
  **generated**: `scripts/docs-matrix.py` earns each tick from the tree (the page exists and the
  navigation reaches it; a file under `examples/` names a marker the area owns; the area's page
  carries a Mermaid diagram; a test file names the namespace and the documentation test runs) and
  prints `-` where there is no evidence. 14 areas, 55 of 56 cells earned; the empty one is
  `Observability`'s test column, and the page says why (no test names `jdlib.observability`; the
  signals are covered through `jdlib.security.telemetry` and `jdlib.security.tracing`).
* **`docs/development/portal-validation.md`** - what validates the portal, what it has caught, and
  what it deliberately does not check. Four defects it caught in the portal itself are recorded
  there: `inspect.getdoc` crediting a class with its base's docstring, a namespace walk rooted one
  directory too high, a line-splitting helper that dropped a space at every chunk boundary, and a
  generated page that listed files in filesystem order - which is why it passed on Windows and
  failed in CI, and why both generators now name the first differing line instead of only the fact.
* **`docs/development/portal-review.md`** - the directive's section 38 review from four chairs
  (developer, architect, security engineer, operations engineer), each question answered with the
  page that answers it, and what the review changed: the deployment topology and the MCP invocation
  chain now have diagrams, and the failure-mode table says what a *degraded* policy engine means.
* **`docs/jdlib/successor/07-portal-report.md`** - the closing report: the deliverables, the
  directive's forty-four success criteria each against its evidence, and what remains open.
* **The navigation now follows the directive's reading order** (Getting Started, Concepts,
  Architecture, Features, Capabilities, Integrations, Guides, Examples, Security, Reliability,
  Observability, Operations, Reference, Development, Programme), and `README.md` points at the
  portal, says how to build it, and marks `knowledge_base/` as an archived snapshot.
* **`scripts/docs-matrix.py --check` runs in both gates**, and the Mermaid check now also fails on
  an unclosed or empty fence rather than only on an unknown diagram type.

### The last empty cell, the diagram bodies, and the live labs (documentation directive §34–§40, closed)

Commit: `6696430` (`docs(portal): the matrix's last cell, and the checks behind it`)

* **The matrix's empty cell was a wrong namespace, not a missing test.** `Observability`'s row named
  `jdlib.observability`, a module that has never existed in this tree; that held the validated column
  empty and hid the test that does assert the span allow-list. The area's real surface is
  `jdlib.security.tracing` (with `jdlib.security.telemetry` and `reliability/` beside it), which
  `tests/unit/test_boundary_spans.py` imports and asserts `FORBIDDEN_SPAN_ATTRIBUTES` against, and
  which `tests/infra/test_otel_infra.py` exercises against a live collector. The row is corrected,
  the page's front-matter now lists the test that asserts its own security claim, and the matrix
  reads **14 areas, 56 of 56 cells earned** — no dash, no note explaining a dash.
* **Mermaid bodies are now checked, not only their fences.** A second documentation test fails on
  the two mistakes that survive review because the fence and the first line look right: a sequence
  keyword (`participant`, `actor`) in a flowchart or a `subgraph` in a sequence diagram, and a
  `subgraph` that is never closed. It is a structural check, not a parser, and
  `docs/development/portal-validation.md` says exactly that.
* **The infrastructure layer runs live: 44 tests, no skips.** `docker compose -f
  tests/infra/docker-compose.yml up -d cerbos neo4j otel-collector zitadel`, then the runbook's
  environment (`tests/infra/README.md`). The ZITADEL service advertises `localhost` as its
  ExternalDomain, so `JDLIB_INFRA_ZITADEL_ISSUER=http://localhost:8080` — pointing the suite at a
  ZITADEL that advertises something else fails two of the four tests, correctly, because the
  discovery document and the derived endpoints disagree.
* **The whole suite against every lab at once: 2704 passed, 8 skipped.** The remaining skips are by
  design: the e2e shutdown assertion that only runs on POSIX (Windows has no `SIGTERM`, so the exit
  status says nothing about the shutdown path) and the no-op front-matter parametrisations. The
  service-driven skips are gone because the services are up.
* **One flake recorded rather than hidden.** That all-live run failed once (of nine) on an unraisable
  `ResourceWarning` — an asyncpg connection to the example database collected while still open, which
  the gate's `-W error` turns into a failure. It has not reproduced since: not in three further
  all-live gates, not in a forced `gc.collect()` at session end over the example, infra, integration
  and e2e layers separately or together. The asyncio-debug traceback is the next step if it returns,
  and `docs/jdlib/successor/07-portal-report.md` records it in those words.

