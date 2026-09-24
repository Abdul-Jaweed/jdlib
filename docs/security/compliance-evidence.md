# Compliance Control + Evidence System (Phase 9)

Status: **COMPLETE** — §9.1 to §9.5 are implemented and verified: the control
register, the evidence record and its collectors (checkout-side and
session-backed), the posture layer, and the CLI. Nothing below is claimed on
behalf of an auditor, and the register's own gaps are in the register.

Source: `src/jdlib/security/compliance/controls.py`,
`src/jdlib/security/compliance/evidence.py`,
`src/jdlib/security/compliance/posture.py`,
`src/jdlib/security/compliance/session.py` and
`src/jdlib/security/compliance/__init__.py` (the namespace is new in this phase);
`src/jdlib/persistence/strategies/rls.py` gained the shared catalog inspection
and `src/jdlib/integrations/cli.py` the `security` sub-app.

Tests: `tests/unit/security/test_compliance_controls.py` (9),
`tests/unit/security/test_compliance_evidence.py` (12),
`tests/unit/security/test_compliance_posture.py` (31),
`tests/unit/test_cli_security.py` (13),
`tests/integration/test_compliance_live_collectors.py` (6, real PostgreSQL)

---

## 1. Control registry (§9.1)

`CONTROL_REGISTRY` holds the controls this library actually implements, each
mapped onto the frameworks the directive names: SOC 2 Trust Services Criteria,
ISO/IEC 27001 (2022 Annex A), NIST CSF 2.0, NIST SP 800-53 Rev. 5, OWASP ASVS,
OWASP API Security Top 10 and CIS Controls v8 — all seven are in use, and a test
asserts each one has at least one control mapped onto it.

The registry lives in a **new submodule** (`jdlib.security.compliance`) rather
than in `jdlib.security`: the core's public surface is pinned by an
exact-equality test, so this is additive by construction and nothing existing
moves.

**A mapping is a description, not a certification.** Each `ControlMapping` names
the framework and its own reference (`CC6.1`, `A.8.5`, `IA-5`, `API1:2023`, …).
The registry never states an audit result, and the package docstring says so:
the directive's "do not claim certification" is enforced by what the model can
express, not by a note in a README.

## 2. Control model (§9.2)

`Control` carries the fields the directive lists — `control_id`, `title`,
`description`, `category`, `implementation_status`, `evidence_requirements`,
`technical_owner`, `verification_method` — plus what makes the register usable
rather than decorative:

| Field | Why it exists |
|---|---|
| `mappings` | one control, several frameworks; a per-framework `reference` on each |
| `evidence_sources` | the reproducible artefact behind the claim: a test file, a document, a live harness |
| `status_note` | the reason a control is not fully implemented, or why it does not apply |
| `category` | a `ControlCategory`, so posture can be grouped by concern |
| `verification_method` | `TEST` / `INSPECTION` / `ANALYSIS` / `RUNTIME` / `EXTERNAL` — how the claim is shown to be true |

The vocabularies are deliberately distinct from the posture result
(`PASS`/`WARN`/`FAIL`/`NOT_APPLICABLE`, §9.4): a status is a standing property of a
control, a posture result is what today's check said.

Four invariants are enforced by tests because each of them decays silently:

* control ids are unique and shaped (`JDL-…`),
* every control has a description, an owner, at least one mapping, at least one
  evidence requirement, and a reference on every mapping,
* **no silent partials** — `PARTIAL`, `NOT_IMPLEMENTED` and `NOT_APPLICABLE` each
  require a substantive `status_note`;
* **every cited evidence source exists on disk**, so a rename or a delete cannot
  leave the register pointing at something that is gone.

The register records nineteen controls: fifteen `IMPLEMENTED`, two `PARTIAL`
(Tyk plugin verification — engine limitation; pipeline security — Phase 10
verifies those gates), one `NOT_IMPLEMENTED` with its reason (tamper-evident
audit storage, which is deliberately outside this library, per
`audit-hardening.md` §7) and one `NOT_APPLICABLE` (bearer-token replay, which a
stateless validator cannot address). A test requires at least three recorded gaps
so the register cannot quietly become a wish list.

**Mutation check.** Making the register dishonest — deleting one `status_note`
and pointing one `evidence_sources` entry at a file that does not exist — fails
2 of the 9 tests (`test_a_recorded_gap_must_explain_itself`,
`test_every_cited_evidence_source_exists`). A register test that cannot fail would
be decoration.

## 3. Evidence collection (§9.3)

`SecurityEvidence` carries the directive's five properties as structure rather
than convention: observations are a flat mapping of JSON scalars (*structured*),
`collected_at` comes from an injected clock (*timestamped*), `collected_by` names
the collector and cannot be blank (*attributable*), and `reproducible` carries the
command or procedure that regenerates the observation (*reproducible*).

*Safe* is the one that needed a decision. Observations pass the **same**
sanitiser the audit trail uses (`audit_metadata` from `jdlib.security.audit`): a
credential-shaped value is redacted, a value under a credential-named key is
redacted whole, and a nested structure or an oversized value is refused rather
than smuggled into a report. There is deliberately no second sanitiser — two
redaction paths would be two behaviours to keep in step, and the audit path's
patterns are already the ones the leak corpus tests.

Two collectors run without a database:

| Collector | Subject | Notes |
|---|---|---|
| `collect_configuration_evidence` | the deployment's `SecurityConfig` | reports only facts on a fixed allow-list (`CONFIGURATION_EVIDENCE_KEYS`), so a configuration field added later cannot arrive in a report unreviewed; a test asserts the reported key set is exactly that list |
| `collect_migration_evidence` | the revision history this checkout carries | records one head per branch and refuses a branch with two heads or a file with no revision identifier; what a *live* schema has applied is a database question for the session-backed collector |

Recording the checkout's expected head matters because it is the other half of
"is the deployment at the expected revision": without it, drift between the
repository and a running schema would have nothing to compare against.

`repr` prints observation keys, never values — the same rule the audit envelope
follows, so a stray log line cannot become a second copy of a deployment's
details.

## 4. Posture (§9.4)

Posture answers *which controls are in force here, and how do we know*, with the
four outcomes the directive names. The semantics are fixed in `posture.py` rather
than left to each rule, because they are the part that decides whether the report
is worth reading:

| Outcome | Meaning |
|---|---|
| `PASS` | the control is in force — either a gate in a code path a caller cannot route around, or a state something actually observed |
| `WARN` | in force but unverified here (no evidence, or incomplete evidence, in which case the reason names what is missing); switched off in a profile that declares itself unsafe on purpose (`development`); or a control the library deliberately leaves to the deployment |
| `FAIL` | a control that should be in force is absent, disabled, or contradicted by what was observed |
| `NOT_APPLICABLE` | the control's subject does not exist in this deployment (no gateway identity trust; replay protection for a validator that keeps no session) |

One property of this codebase shapes the failure cases: **the production profile
refuses to construct an unsafe configuration** — `allow_all`, optional
authentication and debug security errors are all rejected at construction (Phase
1 validation). A posture layer that could only fail on those combinations would
be decorative, so the unsafe-combination failures are reported for the profiles
where they can exist (`test`, `staging`), and in production the failures that
remain are missing evidence, schema drift and a decision point with no policy.
Each has its own test:
`test_a_control_that_should_be_in_force_and_is_not_fails`,
`test_the_same_unsafe_combination_warns_in_development`,
`test_production_refuses_to_construct_the_profiles_that_would_fail`.

`PostureReport` states every control exactly once, in a deterministic order, with
counts and a worst outcome. A finding without an explanation of at least twenty
characters, for an unknown control, citing another control's evidence, or stated
twice in one report is refused. Serialization carries outcomes, reasons and
evidence *summaries* — never observation values, so a report cannot become a
second copy of a deployment's details. Findings are sorted, and evidence within a
finding is sorted, so the same inputs always serialize identically.

**Mutation checks.** Turning "no isolation evidence" into `PASS` fails
`test_missing_evidence_warns_instead_of_passing_silently`; accepting a blank or
too-short reason fails 3 tests; removing the report's own ordering fails 2.
Restoring the file returns 31 passing.

**A bug this phase found in itself.** `_gate_rule` selected its configuration
section by comparing a string against `"authentication"`, so the audit rule
silently read `authorization.enabled` and would have passed a deployment with the
audit trail switched off. It now takes the section name and uses `getattr`, and
`test_a_disabled_audit_trail_fails_the_audit_control` fails if that regresses.

## 5. The CLI and the session-backed collectors (§9.5)

```bash
jdlib security posture    # every control, with reasons; exits 1 when one fails
jdlib security evidence   # the records behind the report
jdlib security compliance # the register and its framework mappings
```

The commands are a typer sub-app beside `tenant`, `db`, `rls` and `schema`, and
they assess **the profile the operator declares** (`--environment`): the CLI
cannot read a deployment's private settings and does not pretend to, so every
report says which profile it describes. `--database-url` with `--schema` adds the
live observations, and `--branch` says which revision branch that schema carries
rather than guessing it. `posture` exits non-zero when a control fails, so it can
gate a pipeline; a warning keeps the exit code at zero. The wording is readiness
language — "technical controls", "evidence", "readiness" — with an explicit
disclaimer, and no `certified` or `compliant` anywhere in the output.

Three collectors observe infrastructure rather than the checkout:

| Collector | Subject | Notes |
|---|---|---|
| `collect_isolation_evidence` | the PostgreSQL catalog, on the schema the engine is bound to | shares `inspect_rls` with `jdlib rls verify`, so the guard that raises and the evidence that reports cannot disagree about what they saw |
| `collect_schema_revision_evidence` | the revision a live schema has applied, against the checkout's expected head | absence and drift are observations, not errors |
| `collect_policy_evidence` | the policy files a deployment declares | names and counts only — a policy body is never read, so it cannot reach a report |

`verify_rls` was refactored onto the same inspection rather than gaining a twin
(`RlsInspection` and `inspect_rls`), which is why the existing RLS integration
tests still pass unchanged; the CLI's `rls verify` therefore reports exactly what
the evidence records. The collectors are exercised on real PostgreSQL in
`tests/integration/test_compliance_live_collectors.py`: an enforced schema, a
dropped policy, an unforced table, a schema that was never provisioned, a schema
with no revision table, a schema behind the head, and a schema at it — the
directive's warning, as tests, that a `TenantSession` proves nothing about the
database.

`jdlib.security.compliance` still imports nothing from the persistence layer: the
session-backed collectors live in `jdlib.security.compliance.session` and are
imported explicitly by the CLI.

## 6. Gate

```bash
pytest -q -W error   # 1215 passed, 6 skipped
ruff check .         # All checks passed!
mypy src/jdlib       # Success: no issues found in 101 source files
```

The six skips are the documented Tyk ones (`tests/infra/test_tyk_infra.py`; the
OSS image has no coprocess runtime) and each is attributable to that limitation:
no new skip was introduced in this phase. The integration layer ran against real
PostgreSQL through testcontainers, including all six live-collector tests.

## 7. Self-evaluation (directive §96)

**Delivered.** The register and model (§9.1, §9.2), evidence records and
collectors (§9.3), posture (§9.4), the CLI and the session-backed collectors
(§9.5), with the honesty rules enforced by tests: no explanation, no finding; no
silent partials; every cited artefact machine-checked; incomplete evidence
downgrades a finding and names what is missing; and each of the four outcomes
exercised against real configurations, a real catalog and a real policy
directory.

**A bug this phase found in itself.** The audit-posture rule read the wrong
configuration section and would have passed a deployment with no audit trail; the
fix and its regression test are in §4.

**Not claimed.** Nothing here is a certification, an audit result, or a statement
about an external auditor's opinion. The register's `NOT_IMPLEMENTED` (tamper
evidence) and `PARTIAL` (Tyk plugin execution, pipeline gates) entries are the
evidence for that: the gaps this library knows about are in the register rather
than omitted from it.
