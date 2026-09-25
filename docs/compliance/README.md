# Compliance surface — controls, evidence and posture

This directory is the reader-facing view of the compliance surface for someone
who has to review it rather than write it: an assessor, an auditor or an
internal control owner. It says where each artefact lives, what it does and does
not state, and which gaps the register itself records.

**Read this first.** JDLib provides technical controls, evidence collection and
readiness reporting. Installing it does not make an organisation SOC 2, ISO/IEC
27001, NIST or any other framework *certified* or *compliant*, and nothing in
this directory is an audit result or an auditor's opinion. A `ControlMapping`
names where a control belongs in a framework (`CC6.1`, `A.5.17`, `IA-5`,
`API2:2023`, …) — it is a description, not a finding. The `jdlib security
compliance` command prints the same disclaimer, and
`tests/unit/test_cli_security.py` asserts the words `not a certification` and
`does not make an organisation certified or compliant` are in its output.

The engineering record for this surface is
[`docs/security/compliance-evidence.md`](../security/compliance-evidence.md)
(phase 9). This document is navigation across it; it does not restate it.

## 1. What lives where

| Artefact | Path | What it is |
|---|---|---|
| Control register | `src/jdlib/security/compliance/controls.py` (`CONTROL_REGISTRY`, `Control`, `ControlMapping`, `ControlFramework`, `ControlCategory`, `ImplementationStatus`, `VerificationMethod`, `control_by_id`, `controls_for_framework`, `frameworks_in_use`) | The controls this library implements, each mapped onto the framework families an assessor asks about. |
| Evidence record and checkout collectors | `src/jdlib/security/compliance/evidence.py` (`SecurityEvidence`, `collect_configuration_evidence`, `collect_migration_evidence`, `collect_policy_evidence`, `CONFIGURATION_EVIDENCE_KEYS`, `MIGRATION_BRANCHES`) | The reproducible observation behind a claim, plus the collectors that need no database. |
| Posture evaluation | `src/jdlib/security/compliance/posture.py` (`PostureOutcome`, `PostureFinding`, `PostureReport`, `Severity`, `evaluate_posture`) | Turns the register plus today's evidence into one finding per control. |
| Live (session-backed) collectors | `src/jdlib/security/compliance/session.py` (`collect_isolation_evidence`, `collect_schema_revision_evidence`) | Observe a running database: the catalog's row-level security, and the revision a schema has actually applied. Imported explicitly by the CLI so `jdlib.security.compliance` stays free of the persistence layer. |
| CLI | `src/jdlib/integrations/cli.py` (`security` sub-app beside `tenant`, `db`, `rls`, `schema`) | `jdlib security posture`, `jdlib security evidence`, `jdlib security compliance`. |
| Register tests | `tests/unit/security/test_compliance_controls.py`, `tests/unit/security/test_compliance_evidence.py`, `tests/unit/security/test_compliance_posture.py`, `tests/unit/test_cli_security.py`, `tests/integration/test_compliance_live_collectors.py` | The invariants below are enforced here, including against a real PostgreSQL catalog. |
| Operating the checks | [`docs/operations/README.md`](../operations/README.md) | How to run the commands, how to read their exit codes, and what remains the operator's responsibility. |

## 2. The control register

Nineteen controls, identified `JDL-…`, each carrying a title, description,
category, implementation status, framework mappings, evidence requirements,
evidence sources, technical owner, verification method and — for anything that
is not simply implemented — a status note explaining it. `verification_method`
says how the claim is shown to be true: `test`, `inspection`, `analysis`,
`runtime` (verified against a running service by the harness in `tests/infra`)
or `external` (the deployment's responsibility, not discharged by this library).

| Control | Status | Category | Frameworks |
|---|---|---|---|
| `JDL-AUDIT-01` Security events are recorded with fail-closed attribution | `implemented` | `audit` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-AUDIT-02` Reading and exporting the trail are separately authorized | `implemented` | `audit` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-AUDIT-03` Tamper-evident audit storage outside the database | `not_implemented` | `audit` | soc2, iso_27001, nist_sp_800_53, cis |
| `JDL-AUTHN-01` Inbound token validation fails closed | `implemented` | `authentication` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, owasp_api_top10, cis |
| `JDL-AUTHN-02` API key authentication is scoped and time-bounded | `implemented` | `authentication` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-AUTHN-03` Bearer-token replay is bounded by the token's own lifetime | `not_applicable` | `authentication` | owasp_asvs, nist_sp_800_53 |
| `JDL-AUTHZ-01` Every authorization decision goes through one policy enforcement point | `implemented` | `authorization` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, owasp_api_top10, nist_csf |
| `JDL-AUTHZ-02` A policy engine that cannot answer denies everything | `implemented` | `authorization` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-AUTHZ-03` Just-in-time privilege stops authorizing when its window closes | `implemented` | `authorization` | soc2, iso_27001, nist_sp_800_53, owasp_asvs |
| `JDL-CONF-01` Unsafe security configuration cannot start | `implemented` | `configuration` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-GW-01` Gateway-derived identity requires an authenticated integrity boundary | `implemented` | `authentication` | soc2, iso_27001, nist_sp_800_53, owasp_api_top10, cis |
| `JDL-GW-02` Gateway plugin verification across products | `partial` | `authentication` | soc2, iso_27001, cis |
| `JDL-ISO-01` Tenant isolation is enforced by the database, not only by the library | `implemented` | `tenant_isolation` | soc2, iso_27001, nist_sp_800_53, nist_csf, cis |
| `JDL-ISO-02` Cross-tenant references are impossible at the schema level | `implemented` | `tenant_isolation` | soc2, iso_27001, nist_sp_800_53, owasp_asvs |
| `JDL-LIFE-01` Tenant lifecycle transitions are bounded and recorded | `implemented` | `lifecycle` | soc2, iso_27001, nist_sp_800_53, cis |
| `JDL-OBS-01` Security telemetry is structured, bounded and non-blocking | `implemented` | `observability` | soc2, iso_27001, nist_sp_800_53, nist_csf, cis |
| `JDL-SECRET-01` Secrets are redacted on every path that leaves the process | `implemented` | `data_protection` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-SQL-01` Raw SQL is validated by parsing, not by pattern matching | `implemented` | `tenant_isolation` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |
| `JDL-SUPPLY-01` Dependency and pipeline security gates | `partial` | `supply_chain` | soc2, iso_27001, nist_sp_800_53, owasp_asvs, cis |

Generate this list from the register itself rather than trusting a copy:

```bash
jdlib security compliance --json          # every control, its status and its mappings
jdlib security compliance --framework soc2
```

### The register's own gaps

Recorded in the register, not omitted from it:

* **`JDL-AUDIT-03` — tamper-evident audit storage: `not_implemented`, owner
  `platform-operations`, verification method `external`.** Per-row hash chaining
  inside the same database was evaluated and rejected: an actor holding
  `UPDATE`/`DELETE` can drop a trigger and rewrite the chain. Detecting that
  requires storage the application's role cannot rewrite (WAL/CDC streaming,
  retention-locked object storage, a SIEM) plus a periodic anchored digest of
  each tenant's audit range. The residual risk — a database-level actor can
  alter history undetectably — is stated in
  [`docs/security/audit-hardening.md`](../security/audit-hardening.md) §7 and
  must be closed by the deployment.
* **`JDL-GW-02` — gateway plugin verification.** Kong 3.6 and Tyk 5.3.1 are both
  verified end to end: the six tests in `tests/infra/test_tyk_infra.py` pass against
  the live harness, which also refuted the earlier "no JavaScript runtime" note
  (the JSVM exists; the middleware failed to load because the fixture named an
  unknown driver and the gateway was hostname-bound - see
  `docs/security/gateway-hardening.md` §6).
* **`JDL-SUPPLY-01` — dependency and pipeline gates: `partial`, verification
  method `inspection`.** The register's status note was written when the
  test/lint/type gate was the whole of CI and describes the pipeline-security
  work as the next phase's scope. That work has since landed as the `security`
  job (see [`docs/security/ci-security.md`](../security/ci-security.md)); the
  register has not been re-statused since, so read the status note as a record
  of when it was written and `ci-security.md` as the current state of the gates.
* **`JDL-AUTHN-03` — bearer-token replay: `not_applicable`.** The validator keeps
  no server-side session, so token lifetime and audience checks are what bound a
  stolen token. A framework mapping is still recorded (owasp_asvs,
  nist_sp_800_53) because the control is *described* there, not because it is
  implemented here.

`JDL-AUDIT-03`, `JDL-GW-02` and `JDL-SUPPLY-01` are the three recorded gaps; a
test requires at least three of them, so the register cannot quietly become a
wish list.

### What keeps the register honest

Enforced by `tests/unit/security/test_compliance_controls.py`:

* control ids are unique and shaped (`JDL-…`);
* every control has a description, a technical owner, at least one mapping, at
  least one evidence requirement, and a reference on every mapping;
* **no silent partials** — `partial`, `not_implemented` and `not_applicable`
  each require a substantive `status_note`;
* **every cited evidence source exists on disk**, so a rename or a delete cannot
  leave the register pointing at something that is gone.

The register's own tests were checked against a dishonest register (a deleted
`status_note`, an evidence source pointing at a missing file): 2 of 9 tests
fail, which is what makes them tests rather than decoration
([`docs/security/compliance-evidence.md`](../security/compliance-evidence.md) §2).

## 3. Framework families

Seven families are in use, and a test asserts each has at least one control
mapped onto it:

| Framework | `--framework` value | Register's name for it |
|---|---|---|
| SOC 2 Trust Services Criteria | `soc2` | SOC 2 Trust Services Criteria |
| ISO/IEC 27001 (2022 Annex A) | `iso_27001` | ISO/IEC 27001 |
| NIST Cybersecurity Framework 2.0 | `nist_csf` | NIST CSF |
| NIST SP 800-53 Rev. 5 | `nist_sp_800_53` | NIST SP 800-53 |
| OWASP Application Security Verification Standard | `owasp_asvs` | OWASP ASVS |
| OWASP API Security Top 10 | `owasp_api_top10` | OWASP API Security Top 10 |
| CIS Critical Security Controls v8 | `cis` | CIS Controls |

Each `ControlMapping` carries the framework's own reference (`CC6.1`, `A.8.5`,
`IA-5`, `API1:2023`, `V14.2`, `12.6`, `PR.AA-05`, …). A control may map into
several families; the reference is per mapping, not per control.

## 4. The evidence record

`SecurityEvidence` carries the five properties the compliance directive asks for
as structure rather than convention:

| Property | How it is carried |
|---|---|
| Structured | `observations` is a flat mapping of JSON scalars. |
| Timestamped | `collected_at`, from an injected clock. |
| Attributable | `collected_by` names the collector and cannot be blank. |
| Reproducible | `reproducible` carries the command or procedure that regenerates the observation; the CLI prints it as `reproduce: …`. |
| Safe | Observations pass the **same** sanitiser the audit trail uses (`audit_metadata`): a credential-shaped value is redacted, a value under a credential-named key is redacted whole, and a nested or oversized value is refused. There is deliberately no second sanitiser. |

`repr` prints observation **keys**, never values, so a stray log line cannot
become a second copy of a deployment's details.

Collectors, and the subject each observes:

| Collector | Module | Subject |
|---|---|---|
| `collect_configuration_evidence` | `evidence.py` | The deployment's `SecurityConfig`. Reports only the facts on a fixed allow-list (`CONFIGURATION_EVIDENCE_KEYS`, 16 keys), so a configuration field added later cannot reach a report unreviewed; a test asserts the reported key set is exactly that list. |
| `collect_migration_evidence` | `evidence.py` | The revision history this checkout carries — one head per branch (`control`, `tenant`). What a *live* schema has applied is the session-backed collector's job. |
| `collect_policy_evidence` | `evidence.py` | The policy files a deployment declares — names and counts only (bounded list). A policy body is never read, so it cannot reach a report; `tests/unit/test_cli_security.py` asserts a marker planted inside a policy file never appears in the output. |
| `collect_isolation_evidence` | `session.py` | The PostgreSQL catalog on the schema the engine is bound to; shares `inspect_rls` with `jdlib rls verify`, so the guard that raises and the evidence that reports cannot disagree about what they saw. |
| `collect_schema_revision_evidence` | `session.py` | The revision a live schema has applied, compared with the checkout's expected head for the named branch. Absence and drift are observations, not errors. |

A collector that cannot reach its subject raises rather than fabricating a
result: "no evidence" is a state a report may describe (`warn`), an assumed
state is not.

## 5. Posture outcomes

Posture answers *which controls are in force here, and how do we know*, with one
finding per control. The semantics are fixed in `posture.py`, not left to each
rule:

| Outcome | Meaning |
|---|---|
| `pass` | The control is in force — a gate in a code path a caller cannot route around, or a state something actually observed. |
| `warn` | In force but unverified here (no evidence, or incomplete evidence — the reason names what is missing); switched off in a profile that declares itself unsafe on purpose (`development`); or a control the library deliberately leaves to the deployment. |
| `fail` | A control that should be in force is absent, disabled, or contradicted by what was observed. |
| `not_applicable` | The control's subject does not exist in this deployment (for example: no gateway identity trust, so the gateway trust model does not apply). |

A report also states its worst outcome — the ranking is `fail` > `warn` >
`not_applicable` > `pass` — and `is_ready`, which is true when nothing failed.
Every finding carries a reason of at least 20 characters; a finding for an
unknown control, citing another control's evidence, or stated twice in one
report is refused at construction. Serialization carries outcomes, reasons and
evidence *summaries* — never observation values — and the ordering is canonical,
so the same inputs always serialize identically.

## 6. The CLI

```bash
jdlib security posture      # every control, with reasons; exits 1 when a control fails
jdlib security evidence     # the records behind the report
jdlib security compliance   # the register and its framework mappings
```

`--json` is available on all three. (The `jdlib` console script comes from a
consumer's `[project.scripts]` entry — this checkout installs none, so run the
app directly; the invocation is in
[`docs/operations/README.md`](../operations/README.md) §1.) The commands assess
**the profile the operator declares** (`--environment development|test|staging|production`); the
CLI cannot read a deployment's private settings and does not pretend to, so
every report says which profile it describes. Adding live observations takes
`--database-url` together with `--schema`, and `--branch` names the revision
branch that schema carries (`control` or `tenant`) rather than guessing.
`--policy-directory` adds policy-configuration evidence, `--framework` filters
the register view. Exit codes are documented in
[`docs/operations/README.md`](../operations/README.md) §2, together with what a
`warn` or a `fail` means for an operator.

## 7. What an assessor should take from this

* The technical controls, their framework mappings, their evidence requirements
  and the artefact behind each claim are in the register, machine-readable, and
  regenerable with `jdlib security compliance --json`.
* Observations and posture are reproducible: each evidence record names the
  command or procedure that produces it.
* The gaps are in the register — including a control the library deliberately
  does not implement — so nothing has to be inferred from absence.
* Nothing here is a certification, an audit result or advice about an external
  auditor's opinion. Organisation-level controls (governance, people, physical
  security, backup and retention, keys, audit-storage tamper evidence) are the
  deployment's, as listed in [`SECURITY.md`](../../SECURITY.md) under *What is
  out of scope*, and in [`docs/operations/README.md`](../operations/README.md).
