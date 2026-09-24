# Compliance Control + Evidence System (Phase 9)

Status: **IN PROGRESS** — §9.1 (control registry) and §9.2 (control model) are
implemented and verified. §9.3 (evidence collection), §9.4 (posture) and §9.5
(CLI) are the remaining slices; nothing below claims them.

Source: `src/jdlib/security/compliance/controls.py` (new),
`src/jdlib/security/compliance/__init__.py` (new)
Tests: `tests/unit/security/test_compliance_controls.py` (9)

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

The register currently records seventeen controls: fourteen `IMPLEMENTED`, two
`PARTIAL` (Tyk plugin verification — engine limitation; pipeline security —
next phase's scope) and one `NOT_IMPLEMENTED` with its reason (tamper-evident
audit storage, which is deliberately outside this library, per
`audit-hardening.md` §7), plus one `NOT_APPLICABLE` (bearer-token replay, which a
stateless validator cannot address). A test requires at least three recorded gaps
so the register cannot quietly become a wish list.

**Mutation check.** Making the register dishonest — deleting one `status_note`
and pointing one `evidence_sources` entry at a file that does not exist — fails
2 of the 9 tests (`test_a_recorded_gap_must_explain_itself`,
`test_every_cited_evidence_source_exists`). A register test that cannot fail would
be decoration.

## 3. Still to come in this phase

* **§9.3 evidence collection** — structured, timestamped, attributable and safe
  evidence for what the library can technically verify (configuration, isolation,
  audit, migrations, policy state, test results), never collecting a secret.
* **§9.4 posture** — `PASS`/`WARN`/`FAIL`/`NOT_APPLICABLE` with every finding
  explained, and no hidden failures.
* **§9.5 CLI** — `jdlib security posture|evidence|compliance` following the
  existing typer conventions in `src/jdlib/integrations/cli.py` (a `security`
  sub-app beside `tenant`, `db`, `rls` and `schema`).

## 4. Gate

```bash
pytest -q -W error      # see the commit message for the counts on this slice
ruff check .
mypy src/jdlib
```

## 5. Self-evaluation (directive §96)

**Delivered.** The registry and model of §9.1 and §9.2, mapped onto all seven
frameworks, with the honesty rules that make a register worth reading enforced by
tests instead of by convention, and every cited artefact machine-checked to
exist.

**Not claimed.** Evidence collection, posture reporting and the CLI (they are the
next slices, and the phase status says so). Nothing here is a certification, and
the registry's own `NOT_IMPLEMENTED` and `PARTIAL` entries are the evidence for
that: the gaps this library knows about are in the register, not omitted from it.
