# Adversarial Security Review (Phase 8)

Status: **COMPLETE for the review list below** — every item is labelled, two
genuine findings were fixed, and the rest are either attacked with no finding
(the evidence is named) or covered by an earlier phase's tests (named). No item
is left unlabelled, and nothing is recorded as passed because a suite was green:
each claim below names the test that would fail if the control were removed.

Source (this slice): `src/jdlib/context.py`, `src/jdlib/persistence/session.py`,
`src/jdlib/persistence/models.py`, `src/jdlib/models/audit_recorder.py`
Tests: `tests/unit/security/test_adversarial.py` (18),
`tests/integration/test_adversarial_raw_sql.py` (8),
`tests/unit/security/test_adversarial_privilege.py` (10),
`tests/unit/security/test_adversarial_audit_integrity.py` (9),
`tests/unit/security/test_adversarial_service_identity.py` (5),
`tests/integration/test_adversarial_tenant_isolation.py` (5) — 55 attacks in
total for the phase.

---

## 1. Findings that were fixed

### 1.1 An expired privilege still authorized privileged work (severity: high)

`PrivilegeContext` carries `issued_at` and `expires_at`, and `for_operator`
mints one with a TTL (the JIT-access shape). Nothing read `expires_at` on the
enforcement paths: every one of them asked only "is there a privilege?" —

| Enforcement point | Before | Now |
|---|---|---|
| `TenantSession.raw_sql(mode=PRIVILEGED)` | a lapsed privilege ran arbitrary platform SQL | refused, and the refusal is recorded with the capability it was minted for |
| `TenantSession.delete_where` (hard delete of a `SoftDelete` model) | a lapsed privilege deleted rows for real | refused |
| `TenantSession.update_where({"tenant_id": ...})` | a lapsed privilege could re-home rows | refused |
| the `before_flush` hard-delete check | same | same refusal, same path |
| `privileged_bypass` (unit-of-work write fence, relocation) | a lapsed system privilege skipped the fence | the fence runs |

The fix is at the model, not at five call sites: `PrivilegeContext.is_live(now)`
and `TenantContext.live_privilege(now)` (`src/jdlib/context.py`), plus a single
`_privilege_refusal(...)` helper in `src/jdlib/persistence/session.py` that every
gate calls. `TenantSession` takes an injectable `clock` (additive optional
parameter) so liveness is decided against one clock, and the refusal message
distinguishes *never had it* from *it lapsed* — for an investigator those are
different findings.

Both bounds are enforced: a privilege used **before** it was issued is refused
too, so a clock that moves backwards cannot resurrect authorization.

**Behaviour change (§90).** Work that used to succeed now fails when the
privilege is expired or not yet valid: privileged raw SQL, hard deletes,
tenant-id rewrites and the relocation write-fence bypass. `expires_at is None`
(system/backfill contexts) is unchanged — no expiry still means no expiry.

### 1.2 The audit trail could be mis-attributed and backdated (severity: medium)

`TenantAuditRecorder.record_security` refused a tenant mismatch (phase 6) but
took the actor and the timestamp from the event as given, so application code
that fed request-derived data into an audit call could:

* **forge the actor** — `SecurityAuditEvent(principal_id=<someone else>)` was
  persisted as that principal, and `principal_kind="platform_operator"` made a
  user's action look like an operator's,
* **manipulate the timestamp** — `occurred_at` was stored verbatim, so an event
  could be backdated past a policy change or a revocation, or postdated,
* **name no actor at all** — the row was written with `actor_id = NULL` even
  inside a request whose caller was known.

Now the recorder corroborates both: the actor must be the ambient principal, the
timestamp must be within `MAX_TIMESTAMP_SKEW` (1 minute) of the recorder's
clock, and an event that names no actor is attributed from the context the same
way the tenant already was. Refusal is fail-closed — a `ValueError` at the call
site, no row — because an operation whose evidence is a lie is worse than one
whose evidence is missing. The read path is unaffected: export rebuilds
envelopes from stored rows with their original timestamps (reading history is
not writing it).

The ambient actor is read from the bound **security context** when there is one
(that is also the source the envelope's own fields default from), and from the
tenant context otherwise (a background job, a direct call). Comparing against the
same source the fields were filled from is what keeps the check from flagging its
own defaults.

**Behaviour change (§90).** An audit event that names another actor, another
actor kind, no actor inside a request where one is known, or a timestamp more
than a minute away from now, is now refused with a `ValueError` instead of being
persisted. Producers that used the defaults are unaffected.

**A pre-existing test was updated deliberately.** `test_a_kind_outside_the_column_vocabulary_is_preserved_in_metadata`
built a row with a *named user's id and an `anonymous` kind* — the artificial
inconsistency the new check refuses. The requirement it protects (a kind the
column's vocabulary cannot hold is preserved in metadata) is real, so the test
was rewritten around an anonymous request, which is the case that actually
occurs; the assertion is unchanged.

## 2. Attacked with no finding (the evidence)

| Area | Attack | Result |
|---|---|---|
| Tenant isolation | bulk `update_where` / `delete_where` aimed at another tenant's rows, and a bulk update with no criteria at all | `tests/integration/test_adversarial_tenant_isolation.py` (5, real PostgreSQL): 0 rows changed for the foreign predicate, the victim row intact, and a criteria-less update cannot leave its own tenant |
| Tenant isolation | cross-tenant foreign-key reference, attempted on a **raw connection** with no library guard in the way | refused by the composite constraint `(tenant_id, invoice_id) → (tenant_id, id)` — isolation holds at the schema, not just in the session guard; the same-tenant control insert is accepted |
| Tenant isolation | switching tenants repeatedly on one engine/pool | nothing bleeds: each context sees exactly one tenant's rows |
| Service identity | token-cache key: a narrow scope set served for a broader one, a token minted for one audience presented to another | `tests/unit/security/test_adversarial_service_identity.py` (5): different scope set or audience ⇒ separate acquisition (mutation check: 1 failure when the scope key is dropped), the caller's scopes reach the endpoint, and a token past its lifetime is never reused |
| Raw SQL | comments, CTEs, `UNION` branches, unscoped `SELECT`/`DELETE`, `INSERT`/`UPDATE`/`ON CONFLICT` tenant assignment | phase 8 part 1 (26 attacks) — the gate is pglast, a real PostgreSQL parser; the CTE case additionally proves nothing executed |
| Authentication | `alg=none`, HS/RS confusion, forged RS256 signature with the right `kid`, unknown `kid`, malformed token, expired/nbf/iat/iss/aud/sub claims | `tests/unit/security/test_jwt_validator.py` — every one refused |
| Authentication | JWKS rotation, outage, stale keys, refresh stampede, bounded refresh interval, secret material in `repr` | `tests/unit/security/test_jwks_hardening.py` — cache keeps serving on a failed refresh, one fetch under concurrency, timeouts bounded |
| Authorization | engine unavailable / timing out / malformed response / missing action / unknown effect / all-actions-must-allow | `tests/unit/security/test_cerbos_pdp.py` + **live** `tests/infra/test_cerbos_infra.py` (29 infra tests passed against the running Cerbos 0.37.0, Kong 3.6, ZITADEL and an OTel collector): wrong tenant, wrong role, wrong action, unknown resource and a missing attribute all deny on the real engine; unavailability and timeouts never allow |
| Authorization | stale decisions after a revocation, cross-tenant cache collision | the request-scoped `AuthzCache` is invalidated on every mutation that changes authorization (`tests/integration/test_access_roles.py`, `test_access_grants.py`, `test_access_invitations.py` probe exactly that), and the memo's keys carry the tenant; there is no cross-request authorization cache in v1 |
| Gateway trust | spoofed identity/tenant/auth headers, secret downgrade, tampered signature, expiry/validity-window abuse | `tests/unit/security/test_gateway_adapters.py` (28) + FastAPI end-to-end (`test_key_pinned_to_other_tenant_with_header_override_returns_404`) + live Kong verification in `gateway-hardening.md` |
| Audit | unauthorized read/export, missing capability, cross-tenant read, forged tenant, rollback, partial failure | phase 6 tests (`test_audit_access_export.py`, `test_audit_isolation_export.py`, `test_security_audit_persistence.py`) |
| Background execution | envelopes replayed for the wrong tenant, deactivated principal, revoked membership, suspended tenant; context installed and **cleared** on success and on error | `tests/unit/test_jobs.py`; context bleed attacks in phase 8 part 1 |

## 3. Considered and deliberately not implemented

* **Token replay.** Bearer tokens here are validated statelessly against the
  issuer's JWKS; there is no `jti` denylist and no session store to consult.
  Replay is bounded by the token's own lifetime, and revocation is the identity
  provider's responsibility — implementing a local denylist would look like
  control while only covering tokens this library happens to have seen. Recorded
  as *not applicable at this layer*, not as covered.
* **Audit integrity against a database-level actor.** Unchanged from
  `audit-hardening.md` §7: an actor with `UPDATE`/`DELETE` on `audit_events` can
  rewrite history, and no in-database scheme stops them. The phase-8 additions
  raise the bar for *application-level* forgery only; the compensating controls
  (ship the trail to append-only storage, anchor a periodic digest, no
  `UPDATE`/`DELETE` for the application role) remain deployment work, and the
  residual risk stays recorded rather than papered over.
* **Live Tyk verification.** Unchanged: stock Tyk 5.3.1 OSS ships no JavaScript
  or coprocess runtime, so the Tyk harness is documented PARTIAL and its six
  tests skip with the reason; Kong is the verified gateway.

## 4. A test-level finding

`test_pagination_is_stable_and_complete` asserted "no row is returned twice"
over a tenant the whole integration suite writes to, so its verdict depended on
which files ran before it — a run in the other order failed on duplicate action
values that were legitimately there. Pagination now seeds and pages a tenant of
its own, which makes the claim decidable and order-independent (verified in both
file orders). This is the shared-database trap the phase discipline names:
assert a superset of your own seed and filter by it.

## 5. Gate

```bash
pytest -q -W error      # 1144 passed, 6 skipped
ruff check .            # clean
mypy src/jdlib          # clean, 96 source files
```

The six skips are the documented Tyk limitation; every other infrastructure
layer ran against its live service (29 infra tests passed).

**Mutation checks** (the skill's rule: a guard that cannot fail is decoration):

| Control removed | Tests that fail |
|---|---|
| privilege liveness (`_privilege_refusal` → always `None`, `is_live` → always `True`) | 7 of 10 in `test_adversarial_privilege.py` |
| audit actor attribution, unnamed-actor fill and timestamp corroboration | 6 of 9 in `test_adversarial_audit_integrity.py` |
| scope set dropped from the outbound-token cache key | 1 of 5 in `test_adversarial_service_identity.py` (the scope-separation attack) |

## 6. Self-evaluation (directive §96)

**Delivered.** A labelled verdict for every item on the directive's review list;
two genuine vulnerabilities found and fixed at the enforcement layer rather than
at one call site; the fixes proven by tests that fail when the control is removed
(7/10 and 6/9 above); the isolation claims re-attacked on real PostgreSQL,
including an attack that bypasses the library entirely and lands on the schema's
own constraint; and a test-level order dependence found and fixed rather than
worked around.

**Verification honesty.** The privilege-liveness fix is enforced on every path
that consumes `context.privilege`; `TenantContext.live_privilege` is the single
reader, so a new gate cannot silently skip it. The audit corroboration is
deliberately *not* a signature: it compares an event against the ambient context
and the local clock inside one process, which is what makes request-derived data
unusable for forgery — an attacker who can already call the recorder directly
with a matching context can still write what they like, and that is the
database-level adversary §7 describes. A migration, an import, or a deliberate
historical replay must go through the ORM model directly; the recorder is the
sanctioned path and now refuses to store a claim it cannot corroborate.

**Not claimed.** No certification, no claim that the controls are complete
against an attacker with database credentials, and no claim that the Tyk layer is
verified.
