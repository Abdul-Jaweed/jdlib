# Authorization Hardening (Phase 3)

Status: **COMPLETE** — decision model, PDP port, Cerbos adapter, enforcement

> **Superseded in one respect by Phase 5:** a decision that could not be taken
> (engine unavailable) is reported as a `503 AuthorizationUnavailable` rather
> than a `403 PermissionDenied`. It is still a denial — nothing is allowed
> because an engine was down — but the outage is now distinguishable from a
> policy denial. See `error-responses.md` §4.

point and fail-closed semantics are implemented and verified against a real
Cerbos 0.37.0 engine.

Source: `src/jdlib/security/authz/` (new),
`src/jdlib/security/authz/transports.py` (`http` extra)
Tests: `tests/unit/security/test_authz_decision.py`,
`tests/unit/security/test_cerbos_pdp.py`,
`tests/unit/security/test_authz_pep.py`,
`tests/infra/test_cerbos_infra.py` (real Cerbos)
Policies: `tests/infra/cerbos/policies/`

| Evidence | Result |
|---|---|
| Unit (decision + adapter + PEP) | 53 passed |
| Infra against real Cerbos 0.37.0 | 12 passed (skipped without `JDLIB_INFRA_CERBOS_URL`) |
| Unit (security layer, total) | 218 passed |
| `ruff check .` | clean |
| `mypy src/jdlib` | clean (82 files) |

---

## 1. The chain, and why it is the chain

```text
FastAPI / application code
        ↓
JDLib PEP              (jdlib.security.authz.pep.AuthorizationPEP)
        ↓
PolicyDecisionPoint    (jdlib.security.authz.interfaces - a port)
        ↓
CerbosPDP              (jdlib.security.authz.cerbos - the only Cerbos-aware code)
        ↓
Cerbos                 (real engine, HTTP transport in ...authz.transports)
```

Application code never imports Cerbos and never sees a Cerbos type. It asks the
PEP a question in product terms (`AuthorizationQuery`: principal, tenant, resource
kind/id, actions, attributes) and gets a neutral `AuthorizationDecision` back,
or a mapped, typed error.

Two decision points exist in this repository and they are deliberately different
contracts — the internal, database-backed `jdlib.authz.pdp.PolicyDecisionPoint`
(`evaluate(principal, permission, target, context, session)`) keeps serving the
tenant plane, while `jdlib.security.authz.interfaces.PolicyDecisionPoint`
(`decide(query)`) is the seam for external engines. The docstrings say so
explicitly so a future reader does not merge them by accident.

## 2. Decision model (`jdlib.security.authz.decision`)

| Invariant | Why it matters |
|---|---|
| An allowed decision must carry an `ALLOW` effect (`ValueError` otherwise) | a mapping mistake cannot produce "allowed" from a DENY |
| A degraded decision can never be allowed (`ValueError` otherwise) | "we could not ask the engine" is structurally incapable of meaning yes |
| Queries are immutable, attributes are copied into a read-only mapping | a caller cannot mutate what was evaluated, or evaluate something else |
| An empty action set is rejected | "no action" is a programming error, not an implicit allow-everything |
| `repr` shows resource identity and attribute *names*, never attribute *values* | resource data stays out of logs and tracebacks |

`AuthorizationDecision.safe_metadata()` is the only view intended to leave the
trust boundary, and it contains exactly: `decision`, `policy_id`,
`policy_version`, `decided_at`, `reason` (directive §17). Action names, attribute
values, tenant ids and principal ids are not in it (tested).

## 3. Fail-closed semantics (directive §16)

A denial-by-construction covers every failure mode, and each has a test:

| Failure | Result |
|---|---|
| Connection refused / Cerbos unreachable | denied, `degraded=True`, `reason="engine_unavailable"` |
| Timeout (including a transport that never returns) | denied, degraded; the call completes in bounded time |
| Non-2xx response (5xx/4xx) | denied, degraded |
| Body that is not a mapping / not JSON | denied, degraded |
| `results` missing, empty, or not a list | denied, degraded |
| Result carrying an engine/policy error `status` | denied, degraded |
| Result for a different resource id | denied, degraded |
| `actions` missing or empty in the result | denied, degraded |
| Unknown effect token (anything but `EFFECT_ALLOW`) | denied |
| Requested action absent from the result | denied, and named in `denied_actions` |
| All actions requested, at least one not allowed | denied (all-or-nothing) |
| Query whose principal carries no roles | denied, **not** degraded, `reason="no_roles"`; the engine is never called |

The last row is the one failure mode that is decided locally, and it was added
after the reference application met it: Cerbos refuses a principal with no roles
as an invalid request (400, `principal.roles: value is required`), and a client
error is not an answer — routed through the failure path it became a *degraded*
decision, which the middleware turns into `503`, for what is really a denial. No
role-based policy can grant anything to a principal that carries no roles, so
`CerbosPDP.decide` answers it without asking (`tests/unit/security/test_cerbos_pdp.py`,
mutation-checked). The "non-2xx response" row above is unchanged: it covers the
requests the library does send.

There is no configuration field that can change this: `CerbosConfig` rejects
unknown fields and has no `fail_open`/`allow_on_error` switch (tested).

Verified against the real engine, not only against fixtures: with Cerbos
reachable and a valid policy the decision allows; with a dead endpoint, a
microsecond timeout, a resource with no matching policy, a foreign tenant, a
non-owner principal, a missing attribute or an undefined action, the decision
never allows.

## 4. Real wire protocol

The infra suite caught two vendor assumptions that fixtures alone would have
preserved as bugs, which is precisely why the real-engine layer exists:

* CheckResources takes `resources` as an **array of entries**
  (`{"resource": {kind, id, attr}, "actions": [...]}`), not a single top-level
  `resource` plus `actions`,
* a resource with **no matching policy** is answered with `200` and
  `EFFECT_DENY` plus `matchedPolicy: "NO_MATCH"` — a decision, not an engine
  error, so it is mapped as a plain deny with that policy id rather than as a
  degraded one.

Policy metadata (directive §17): `matchedPolicy` is recorded verbatim as
`policy_id`. It is Cerbos' fully qualified policy name
(`resource.document.vdefault`), which identifies both the policy and its
version; `matchedScope` is recorded as `policy_version` when a scope matched.

## 5. Enforcement point (`AuthorizationPEP`)

| Input | Outcome |
|---|---|
| Authenticated, tenant-bound context, decision allows | the decision is returned |
| Decision denies (including degraded) | `PermissionDenied` → **403**, message names the actions, resource and reason/policy; never attribute values |
| Context is anonymous or unauthenticated | `AuthenticationError` → **401** |
| Context has no bound tenant | `MissingTenantContext` → **500** (fail closed, never treated as unscoped) |
| Query targets another tenant's resource | `TenantAccessDenied` → **404**, *before* the engine is asked, so existence is not confirmed |
| `check()` (optional checks) | returns the decision without raising |

`on_decision` is the audit seam: it is invoked for allowed, denied and degraded
decisions alike, and an observer failure propagates. A lost audit record can
never buy a served request (tested both for deny and for allow).

## 6. Test policies and infrastructure

`tests/infra/cerbos/policies/` is a deliberately small policy pack used to make
the engine's behaviour observable: a `document` resource with `view`/`edit`/
`delete`/`publish` actions, derived roles (`reader`, `owner`, `publisher`) and a
tenant-equality condition on every rule, so cross-tenant requests deny even for
an admin.

```bash
docker compose -f tests/infra/docker-compose.yml up -d cerbos
export JDLIB_INFRA_CERBOS_URL=http://localhost:3592
pytest -q -W error -m infra
```

## 7. Deferred (explicitly not implemented)

* The PEP is not yet wired into the FastAPI request path, and the internal
  `DefaultPDP` does not yet compose with an external engine. Both change
  request-path behaviour, so they belong with the gateway integration phase
  where the request edge is being reworked anyway, with their own tests.
* The Cerbos transport uses the HTTP API; the gRPC API is not implemented.
* The policy pack in `tests/infra/` is a test fixture, not a production policy
  set; production policies ship with the deployment that owns them.
* Cerbos decision-log export and its audit-record verification are not wired
  into the audit phase's sinks yet.
