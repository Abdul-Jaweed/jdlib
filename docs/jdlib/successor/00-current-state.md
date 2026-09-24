# JDLib successor programme — current state

**Measured at commit `15a7058dd2c1bb75ca853be6d8e6bfc30104e280`** (`test(audit): the doubles follow the protocol they stand in for`),
branch `main`, working tree clean apart from this programme's own `.gitignore` addition.
Every number in this document was produced by a command run against that revision; nothing is
copied from JDLib's own documentation. Method, raw commands and raw outputs:
`.recon/current-state.md` (untracked by design — it names the archived library, which §1.2 of
this programme forbids in published documentation).

This document is the baseline the rest of Phase 0 reasons from. It is deliberately a
**statement of what exists**, not a plan: the plan is `05-roadmap.md`.

## 1. What JDLib is today

A private, tenant-isolated enterprise foundation library for Python 3.12+, layered
ports-and-adapters, async-first, consumed by applications as a path or private-wheel dependency.
It is *not* a data-access toolkit and has never shipped: version `0.1.0`, `__version__` in
`src/jdlib/__init__.py`.

| Property | Value |
|---|---|
| Public top-level API | **13 symbols** (`jdlib.__all__`): `AccessControl`, `ContextFactory`, `JdlibError`, `TenancyConfig`, `TenantContext`, `TenantRegistry`, `TenantRepository`, `UnitOfWork`, `authorize`, `current_principal`, `current_tenant`, `errors`, `requires` |
| Source size | **101** Python files under `src/jdlib/` |
| Test size | **112** Python files under `tests/` |
| Unit tests collected | **869** |
| Integration tests collected | **331** |
| Public namespaces | 17 (see §3) |
| Extension points (ports) | **34** (see §5) |
| CI jobs | `test`, `security` |

## 2. Repository state

- **Branch** `main`; **HEAD** `15a7058`; tree clean at the measured revision.
- JDLib's own CI is **green** on this SHA (run `36020808274`, both jobs).
- The suite was **not executed** by this assessment — collection counts only. Full-suite
  execution belongs to the phase gates, and the integration layer needs Docker.
- No coverage measurement exists anywhere in the tree: no `[tool.coverage]`, no `--cov` in CI.
  Coverage percentage is therefore **unknown, not zero and not high**.

## 3. Public namespaces

Each namespace below is verified present in `src/jdlib/`; the description is derived from the
module's own source, not from docs.

| Namespace | Provides |
|---|---|
| `jdlib` | re-exports only; the 13-symbol surface above |
| `jdlib.authn` | `Authenticator` port, OIDC/JWKS implementation, API-key authenticator, composite, wiring |
| `jdlib.authz` | permissions catalog, resource types, scopes, access reader, PDP, request-scoped cache, guards, `AccessControl`, ownership |
| `jdlib.control` | control-plane models, registry, purge, audit sink, provisioning/seed hooks |
| `jdlib.integrations` | FastAPI wiring, CLI (typer) |
| `jdlib.migrations` | programmatic Alembic runner, control and tenant baselines |
| `jdlib.models` | tenancy ORM mixins, org/team, settings, audit, tenant-plane base |
| `jdlib.persistence` | `TenantSession`, raw-SQL validator (pglast), `SessionRouter`, `SecretProvider`, `UnitOfWork`, `TenantRepository`, ORM events, isolation strategies |
| `jdlib.persistence.strategies` | `IsolationStrategy`, shared / schema-per-tenant / database-per-tenant, RLS install and verify |
| `jdlib.security` | the security-hardening programme's surface: audit, authn, authz, compliance, gateway, error taxonomy, tracing, config, metrics |
| `jdlib.security.audit` | security event emitters, sinks, export |
| `jdlib.security.authn` | JWT verification, signing-key source, provider |
| `jdlib.security.authz` | PDP interfaces, enforcement point, transports |
| `jdlib.security.compliance` | compliance control catalogue and reporting |
| `jdlib.security.gateway` | gateway identity assertion handling |
| `jdlib.tenancy` | request resolution chain, middleware, jobs |
| `jdlib.testing` | fixtures, fakes, assertions for consumers |

## 4. The pinned-surface constraint (binding on every phase)

`tests/unit/security/test_security_public_surface.py` asserts `frozenset(jdlib.security.__all__) == EXPECTED_SURFACE`
**by exact equality**, and line 95 additionally asserts `"SecurityConfig" not in jdlib.__all__`.
The top-level `__all__` is a curated 13-symbol list.

**Consequence for this programme:** new public API must be added in **new submodule namespaces**,
never by appending to `jdlib.__all__` or `jdlib.security.__all__`. This makes every adoption
additive by construction, and it is the reason §7 of this programme's naming document proposes
new namespaces rather than extending existing pinned ones.

## 5. Extension points (ports) — the seams new capability must attach to

34 protocols are declared. The ones the successor phases touch:

| Port | Location | Role |
|---|---|---|
| `IsolationStrategy` | `persistence/strategies/base.py:19` | per-placement isolation adapter |
| `SecretProvider` | `persistence/secrets.py:7` | secret reference → connection handle |
| `PolicyDecisionPoint` | `authz/pdp.py:30` and `security/authz/interfaces.py:25` | authorization evaluation |
| `AccessReader` | `authz/reader.py:28` | actor authority reads for anti-escalation |
| `Authenticator` | `authn/base.py:10` | credential verification |
| `TenantResolver` | `tenancy/resolution.py:24` | one step of the resolution chain |
| `PrincipalProvider` | `tenancy/middleware.py:57` | principal identification in middleware |
| `PlatformAudit` | `control/audit.py:27` | control-plane audit sink |
| `SecurityEventSink` | `security/audit/emitters.py:44`, `security/audit/export.py:64` | security event sinks (async `emit`) |
| `WriteFence` | `persistence/models.py:33` | write admission fence |
| `RawSqlAuditor` | `persistence/session.py:26` | raw-SQL observation in `TenantSession` |
| `SeedHook` | `control/registry.py:73` | provisioning seed step |
| `Clock` | `context.py:113` | injectable time source |
| `TracerLike` | `security/tracing.py:158` | duck-typed OTel tracer |
| `TokenValidator` / `TokenProvider` / `GatewayAdapter` / `RateLimiter` | `security/interfaces.py:48/75/105/141` | gateway and token seams |
| `SigningKeySource` | `security/authn/jwt.py:37` | public signing keys by `kid` |
| `ServabilityChecker` / `EntitlementChecker` / `OperatorAuthorizer` / `PrivilegeAudit` | `context.py:166/170/174/178` | `ContextFactory` collaborators |
| `ScopeLookup` / `ResourceLookup` / `TenantWriteSession` | `authz/access.py:53/73/85` | ownership and anti-escalation surface |
| `PrincipalDirectory` / `TenantDirectory` | `context.py:158/162` | identity and tenancy lookups |

Two namespaces declare a `PolicyDecisionPoint` and two declare a `SecurityEventSink`. They serve
different programmes (foundation vs security) and are **not** duplicates to be merged in this
work — see `04-adoption-decisions.md` ADR-9.

## 6. Dependencies

Core dependencies, each optional extra, and the declared entry points are as pyproject.toml
states them (build backend, `requires-python >= 3.12`, `[project.scripts]`, `pytest11` plugin).
One **real defect** was found by comparing declared dependencies against actual imports:

> `src/jdlib/integrations/fastapi.py:21` imports `starlette.responses` directly, and `starlette`
> is declared nowhere — neither in `[project.dependencies]` nor in any extra. It arrives
> transitively through `fastapi` today, so the integration works and the declaration is wrong.

This is the same class of defect the capability inventory found in the archived library
(undeclared `orjson`, an undeclared `pulsar`). It is scheduled as a fix in `05-roadmap.md` §1,
because the successor phases add optional integrations and would multiply the pattern.

## 7. Documentation that exists

- `docs/jdlib/` — **the approved design documents**, and the constraint set for this programme:
  `02-relational-schema.md`, `03-isolation-invariants.md`, `04-authorization-model.md`,
  `05-tenant-lifecycle.md`, `06-strategy-matrix.md`, `07-implementation-design.md`.
- `docs/security/` — the hardening programme's phase documents and its certification.
- `docs/operations/`, `docs/compliance/`, `docs/threat-model/`, `docs/superpowers/`.
- `docs/jdlib/successor/` — this programme's documents (created by Phase 0).

## 8. Known limitations carried into this programme

| # | Limitation | Where recorded |
|---|---|---|
| L1 | Tyk OSS 5.3.1 has no coprocess runtime; its harness tests always skip. Kong 3.6 is the verified gateway. | `docs/security/`, JDLib CI annotations |
| L2 | The error-envelope gap (G10) is frozen by decision, not implemented. | security programme |
| L3 | Integration-layer tests need live infrastructure (Cerbos, Kong, ZITADEL, collector) via `JDLIB_INFRA_*`; without them they skip. | `tests/infra/` |
| L4 | No coverage measurement exists; the figure is unknown. | this document |
| L5 | `starlette` is imported but undeclared (§6). | this document |
| L6 | `tests/integration` has no infrastructure skip guard: without Docker the fixtures raise rather than skip. | `.recon/current-state.md` |

## 9. What this programme must not redo

JDLib already implements, and this programme therefore **keeps** (no re-implementation, no
parallel twin): multi-strategy tenancy and RLS; authentication (OIDC/JWKS/API-key) and the
one-evaluator authorization model with anti-escalation rules; `TenantSession` /
`TenantRepository` / `UnitOfWork`; `SecretProvider`; platform and tenant audit with fail-closed
mandatory events; the security programme's audit/authz/tracing/compliance surface; migrations;
the FastAPI and CLI integrations; the testing toolkit.

The successor phases address the capability areas JDLib does **not** have — resource hydration,
caching, credential and cryptographic provider abstractions, connectors, object storage, a
bounded query specification, background-job context envelopes, delegation — and they attach them
at the seams in §5 rather than beside them.
