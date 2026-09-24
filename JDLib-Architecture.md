# JDLib — Complete Technical Architecture and Implementation Reference

> **Single source of truth for the `jdlib` library.**
> Derived from the repository at commit `a30601d` (`main`) and synchronised with
> the security-hardening programme at commit `4d113e5` (`main`, plus the
> uncommitted phase 11 documentation sweep). §26.6 records exactly what that
> synchronisation revised, what was verified by execution, and what remains as
> inspected at `a30601d`.
> Every architectural claim below is grounded in source code, tests, packaging
> metadata, or the frozen design documents under `docs/`.
> All file references use repository-relative paths with line numbers, e.g.
> `src/jdlib/control/registry.py:51-58`.

---

## Document Conventions

### Status legend

| Label | Meaning |
|---|---|
| **Implemented** | Present in shipped source and covered by tests. |
| **Partial** | Present but with a narrower scope than the design documents imply. |
| **Experimental** | Present, unstable, or lightly covered. |
| **Configured but unused** | A configuration field exists but no shipped code path consumes it. |
| **Not implemented** | Named in design docs, absent from source. |
| **Recommended** | A usage pattern endorsed by the README/design docs, not enforced by code. |
| **Unknown / Requires Confirmation** | Cannot be determined from the repository. |

### Accuracy rules applied

* No API, class, function, feature, dependency, or workflow is described unless
  it exists in the source tree.
* Design documents that drift from source are called out explicitly in
  [§26 Accuracy and Verification Notes](#26-accuracy-and-verification-notes).
* No credentials, tokens, or real secrets appear in this document; only
  placeholder DSNs are used.

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [JDLib Purpose and Design Goals](#2-jdlib-purpose-and-design-goals)
3. [Package Architecture](#3-package-architecture)
4. [High-Level Architecture](#4-high-level-architecture)
5. [Module Architecture](#5-module-architecture)
6. [Public API Architecture](#6-public-api-architecture)
7. [Internal and Low-Level Architecture](#7-internal-and-low-level-architecture)
8. [Feature-by-Feature Architecture](#8-feature-by-feature-architecture)
9. [Runtime and Execution Model](#9-runtime-and-execution-model)
10. [Data Architecture](#10-data-architecture)
11. [Dependency Architecture](#11-dependency-architecture)
12. [Configuration Architecture](#12-configuration-architecture)
13. [Error and Exception Architecture](#13-error-and-exception-architecture)
14. [Logging and Observability](#14-logging-and-observability)
15. [Security Architecture](#15-security-architecture)
16. [Performance and Concurrency](#16-performance-and-concurrency)
17. [Extensibility and Plugin Architecture](#17-extensibility-and-plugin-architecture)
18. [Packaging and Distribution](#18-packaging-and-distribution)
19. [Testing Architecture](#19-testing-architecture)
20. [Consumer Integration](#20-consumer-integration)
21. [End-to-End Workflows](#21-end-to-end-workflows)
22. [Architectural Decisions](#22-architectural-decisions)
23. [Current Limitations](#23-current-limitations)
24. [Future Architecture (Proposed / Not Currently Implemented)](#24-future-architecture-proposed--not-currently-implemented)
25. [Complete Architecture Diagrams](#25-complete-architecture-diagrams)
26. [Accuracy and Verification Notes](#26-accuracy-and-verification-notes)
27. [Final Architecture Summary](#27-final-architecture-summary)

---

## 1. Executive Overview

### 1.1 What JDLib is

`jdlib` is a **Python library (importable package, not a service)** that provides
the repetitive, failure-prone infrastructure of a multi-tenant SaaS application
on top of **PostgreSQL** and **SQLAlchemy 2.0 (async)**.

It is a *foundation*: it owns request-scoped tenant context, physical/logical
tenant isolation, row-level tenant scoping, scoped RBAC, authentication wiring,
tenant lifecycle management, migrations, and audit — while leaving application
models, HTTP routing, and business logic to the consumer.

| Property | Value | Source |
|---|---|---|
| Distribution name | `jdlib` | `pyproject.toml:5-6` |
| Version | `0.1.0` | `pyproject.toml:7`, `src/jdlib/__init__.py:27` |
| Python | `>=3.12` (PEP 604 unions, PEP 695 generics) | `pyproject.toml:9` |
| Database | PostgreSQL 15+ (`citext` extension required by control plane) | `docs/jdlib/02-relational-schema.md:1-54` |
| Async model | `AsyncSession` / `create_async_engine` | `src/jdlib/persistence/session.py:256` |
| Build backend | `hatchling` | `pyproject.toml:1-3` |
| Public exports | 13 names | `src/jdlib/__init__.py:11-25` |
| Test suite | 568 tests passing (`-W error`) | verified on `a30601d` |

### 1.2 The problem it solves

Multi-tenancy has a small number of design options and a large number of
subtle failure modes. The most common production failures are:

* a query that silently reads or writes another tenant's rows;
* a raw SQL escape hatch that bypasses ORM scoping;
* a lifecycle operation that is not idempotent or not serialized;
* an authorization decision that silently widens for API keys;
* privileged access that is not explicit, bounded, or audited;
* an async background hop that executes under a stale tenant.

`jdlib` encodes these as **mechanisms**, not conventions:

| Failure mode | Mechanism | Implementation |
|---|---|---|
| Cross-tenant read/write | `TenantSession` event hooks scope every statement | `src/jdlib/persistence/session.py:109-254` |
| Raw SQL escape | pglast AST proof of `tenant_id = $n` per relation | `src/jdlib/persistence/rawsql.py:146-256` |
| Non-idempotent lifecycle | advisory locks + idempotent create/provision | `src/jdlib/control/registry.py:285-365` |
| Authorization widening | additive, scope-checked, cache-invalidated, audited mutations | `src/jdlib/authz/access.py:120-1027` |
| Implicit privilege | capability-bearing, time-bounded, audited `PrivilegeContext` | `src/jdlib/context.py:53-60, 254-302` |
| Stale async context | HMAC-signed envelope + re-validation at execution | `src/jdlib/context.py:375-438`, `src/jdlib/tenancy/jobs.py:24-81` |

### 1.3 Who consumes it

A Python application team that:

* runs a multi-tenant SaaS product on PostgreSQL;
* wants one data-access API regardless of whether a tenant lives in a shared
  schema, its own schema, or its own database;
* wants framework-adjacent integrations (FastAPI, Typer) without adopting an
  application framework of its own.

### 1.4 Main use cases

1. **Shared-schema SaaS** with logical `tenant_id` scoping, optionally hardened
   with PostgreSQL row-level security.
2. **Mid-market schema-per-tenant** with per-schema namespaces and
   `search_path` transaction scoping.
3. **Enterprise database-per-tenant** with secret-resolved DSNs and a bounded
   engine cache.
4. **Hybrid deployments** — placement is per-tenant data; all three strategies
   share one `TenantSession` surface (`README.md:271-298`).

### 1.5 Core capabilities

* Request-scoped `TenantContext` with fail-closed accessors.
* Five tenant resolvers (JWT claim, subdomain, path, header, API key) behind a
  first-match chain.
* Signed envelopes for internal/async hops with re-authorization at execution.
* `TenantSession` with automatic `tenant_id` scoping, stamping, immutability,
  and bulk-operation rejection.
* Structural raw-SQL validation for `SELECT`/`UPDATE`/`DELETE`/`INSERT`.
* Scoped RBAC: permission catalog, roles, bindings, resource grants,
  invitations, ownership transfer, PDP with frozen precedence, request-scoped
  cache.
* Authentication: OIDC (JWKS + user linking) and Argon2-hashed API keys behind
  one `Authenticator` protocol.
* Tenant lifecycle: create, provision, migrate, suspend, resume, archive,
  deprovision (archive/purge/destroy), plus tenant-plane purge.
* Programmatic Alembic migration runner for both planes.
* Platform and tenant audit sinks with caller-transaction participation.
* Schema metadata linter (12 implemented invariant rules).
* Testing kit: assertions plus an autoloaded pytest plugin.
* FastAPI middleware/dependencies and a Typer operator CLI.

### 1.6 Architectural principles (evidenced in source)

1. **Fail closed.** No context → no data. `current_tenant()` raises
   `MissingTenantContext` (`src/jdlib/context.py:113-117`); `TenantSession`
   constructed with `context=None` raises immediately
   (`src/jdlib/persistence/session.py:265-272`).
2. **Isolation is layered.** Logical scoping is applied even when physical
   separation already exists (invariant I9, `docs/jdlib/03-isolation-invariants.md`).
3. **Placement is data, not code.** The strategy is chosen from a control-plane
   row, not from branching code (`src/jdlib/persistence/router.py:13-23`).
4. **Privilege is explicit and audited.** No implicit superuser path;
   `for_system`/`for_test` require the module-private `PRIVILEGE_ISSUER`
   sentinel and write an audit record before returning
   (`src/jdlib/context.py:304-372`).
5. **Ports and adapters at the edges.** `Protocol` definitions
   (`Authenticator`, `TenantResolver`, `IsolationStrategy`, `AccessReader`,
   `WriteFence`, `PlatformAudit`, `SecretProvider`, `SeedHook`, `PrivilegeAudit`,
   `OperatorAuthorizer`, `PrincipalDirectory`, `TenantDirectory`,
   `ServabilityChecker`, `EntitlementChecker`, `PolicyDecisionPoint`) receive
   consumer implementations.
6. **Crossing module boundaries uses `JdlibError` only**
   (`README.md:389-390`).

### 1.7 Major abstractions

| Abstraction | Role |
|---|---|
| `TenantContext` / `Principal` / `PrivilegeContext` | immutable request identity and authority |
| `ContextFactory` | builds a context after five fail-closed checks |
| `TenantSession` | scoped unit of database access |
| `UnitOfWork` | write-admission fence + transaction lifecycle |
| `TenantRepository` | scoped CRUD helper |
| `TenantRegistry` | control-plane lifecycle authority |
| `IsolationStrategy` | physical placement adapter |
| `DefaultPDP` / `Decision` / `MatchedRule` | authorization evaluation |
| `AccessControl` | authorization mutation authority |
| `AccessReader` / `ControlAccessReader` | control-plane authorization reads |
| `MigrationRunner` | programmatic Alembic driver |
| `EnvelopeCodec` / `ContextPropagator` | signed cross-hop context |
| `TenantMiddleware` | raw-ASGI request pipeline |
| `PermissionCatalog` / `ResourceTypeRegistry` / `ScopeResolver` | authorization vocabulary |

### 1.8 Main entry points

```python
from jdlib import (
    AccessControl, ContextFactory, JdlibError, TenancyConfig, TenantContext,
    TenantRegistry, TenantRepository, UnitOfWork, authorize,
    current_principal, current_tenant, errors, requires,
)
```

Framework entry points (submodules, not top-level re-exports):

```python
from jdlib.integrations.fastapi import JdlibContainer, install, get_context, get_uow, require
from jdlib.integrations.cli import app  # Typer
from jdlib.testing import assert_tenant_isolated  # consumer test kit
```

### 1.9 System context

```mermaid
graph TB
    subgraph Consumer["Consumer Application (not shipped by jdlib)"]
        APP["Business app<br/>models, routes, jobs"]
        CONFIG["Configuration & wiring<br/>TenancyConfig, engines, DI"]
    end

    subgraph JDLIB["JDLib library (src/jdlib)"]
        API["Public API<br/>context · registry · uow · access · guards"]
        CORE["Core enforcement<br/>TenantSession · raw SQL validator · PDP · lifecycle"]
        ADAPTERS["Adapters<br/>FastAPI · Typer CLI · strategies · Alembic"]
    end

    subgraph EXT["External dependencies"]
        PG[("PostgreSQL 15+<br/>control plane + tenant planes")]
        IDP["OIDC identity provider"]
        HTTP["httpx JWKS endpoint"]
        FASTAPI["FastAPI / ASGI server"]
        TYPER["Typer CLI host"]
    end

    APP --> API
    CONFIG --> API
    FASTAPI --> ADAPTERS --> CORE
    TYPER --> ADAPTERS
    CORE --> PG
    ADAPTERS --> IDP
    ADAPTERS --> HTTP
    IDP --> HTTP
```

---

## 2. JDLib Purpose and Design Goals

### 2.1 Stated purpose

From `README.md:1-7`: *"Reusable multi-tenant foundation for PostgreSQL +
SQLAlchemy applications. jdlib owns the repetitive, failure-prone parts of SaaS
tenancy."*

From `pyproject.toml:8`: `description = "Reusable multi-tenant foundation"`.

### 2.2 Frozen design goals

The approved specification (`docs/superpowers/specs/2026-09-21-jdlib-multitenancy-foundation-design.md:1-64`)
and the six design documents in `docs/jdlib/` establish the following goals,
each of which is implemented:

| Goal | Design doc | Shipped mechanism |
|---|---|---|
| Two-plane data model: control plane owns metadata, tenant plane owns tenant data | `02-relational-schema.md:1-54` | `ControlBase` (`jd_control` schema) vs `TenantBase` (unqualified) — `src/jdlib/control/base.py:6-21`, `src/jdlib/models/base.py:13-14` |
| Composite `(tenant_id, id)` identity, tenant-owned FKs, no cross-plane FKs | `02:462-527` | `TenantOwned` + lint rules L1–L4 — `src/jdlib/models/base.py:17-23`, `src/jdlib/lint.py:82-128` |
| Fail-closed tenant scoping of every data path (I1–I13) | `03-isolation-invariants.md:8-233` | `TenantSession` events + `RawSqlValidator` |
| Explicit, capability-bearing, time-bounded, audited privilege (I6) | `04-authorization-model.md:248-290` | `PrivilegeContext`, `ContextFactory.for_operator` |
| Signed envelopes with re-authorization across async boundaries (I7) | `05-tenant-lifecycle.md`, phase-2 plan | `EnvelopeCodec` + `ContextPropagator.reconstruct` |
| Placement as data across three strategies | `06-strategy-matrix.md:7-51` | `IsolationStrategy` implementations + `SessionRouter` |
| Single servability predicate | `05:73-101` | `TenantRegistry._servability_error` (`src/jdlib/control/registry.py:124-140`) |
| Platform and tenant audit with caller-transaction participation | `05:164-173` | `DatabaseAuditSink(session=...)`, `TenantAuditRecorder` |
| Framework-independent core, optional adapters | `07-implementation-design.md:747-787` | `pyproject.toml` extras `fastapi`, `cli`; top-level package imports no optional dependency |

### 2.3 Non-goals (evidenced by absence)

* **Not a web framework.** `jdlib` ships no router, no app object, no template
  engine; `README.md` snippets compose it into FastAPI.
* **Not an ORM.** SQLAlchemy models are declared, but no identity map, unit of
  identity, or migration authoring is provided beyond the two baseline
  revisions and the programmatic runner.
* **Not a policy language engine.** The PDP is Python code with SQL reads; no
  OPA/Cedar/Casbin integration exists.
* **Not a job runner.** `tenancy/jobs.py` provides context reconstruction and a
  decorator; there is no queue, scheduler, or worker loop.
* **Not a secret manager.** Secrets arrive through a `SecretProvider` the
  consumer implements.
* **Not a billing/metering product.** No quota, plan, or entitlement
  persistence; `EntitlementChecker` is a consumer-supplied port.

### 2.4 Design tensions and how the code resolves them

| Tension | Resolution in code |
|---|---|
| Convenience vs. isolation guarantees | Ergonomic repository/UoW API on top of hard enforcement in session events; guards read ambient context rather than accepting a tenant argument |
| One API across three placements | `TenantSession` wraps a plain `AsyncSession`; strategies only produce sessions and own physical lifecycle |
| Performance vs. proof | Bulk DML is refused (`UnscopedBulkOperation`) unless it flows through the scoped helpers; raw SQL is parsed and proven rather than regex-matched |
| Correctness vs. availability | Lifecycle failures are committed as `failed` state and re-raised; the tenant remains `provisioning` and unservable |

---

## 3. Package Architecture

### 3.1 Repository tree (tracked files)

```text
jdlib/
├── .github/
│   └── workflows/
│       └── ci.yml                     # two jobs: test (ruff, mypy, pytest) and
│                                      #   security (phase 10 gates — §19.6)
├── .gitleaks.toml                     # reviewed, value-pinned allowlist (phase 10)
├── .gitignore                         # ignores .venv, caches, dist, .superpowers,
│                                      #   .worktrees, tests/infra/out/, security-artifacts
├── README.md                          # 390-line consumer guide + canonical wiring
│                                      #   (+ a security/compliance section, phase 11)
├── pyproject.toml                     # hatchling metadata, deps, tool config (64 lines)
├── docs/
│   ├── jdlib/
│   │   ├── 02-relational-schema.md    # 538 lines — schema contract
│   │   ├── 03-isolation-invariants.md # 293 lines — I1–I13 + raw-SQL proof table
│   │   ├── 04-authorization-model.md  # 360 lines — RBAC contract + role/action matrix
│   │   ├── 05-tenant-lifecycle.md     # 304 lines — lifecycle + relocation phases
│   │   ├── 06-strategy-matrix.md      # 201 lines — three strategies + RLS
│   │   └── 07-implementation-design.md# 839 lines — code-level blueprint
│   ├── security/
│   │   ├── security-core.md           # Phase 1 — context, config, errors, ports
│   │   ├── authentication-hardening.md# Phase 2 — JWKS/JWT, tokens, ZITADEL, identity
│   │   ├── authorization-hardening.md # Phase 3 — decisions, PDP port, Cerbos, PEP
│   │   ├── gateway-hardening.md       # Phase 4 — adapters (Kong verified; Tyk limited)
│   │   ├── error-responses.md         # Phase 5 — codes, envelope, WWW-Authenticate
│   │   ├── audit-hardening.md         # Phase 6 — vocabulary, envelope, access, export
│   │   ├── observability-hardening.md # Phase 7 — logs, metrics, spans, collector
│   │   ├── adversarial-review.md      # Phase 8 — attacks, findings, verdicts
│   │   ├── compliance-evidence.md     # Phase 9 — register, evidence, posture, CLI
│   │   └── ci-security.md             # Phase 10 — the CI security gates
│   └── superpowers/
│       ├── specs/2026-09-21-jdlib-multitenancy-foundation-design.md
│       └── plans/2026-09-21-jdlib-*.md   # 9 phase plans, all marked complete
├── knowledge_base/                    # 36 documents describing the library at a30601d
├── src/
│   └── jdlib/                         # 104 tracked files, 15,202 lines (shipped package)
└── tests/                             # 125 tracked files, 23,269 lines
    ├── unit/                          # 66 modules (37 top-level + 29 under security/),
    │                                  #   677 test defs
    ├── integration/                   # 33 test modules + 3 support modules, 307 test defs
    ├── infra/                         # 5 modules, 35 test defs — Kong, Cerbos, ZITADEL,
    │                                  #   OpenTelemetry and Tyk harnesses
    └── support/                       # test-only fakes and a consumer model fixture
```

**Absent by design or by omission:** `examples/`, `LICENSE`, `CONTRIBUTING.md`,
`Dockerfile`, root compose files, `Makefile`, `tox.ini`, `noxfile.py`, lock files
(`uv.lock`, `poetry.lock`), `setup.py`, `setup.cfg`, `requirements*.txt`,
`.pre-commit-config.yaml`, `AGENTS.md`. `pyproject.toml` declares no `readme`,
`license`, `authors`, `classifiers`, `keywords`, or `urls` metadata.

**Added by the phase 11 documentation sweep (working tree, uncommitted at
`4d113e5`; the tree above lists tracked files):** `CHANGELOG.md`, `SECURITY.md`,
`docs/security/README.md`, `docs/compliance/README.md`,
`docs/operations/README.md`, and a modified `README.md`.

### 3.2 Shipped package tree

```text
src/jdlib/
├── __init__.py                    # 13 public re-exports + __version__
├── _uuid.py                       # uuid7() (private module)
├── config.py                      # pydantic-settings configuration models
├── context.py                     # Principal/PrivilegeContext/TenantContext,
│                                  #   ContextFactory, EnvelopeCodec, context_scope
├── errors.py                      # JdlibError hierarchy (27 subclasses)
├── lint.py                        # metadata invariant linter (12 implemented rules)
├── py.typed                       # PEP 561 marker
├── authn/
│   ├── __init__.py                # empty (0 bytes)
│   ├── base.py                    # Authenticator protocol, bearer_token, record_authn_failure
│   ├── apikey.py                  # parse/hash/verify + ApiKeyAuthenticator
│   ├── oidc.py                    # JwksCache, TokenVerifier, ClaimMapper, UserLinker,
│   │                              #   OidcAuthenticator
│   ├── composite.py               # CompositeAuthenticator (first success wins)
│   └── wiring.py                  # build_authenticator + Principal/Tenant/Entitlement adapters
├── authz/
│   ├── __init__.py                # empty (0 bytes)
│   ├── permissions.py             # Permission, PermissionCatalog, 13 built-ins
│   ├── resource_types.py          # ResourceTypeDefinition, ResourceTypeRegistry
│   ├── scopes.py                  # ScopeRef, ResourceRef, Target, ScopeResolver
│   ├── reader.py                  # AccessReader protocol, ControlAccessReader
│   ├── pdp.py                     # Decision, MatchedRule, PolicyDecisionPoint, DefaultPDP
│   ├── cache.py                   # AuthzCache (request-scoped memo, one-way invalidation)
│   ├── guards.py                  # tenant_target, Enforcer, requires, authorize
│   └── access.py                  # AccessControl (roles/bindings/grants/invitations/transfer)
├── control/                       # namespace package (NO __init__.py)
│   ├── base.py                    # CONTROL_SCHEMA="jd_control", naming convention, ControlBase
│   ├── enums.py                   # control-plane StrEnums + sql_in()
│   ├── models.py                  # 16 control-plane SQLAlchemy models
│   ├── audit.py                   # PlatformAudit protocol, DatabaseAuditSink,
│   │                              #   CompositeAuditSink, RecordingPlatformAudit,
│   │                              #   PrivilegeAuditAdapter
│   ├── registry.py                # TenantRegistry, RegistryWriteFence, SeedHook
│   ├── purge.py                   # TenantPlanePurger
│   └── session.py                 # ControlPlaneSession wrapper
├── integrations/
│   ├── __init__.py                # docstring + __future__ only
│   ├── fastapi.py                 # install, JdlibContainer, get_context, get_uow, require
│   └── cli.py                     # Typer app: tenant/db/rls/schema/security groups
├── migrations/
│   ├── __init__.py                # empty
│   ├── runner.py                  # MigrationRunner (synchronous, programmatic Alembic)
│   ├── control/
│   │   ├── env.py, script.py.mako
│   │   └── versions/0001_control_baseline.py
│   └── tenant/
│       ├── env.py, script.py.mako
│       └── versions/0001_tenant_baseline.py
├── models/                        # namespace package (NO __init__.py)
│   ├── base.py                    # TenantBase, TenantOwned, TenantRouted, Timestamped,
│   │                              #   SoftDelete, OwnableByOrg/Team, ownership_constraints
│   ├── org.py                     # Organization, Team
│   ├── settings.py                # TenantSetting
│   ├── audit.py                   # tenant-plane AuditEvent
│   └── audit_recorder.py          # TenantAuditRecorder + fail-closed attribution (§8.13)
├── persistence/
│   ├── __init__.py                # empty
│   ├── models.py                  # tenant_table_map, WriteFence, NullWriteFence,
│   │                              #   privileged_bypass
│   ├── session.py                 # TenantSession + SQLAlchemy event enforcement
│   ├── rawsql.py                  # RawSqlValidator, RawSqlMode, CompiledRawSql
│   ├── uow.py                     # UnitOfWork
│   ├── repository.py              # TenantRepository[ModelT]
│   ├── router.py                  # SessionRouter
│   ├── secrets.py                 # SecretProvider, MemorySecretProvider, EnvSecretProvider
│   └── strategies/
│       ├── __init__.py            # empty
│       ├── base.py                # StrategyCapabilities, IsolationStrategy protocol
│       ├── deprovision.py         # DeprovisionMode
│       ├── shared.py              # SharedSchemaStrategy
│       ├── schema.py              # SchemaPerTenantStrategy, validate_schema_name
│       ├── database.py            # DatabasePerTenantStrategy, validate_database_handle
│       └── rls.py                 # rls_eligible_tables, emit_rls_policies, install_rls,
│                                  #   RlsInspection, inspect_rls, verify_rls
├── security/                    # security programme (§15.4); __init__ files re-export
│   ├── __init__.py              # core surface: context, config, errors, interfaces, responses
│   ├── config.py                # SecurityConfig + sections, validate_security_config
│   ├── context.py               # SecurityContext, RequestIds, AuthMethod, contextvar binding
│   ├── errors.py                # SecurityCode/Descriptor, describe_error, www_authenticate
│   ├── identity.py              # service-identity formalisation (IdentityKind, ServiceIdentity)
│   ├── interfaces.py            # Authenticator/Gateway/RateLimiter/TokenProvider ports
│   ├── redaction.py             # the one canonical secret-redaction pattern set
│   ├── responses.py             # ErrorResponse, error_response (safe client-visible failures)
│   ├── telemetry.py             # security_log_record, SecurityMetrics, safe_emit (Phase 7)
│   ├── tracing.py               # traceparent parse/format, security spans (Phase 7)
│   ├── audit/                   # vocabulary, envelope, emitters, access, export, adapters
│   ├── authn/                   # algorithm policy, JwtTokenValidator, token provider, ZITADEL
│   ├── authz/                   # decision model, PDP port, Cerbos adapter, AuthorizationPEP
│   ├── gateway/                 # NoGatewayAdapter, KongGatewayAdapter, TykGatewayAdapter
│   └── compliance/              # control register, evidence, posture, session collectors (§8.22)
├── tenancy/
│   ├── __init__.py                # empty
│   ├── resolution.py              # RequestInfo, resolvers, ResolverChain, build_chain
│   ├── middleware.py              # TenantMiddleware, http_status_for, PrincipalProvider
│   └── jobs.py                    # ContextPropagator, tenant_job
└── testing/
    ├── __init__.py                # 3 assertion re-exports
    ├── assertions.py              # assert_scoped_count, assert_tenant_isolated,
    │                              #   assert_cross_tenant_write_rejected
    └── pytest_plugin.py           # pytest11 plugin: jdlib_* fixtures
```

### 3.3 Public vs. internal API boundary

**Public (top-level `jdlib`):** exactly the 13 names in `src/jdlib/__init__.py:11-25`.
`tests/unit/test_public_api.py:9-25` asserts this exact set, and
`tests/unit/test_public_api.py:46-59` asserts that importing `jdlib` does **not**
import `fastapi`, `pytest`, or `typer`.

**Public-by-submodule (used by the README quickstart, therefore de facto public):**

| Submodule | Public symbols |
|---|---|
| `jdlib.authn.wiring` | `build_authenticator`, `PrincipalDirectoryAdapter`, `TenantDirectoryAdapter`, `EntitlementAdapter`, `fetch_jwks` |
| `jdlib.authz.guards` | `Enforcer`, `tenant_target`, `requires`, `authorize` |
| `jdlib.authz.pdp` | `Decision`, `MatchedRule`, `PolicyDecisionPoint`, `DefaultPDP` |
| `jdlib.authz.permissions` | `Permission`, `PermissionCatalog` |
| `jdlib.authz.resource_types` | `ResourceTypeDefinition`, `ResourceTypeRegistry` |
| `jdlib.authz.scopes` | `ScopeRef`, `ResourceRef`, `Target`, `ScopeResolver` |
| `jdlib.authz.reader` | `AccessReader`, `ControlAccessReader`, `Binding` |
| `jdlib.authz.cache` | `AuthzCache` |
| `jdlib.control.enums` | `TenantStatus`, `PlacementStrategy`, `MigrationStatus`, `RelocationPhase`, `OperatorLevel`, `PrincipalType`, `ScopeType`, `MembershipStatus`, `InvitationStatus`, `ApiKeyStatus`, `ActorType`, `AuditSeverity` |
| `jdlib.control.registry` | `TenantRegistry`, `RegistryWriteFence`, `SeedHook` |
| `jdlib.control.audit` | `PlatformAudit`, `DatabaseAuditSink`, `CompositeAuditSink`, `RecordingPlatformAudit`, `PrivilegeAuditAdapter` |
| `jdlib.control.session` | `ControlPlaneSession` |
| `jdlib.control.purge` | `TenantPlanePurger` |
| `jdlib.migrations.runner` | `MigrationRunner` |
| `jdlib.persistence.session` | `TenantSession`, `RawSqlAuditor` |
| `jdlib.persistence.uow` | `UnitOfWork` |
| `jdlib.persistence.repository` | `TenantRepository` |
| `jdlib.persistence.router` | `SessionRouter` |
| `jdlib.persistence.models` | `tenant_table_map`, `WriteFence`, `NullWriteFence`, `privileged_bypass` |
| `jdlib.persistence.rawsql` | `RawSqlMode`, `RawSqlValidator`, `CompiledRawSql` |
| `jdlib.persistence.secrets` | `SecretProvider`, `MemorySecretProvider`, `EnvSecretProvider` |
| `jdlib.persistence.strategies.*` | strategy classes, `StrategyCapabilities`, `IsolationStrategy`, `DeprovisionMode`, `validate_schema_name`, `validate_database_handle`, `install_rls`, `verify_rls`, `emit_rls_policies`, `rls_eligible_tables` |
| `jdlib.tenancy.resolution` | `RequestInfo`, `TenantResolver`, 5 resolvers, `ResolverChain`, `build_chain` |
| `jdlib.tenancy.middleware` | `TenantMiddleware`, `http_status_for`, `PrincipalProvider` |
| `jdlib.tenancy.jobs` | `ContextPropagator`, `tenant_job` |
| `jdlib.models.base` | `TenantBase`, `TenantOwned`, `TenantRouted`, `Timestamped`, `SoftDelete`, `OwnableByOrg`, `OwnableByTeam`, `ownership_constraints` |
| `jdlib.models.audit_recorder` | `TenantAuditRecorder` |
| `jdlib.lint` | `LintIssue`, `lint_metadata`, `assert_clean` |
| `jdlib.context` | `Principal`, `PrincipalKind`, `PrivilegeContext`, `PrivilegeKind`, `TenantContext`, `TenantRef`, `TenantRecord`, `Clock`, `SystemClock`, `ContextFactory`, `EnvelopeCodec`, `TenantContextEnvelope`, `context_scope`, `current_tenant`, `current_principal`, `current_privilege`, `scoped_key`, and the six collaborator protocols |

**Internal (underscore-prefixed or clearly private):**

| Symbol | Location | Note |
|---|---|---|
| `_CTX` | `src/jdlib/context.py:99-101` | the single `ContextVar` |
| `_PrivilegeIssuer`, `PRIVILEGE_ISSUER` | `src/jdlib/context.py:167-171` | identity sentinel gating `for_system`/`for_test` |
| `_uuid.uuid7` | `src/jdlib/_uuid.py:8` | private module, imported by internal models |
| `_STATUS_MAP` | `src/jdlib/tenancy/middleware.py:26-35` | HTTP mapping table |
| `_transition`, `_servability_error`, `_advisory_lock` | `src/jdlib/control/registry.py` | registry internals |
| `_register_events`, `_context_of` | `src/jdlib/persistence/session.py:46-109` | SQLAlchemy event wiring |
| All `rawsql` private helpers | `src/jdlib/persistence/rawsql.py:42-143` | AST walking internals |

**Naming-package caveat:** `jdlib.models` and `jdlib.control` have **no**
`__init__.py`; they are namespace-package portions. `jdlib.authz`,
`jdlib.authn`, `jdlib.persistence`, `jdlib.tenancy`, and
`jdlib.persistence.strategies` have **empty** `__init__.py` files with no
re-exports. The security programme's namespaces are the exception: `jdlib.security`
and its sub-packages (`jdlib.security.audit`, `.authn`, `.authz`, `.gateway`,
`.compliance`) have **non-empty** `__init__.py` files that re-export their
deliberate public surface (§15.4, §8.22).

---

## 4. High-Level Architecture

### 4.1 Layering

`jdlib` is a four-layer library:

```mermaid
graph TB
    subgraph L4["Layer 4 — Adapters (optional deps)"]
        FA["integrations/fastapi.py"]
        CLI["integrations/cli.py"]
        ALE["migrations/runner.py + env.py"]
        RP["testing/pytest_plugin.py"]
    end

    subgraph L3["Layer 3 — Domain services"]
        CTXF["ContextFactory"]
        REG["TenantRegistry + RegistryWriteFence"]
        AC["AccessControl"]
        PDP["DefaultPDP / Enforcer / guards"]
        PDPORT["AccessReader / TenantDirectory / EntitlementChecker / OperatorAuthorizer / SecretProvider / SeedHook / PlatformAudit"]
    end

    subgraph L2["Layer 2 — Core enforcement"]
        TS["TenantSession (SQLAlchemy events)"]
        RSV["RawSqlValidator (pglast AST)"]
        UOW["UnitOfWork (fence + txn)"]
        REPO["TenantRepository"]
        CACHE["AuthzCache"]
        ENV["EnvelopeCodec / ContextPropagator"]
        LINT["lint_metadata"]
    end

    subgraph L1["Layer 1 — Value types and vocabularies"]
        CTX["TenantContext / Principal / PrivilegeContext"]
        ERR["errors.py (JdlibError)"]
        CFG["config.py (TenancyConfig)"]
        ENUM["control/enums.py + ScopeType + PermissionCatalog + ResourceTypeRegistry"]
        BASE["models/base.py + control/base.py (SQLAlchemy bases)"]
    end

    L4 --> L3
    L3 --> L2
    L2 --> L1
    L1 --> PG[("PostgreSQL")]
    L4 --> PG
```

Dependency direction is strictly downward. No import cycles exist in the
static module graph (verified in [§26](#26-accuracy-and-verification-notes)).

### 4.2 Component responsibilities

| Component | Responsibility | Key modules |
|---|---|---|
| Context subsystem | identity, authority, request scope, cross-hop propagation | `context.py`, `tenancy/resolution.py`, `tenancy/jobs.py` |
| Request pipeline | ASGI authentication → tenant resolution → context install → cleanup; error-to-HTTP mapping | `tenancy/middleware.py` |
| Control plane | tenant metadata, placement, lifecycle, users/service accounts/API keys, audit | `control/*` |
| Isolation strategies | physical placement provisioning, session production, deprovisioning | `persistence/strategies/*` |
| Data access | tenant-scoped session, repository, unit of work, session routing | `persistence/session.py`, `repository.py`, `uow.py`, `router.py` |
| Raw SQL gate | AST-level tenant proof and privileged escape hatch | `persistence/rawsql.py` |
| Authentication | OIDC, API keys, composition, wiring adapters | `authn/*` |
| Authorization | vocabulary, scope resolution, decisions, mutations | `authz/*` |
| Migrations | in-memory Alembic configuration and two baselines | `migrations/*` |
| Schema governance | metadata invariant linter | `lint.py` |
| Consumer tooling | FastAPI deps, Typer CLI, pytest fixtures, assertions | `integrations/*`, `testing/*` |

### 4.3 Package-level architecture

```mermaid
graph LR
    CONSUMER["Consumer app"] --> PUBAPI["jdlib (13 exports)"]
    PUBAPI --> CTX["context + tenancy"]
    PUBAPI --> PERS["persistence"]
    PUBAPI --> REG["control.registry"]
    PUBAPI --> AUTHZ["authz"]
    PUBAPI --> ERR["errors"]

    CTX --> CFG["config"]
    CTX --> ENUM["control.enums"]
    PERS --> MODELS["models"]
    PERS --> STRAT["persistence.strategies"]
    REG --> STRAT
    REG --> MIG["migrations.runner"]
    REG --> PURGE["control.purge"]
    AUTHZ --> CTRL["control.models + control.session"]
    AUTHN["authn"] --> CTRL
    AUTHN --> TENRES["tenancy.resolution"]
    AUTHZ --> SCOPES["authz.scopes"]
    SCOPES --> PERS
    CLI["integrations.cli"] --> LINT["lint"]
    CLI --> RLS["strategies.rls"]
    FASTAPI["integrations.fastapi"] --> MW["tenancy.middleware"]
    FASTAPI --> GUARDS["authz.guards"]
    TESTING["testing"] --> PERS
```

### 4.4 Public API flow

```mermaid
sequenceDiagram
    autonumber
    participant App as Consumer handler
    participant Ctx as current_tenant()
    participant UoW as UnitOfWork
    participant Fence as RegistryWriteFence
    participant TS as TenantSession
    participant Repo as TenantRepository
    participant DB as PostgreSQL

    App->>Ctx: read ambient context
    Ctx-->>App: TenantContext (or raise MissingTenantContext)
    App->>UoW: __aenter__(context, fence=…)
    UoW->>Fence: assert_writable(tenant_id)
    Fence->>DB: read tenants + migration state + relocations
    DB-->>Fence: servability rows
    UoW->>TS: wrap AsyncSession
    App->>Repo: list() / get() / add() / count()
    Repo->>TS: ORM statement
    TS->>TS: do_orm_execute → with_loader_criteria(tenant_id)
    TS->>DB: SELECT … WHERE tenant_id = $1
    DB-->>App: rows
    App->>UoW: __aexit__(no exception)
    UoW->>TS: commit + close
```

---

## 5. Module Architecture

### 5.1 Module inventory (64 pre-hardening modules + 2 Mako templates)

The modules the library shipped at `a30601d`. The security programme's modules
(added by phases 1–10) are inventoried separately in §5.3.

| Module | Purpose | Public classes/functions | Depends on |
|---|---|---|---|
| `jdlib.__init__` | curated public surface | 13 re-exports, `__version__` | authz.access, authz.guards, config, context, control.registry, errors, persistence.repository, persistence.uow |
| `jdlib._uuid` | UUIDv7 generation | `uuid7()` | stdlib only |
| `jdlib.config` | settings schema | `ResolverName`, `ContextConfig`, `ResolverConfig`, `OidcConfig`, `ApiKeyConfig`, `RlsConfig`, `TenancyConfig` | pydantic, pydantic_settings |
| `jdlib.context` | identity + context factory + envelopes | see §3.3 | config, control.enums, errors |
| `jdlib.errors` | exception hierarchy | `JdlibError` + 27 subclasses | stdlib only |
| `jdlib.lint` | metadata invariants | `LintIssue`, `lint_metadata`, `assert_clean` | sqlalchemy, control.base, errors, models.base |
| `jdlib.authn.base` | authn port + helpers | `Authenticator`, `record_authn_failure`, `bearer_token` | context, control.audit, tenancy.resolution |
| `jdlib.authn.apikey` | API-key authentication | `ParsedApiKey`, `parse_api_key`, `hash_api_key_secret`, `verify_api_key_secret`, `ApiKeyAuthenticator` | argon2, sqlalchemy, control.models/session/audit, context, config, errors |
| `jdlib.authn.oidc` | OIDC authentication | `JwksCache`, `TokenVerifier`, `IdentityClaims`, `ClaimMapper`, `UserLinker`, `OidcAuthenticator` | pyjwt, sqlalchemy, control.models/session/audit, context, config, errors, `_uuid` |
| `jdlib.authn.composite` | authenticator fan-in | `CompositeAuthenticator` | authn.base |
| `jdlib.authn.wiring` | assembly + adapters | `fetch_jwks`, `build_authenticator`, `PrincipalDirectoryAdapter`, `TenantDirectoryAdapter`, `EntitlementAdapter` | httpx, authn.*, authz.reader, control.registry |
| `jdlib.authz.permissions` | permission vocabulary | `Permission`, `PermissionCatalog` | control.enums, errors |
| `jdlib.authz.resource_types` | resource type vocabulary | `ResourceTypeDefinition`, `ResourceTypeRegistry` | authz.permissions, errors |
| `jdlib.authz.scopes` | scope chain computation | `ScopeRef`, `ResourceRef`, `Target`, `ScopeResolver` | authz.resource_types, control.enums, models.org, persistence.session |
| `jdlib.authz.reader` | authorization reads | `Binding`, `principal_key`, `AccessReader`, `ControlAccessReader` | sqlalchemy, control.models/session, context, control.enums |
| `jdlib.authz.pdp` | decision evaluation | `MatchedRule`, `Decision`, `PolicyDecisionPoint`, `DefaultPDP` | authz.{cache,permissions,reader,scopes}, context, errors, persistence.session |
| `jdlib.authz.cache` | request-scoped memo | `AuthzCache` | stdlib only |
| `jdlib.authz.guards` | enforcement helpers | `tenant_target`, `Enforcer`, `requires`, `authorize` | authz.{pdp,scopes}, context, control.enums, errors |
| `jdlib.authz.access` | authorization mutations | `AccessControl`, `ScopeRecord`, `ResourceRecord`, `ScopeLookup`, `ResourceLookup`, `TenantWriteSession`, `build_invitation_token`, `hash_invitation_secret`, `verify_invitation` | argon2, sqlalchemy, control.models/session/audit, authz.{cache,permissions,reader,resource_types}, models.org, context, errors, `_uuid` |
| `jdlib.control.base` | control metadata | `CONTROL_SCHEMA`, `NAMING_CONVENTION`, `ControlBase` | sqlalchemy |
| `jdlib.control.enums` | control vocabularies | 12 `StrEnum`s + `sql_in` | stdlib only |
| `jdlib.control.models` | control schema | 16 ORM models | sqlalchemy, control.base/enums, `_uuid` |
| `jdlib.control.audit` | platform audit | `PlatformAudit`, `NullPlatformAudit`, `RecordingPlatformAudit`, `DatabaseAuditSink`, `CompositeAuditSink`, `PrivilegeAuditAdapter` | sqlalchemy, control.session, context, errors |
| `jdlib.control.registry` | lifecycle authority | `TenantRegistry`, `RegistryWriteFence`, `SeedHook` | sqlalchemy, control.{audit,enums,models,purge,session}, errors, migrations.runner, persistence.strategies.{base,database,deprovision,schema}, context |
| `jdlib.control.purge` | tenant-plane purge | `TenantPlanePurger` | sqlalchemy, config, context, models.base, persistence.models/session |
| `jdlib.control.session` | control session wrapper | `ControlPlaneSession` | sqlalchemy |
| `jdlib.integrations.fastapi` | FastAPI adapter | `JdlibContainer`, `install`, `get_context`, `get_uow`, `require` | fastapi, starlette, authz.guards/scopes, context, errors, persistence.uow, tenancy.middleware/resolution |
| `jdlib.integrations.cli` | Typer CLI | `app` (+ 5 sub-apps, incl. `security_app`) | typer, sqlalchemy, control.*, errors, lint, migrations.runner, models.base, persistence.strategies.{rls,schema,shared}, security.compliance(.session), security.config |
| `jdlib.migrations.runner` | programmatic Alembic | `MigrationRunner` | alembic, sqlalchemy, control.base, errors |
| `jdlib.migrations.control.env` | control Alembic env | `run_migrations_offline/online` | alembic, sqlalchemy, control.models/base |
| `jdlib.migrations.tenant.env` | tenant Alembic env | `run_migrations_offline/online` | alembic, sqlalchemy, models.* |
| `jdlib.models.base` | tenant metadata + mixins | `TenantBase`, `TenantOwned`, `TenantRouted`, `Timestamped`, `SoftDelete`, `OwnableByOrg`, `OwnableByTeam`, `ownership_constraints` | sqlalchemy, control.base |
| `jdlib.models.org` | example org graph | `Organization`, `Team` | sqlalchemy, models.base, `_uuid` |
| `jdlib.models.settings` | example KV model | `TenantSetting` | sqlalchemy, models.base |
| `jdlib.models.audit` | tenant audit model | `AuditEvent` | sqlalchemy, control.enums, models.base, `_uuid` |
| `jdlib.models.audit_recorder` | tenant audit writer | `TenantAuditRecorder` (`record`, `record_security`) | context, models.audit, security.audit, security.context |
| `jdlib.persistence.models` | tenant model discovery + fence port | `tenant_table_map`, `WriteFence`, `NullWriteFence`, `privileged_bypass` | context, models.base |
| `jdlib.persistence.session` | scoped session | `TenantSession`, `RawSqlAuditor` | sqlalchemy, context, errors, models.base, persistence.models, persistence.rawsql |
| `jdlib.persistence.rawsql` | raw SQL proof | `RawSqlMode`, `CompiledRawSql`, `RawSqlValidator` | pglast, sqlalchemy, errors, persistence.models |
| `jdlib.persistence.uow` | unit of work | `UnitOfWork` | context, persistence.models/session |
| `jdlib.persistence.repository` | scoped repository | `TenantRepository[ModelT]` | sqlalchemy, persistence.session |
| `jdlib.persistence.router` | strategy dispatch | `SessionRouter` | sqlalchemy, context, control.enums, errors, persistence.strategies.base |
| `jdlib.persistence.secrets` | secret ports | `SecretProvider`, `MemorySecretProvider`, `EnvSecretProvider` | stdlib only |
| `jdlib.persistence.strategies.base` | strategy port | `StrategyCapabilities`, `IsolationStrategy` | context, migrations.runner, persistence.strategies.deprovision |
| `jdlib.persistence.strategies.deprovision` | deprovision modes | `DeprovisionMode` | stdlib only |
| `jdlib.persistence.strategies.shared` | shared-schema strategy | `SharedSchemaStrategy` | config, context, errors, migrations.runner, strategies.base/deprovision |
| `jdlib.persistence.strategies.schema` | schema strategy | `validate_schema_name`, `SchemaPerTenantStrategy` | context, errors, migrations.runner, strategies.base/deprovision |
| `jdlib.persistence.strategies.database` | database strategy | `validate_database_handle`, `DatabasePerTenantStrategy` | context, errors, migrations.runner, persistence.secrets, strategies.base/deprovision |
| `jdlib.persistence.strategies.rls` | RLS install/inspect/verify | `rls_eligible_tables`, `emit_rls_policies`, `install_rls`, `RlsInspection`, `inspect_rls`, `verify_rls` | sqlalchemy, errors, models.base |
| `jdlib.tenancy.resolution` | tenant resolution | `RequestInfo`, `TenantResolver`, `JwtClaimResolver`, `SubdomainResolver`, `PathResolver`, `HeaderResolver`, `ApiKeyResolver`, `ResolverChain`, `build_chain` | config, context |
| `jdlib.tenancy.middleware` | ASGI pipeline | `http_status_for`, `PrincipalProvider`, `TenantMiddleware` | context, errors, tenancy.resolution |
| `jdlib.tenancy.jobs` | cross-hop context | `ContextPropagator`, `tenant_job` | context, errors |
| `jdlib.testing.assertions` | isolation assertions | `assert_scoped_count`, `assert_tenant_isolated`, `assert_cross_tenant_write_rejected` | sqlalchemy, context, errors, persistence.session |
| `jdlib.testing.pytest_plugin` | consumer fixtures | `jdlib_test_models` + 5 fixtures | pytest, optional pytest_asyncio, sqlalchemy, models.base |

### 5.2 Module dependency graph (verified static imports)

```mermaid
graph LR
    subgraph root["root modules"]
        JD["jdlib"]
        CFG["config"]
        CTX["context"]
        ERR["errors"]
        LINT["lint"]
        UUID["_uuid"]
    end

    subgraph model["models"]
        MB["models.base"]
        MORG["models.org"]
        MSET["models.settings"]
        MAUD["models.audit"]
        MAREC["models.audit_recorder"]
    end

    subgraph control["control"]
        CB["control.base"]
        CE["control.enums"]
        CM["control.models"]
        CS["control.session"]
        CA["control.audit"]
        CREG["control.registry"]
        CPURGE["control.purge"]
    end

    subgraph pers["persistence"]
        PM["persistence.models"]
        PS["persistence.session"]
        PRAW["persistence.rawsql"]
        PUOW["persistence.uow"]
        PREPO["persistence.repository"]
        PROUT["persistence.router"]
        PSEC["persistence.secrets"]
        SB["strategies.base"]
        SDEP["strategies.deprovision"]
        SSH["strategies.shared"]
        SSC["strategies.schema"]
        SD["strategies.database"]
        SR["strategies.rls"]
    end

    subgraph auth["authn + authz"]
        ANB["authn.base"]
        ANK["authn.apikey"]
        ANO["authn.oidc"]
        ANC["authn.composite"]
        ANW["authn.wiring"]
        AZP["authz.permissions"]
        AZR["authz.resource_types"]
        AZS["authz.scopes"]
        AZRD["authz.reader"]
        AZPDP["authz.pdp"]
        AZC["authz.cache"]
        AZG["authz.guards"]
        AZA["authz.access"]
    end

    subgraph tctx["tenancy"]
        TR["tenancy.resolution"]
        TM["tenancy.middleware"]
        TJ["tenancy.jobs"]
    end

    MIG["migrations.runner"]

    JD --> CFG
    JD --> CTX
    JD --> ERR
    JD --> CREG
    JD --> AZA
    JD --> AZG
    JD --> PUOW
    JD --> PREPO

    CTX --> CFG
    CTX --> CE
    CTX --> ERR

    LINT --> CB
    LINT --> MB
    LINT --> ERR

    MB --> CB
    CM --> CB
    CM --> CE
    CM --> UUID
    MAUD --> CE
    MORG --> UUID
    MAREC --> MAUD
    MAREC --> CTX

    CE -.used by.-> AZP
    CB --> MIG

    PS --> PM
    PS --> PRAW
    PS --> CTX
    PS --> ERR
    PRAW --> PM
    PRAW --> ERR
    PRAW --> AZPDP
    PREPO --> PS
    PUOW --> PS
    PUOW --> PM
    PM --> MB
    PM --> CTX
    PROUT --> SB
    SD --> PSEC
    SSH --> CFG
    SR --> MB
    SSC --> MIG
    SD --> MIG
    SSH --> MIG
    SB --> MIG
    SB --> SDEP
    SSH --> SDEP
    SSC --> SDEP
    SD --> SDEP

    CREG --> CM
    CREG --> CA
    CREG --> CS
    CREG --> CE
    CREG --> ERR
    CREG --> CTX
    CREG --> CPURGE
    CREG --> MIG
    CREG --> SB
    CREG --> SD
    CREG --> SDEP
    CREG --> SSC
    CPURGE --> PM
    CPURGE --> PS
    CPURGE --> CFG
    CA --> CS
    CA --> CTX

    ANB --> TR
    ANB --> CTX
    ANK --> ANB
    ANK --> CM
    ANK --> CS
    ANO --> ANB
    ANO --> CM
    ANO --> UUID
    ANC --> ANB
    ANW --> ANK
    ANW --> ANO
    ANW --> ANC
    ANW --> AZRD
    ANW --> CREG

    AZP --> CE
    AZR --> AZP
    AZS --> AZR
    AZS --> MORG
    AZS --> PS
    AZRD --> CM
    AZRD --> CS
    AZPDP --> AZRD
    AZPDP --> AZS
    AZPDP --> AZP
    AZPDP --> AZC
    AZPDP --> PS
    AZG --> AZPDP
    AZG --> AZS
    AZA --> AZRD
    AZA --> AZP
    AZA --> AZR
    AZA --> AZC
    AZA --> CM
    AZA --> CS
    AZA --> CA
    AZA --> MORG
    AZA --> UUID

    TM --> TR
    TM --> CTX
    TM --> ERR
    TJ --> CTX
    TR --> CFG
```

Leaves (no intra-package imports): `_uuid`, `config`, `errors`, `authn`,
`authz`, `authz.cache`, `control.base`, `control.enums`, `control.session`,
`integrations`, `migrations`, `persistence`, `persistence.secrets`,
`persistence.strategies`, `persistence.strategies.deprovision`, `tenancy`.
**No import cycles** exist in the static graph.

### 5.3 Security-programme module inventory (`jdlib.security.*`)

Added by the security-hardening programme (phases 1–10; see §15.4 for the phase
documents). "Public names" counts `__all__` entries; "Depends on" lists
module-level `jdlib.*` imports only. Third-party module-level imports across the
whole namespace are limited to `pydantic` (the configuration models),
`sqlalchemy` (`audit/export.py`, `compliance/session.py`), `pyjwt` (parts of
`authn/`) and `httpx` (the two `transports.py` modules, behind the `http`
extra); no web framework and no OpenTelemetry SDK is imported anywhere.

| Module | Purpose | Public names | Depends on |
|---|---|---|---|
| `jdlib.security` | curated core surface | 38 re-exports | security.{config,context,errors,interfaces,responses} |
| `jdlib.security.config` | `SecurityConfig` + sections, `validate_security_config`, `assert_strong_signing_key` | 13 | security.errors |
| `jdlib.security.context` | `SecurityContext`, `RequestIds`, `AuthMethod`, `TokenMetadata`, contextvar binding | 8 | context, errors |
| `jdlib.security.errors` | `SecurityCode`/`SecurityDescriptor`, `describe_error`, `www_authenticate` | 8 | errors |
| `jdlib.security.identity` | service-identity formalisation (`IdentityKind`, `ServiceIdentity`) | 5 | context, errors |
| `jdlib.security.interfaces` | `GatewayAdapter`, `TokenProvider`, `TokenValidator`, `RateLimiter`, … | 8 | security.context, tenancy.resolution |
| `jdlib.security.redaction` | `REDACTED`, `SECRET_PATTERNS`, `SENSITIVE_KEYS`, `redact_text`, `is_sensitive_key` | 5 | stdlib only |
| `jdlib.security.responses` | `ErrorResponse`, `error_response`, `MAX_MESSAGE_LENGTH` | 3 | security.{context,errors,redaction} |
| `jdlib.security.telemetry` | structured logs, bounded metrics, `safe_emit` (phase 7) | 8 | security.{context,redaction} |
| `jdlib.security.tracing` | W3C trace context and security spans (phase 7) | 12 | security.{context,redaction} |
| `jdlib.security.audit` | audit namespace surface | 26 re-exports | security.audit.{access,adapters,emitters,events,export} |
| `jdlib.security.audit.events` | `SecurityEventType`, `SecurityAuditEvent`, `audit_metadata` | 5 | `_uuid`, security.{context,redaction} |
| `jdlib.security.audit.emitters` | `SecurityEventSink`, `TransactionAuditSink`, `authorization_audit_observer` | 6 | audit.events, security.authz.decision |
| `jdlib.security.audit.access` | `AuditAccess`, `AuditCapability` | 2 | errors |
| `jdlib.security.audit.export` | `AuditQuery`, `AuditPage`, `read_events`, `export_events`, renderers | 10 | models.audit, audit.{access,events} |
| `jdlib.security.audit.adapters` | `AuditControlPlaneAudit`, `AuditPrivilegeAudit`, `AuditRawSqlAuditor` | 5 | context, persistence.rawsql, audit.{emitters,events} |
| `jdlib.security.authn` | authentication namespace surface | 16 re-exports | security.authn.{algorithms,jwt,provider,zitadel} |
| `jdlib.security.authn.algorithms` | `ASYMMETRIC_ALGORITHMS`, `assert_safe_algorithms` | 2 | security.errors |
| `jdlib.security.authn.jwt` | `JwtTokenValidator`, `JwtClaimMapping`, `SigningKeySource` | 3 | authn.oidc, config, context, errors, security.* |
| `jdlib.security.authn.provider` | `ClientCredentialsTokenProvider`, `ClientCredentialsConfig`, `ClientAuthMethod` | 6 | context, errors, security.* |
| `jdlib.security.authn.zitadel` | `ZitadelConfig`, `build_zitadel_token_validator/provider`, `zitadel_provider_config` | 5 | authn.oidc, security.* |
| `jdlib.security.authn.transports` | HTTP transports for authentication (the `http` extra) | 3 | security.authn.provider |
| `jdlib.security.authz` | authorization namespace surface | 8 re-exports | security.authz.{cerbos,decision,interfaces,pep} |
| `jdlib.security.authz.decision` | `AuthorizationDecision`, `AuthorizationQuery`, `Effect` | 3 | stdlib only |
| `jdlib.security.authz.interfaces` | `PolicyDecisionPoint` port | 1 | security.authz.decision |
| `jdlib.security.authz.cerbos` | `CerbosPDP`, `CerbosConfig`, `CerbosTransport` | 3 | context, security.authz.decision, security.errors |
| `jdlib.security.authz.pep` | `AuthorizationPEP` | 2 | errors, security.{authz.decision,authz.interfaces,context} |
| `jdlib.security.authz.transports` | HTTP transport for Cerbos (the `http` extra) | 2 | `httpx` only |
| `jdlib.security.gateway` | gateway namespace surface | 5 re-exports | security.gateway.{adapters,config} |
| `jdlib.security.gateway.adapters` | `NoGatewayAdapter`, `KongGatewayAdapter`, `TykGatewayAdapter` | 3 | context, security.{gateway.config,interfaces}, tenancy.resolution |
| `jdlib.security.gateway.config` | `GatewayConfig`, `GatewayMode` | 3 | security.errors |
| `jdlib.security.compliance` | compliance namespace surface (§8.22) | 22 re-exports | security.compliance.{controls,evidence,posture} |
| `jdlib.security.compliance.controls` | `CONTROL_REGISTRY` and the control model | 10 | stdlib only |
| `jdlib.security.compliance.evidence` | `SecurityEvidence` and the checkout-side collectors | 8 | `_uuid`, context, security.audit, security.config |
| `jdlib.security.compliance.posture` | outcomes, findings, report, rules, `evaluate_posture` | 7 | context, security.compliance.{controls,evidence}, security.config |
| `jdlib.security.compliance.session` | `collect_isolation_evidence`, `collect_schema_revision_evidence` | 2 | context, models.base, persistence.strategies.rls, security.compliance.evidence |

The graph is acyclic and layered: `redaction`, `compliance.controls` and
`authz.decision` are the leaves. `compliance.session` is the **only** module in
the security tree that imports the persistence layer (§8.22). Inside the
pre-hardening tree only two modules import the security namespace:
`models/audit_recorder.py` (the security-audit envelope and the ambient security
context) and `integrations/cli.py` (the `security` sub-app, §8.20).

---

## 6. Public API Architecture

### 6.1 The 13 top-level exports

`src/jdlib/__init__.py:11-25` (authoritative; asserted by
`tests/unit/test_public_api.py:9-25`):

```python
__all__ = [
    "AccessControl", "ContextFactory", "JdlibError", "TenancyConfig",
    "TenantContext", "TenantRegistry", "TenantRepository", "UnitOfWork",
    "authorize", "current_principal", "current_tenant", "errors", "requires",
]
```

---

#### `TenancyConfig`

* **Import path:** `from jdlib import TenancyConfig` (`jdlib.config.TenancyConfig`)
* **Purpose:** pydantic-settings model holding every deployment-level setting.
* **Signature:** `TenancyConfig()` — constructed from keyword arguments and/or
  `JDLIB_*` environment variables (`env_prefix="JDLIB_"`,
  `env_nested_delimiter="__"`, `src/jdlib/config.py:70-78`).
* **Fields:** `control_dsn: SecretStr | None = None`, `context: ContextConfig`
  (required), `resolvers: ResolverConfig = ResolverConfig()`,
  `oidc: OidcConfig | None = None`, `api_keys: ApiKeyConfig = ApiKeyConfig()`,
  `rls: RlsConfig = RlsConfig()`.
* **Returns:** a validated instance.
* **Exceptions:** `pydantic.ValidationError` — e.g. missing
  `JDLIB_CONTEXT__SIGNING_KEY` (`src/jdlib/config.py:19` is required), or
  `path_prefix` not starting with `/`
  (`src/jdlib/config.py:38-43`).
* **Side effects:** none; no I/O, no engine creation.
* **Secrets:** `control_dsn` and `context.signing_key` are `SecretStr`; they are
  excluded from `repr` (`tests/unit/test_config.py:48-51`).
* **Concurrency:** stateless and immutable-by-convention; the library has **no**
  settings singleton or cached `get_settings()` — every caller constructs it.

```python
config = TenancyConfig()                                    # env-driven
config = TenancyConfig(context={"signing_key": "…"})         # code-driven
dsn = config.control_dsn.get_secret_value()                  # unwrap explicitly
```

---

#### `TenantContext`

* **Import path:** `from jdlib import TenantContext` (`jdlib.context.TenantContext`)
* **Purpose:** immutable, request-scoped identity + tenant + authority object.
* **Signature:** frozen, slotted dataclass (`src/jdlib/context.py:63-72`):

```python
@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: uuid.UUID
    tenant_slug: str
    strategy: PlacementStrategy
    principal: Principal
    request_id: str
    correlation_id: str
    trace_id: str | None = None
    privilege: PrivilegeContext | None = None
```

* **Notes:** it deliberately does **not** carry tenant status or
  `target_handle`; servability and placement resolution are separate
  lookups. `correlation_id` is always populated because
  `ContextFactory._build` falls back to `request_id`
  (`src/jdlib/context.py:212-221`).
* **Exceptions:** none on construction.
* **Concurrency:** immutable; safe to share across tasks.

---

#### `current_tenant` / `current_principal`

* **Import paths:** `from jdlib import current_tenant, current_principal`
* **Signatures:** `def current_tenant() -> TenantContext` and
  `def current_principal() -> Principal` (`src/jdlib/context.py:113-121`).
* **Behavior:** read the module `ContextVar` `_CTX`
  (`src/jdlib/context.py:99-101`). `current_principal()` delegates to
  `current_tenant().principal`.
* **Exceptions:** `MissingTenantContext("no tenant context is active")` when
  unset — **fail closed**.
* **Concurrency:** `contextvars` are task-local and copy-on-task-creation, so a
  context installed in one request/task is not visible to a sibling task.
* **Example:**

```python
from jdlib import current_tenant

tenant_id = current_tenant().tenant_id      # raises if no context
```

---

#### `ContextFactory`

* **Import path:** `from jdlib import ContextFactory`
* **Purpose:** the single authority that turns a principal + tenant reference
  into a `TenantContext` after fail-closed checks.
* **Constructor** (`src/jdlib/context.py:174-194`):

```python
ContextFactory(
    *,
    config: ContextConfig,
    principals: PrincipalDirectory,
    tenants: TenantDirectory,
    servability: ServabilityChecker,
    entitlements: EntitlementChecker,
    operators: OperatorAuthorizer,
    audit: PrivilegeAudit,
    clock: Clock | None = None,
)
```

* **Methods:** `for_principal`, `for_operator`, `for_system`, `for_test` — see
  [§8.1](#81-tenant-context-and-contextfactory).
* **Side effects:** every privileged path writes an audit record **before**
  returning; `for_system`/`for_test` also mint a random `request_id`.
* **Exceptions:** `UnknownPrincipal`, `TenantNotFound`,
  `TenantAccessDenied`, `TenantSuspended`, `AuthorizationError`.
* **Consumer wiring:** `README.md:176-194` shows the production wiring using
  `PrincipalDirectoryAdapter`, `TenantDirectoryAdapter`,
  `EntitlementAdapter`, `RegistryWriteFence`-free `registry` as the
  `ServabilityChecker`, and `PrivilegeAuditAdapter`.

---

#### `UnitOfWork`

* **Import path:** `from jdlib import UnitOfWork`
* **Purpose:** the write-admission gate and transaction lifecycle for tenant
  data access.
* **Signature** (`src/jdlib/persistence/uow.py:11-24`):

```python
UnitOfWork(
    session_factory: Callable[[], Any],
    context: TenantContext,
    *,
    fence: WriteFence,
    auditor: RawSqlAuditor | None = None,
)
```

* **Returns:** an async context manager whose `__aenter__` yields a
  `TenantSession`.
* **Exceptions:** propagates `TenantNotWritable`/`TenantNotFound` from the
  fence before any session is opened; rolls back on body exceptions.
* **Side effects:** `fence.assert_writable()` → `TenantSession(session, context,
  auditor=…)` → `commit()` on clean exit, `rollback()` on exception, `close()`
  always (`src/jdlib/persistence/uow.py:26-41`).
* **Concurrency:** the fence is an **admission-time check**, not a lock held for
  the transaction's duration. There is no optimistic version column, no
  `SELECT … FOR UPDATE`, and no re-check at commit. See
  [§16.3](#163-concurrency-model) and [§23](#23-current-limitations).

```python
async with UnitOfWork(tenant_sessions, context, fence=write_fence) as session:
    invoices = await TenantRepository(session, Invoice).list()
```

---

#### `TenantRepository`

* **Import path:** `from jdlib import TenantRepository`
* **Purpose:** scoped CRUD helper for `TenantRouted` models.
* **Signature** (`src/jdlib/persistence/repository.py:13-16`):

```python
class TenantRepository[ModelT]:
    def __init__(self, session: TenantSession, model: type[ModelT]) -> None
```

* **Methods** (`src/jdlib/persistence/repository.py:24-77`):
  `get(entity_id)`, `list(*criteria, order_by=None, limit=None, offset=None)`,
  `add(obj)`, `update(obj, **changes)`, `soft_delete(obj)`, `count(*criteria)`.
* **Exceptions:** `CrossTenantReferenceError` when flushing a row owned by
  another tenant (raised by `TenantSession.before_flush`); `TypeError` from
  `soft_delete` when the model has no `deleted_at`.
* **Side effects:** `add`/`update`/`soft_delete` `flush()`; they never commit —
  the `UnitOfWork` owns the transaction.
* **Details:** soft-delete support is duck-typed by the presence of
  `deleted_at`; for soft-deletable models, `get()` issues a live-row `SELECT`
  rather than using the identity map; a bare `Table` is never accepted because
  `TenantSession` rejects untrusted table-level queries.

---

#### `TenantRegistry`

* **Import path:** `from jdlib import TenantRegistry`
* **Purpose:** the control-plane lifecycle authority (create/provision/
  migrate/suspend/resume/archive/deprovision + servability).
* **Constructor** (`src/jdlib/control/registry.py:143-165`):

```python
TenantRegistry(
    *,
    session_factory: Callable[[], AsyncSession],
    strategies: Mapping[PlacementStrategy, IsolationStrategy],
    runner: MigrationRunner,
    audit: PlatformAudit,
    seeder: SeedHook | None = None,
    desired_version: str = "0001_tenant_baseline",
    purger: TenantPlanePurger | None = None,
)
```

* **Methods:** `get`, `create`, `provision`, `migrate`, `suspend`, `resume`,
  `archive`, `deprovision`, `assert_servable`, `list_for_user`, `find`.
  There is **no** public `purge`, `relocate`, or generic `transition` method
  (`src/jdlib/control/registry.py:194-623`).
* **Exceptions:** `ProvisioningError`, `TenantOperationInProgress`,
  `TenantNotFound`, `TenantSuspended`, `StrategyCapabilityError`.
* **Side effects:** control-plane writes, advisory locks, strategy DDL,
  migrations, seeding, platform audit.
* **Concurrency:** serialization is via PostgreSQL transaction advisory locks
  `jdlib:tenant:{id}`, `jdlib:tenant-slug:{slug}`,
  `jdlib:tenant-handle:{handle}` (`src/jdlib/control/registry.py:285-304`).
  Multi-process safe against the same control database.

---

#### `AccessControl`

* **Import path:** `from jdlib import AccessControl`
* **Purpose:** the authorization **mutation** authority (roles, bindings,
  grants, invitations, ownership transfer, team movement) with anti-escalation
  and auditing.
* **Constructor** (`src/jdlib/authz/access.py:120-140`):

```python
AccessControl(
    *,
    session_factory: Callable[[], AsyncSession],
    catalog: PermissionCatalog,
    reader: AccessReader,
    cache: AuthzCache,
    audit: PlatformAudit,
    registry: ResourceTypeRegistry | None = None,
    scope_lookup: ScopeLookup | None = None,
    resource_lookup: ResourceLookup | None = None,
)
```

* **Public methods:** `actor_permissions`, `create_role`, `update_role`,
  `delete_role`, `bind_role`, `unbind_role`, `grant_resource`, `revoke_grant`,
  `transfer_resource`, `move_team`, `invite`, `accept_invitation`.
* **Exceptions:** `PermissionDenied`, `RoleEscalationBlocked`,
  `UnknownPermission`, `UnknownResourceType`, `InvalidResourcePermission`,
  `RoleScopeMismatch`, `InvalidReference`, `AuthorizationError`.
* **Side effects:** control-plane rows, `AuthzCache.invalidate()` before every
  attempted mutation, advisory locks in `unbind_role` and `invite`, Argon2
  invitation-token hashing, platform audit.
* **Not in this service:** membership management, API-key issuance,
  authentication, and decision evaluation (those are `reader`/PDP concerns).

---

#### `requires` and `authorize`

* **Import paths:** `from jdlib import requires, authorize`
  (`jdlib.authz.guards`)
* **Signatures** (`src/jdlib/authz/guards.py:34-58`):

```python
def requires(
    permission: str,
    *,
    enforcer: Enforcer,
    target_factory: Callable[..., Target] | None = None,
) -> Callable[[F], F]: ...

async def authorize(
    permission: str, target: Target, *, enforcer: Enforcer, session: object
) -> Decision: ...
```

* **Behavior:** both ultimately call `Enforcer.require`, which evaluates the
  PDP with the ambient context and raises `PermissionDenied(f"{permission}: {
  decision.reason}")` on denial (`src/jdlib/authz/guards.py:20-31`).
* **`requires` specifics:** the wrapped function runs only after authorization
  succeeds; the session is taken from `kwargs.get("session")` **only** — a
  positional or differently named session argument yields `session=None` and a
  `MissingTenantContext` from the PDP. The default target is `tenant_target()`.
* **Exceptions:** `PermissionDenied`, plus any PDP exception (e.g.
  `UnknownPermission`).

---

#### `JdlibError` and `errors`

* **Import paths:** `from jdlib import JdlibError, errors`
* **Purpose:** the single exception family that crosses module boundaries
  (`README.md:389-390`); `errors` exposes all 27 subclasses via `__all__`
  (`src/jdlib/errors.py:119-147`).
* **Shape:** every class subclasses `JdlibError(Exception)`. Only three define
  custom constructors: `TenantNotFound(tenant)`,
  `CrossTenantReferenceError(reference, expected_tenant, actual_tenant)`, and
  `SchemaLintError(issues)` (which stores `self.issues`). The rest use the
  default constructor.
* **Mapping to HTTP:** via `jdlib.tenancy.middleware.http_status_for` — see
  [§13.3](#133-error-to-http-status-mapping).

---

### 6.2 De facto public submodule entry points

| Symbol | Import path | Signature (verbatim) |
|---|---|---|
| `install` | `jdlib.integrations.fastapi` | `install(app: FastAPI, *, factory: ContextFactory, chain: ResolverChain, principal_provider: PrincipalProvider, container: JdlibContainer | None = None) -> None` |
| `JdlibContainer` | `jdlib.integrations.fastapi` | dataclass: `session_factory`, `uow_factory`, `enforcer` |
| `get_context` | `jdlib.integrations.fastapi` | `async def get_context() -> TenantContext` |
| `get_uow` | `jdlib.integrations.fastapi` | `async def get_uow(request: Request) -> AsyncIterator[UnitOfWork]` |
| `require` (FastAPI) | `jdlib.integrations.fastapi` | `require(permission: str, target_factory: Callable[..., Target] | None = None) -> Callable[[Request], Awaitable[None]]` |
| `app` (Typer) | `jdlib.integrations.cli` | `app = typer.Typer(no_args_is_help=True)` |
| `TenantSession` | `jdlib.persistence.session` | `TenantSession(session: AsyncSession, context: TenantContext | None, *, auditor: RawSqlAuditor | None = None, validator: RawSqlValidator | None = None)` |
| `SessionRouter` | `jdlib.persistence.router` | `SessionRouter(strategies: Mapping[PlacementStrategy, IsolationStrategy])` |
| `MigrationRunner` | `jdlib.migrations.runner` | `MigrationRunner(database_url: str)` |
| `RegistryWriteFence` | `jdlib.control.registry` | `RegistryWriteFence(*, session_factory: Callable[[], AsyncSession])` |
| `DatabaseAuditSink` | `jdlib.control.audit` | `DatabaseAuditSink(session_factory: Callable[[], AsyncSession])` |
| `ControlPlaneSession` | `jdlib.control.session` | `ControlPlaneSession(session: AsyncSession)` |
| `TenantPlanePurger` | `jdlib.control.purge` | `TenantPlanePurger(session_factory, *, factory: ContextFactory, rls: RlsConfig | None = None)` |
| `DefaultPDP` | `jdlib.authz.pdp` | `DefaultPDP(*, catalog: PermissionCatalog, reader: AccessReader, scopes: ScopeResolver, cache: AuthzCache | None = None)` |
| `Enforcer` | `jdlib.authz.guards` | `Enforcer(pdp: PolicyDecisionPoint)` |
| `PermissionCatalog` | `jdlib.authz.permissions` | `PermissionCatalog.with_builtins() -> PermissionCatalog` |
| `ResourceTypeRegistry` | `jdlib.authz.resource_types` | `ResourceTypeRegistry()` + `register`, `get`, `all`, `validate_permission` |
| `ScopeResolver` | `jdlib.authz.scopes` | `ScopeResolver(registry: ResourceTypeRegistry)` |
| `ControlAccessReader` | `jdlib.authz.reader` | `ControlAccessReader(session_factory: Callable[[], AsyncSession])` |
| `AuthzCache` | `jdlib.authz.cache` | `AuthzCache()` |
| `build_authenticator` | `jdlib.authn.wiring` | `build_authenticator(config: TenancyConfig, session_factory, audit: PlatformAudit) -> CompositeAuthenticator` |
| `EnvelopeCodec` | `jdlib.context` | `EnvelopeCodec(*, config: ContextConfig, clock: Clock | None = None)` |
| `ContextPropagator` | `jdlib.tenancy.jobs` | `ContextPropagator(*, codec, principals, tenants, servability, entitlements)` |
| `tenant_job` | `jdlib.tenancy.jobs` | `tenant_job(propagator: ContextPropagator) -> Callable[[F], F]` |
| `TenantMiddleware` | `jdlib.tenancy.middleware` | `TenantMiddleware(app: ASGIApp, *, factory, chain, principal_provider)` |
| `build_chain` | `jdlib.tenancy.resolution` | `build_chain(config: ResolverConfig) -> ResolverChain` |
| `lint_metadata` / `assert_clean` | `jdlib.lint` | `lint_metadata(controls: list[MetaData], rls_enabled: bool = False) -> list[LintIssue]` / `assert_clean(...) -> None` |
| `TenantAuditRecorder` | `jdlib.models.audit_recorder` | `TenantAuditRecorder(session: object)` + `record(*, action, target_type=None, target_id=None, metadata=None) -> AuditEvent` |
| `install_rls` / `verify_rls` | `jdlib.persistence.strategies.rls` | `install_rls(engine: AsyncEngine, *, metadata: sa.MetaData, app_role: str) -> None` / `verify_rls(engine: AsyncEngine, app_role: str, *, metadata: sa.MetaData) -> None` (built on `inspect_rls`, §8.12) |
| `RlsInspection` / `inspect_rls` | `jdlib.persistence.strategies.rls` | `inspect_rls(engine: AsyncEngine, *, metadata: sa.MetaData) -> RlsInspection`; frozen dataclass with `tables_checked`, `tables_enforced`, `tables_missing_rls`, `tables_missing_force`, `tables_missing_policy`, `tables_unprovisioned`, `is_enforced` |
| `CONTROL_REGISTRY` and the control model | `jdlib.security.compliance` | `CONTROL_REGISTRY: Mapping[str, Control]`; `Control`, `ControlMapping`, `ControlFramework`, `ControlCategory`, `ImplementationStatus`, `VerificationMethod`, `control_by_id`, `controls_for_framework`, `frameworks_in_use` |
| `evaluate_posture` / `PostureReport` | `jdlib.security.compliance` | `evaluate_posture(config: SecurityConfig, *, evidence=(), rules=None, clock=None, environment=None) -> PostureReport`; `PostureOutcome`, `Severity`, `PostureFinding`, `POSTURE_RULES` |
| `SecurityEvidence` and collectors | `jdlib.security.compliance` / `.session` | `collect_configuration_evidence`, `collect_migration_evidence`, `collect_policy_evidence`; the session-backed `collect_isolation_evidence` / `collect_schema_revision_evidence` (async, `AsyncEngine`) |
| `security_app` | `jdlib.integrations.cli` | `security_app = typer.Typer(no_args_is_help=True)` — the `security` group: `posture`, `evidence`, `compliance` (§8.20) |
| assertions | `jdlib.testing` | `assert_scoped_count`, `assert_tenant_isolated`, `assert_cross_tenant_write_rejected` |

### 6.3 What happens internally after a consumer call

| Consumer call | Internal path |
|---|---|
| `current_tenant()` | `_CTX.get()` → raise `MissingTenantContext` if unset (`context.py:113-117`) |
| `UnitOfWork.__aenter__` | fence check → wrap session → `TenantSession.__init__` → `session.sync_session.info["jdlib_context"] = context` (`persistence/session.py:265-272`) |
| `TenantSession.execute(orm_select)` | `do_orm_execute` → mapper trust analysis → `with_loader_criteria(tenant_id)` → SQLAlchemy (`persistence/session.py:109-211`) |
| `TenantSession.raw_sql(...)` | privilege check → `RawSqlValidator.compile` → `validate_tenant_bound` / `validate_privileged` → audit (privileged) → `execute(execution_options={"jdlib_raw_sql": True})` (`persistence/session.py:335-363`) |
| `registry.provision(id)` | advisory lock → status guard → `strategy.provision` → migration state `running` → `strategy.migrate` → `SeedHook.seed` → version equality check → audit → commit (`control/registry.py:306-365`) |
| `Enforcer.require(...)` | `current_tenant()` → `PDP.evaluate` (catalog validate → principal → tenant → membership → scope chain → bindings → permissions → grants → key-scope intersection) → raise or return `Decision` (`authz/pdp.py:77-150`) |
| `AccessControl.grant_resource(...)` | cache invalidate → `resource:share` + permission check → resource/namespace validation → `INSERT … ON CONFLICT DO NOTHING RETURNING` → audit (`authz/access.py:540-624`) |

---

## 7. Internal and Low-Level Architecture

### 7.1 Value objects and protocols

```text
Principal (frozen, slots)                 TenantContext (frozen, slots)
 ├── kind: PrincipalKind                  ├── tenant_id: UUID
 ├── id: UUID                             ├── tenant_slug: str
 ├── user_id: UUID | None                 ├── strategy: PlacementStrategy
 ├── tenant_id: UUID | None   (pin)       ├── principal: Principal
 ├── api_key_id: UUID | None              ├── request_id / correlation_id: str
 ├── scopes: frozenset[str] | None        ├── trace_id: str | None
 └── operator_level: OperatorLevel | None ├── privilege: PrivilegeContext | None
                                          └── live_privilege(now) -> PrivilegeContext | None

PrivilegeContext (frozen, slots)
 ├── kind: PrivilegeKind (operator|system|test)
 ├── capability: str | None
 ├── justification: str | None
 ├── actor: Principal
 ├── issued_at: datetime
 ├── expires_at: datetime | None
 └── is_live(now) -> bool                # bounded on both sides — §8.1
```

Collaborator protocols and their production implementations:

| Protocol | Location | Shipped implementation |
|---|---|---|
| `Clock` | `context.py:90-91` | `SystemClock` (`context.py:94-96`), tests' `FrozenClock` |
| `PrincipalDirectory.is_active` | `context.py:135-136` | `PrincipalDirectoryAdapter` (`authn/wiring.py:60-65`) |
| `TenantDirectory.get` | `context.py:139-140` | `TenantDirectoryAdapter` (`authn/wiring.py:68-73`) |
| `ServabilityChecker.assert_servable` | `context.py:143-144` | `TenantRegistry` (`control/registry.py:571-585`) |
| `EntitlementChecker.can_act` | `context.py:147-148` | `EntitlementAdapter` (`authn/wiring.py:76-87`) |
| `OperatorAuthorizer.authorize` | `context.py:151-152` | **none shipped** (consumer supplies; README example denies all) |
| `PrivilegeAudit.record_privilege` | `context.py:155-164` | `PrivilegeAuditAdapter` (`control/audit.py:153-172`) |
| `Authenticator.authenticate` | `authn/base.py:10-11` | `OidcAuthenticator`, `ApiKeyAuthenticator`, `CompositeAuthenticator` |
| `TenantResolver.resolve` | `tenancy/resolution.py:24-27` | 5 concrete resolvers |
| `IsolationStrategy` | `strategies/base.py:19-37` | `SharedSchemaStrategy`, `SchemaPerTenantStrategy`, `DatabasePerTenantStrategy` |
| `SecretProvider.resolve` | `persistence/secrets.py:7-8` | `MemorySecretProvider`, `EnvSecretProvider` |
| `AccessReader` (7 methods) | `authz/reader.py:28-52` | `ControlAccessReader` |
| `PolicyDecisionPoint.evaluate` | `authz/pdp.py:30-39` | `DefaultPDP` |
| `WriteFence.assert_writable` | `persistence/models.py:32-33` | `RegistryWriteFence`, `NullWriteFence` |
| `PlatformAudit.record` | `control/audit.py:27-37` | `DatabaseAuditSink`, `CompositeAuditSink`, `RecordingPlatformAudit`; `NullPlatformAudit` **raises** |
| `SeedHook.seed` | `control/registry.py:72-78` | **none shipped** (`_NoopSeedHook` default) |
| `ScopeLookup` / `ResourceLookup` | `authz/access.py:53-82` | **none shipped** (fail closed with `AuthorizationError` when omitted) |
| `RawSqlAuditor.record_raw_sql` | `persistence/session.py:26-29` | `_NoopRawSqlAuditor` default; consumers may supply one |

### 7.2 `TenantSession` internals

```text
TenantSession
 ├── Responsibility: single fail-closed, tenant-scoped database session surface
 ├── Constructor: (AsyncSession, TenantContext | None, *, auditor=None, validator=None)
 │     ├── context is None → raise MissingTenantContext            (session.py:265-267)
 │     ├── session.sync_session.info["jdlib_context"] = context    (session.py:270-272)
 │     └── _register_events(session.sync_session)                 (session.py:265-272)
 ├── State: self._session, self.context, self._auditor, self._validator
 ├── Public methods: execute, get, add, delete, update_where, delete_where,
 │                   raw_sql, flush, commit, rollback, close, __aenter__/__aexit__
 └── Collaborators: TenantContext, RawSqlValidator, RawSqlAuditor
```

**Two SQLAlchemy event hooks** are registered per instance
(`src/jdlib/persistence/session.py:109-254`):

1. `do_orm_execute` — read scoping and DML gate:
   * rejects `sa.TextClause` (`"use raw_sql for text statements"`);
   * rejects `FromStatement` ORM selects;
   * rejects non-`*` literal SQL columns;
   * builds the set of *trusted* `TenantRouted` mappers from
     `all_mappers`, entity tables, explicit FROMs, joins, and `bind_mapper`;
   * rejects bare tenant `Table` references and raw table aliases
     (`"aliases of tenant tables must be entity-derived; use aliased(Entity) or
     raw_sql"`);
   * attaches
     `sa.orm.with_loader_criteria(mapper.class_, lambda cls: cls.tenant_id ==
     tenant_id, include_aliases=True)` for every trusted mapper;
   * rejects unscoped ORM `UPDATE`/`DELETE`/`INSERT` with
     `UnscopedBulkOperation` unless execution options mark the statement
     (`jdlib_scoped=True`) or it came from the raw path
     (`jdlib_raw_sql=True`) — `src/jdlib/persistence/session.py:212-224`.
2. `before_flush` — write validation:
   * new `TenantRouted` object: stamps `tenant_id` when unset, raises
     `CrossTenantReferenceError` on mismatch;
   * dirty `TenantRouted` object: any `tenant_id` history change →
     `CrossTenantReferenceError`;
   * deleted `SoftDelete` object: requires a non-`None` privilege.

**Scoped bulk helpers** are the only sanctioned bulk path:

```python
async def update_where(self, model, values: dict[str, Any], *criteria) -> int
async def delete_where(self, model, *criteria) -> int
```

Both append `model.tenant_id == self.context.tenant_id` and mark the statement
`jdlib_scoped=True` (`src/jdlib/persistence/session.py:308-333`).
`get()` loads by composite primary key: `session.get(model, (tenant_id,
entity_id))` — a row owned by another tenant returns `None` rather than
erroring (`src/jdlib/persistence/session.py:297-300`).

**Trust-boundary caveat (verified):** the DML gate trusts execution-option
markers; a consumer who constructs `sa.update(…).execution_options(
jdlib_scoped=True)` directly can bypass the predicate the marker implies. The
markers are a convention-enforced internal capability, not a
cryptographically unforgeable one.

### 7.3 `DefaultPDP` internals

```text
DefaultPDP
 ├── Responsibility: additive, allow-only authorization decisions
 ├── Constructor: (*, catalog, reader, scopes, cache=None)
 ├── State: references only (no mutable state of its own beyond cache use)
 ├── evaluate(principal, permission, target, context, *, session) -> Decision
 │     1 catalog.validate(permission)            → UnknownPermission
 │     2 reader.principal_active(principal)      → "principal_inactive"
 │     3 reader.tenant_status_of(tenant_id)      → "tenant_suspended"
 │     4 reader.membership_active(...)           → "membership_inactive"
 │     5 session is None                         → MissingTenantContext
 │     6 scopes.chain(session, target)           → ScopeRef tuple
 │     7 reader.bindings_for(principal, tenant, chain) → bindings
 │     8 reader.permissions_by_role(tenant, role_ids) → frozenset
 │     9 reader.grants_for(...) for ResourceRef → frozenset
 │    10 principal.scopes is not None           → "outside_key_scopes"
 │    11 permission in authority                 → "allowed" / else "no_allow"
 └── Collaborators: PermissionCatalog, AccessReader, ScopeResolver, AuthzCache
```

Decision reasons are exactly: `allowed`, `principal_inactive`,
`tenant_suspended`, `membership_inactive`, `outside_key_scopes`, `no_allow`
(`src/jdlib/authz/pdp.py:77-150`). Provenance is carried in
`matched: tuple[MatchedRule, ...]` with kinds `binding` and `grant`.

**Cache keys** (`src/jdlib/authz/pdp.py:88-138`): `("principal_active",
principal)`, `("tenant_status", tenant_id)`, `("membership_active", principal,
tenant_id)`, `("scope_chain", target)`, `("bindings", tenant_id, principal,
scope_chain)`, `("role_permissions", tenant_id, role_ids)`, `("grants",
tenant_id, principal, resource_type, resource_id)`. Note the **scope-chain key
omits the tenant id**, which is why the PDP/cache must be request-scoped.

### 7.4 `AuthzCache` semantics

`src/jdlib/authz/cache.py:6-19`: a dict memo with `get`, `put`, and
`invalidate()`. `invalidate()` sets a **permanent dirty flag**, clears the
memo, and makes every later `get()` return `None` — caching is never re-enabled
for the instance's lifetime. `AccessControl` invalidates before every attempted
mutation, so any authorization-changing call makes the rest of the request
uncached. This is deliberate (no cross-request staleness) but means a
single mutation permanently disables caching for that request.

### 7.5 `TenantRegistry` internals

```text
TenantRegistry
 ├── Responsibility: lifecycle state machine + placement + migrations + servability
 ├── Constructor: (*, session_factory, strategies, runner, audit, seeder=None,
 │                desired_version="0001_tenant_baseline", purger=None)
 ├── Allowed transitions (registry.py:51-58):
 │     provisioning → {active, deleted}
 │     active       → {suspended, archived}
 │     suspended    → {active, archived}
 │     archived     → {active, deprovisioning}
 │     deprovisioning → {deleted, archived}
 │     deleted      → {}
 ├── Internal helpers:
 │     _advisory_lock(key)  → SELECT pg_advisory_xact_lock(hashtextextended(key,0))
 │     _transition(...)     → guarded status change + audit + commit
 │     _servability_error(tenant, state, relocating) → str | None
 └── Collaborators: IsolationStrategy map, MigrationRunner, PlatformAudit,
                     SeedHook, TenantPlanePurger, ControlPlaneSession
```

**Servability predicate** (single source of truth,
`src/jdlib/control/registry.py:124-140`, `571-585`):

```text
tenants.status == 'active'
AND tenant_migration_states.status == 'success'
AND current_version == desired_version
AND no tenant_relocations row in {copying, verifying, flipping, post_flip_verification}
AND a placement row exists
```

Failure mapping: unknown tenant → `TenantNotFound`; any failed predicate →
`TenantSuspended`; missing placement → `ProvisioningError`.
`RegistryWriteFence.assert_writable` uses the same predicate but raises
`TenantNotWritable` (`src/jdlib/control/registry.py:636-652`).

**Handle validation** at `create` time
(`src/jdlib/control/registry.py:194-283`): schema handles must match
`^t_[a-z0-9][a-z0-9_]{0,50}$`; database handles must match
`[a-z0-9][a-z0-9-]{0,50}`; shared handles need only be non-empty. Invalid
values raise `ProvisioningError`; an unknown/unhashable `strategy` value also
raises `ProvisioningError` (normalization at
`src/jdlib/control/registry.py:194-200`).

### 7.6 `MigrationRunner` internals

```text
MigrationRunner(database_url)
 ├── _sync_url(url): postgresql|postgresql+asyncpg|postgresql+psycopg2
 │                     → postgresql+psycopg   (runner.py:17-29)
 ├── _config(plane, *, tenant_schema=None, database_url=None) -> alembic.Config
 │     ├── script_location = Path(__file__).parent / plane
 │     ├── sqlalchemy.url  = sync URL with '%' doubled (ConfigParser safety)
 │     └── config.attributes["tenant_schema"] = tenant_schema
 ├── upgrade_control(revision="head")  → creates schema, then command.upgrade
 ├── upgrade_tenant(schema, revision)  → no schema creation
 ├── upgrade_tenant_url(dsn, schema, revision)
 ├── provision_tenant_schema(schema, revision) → CREATE SCHEMA IF NOT EXISTS then upgrade
 ├── tenant_version(schema) / tenant_version_url(dsn, schema)
 └── Validation: _TENANT_SCHEMA_RE = t_[a-z0-9][a-z0-9_]{0,50}
                 DEPLOYMENT_SCHEMA_RE = [a-z_][a-z0-9_]{0,62}
                 (fullmatch; failures → ProvisioningError before any engine)
```

All migration methods are **synchronous**; they are called from the async
registry (blocking by design — see [§23](#23-current-limitations)).

### 7.7 Internal helper functions worth knowing

| Helper | Location | Purpose |
|---|---|---|
| `tenant_table_map()` | `persistence/models.py:11-29` | discovers all loaded `TenantRouted` subclasses by table name (dynamic import of framework model modules) |
| `privileged_bypass(context)` | `persistence/models.py:41-47` | `True` only for `PrivilegeKind.SYSTEM` **and** capability exactly `relocation.manage` |
| `scoped_key(namespace, *parts)` | `context.py:128-132` | tenant-prefixed, percent-encoded external cache key `jdlib:v1:{tenant_id}:{ns}{parts}` |
| `sql_in(column, values)` | `control/enums.py:90-92` | renders `col IN ('a','b')` for CHECK constraints |
| `ownership_constraints()` | `models/base.py:56-74` | check + two composite FKs with `ondelete="RESTRICT"` |
| `http_status_for(exc)` | `tenancy/middleware.py:38-42` | ordered `isinstance` match, default 500 |
| `_b64`/`_unb64` | `context.py:441-447` | unpadded URL-safe base64 for envelopes |
| `parse_api_key`, `hash_api_key_secret`, `verify_api_key_secret` | `authn/apikey.py:29-44` | `jd.<prefix>.<secret>` parsing; Argon2 hashing |
| `build_invitation_token`, `hash_invitation_secret`, `verify_invitation` | `authz/access.py:102-117` | `inv_<32 hex>_<64 hex>`; Argon2 hash of the secret half |
| `_resolve_actor_type(actor_id, actor_type)` | `control/audit.py` | `actor_type or ("system" if actor_id is None else "user")` |
| `_request_ids(headers)` | `tenancy/middleware.py:68-77` | generates `request_id`, reads `x-correlation-id`, extracts 32-hex trace id from `traceparent` |

---

## 8. Feature-by-Feature Architecture

Each feature below states: overview, public API, internal architecture,
execution flow, error flow, and (for the major ones) a sequence diagram.

### 8.1 Tenant context and `ContextFactory`

**Overview.** `ContextFactory` is the only sanctioned way to create a
`TenantContext`. It enforces five fail-closed checks in a fixed order and can
mint three privilege flavours (operator, system, test), each audited before
return.

**Public API.** `ContextFactory` (top-level), `TenantContext`, `Principal`,
`PrivilegeContext`, `current_tenant`, `current_principal`,
`current_privilege`, `context_scope`, `PRIVILEGE_ISSUER`, `SystemClock`.

**Internal architecture.** `context.py:174-372`. Collaborators are the six
protocols in §7.1. `for_system` and `for_test` require the module-private
`_PrivilegeIssuer` instance and check identity (`issuer is PRIVILEGE_ISSUER`),
so external callers cannot construct system privileges by passing a look-alike.

**Execution flow — `for_principal`** (`context.py:223-252`):

1. `principals.is_active(principal)` → false ⇒ `UnknownPrincipal(str(id))`.
2. `tenants.get(ref)` → `None` ⇒ `TenantNotFound(slug or id)`.
3. `SERVICE_ACCOUNT` only: `principal.tenant_id == record.id` else
   `TenantAccessDenied`.
4. `entitlements.can_act(principal, record.id)` → false ⇒
   `TenantAccessDenied`.
5. `servability.assert_servable(record.id)`.
6. Build the context with `privilege=None`, `correlation_id or request_id`.

**Execution flow — `for_operator`** (`context.py:254-302`): requires
`PrincipalKind.PLATFORM_OPERATOR` and a non-blank `justification`
(otherwise `AuthorizationError`); TTL defaults to and is capped by
`config.operator_ttl`; `operators.authorize(principal, capability)` must return
`True`; tenant resolution and servability follow; a `PrivilegeContext` is
created, **audited**, and only then returned.

**Execution flow — `for_system` / `for_test`** (`context.py:304-372`): sentinel
check; `for_test` additionally requires `config.allow_test_contexts`; a random
`PLATFORM_OPERATOR` actor and non-expiring `SYSTEM`/`TEST` privilege are built
and audited. Neither path consults the tenant directory, entitlement checker,
or servability checker.

**Privilege liveness (phase 8).** A privilege is bounded on both sides.
`PrivilegeContext.is_live(now)` (`context.py:63-72`) refuses a context used
before `issued_at` as well as one used at or after `expires_at` (`None` means the
kind carries no expiry), and every enforcement point reads the privilege through
`TenantContext.live_privilege(now)` (`context.py:86-95`) rather than the field,
so "the context carries a privilege" can never be mistaken for "the privilege is
still good". `TenantSession` decides through one `_privilege_refusal(...)`
helper (`persistence/session.py:258-276`) that names why a missing, not-yet-valid
or expired privilege cannot authorize the action — "you never had it" and "it
lapsed" are different findings for an investigator. Every privileged gate uses
it: hard delete in `before_flush`, `update_where` of `tenant_id`, `delete_where`
on a `SoftDelete` model, and privileged raw SQL, with the refusal recorded
through the auditor before the raise where the path audits
(`persistence/session.py:253, 338, 356, 378-395`).

**Error flow.** All raises are `JdlibError` subclasses, so the ASGI middleware
maps them to 401/404/423 by the table in §13.3. The ordering of entitlement
(4) before servability (5) means an unentitled caller for a suspended tenant
receives 404 `TenantAccessDenied`, not 423 — a deliberate non-disclosure
property.

```mermaid
sequenceDiagram
    autonumber
    participant MW as TenantMiddleware
    participant PP as PrincipalProvider
    participant CF as ContextFactory
    participant PD as PrincipalDirectory
    participant TD as TenantDirectory
    participant EC as EntitlementChecker
    participant SC as ServabilityChecker
    participant PA as PrivilegeAudit

    MW->>PP: authenticate(RequestInfo)
    PP-->>MW: Principal
    MW->>CF: for_principal(principal, ref, request_id=…, correlation_id=…, trace_id=…)
    CF->>PD: is_active(principal)
    PD-->>CF: bool
    CF->>TD: get(ref)
    TD-->>CF: TenantRecord | None
    CF->>EC: can_act(principal, tenant_id)
    EC-->>CF: bool
    CF->>SC: assert_servable(tenant_id)
    SC-->>CF: TenantRecord
    CF-->>MW: TenantContext
    MW->>MW: context_scope(context) → call app
    MW->>MW: reset context
```

---

### 8.2 Tenant resolution and the ASGI middleware

**Overview.** Resolvers answer "which tenant is this request for?" from five
possible signals; the middleware turns that into an installed context and maps
library errors to HTTP responses.

**Public API.** `RequestInfo`, `TenantResolver`, `JwtClaimResolver`,
`SubdomainResolver`, `PathResolver`, `HeaderResolver`, `ApiKeyResolver`,
`ResolverChain`, `build_chain`, `TenantMiddleware`, `PrincipalProvider`,
`http_status_for`.

**Internal architecture.** `tenancy/resolution.py:14-127`,
`tenancy/middleware.py:24-134`. `RequestInfo` is a `NamedTuple` with
`headers`, `query`, `path`, `host`, `claims` (default `{}`). `_slug_ref`
normalizes a value by stripping, lowercasing, trying UUID first, then a slug
regex `^[a-z0-9][a-z0-9-]{1,62}$` (a one-character slug is rejected).
`ResolverChain.resolve` returns the **first** non-`None` result and never
compares conflicting resolvers.

**Middleware flow** (`middleware.py:110-134`):

1. Non-`http` scope → pass through untouched (no auth, no context).
2. Build `RequestInfo` from the ASGI scope: headers decoded latin-1 and
   lowercased, query parsed with last-value-wins, `path` from scope, `host`
   from the `host` header, and **`claims={}`**.
3. `principal = await principal_provider(request)`; `None` ⇒
   `AuthenticationError("no credentials presented")`.
4. `tenant_ref = await chain.resolve(request, principal)`; `None` ⇒
   `TenantNotFound("tenant could not be resolved")`.
5. Generate `request_id` (uuid4 hex), read `correlation_id`
   (`x-correlation-id`, defaulting to `request_id`), and extract a 32-hex trace
   id from `traceparent` when well-formed.
6. `context = await factory.for_principal(...)`.
7. `with context_scope(context): await self.app(...)`.
8. Any `JdlibError` raised in steps 3–6 is converted to a JSON response
   `{"error": "<ClassName>", "detail": "<message>"}` with `content-length` and
   `content-type: application/json`; non-`JdlibError` exceptions propagate.
9. The context is always reset, including when the inner app raises.

**Error flow.** `http_status_for` is the single mapping function, used both by
the middleware and by the FastAPI exception handler.

**Accuracy note (verified):** the shipped middleware always passes
`claims={}` into `RequestInfo`, so the default `JwtClaimResolver` receives no
claims through this path. Supplying OIDC-claim-based tenant selection requires
a custom principal provider/adapter that populates `RequestInfo.claims` or a
custom resolver chain.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant MW as TenantMiddleware
    participant AU as Authenticator
    participant DB as jd_control DB
    participant H as Downstream app

    C->>MW: HTTP request (X-Tenant-Slug: acme, Authorization: Bearer …)
    MW->>AU: authenticate(RequestInfo)
    AU->>DB: api_keys / users / identity_links lookup
    DB-->>AU: rows
    AU-->>MW: Principal
    MW->>MW: ResolverChain → HeaderResolver → TenantRef(slug="acme")
    MW->>DB: tenants.get + servability
    DB-->>MW: TenantRecord
    MW->>MW: context_scope(TenantContext)
    MW->>H: call app
    H-->>C: 200
    MW->>MW: context reset
```

---

### 8.3 Signed envelopes and background jobs

**Overview.** A request context cannot be shared across process/queue
boundaries as an object, so `EnvelopeCodec` serializes a **minimal** identity
payload with an HMAC, and `ContextPropagator` rebuilds a fresh context on the
far side — re-validating principal, tenant, entitlement, and servability.

**Public API.** `EnvelopeCodec(*, config: ContextConfig, clock=None)` with
`encode(context) -> str` and `decode(token) -> TenantContextEnvelope`;
`TenantContextEnvelope`; `ContextPropagator(*, codec, principals, tenants,
servability, entitlements)` with `reconstruct(token) -> TenantContext`;
`tenant_job(propagator)` decorator.

**Envelope format.** `<unpadded-b64url(payload)>.<unpadded-b64url(signature)>`,
where the payload is compact sorted JSON containing exactly `tenant_id`,
`principal_type`, `principal_id`, `request_id`, `correlation_id`, `trace_id`,
`issued_at`, and the signature is `HMAC-SHA256` over those bytes using
`context.signing_key` (`src/jdlib/context.py:387-438`). It intentionally carries
**no** scopes, permissions, roles, or privilege.

**Decode validation order** (`context.py:409-438`): split (`InvalidToken`
"malformed envelope") → base64 decode → `hmac.compare_digest` signature check
(`InvalidToken` "envelope signature mismatch") → JSON parse and dataclass
construction → reject `issued_at` more than 60 s in the future (`InvalidToken`
"envelope issued in the future") → reject age greater than `envelope_ttl`
(`ExpiredToken` "envelope expired") → other parse/type/attribute failures
become `InvalidToken` "invalid envelope payload".

**Reconstruction flow** (`tenancy/jobs.py:40-68`): decode → rebuild a
`Principal` (service accounts get the envelope tenant as their pin; all other
kinds get `tenant_id=None`) → `principals.is_active` → `tenants.get(TenantRef(
id=…))` → `entitlements.can_act` → `servability.assert_servable` → build a new
`TenantContext(privilege=None)` carrying the envelope's request/correlation/trace
ids.

**`tenant_job` behavior** (`tenancy/jobs.py:71-81`): reconstruct **before**
entering `context_scope`; on failure the context is never installed; the
envelope token is consumed and **not** forwarded to the wrapped function; the
decorator does not call the write fence, so write-performing jobs must use a
`UnitOfWork`.

```mermaid
sequenceDiagram
    autonumber
    participant W as Web request
    participant EC as EnvelopeCodec
    participant Q as Queue
    participant CP as ContextPropagator
    participant PD as PrincipalDirectory
    participant TD as TenantDirectory
    participant J as Job handler

    W->>EC: encode(context)
    EC-->>Q: signed token
    Q->>CP: tenant_job wrapper(token)
    CP->>EC: decode(token) → TenantContextEnvelope
    EC-->>CP: envelope
    CP->>PD: is_active(principal)
    CP->>TD: get(TenantRef(id=envelope.tenant_id))
    TD-->>CP: TenantRecord
    CP->>CP: entitlement + servability re-checks
    CP->>J: context_scope(new context) → fn(*args, **kwargs)
    J-->>Q: result
    CP->>CP: context reset
```

---

### 8.4 Control plane, `TenantRegistry`, and the lifecycle state machine

**Overview.** The control plane stores all cross-tenant metadata in the
`jd_control` schema and is the authority for tenant existence, placement,
migration state, relocations, identities, access-control rows, and platform
audit.

**Public API.** `TenantRegistry` (all 11 methods), `RegistryWriteFence`,
`SeedHook`, `ControlPlaneSession`, `TenantPlanePurger`, `DatabaseAuditSink`,
`CompositeAuditSink`, `RecordingPlatformAudit`, `PrivilegeAuditAdapter`,
`TenantStatus`, `PlacementStrategy`, `MigrationStatus`, `RelocationPhase`.

**Internal architecture.** `control/registry.py:143-623`; tables in
`control/models.py:29-487`; schema constant in `control/base.py:6-21`.

**Method contracts:**

| Method | Guards | Side effects |
|---|---|---|
| `create` | strategy normalization (`ProvisioningError` on bad value), handle regex, slug advisory lock, existing-slug idempotency (identical strategy/handle/region → return existing), handle advisory lock for schema/database | inserts `Tenant` + `TenantPlacement` + pending `TenantMigrationState`; audits `tenant.created`; one commit |
| `provision` | tenant advisory lock; already-active ⇒ no-op; status must be `provisioning` | `strategy.provision` → migration state `running` → `strategy.migrate` → `seeder.seed` → version equality check → audit → activate; on failure commits `failed` + `last_error`, audits `tenant.migration.failed`, re-raises (tenant stays `provisioning`) |
| `migrate` | tenant advisory lock; **no** status eligibility check | `strategy.migrate` → set current/success + audit `tenant.migration.succeeded`; on failure mark failed and, if the tenant was active, suspend it with `suspended_reason="migration_failed"` |
| `suspend` / `resume` / `archive` | allowed-transition map; already-in-target-state returns the tenant unchanged | sets/clears `suspended_at`, `suspended_reason`, `archived_at`; audits; commit |
| `deprovision` | `ARCHIVE` requires active/suspended → archived (non-destructive, optional `detach_children`); `PURGE`/`DESTROY` require archived → deprovisioning (or already deprovisioning), then release/reacquire the advisory lock and `populate_existing=True` re-read | deletes control access rows in `_ACCESS_ROW_DELETION_ORDER` (api_keys → service_accounts → invitations → role_bindings → resource_grants → role_permissions → roles → memberships), re-checks children, calls `strategy.deprovision`, requires a `TenantPlanePurger` for shared placement, marks `deleted`, audits counts, commits |
| `assert_servable` | the single servability predicate | none |
| `find` | ID first, then slug; no servability check | none |
| `list_for_user` | active memberships only | none |

**Error flow.** `TenantOperationInProgress` for illegal transitions,
`TenantNotFound` for unknown ids, `TenantSuspended` for unservable tenants,
`ProvisioningError` for invalid handles/strategy/missing placement,
`StrategyCapabilityError` when a strategy lacks a handle/engine/secret.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator/CLI
    participant R as TenantRegistry
    participant PG as jd_control
    participant St as IsolationStrategy
    participant MR as MigrationRunner
    participant A as PlatformAudit

    Op->>R: create(slug, name, strategy, target_handle)
    R->>PG: pg_advisory_xact_lock(jdlib:tenant-slug:acme)
    R->>PG: insert tenants + tenant_placements + migration_state(pending)
    R->>A: tenant.created
    R->>PG: COMMIT
    Op->>R: provision(tenant_id)
    R->>PG: pg_advisory_xact_lock(jdlib:tenant:{id})
    R->>St: provision(TenantRecord)
    St->>PG: CREATE SCHEMA / CREATE DATABASE
    R->>PG: migration_state.status = running
    R->>St: migrate(TenantRecord, runner)
    St->>MR: upgrade_tenant[_url](...)
    MR->>PG: alembic upgrade head
    R->>R: seeder.seed(record)
    R->>MR: tenant_version(migration_schema(record))
    R->>PG: migration success + status=active
    R->>A: audit success + activation
    R->>PG: COMMIT
```

---

### 8.5 Isolation strategies

**Overview.** Three strategies implement the same `IsolationStrategy` protocol
(`src/jdlib/persistence/strategies/base.py:19-37`):
`session`, `provision`, `migrate`, `migration_schema`, `deprovision`, plus the
attributes `name` and `capabilities`.

| Capability | `SharedSchemaStrategy` | `SchemaPerTenantStrategy` | `DatabasePerTenantStrategy` |
|---|---|---|---|
| `name` | `shared` | `schema` | `database` |
| `capabilities.supports_rls` | `True` | `False` | `False` |
| `capabilities.supports_ddl` | `False` | `True` | `True` |
| Session source | caller-supplied `AsyncEngine` | caller-supplied `AsyncEngine` + `SET search_path` | `create_async_engine(resolved DSN)` |
| `migration_schema` | configured shared schema (default `public`) | validated `t_*` handle | `"public"` in the tenant database |
| Provision | no-op | `CREATE SCHEMA IF NOT EXISTS` | catalog check then `CREATE DATABASE` |
| `ARCHIVE` deprovision | no-op | no-op | no-op |
| `PURGE`/`DESTROY` deprovision | no-op (registry requires `TenantPlanePurger`) | `DROP SCHEMA IF EXISTS … CASCADE` | terminate backends, then `DROP DATABASE IF EXISTS` |
| Health check | none | none | none |

**Shared strategy** (`strategies/shared.py:20-65`): rejects unsafe shared
schema names via `DEPLOYMENT_SCHEMA_RE`; a missing engine raises
`StrategyCapabilityError("shared strategy has no engine configured")`; when
`rls.enabled` an `after_begin` listener runs
`SELECT set_config('app.tenant_id', :tenant_id, true)` — transaction-local.
`rls.app_role` is **not used by the strategy** (the engine must already connect
as that role).

**Schema strategy** (`strategies/schema.py:16-107`): `validate_schema_name`
enforces `^t_[a-z0-9][a-z0-9_]{0,50}$`; each transaction issues
`SET search_path TO <driver-quoted schema>`; a SQLAlchemy `checkin` reset
listener issues `RESET search_path` when the connection is asyncio-safe;
provisioning uses `admin_engine or engine`; identifiers are quoted before
interpolation.

**Database strategy** (`strategies/database.py:18-203`):
`validate_database_handle` enforces `[a-z0-9][a-z0-9-]{0,50}`; the handle is
**opaque** (a DSN placed in `target_handle` is rejected by validation);
`_resolve` calls `secrets.resolve(handle)` and converts `KeyError` into
`StrategyCapabilityError`; engine cache is an `OrderedDict[str, AsyncEngine]`
capped by `max_targets=32`; cache hits move the entry to most-recent;
eviction picks the first engine whose `pool.checkedout() == 0` and raises
`PoolCapacityError` if every cached engine is checked out; `invalidate(handle)`
bumps a generation counter, drops the entry and disposes the engine;
`dispose()` clears tenant and admin engines.

**Concurrency notes.** A generation counter makes an `_engine_for` call that
crossed an `await` during idle eviction retry and re-resolve after an
invalidation (`strategies/database.py:101-153`). There is **no** `asyncio.Lock`
around cache lookup, insertion, eviction, invalidation, or admin-engine
creation, so concurrent first-time resolution of the same handle can create
duplicate engines; see [§23](#23-current-limitations).

**RLS is not a strategy.** `strategies/rls.py` is a helper module:
`rls_eligible_tables`, `emit_rls_policies`, `install_rls`, `verify_rls`.

---

### 8.6 `TenantSession`, scoping, and the write fence

Covered structurally in §7.2. The feature-level contract:

**Overview.** `TenantSession` is the only sanctioned way to touch tenant data
in `jdlib`. `UnitOfWork` adds write admission; `TenantRepository` adds
ergonomics; `SessionRouter` selects the physical session by placement.

**Public API.** `TenantSession`, `UnitOfWork`, `TenantRepository`,
`SessionRouter`, `WriteFence`, `NullWriteFence`, `RegistryWriteFence`,
`privileged_bypass`, `tenant_table_map`.

**Execution flow — a scoped read:**

1. `TenantSession.execute(stmt)` triggers `do_orm_execute`.
2. The listener rejects untrusted shapes (text, literal columns, bare tables,
   raw aliases, `FromStatement`).
3. Trusted `TenantRouted` mappers are identified.
4. `with_loader_criteria(...)` is attached per mapper.
5. SQLAlchemy emits `WHERE tenant_id = $1`; relationship loads and subquery
   loaders inherit the criteria.

**Execution flow — a scoped write:** ORM unit-of-work flush triggers
`before_flush`; new rows are stamped with the context tenant; dirty
`tenant_id` changes are rejected; `add`/`update` flush. Bulk
`update_where`/`delete_where` append the predicate themselves. Raw
hard-delete of a `SoftDelete` model requires a privilege.

**Error flow.** `MissingTenantContext` (no context),
`CrossTenantReferenceError` (foreign or mutated `tenant_id`),
`UnscopedBulkOperation` (unscoped bulk DML), `AuthorizationError` (privileged
raw SQL without the required capability), `UnscopedRawSql` (validator
rejection).

**Strategy routing.** `SessionRouter(strategies).session(record)` selects
`strategies[record.strategy]` and delegates; an unregistered strategy raises
`StrategyCapabilityError` (`src/jdlib/persistence/router.py:13-23`). The router
does **not** validate tenant status, secrets, or consistency between the
returned session's placement and a later `TenantContext` — the consumer is
expected to feed it a record from `registry.assert_servable` (README
example: `SessionRouter(strategies).session(await
registry.assert_servable(tenant_id))`, `README.md:267-269`).

### 8.7 Raw SQL validation (`RawSqlValidator`)

**Overview.** `TenantSession.raw_sql` is the only path to hand-written SQL.
The validator parses SQL with **pglast** (`parse_sql`, i.e. the real
PostgreSQL/libpg_query AST — `src/jdlib/persistence/rawsql.py:8-24`) and
requires structural proof that the active tenant is bound; it never
pattern-matches strings.

**Public API.**

```python
class RawSqlMode(StrEnum):        # rawsql.py:31-33
    TENANT_BOUND = "tenant_bound"
    PRIVILEGED = "privileged"

@dataclass(frozen=True, slots=True)   # rawsql.py:36-39
class CompiledRawSql:
    sql: str
    binds: tuple[object, ...]

class RawSqlValidator:                # rawsql.py:146-256
    def __init__(self, tenant_tables: dict[str, type] | None = None) -> None
    @staticmethod
    def compile(statement: sa.TextClause, dialect: sa.Dialect,
                params: dict[str, object]) -> CompiledRawSql
    def validate_tenant_bound(self, compiled: CompiledRawSql,
                              tenant_id: uuid.UUID) -> None
    def validate_privileged(self, compiled: CompiledRawSql) -> None
```

**Capabilities required by `TenantSession.raw_sql`**
(`src/jdlib/persistence/session.py:335-355`):

| Capability | Validation performed | Audited |
|---|---|---|
| none (`RawSqlMode.TENANT_BOUND`) | full `validate_tenant_bound` | no |
| `tenant.raw_sql` | full `validate_tenant_bound` | yes |
| `platform.raw_sql` | `validate_privileged` only | yes |
| any other / missing privilege | — | `AuthorizationError` |

**Compilation.** SQLAlchemy compiles the `TextClause` against the session
dialect; bind order comes from `compiled.positiontup`; failures become
`UnscopedRawSql("raw SQL could not be compiled")` chained from the cause.

**Parse-level rules (both modes).** Exactly one statement; the statement root
must be `SelectStmt`, `InsertStmt`, `UpdateStmt`, or `DeleteStmt`; CTEs are
rejected on all four roots; any parser error becomes
`UnscopedRawSql("raw SQL could not be parsed")`. DDL, transaction control,
`SET`, and `COPY` roots are therefore unsupported by construction.

**Tenant-bound proof rules** (`rawsql.py:179-256`):

* Every relation must be a known tenant table from `tenant_table_map()`;
  schema-qualified names and unknown relations are rejected.
* Relation collection covers `FROM` (including `JoinExpr` recursively),
  `UPDATE … FROM`, and `DELETE … USING`.
* Each relation needs its own **top-level `WHERE` conjunct** of the form
  `<qualifier>.tenant_id = <bound param>` where the bound value equals the
  active tenant UUID. With multiple relations the qualifier must name the
  specific relation/alias.
* `OR` and `NOT` in the `WHERE` decomposition raise
  `UnscopedRawSql("OR/NOT predicates are not allowed in tenant-bound SQL")`.
* Any `SubLink` anywhere in the AST is rejected (scalar and `EXISTS`
  subqueries); `RangeSubselect` relations are rejected.
* `INSERT` requires an explicit `tenant_id` column, a bound value equal to the
  active tenant in **every** `VALUES` row, rejects literals, rejects
  `INSERT … SELECT`, rejects `tenant_id` assignment in `ON CONFLICT DO UPDATE`,
  and rejects `tenant_id` in the `UPDATE` target list.
* Assignment of `tenant_id` anywhere in a DML target list is rejected
  (`rawsql.py:64-70`).
* Union/intersect/except have no dedicated handling: a set-operation root fails
  the per-relation proof (or lands in the relation allow-list check) and is
  rejected. The exact message text depends on the installed pglast version
  (`pglast>=6.0`).

**Privileged proof rules.** `validate_privileged` only checks: one statement,
no CTE, supported root. It performs no tenant, relation, schema, subquery,
boolean, or assignment checks.

**Error flow.** All validator rejections raise `UnscopedRawSql`; missing or
wrong capability raises `AuthorizationError` **before** execution; privileged
calls are audited before execution. Execution errors after validation are not
normalized.

```mermaid
sequenceDiagram
    autonumber
    participant App as Consumer
    participant TS as TenantSession
    participant P as Privilege (context)
    participant V as RawSqlValidator
    participant A as RawSqlAuditor
    participant DB as PostgreSQL

    App->>TS: raw_sql(text("SELECT … WHERE tenant_id = :tid"), {"tid": tenant_id})
    TS->>P: privilege capability check
    alt no privilege (tenant_bound)
        TS->>V: compile(text, dialect, params)
        V-->>TS: CompiledRawSql(sql, binds)
        TS->>V: validate_tenant_bound(compiled, tenant_id)
        V-->>TS: ok (or raises UnscopedRawSql)
    else tenant.raw_sql
        TS->>V: validate_tenant_bound(...)
        TS->>A: record_raw_sql(mode, capability, tenant_id, sql)
    else platform.raw_sql
        TS->>V: validate_privileged(...)
        TS->>A: record_raw_sql(...)
    end
    TS->>DB: execute(execution_options={"jdlib_raw_sql": True})
    DB-->>App: Result
```

---

### 8.8 Authentication (`jdlib.authn`)

**Overview.** One `Authenticator` protocol, two shipped implementations
(OIDC and API keys), a first-success composite, and wiring adapters that
satisfy `ContextFactory`'s collaborator ports.

**`Authenticator` port** (`authn/base.py:10-11`):

```python
class Authenticator(Protocol):
    async def authenticate(self, request: RequestInfo) -> Principal | None: ...
```

Returning `None` means "no credentials / not mine"; raising is reserved for
genuine failures. Helpers in the same module: `bearer_token(request)` (case-
insensitive `Bearer`, arbitrary whitespace, returns `None` when malformed) and
`record_authn_failure(audit, reason)` (writes `authn.failed` with
`tenant_id=None`, `actor_id=None`, `metadata={"reason": reason}`).

#### 8.8.1 API keys

* **Token shape:** `<configured-prefix>.<key-id>.<secret>`; default prefix
  `jd` (`ApiKeyConfig.prefix`, `src/jdlib/config.py:61-62`). The lookup key is
  the first two segments joined by `.`; the secret is Argon2-hashed and
  verified with `argon2` (`authn/apikey.py:29-44`).
* **Flow** (`authn/apikey.py:61-103`): parse → look up `jd_control.api_keys` by
  `key_prefix` → require `status = active` and not expired → require the parent
  `ServiceAccount` to exist and be active → build
  `Principal(kind=SERVICE_ACCOUNT, id=service_account.id,
  tenant_id=key.tenant_id, api_key_id=key.id, scopes=frozenset(scopes) or
  None)` → update and commit `last_used_at`.
* **Scope narrowing:** SQL `NULL` scopes become `None` (no narrowing); any
  non-null list becomes a `frozenset` intersected with base authority by the
  PDP.
* **Audit gating:** a token whose first segment does not match the configured
  prefix is silently ignored (not audited); a matching prefix with an invalid
  key is audited as `authn.failed` (typically `reason="invalid_api_key"`).
  Token material is never included in metadata
  (`tests/integration/test_apikey_auth.py:89-193`).

#### 8.8.2 OIDC

* **JWKS cache** (`authn/oidc.py:26-79`): `JwksCache(*, url, ttl, fetcher,
  clock=None, min_refresh_interval=1s)`; caches JWKs by `kid`; refreshes when
  stale **or** when an unknown `kid` is requested, subject to the minimum
  refresh interval; parses keys via `jwt.PyJWK.from_dict(...).key`;
  malformed keys and JWT-library errors return `None`; fetch exceptions
  propagate to the authenticator, which audits and returns no principal. There
  is no lock around concurrent refreshes.
* **Token verification** (`authn/oidc.py:82-124`): `TokenVerifier.verify` uses
  PyJWT for signature, configured algorithms, audience, and issuer, with
  PyJWT's `exp`/`nbf`/`iat` checks **disabled** and reimplemented: `exp` is
  rejected when `exp <= now - leeway`; `nbf`/`iat` are rejected only beyond
  `now + leeway`.
* **Claim mapping** (`authn/oidc.py:127-150`): `IdentityClaims(issuer,
  subject, email, email_verified)`; `sub` is mandatory; a missing `iss` falls
  back to the configured issuer; an unverified email is dropped.
* **User linking** (`authn/oidc.py:153-216`): `(issuer, subject)` identity
  link first; if `config.email_trusted` then a verified, case-insensitive email
  match to an active user; otherwise create a new active user (storing the
  verified email, or `None`). Identity-link uniqueness races are handled by
  rollback-and-reread. Returns `User | None` (`None` ⇒ audited
  `unlinked_identity`).
* **Result:** always `Principal(kind=USER, id=user.id, user_id=user.id)`. No
  claims, tenant, scopes, or issuer are retained on the principal.
* **Audit:** missing/malformed tokens and missing `kid` are silent; JWT, key,
  or linking failures audit `authn.failed` with the **exception class name**
  only.

#### 8.8.3 Composite and wiring

* `CompositeAuthenticator(authenticators)` returns the first non-`None`
  principal and does not catch exceptions (`authn/composite.py:10-19`).
* `build_authenticator(config, session_factory, audit)` assembles
  `OidcAuthenticator` (only when `config.oidc` is set) followed by
  `ApiKeyAuthenticator` (always), returning a `CompositeAuthenticator`
  (`authn/wiring.py:30-57`).
* `fetch_jwks(url)` creates a `httpx.AsyncClient` per call with no explicit
  timeout and requires a mapping response (`authn/wiring.py:20-27`).
* Adapters: `PrincipalDirectoryAdapter` (delegates to
  `AccessReader.principal_active`), `TenantDirectoryAdapter` (delegates to
  `TenantRegistry.find`), `EntitlementAdapter` (service accounts must match the
  tenant pin **and** be active; other principals need an active principal and
  an active membership; platform operators are consequently denied by
  `ControlAccessReader`) (`authn/wiring.py:60-87`).

```mermaid
sequenceDiagram
    autonumber
    participant MW as TenantMiddleware
    participant CA as CompositeAuthenticator
    participant OA as OidcAuthenticator
    participant JC as JwksCache
    participant IDP as OIDC issuer (httpx)
    participant UL as UserLinker
    participant AK as ApiKeyAuthenticator
    participant PG as jd_control
    participant A as PlatformAudit

    MW->>CA: authenticate(RequestInfo)
    CA->>OA: authenticate(request)
    OA->>OA: bearer_token + kid
    OA->>JC: signing_key(kid)
    JC->>IDP: JWKS fetch (if stale/unknown)
    IDP-->>JC: JWK set
    JC-->>OA: key
    OA->>OA: TokenVerifier.verify (sig/alg/aud/iss/times)
    OA->>UL: link(IdentityClaims)
    UL->>PG: identity_links / users lookup+insert
    PG-->>UL: User
    UL-->>OA: User
    OA-->>CA: Principal(USER)
    Note over CA,AK: API key is only consulted if OIDC returns None
    CA-->>MW: Principal
```

---

### 8.9 Authorization decisioning (`jdlib.authz` PDP, guards, cache)

**Overview.** The vocabulary (permissions, resource types, scopes) is code
defined; authority is data (control-plane rows); decisions are computed by
`DefaultPDP` with frozen precedence; enforcement is `Enforcer`/`requires`/
`authorize`.

**Permission catalog** (`authz/permissions.py:23-66`): `Permission(code,
namespace, allowed_scopes: frozenset[ScopeType], description)`;
`PermissionCatalog.with_builtins()` registers exactly 13 codes:

| Code | Namespace | Bindable scopes |
|---|---|---|
| `tenant:read`, `tenant:manage` | `tenant` | tenant |
| `member:invite`, `member:manage` | `member` | tenant |
| `role:manage` | `role` | tenant |
| `org:manage` | `org` | tenant, org |
| `team:manage` | `team` | tenant, org, team |
| `audit:read` | `audit` | tenant |
| `resource:read`, `resource:create`, `resource:update`, `resource:delete`, `resource:share` | `resource` | tenant, org, team |

Duplicate codes raise `ValueError`; unknown codes raise `UnknownPermission`.

**Resource types** (`authz/resource_types.py:9-56`):
`ResourceTypeDefinition(resource_type, model, tenant_owned, tenant_routed,
permission_namespace)`; `register` rejects empty names/namespace, requires
`tenant_routed ⇒ tenant_owned`, requires the model to expose
`organization_id`/`team_id` when routed, and rejects duplicates; `get` raises
`UnknownResourceType`; `validate_permission` requires
`Permission.namespace == definition.permission_namespace` else
`InvalidResourcePermission`. No application resource type is registered by the
library — consumers register their own.

**Scope resolution** (`authz/scopes.py:15-83`): `ScopeRef(type, id)`,
`ResourceRef(resource_type, resource_id)`, `Target = ScopeRef | ResourceRef`.
`ScopeResolver.chain(session, target)` returns:

* tenant scope: `[(TENANT, None)]`;
* org target: tenant → target org → each parent org to the root (cycle-safe
  via a `seen` set);
* team target: tenant → the team's org and its ancestors → the team;
* resource: looks up the registered model, reads `organization_id`/`team_id`,
  then tenant → org chain → team.

There is **no** `own`, `all`, or `ancestor` scope. Tenant-wide authority exists
because every chain starts at tenant. Missing org/team/resource rows collapse
to the tenant-only chain rather than raising; `deleted_at` is not consulted.

**Decisions, guards, and precedence** are described in §7.3 and §6.1.
`Enforcer.require` is the only place denials become exceptions
(`src/jdlib/authz/guards.py:20-31`).

**Cache.** See §7.4. The README is emphatic that a PDP/cache must not be shared
across requests (`README.md:220-222`) and shows a `RequestScopedEnforcer`
that constructs a fresh PDP per evaluation (`README.md:150-159`).

---

### 8.10 `AccessControl` — authorization mutations

**Overview.** `AccessControl` is the only writer of roles, bindings, grants,
and invitations. It enforces anti-escalation, scope compatibility, resource
existence, last-owner protection, and audit, and invalidates the PDP cache
before every attempt.

**Actor authorization model.** `AccessControl` does **not** call the PDP.
`actor_permissions(tenant_id, principal)` reads only **tenant-scope** bindings
for the principal, unions their role permissions, and intersects
`principal.scopes` when non-`None`; it does not re-check principal/tenant/
membership activity (`src/jdlib/authz/access.py:149-175`). Every method also
accepts both `actor_id` and `actor_principal`, and the code does not verify
that they identify the same principal.

**Method contracts:**

| Method | Required actor authority | Validation | Notes |
|---|---|---|---|
| `create_role` | `role:manage` | every code exists; actor holds every requested code | `is_system=True` is allowed; `is_system` only blocks update/delete |
| `update_role` | `role:manage` + subset | rejects system roles | replaces permissions, audits a sorted diff |
| `delete_role` | `role:manage` | rejects system roles; rejects roles with bindings or invitations | no role rename operation exists |
| `bind_role` | `role:manage` + all role permissions | scope shape via `ScopeLookup`; each permission's `allowed_scopes`; grantee must be an active service account in the tenant or have an active membership; a role named exactly `owner` requires the actor to hold the entire current catalog | validation happens in one control session; insert/audit/commit in a second; duplicates rely on the unique constraint (no idempotent path) |
| `unbind_role` | `role:manage` | advisory lock `jdlib:tenant:{id}`; refuses removing the last binding of a role named `owner` | remaining-owner count is not filtered by active principal/membership status |
| `grant_resource` | `resource:share` **and** the granted permission | resource type exists; namespace matches; `ResourceLookup` confirms existence/tenant/not-deleted | idempotent via `INSERT … ON CONFLICT DO NOTHING RETURNING`; no audit event when an existing grant is returned; grantee activity is **not** validated |
| `revoke_grant` | `resource:share` only | — | does not require holding the originally granted permission |
| `transfer_resource` | `resource:share` | destination scopes; organization required for a team destination | operates on a **caller-supplied tenant session**, flushes only (no commit); grants are preserved unless `revoke_grants=True`; audit is written in a separate control transaction |
| `move_team` | `team:manage` | destination org via `ScopeLookup` | cascades the new org id to every registered model exposing `team_id` + `organization_id`; optional grant revocation; flush-only; separate audit transaction |
| `invite` | `member:invite` | advisory lock; role exists; scope/permission compatibility; owner rule; actor subset; revokes prior pending invitations for the same tenant/email/scope | returns `(Invitation, plaintext_token)`; token is `inv_<32 hex>_<64 hex>`; only the 64-hex secret is Argon2-hashed; no email is sent |
| `accept_invitation` | none (token is the authority) | token, pending status, expiry; atomic conditional claim; re-validates scope and role compatibility | reuses an active membership/existing binding or creates both; does not verify the invitation email against the accepting identity; advisory-free but race-safe via conditional update (`tests/integration/test_access_invitations.py:643-685`) |

**Audit events** (exact action names, `src/jdlib/authz/access.py`):
`role.created`, `role.permissions_changed`, `role.deleted`, `binding.created`,
`binding.removed`, `grant.created`, `grant.revoked`, `resource.owner_changed`,
`team.moved`, `invitation.revoked`, `invitation.created`, `invitation.accepted`.

**Audit actor typing (verified nuance).** `AccessControl` never passes
`actor_type`; `DatabaseAuditSink._resolve_actor_type` therefore records
`"user"` for every non-null actor id — even when the actor was a service
account (`src/jdlib/control/audit.py`).

**Cache invalidation.** Every attempted mutation calls `cache.invalidate()`
first, so the rest of the request is uncached even when the mutation fails.

---

### 8.11 Migrations

**Overview.** `MigrationRunner` configures Alembic in memory (there is no
`alembic.ini` — it was removed; the programmatic runner is the only supported
path) and drives two independent chains: control and tenant.

**Public API.** `MigrationRunner(database_url)` with `upgrade_control`,
`upgrade_tenant`, `upgrade_tenant_url`, `provision_tenant_schema`,
`tenant_version`, `tenant_version_url` (all synchronous).

**Two planes:**

| Aspect | Control chain | Tenant chain |
|---|---|---|
| script location | `src/jdlib/migrations/control` | `src/jdlib/migrations/tenant` |
| target metadata | `ControlBase.metadata` (schema `jd_control`) | `TenantBase.metadata` (unqualified) |
| version table | `jd_control.alembic_version` | `<tenant schema>.alembic_version` |
| baseline revision | `0001_control_baseline` (creates schema, `CREATE EXTENSION citext`, `create_all`) | `0001_tenant_baseline` (`create_all`) |
| connection handling | `engine_from_config(..., poolclass=NullPool)` | same, plus `SET search_path TO <quoted schema>` committed before the migration transaction |
| offline mode | `include_schemas=True`, `literal_binds=True` | no `include_schemas` (tables are unqualified) |

**Transactions.** `upgrade_control` commits `CREATE SCHEMA IF NOT EXISTS` in
one `engine.begin()` block and then runs `command.upgrade` in Alembic's
transaction; `provision_tenant_schema` similarly commits schema creation before
upgrading. There is no single outer transaction spanning both steps, and no
retry.

**Version checks.** `tenant_version` first probes `to_regclass(:quoted)` and
then `SELECT version_num FROM "<schema>".alembic_version LIMIT 1`; a missing
schema yields `None`.

**Schema validation.** `provision_tenant_schema` uses
`_TENANT_SCHEMA_RE = t_[a-z0-9][a-z0-9_]{0,50}`; the deployment-facing methods
use `DEPLOYMENT_SCHEMA_RE = [a-z_][a-z0-9_]{0,62}`; both `fullmatch` and raise
`ProvisioningError` **before** any engine or SQL is created
(`tests/integration/test_migrations.py:10-89`).

---

### 8.12 PostgreSQL row-level security

**Overview.** RLS is opt-in hardening for shared-schema placements. It is a
helper module used by the CLI, by consumer Alembic environments
(`emit_rls_policies`), and by operators (`install_rls`/`verify_rls`).

**Policy emitted per eligible table** (`strategies/rls.py:54-67`):

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON <t>;
CREATE POLICY tenant_isolation ON <t>
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
-- optional: GRANT SELECT, INSERT, UPDATE, DELETE ON <t> TO <app_role>
```

Eligibility: `TenantRouted` subclasses present in the supplied metadata
(`rls_eligible_tables`, `rls.py:40-51`).

**Install** (`rls.py:79-106`): up to three attempts, each with
`SET LOCAL lock_timeout = '5s'` inside the DDL transaction; retries only for
exception class names `DeadlockDetectedError` and `LockNotAvailableError` with
`asyncio.sleep` delays of 0.25 s then 0.50 s; a successful install always
follows with `verify_rls`.

**Inspect** (`rls.py:109-172`): reading the catalog and judging it are separate
concerns. `inspect_rls(engine, *, metadata)` returns a frozen `RlsInspection` —
`tables_checked`, `tables_enforced`, the four problem tuples
(`tables_missing_rls`, `tables_missing_force`, `tables_missing_policy`,
`tables_unprovisioned`) and the `is_enforced` property — and makes no judgement:
a table the engine cannot see is reported as unprovisioned, because for evidence
that is an observation and for a caller who asked for a schema it is a failure
it can explain.

**Verify** (`rls.py:175-197`): the app role must exist, must be neither
`BYPASSRLS` nor a superuser, and then `verify_rls` raises
`StrategyCapabilityError` on the first problem `inspect_rls` reports, including
a hint that the engine must be bound to the target schema
(`tests/unit/test_rls_policies.py:10-53`). The split exists because the guard
must raise on the first problem while evidence has to report *all* of them, and
both must agree on what the catalog said:
`jdlib.security.compliance.session.collect_isolation_evidence` shares
`inspect_rls` (§8.22), which is why the CLI's `rls verify` and the evidence path
cannot drift apart.

**Session binding.** `SharedSchemaStrategy` sets `app.tenant_id` in an
`after_begin` listener with `set_config(..., true)` (transaction-local), so an
unset setting yields **zero** rows, never all rows
(`tests/integration/test_rls_db.py:112-322`).

---

### 8.13 Audit

**Overview.** Two audit domains with separate models and sinks.

| Aspect | Platform audit | Tenant audit |
|---|---|---|
| Port | `PlatformAudit` protocol (`control/audit.py:27-37`) | `TenantAuditRecorder` class (`models/audit_recorder.py:37-117`) |
| Durable model | `jd_control.platform_audit_events` | `<tenant schema>.audit_events` |
| Implementations | `DatabaseAuditSink`, `CompositeAuditSink`, `RecordingPlatformAudit`; `NullPlatformAudit` **raises** `RuntimeError("no platform audit sink is configured")` | writes into the consumer's `TenantSession` |
| Identity columns | `request_id`, `correlation_id`, `trace_id` filled from the active context when present, else `NULL` | same, always from the context (context is required) |
| Tenant id | nullable, **no FK** (history survives deletion) | part of the composite PK |

**`DatabaseAuditSink.record`** (`control/audit.py:79-116`):

* With no `session` argument: create → flush → commit → close (own
  transaction).
* With a `ControlPlaneSession`: flush into the caller's transaction, **no**
  commit, no close — this is how registry and `AccessControl` mutations get
  same-transaction audit.
* Actor inference: `actor_type or ("system" if actor_id is None else "user")`.
* Trace ids come from `current_tenant()` guarded by
  `MissingTenantContext` (`control/audit.py:19-24`); no synthesis when absent.
* `target_*`, `ip`, and `occurred_at` are not protocol parameters, so they stay
  null/default except `severity="info"`.

**`CompositeAuditSink`** (`control/audit.py:119-150`) fans out sequentially and
stops at the first failure; when `actor_type is None` it omits that keyword
entirely so older sinks lacking the parameter still work.

**`PrivilegeAuditAdapter`** (`control/audit.py:153-172`) adapts a
`PlatformAudit` to `ContextFactory`'s `PrivilegeAudit` port, emitting
`action=f"privilege.{kind.value}"`, `actor_id=actor.id`,
`actor_type=actor.kind.value`, and
`metadata={"capability": …, "justification": …}`.

**`TenantAuditRecorder.record`** (`models/audit_recorder.py:42-64`): requires a
context (`MissingTenantContext` otherwise), stamps tenant/actor/request ids,
copies metadata, `add()`s the row, and never flushes or commits.

**Attribution is fail-closed and time is corroborated (phase 8).**
`TenantAuditRecorder.record_security(event)` (`models/audit_recorder.py:66-117`)
persists a `SecurityAuditEvent` (`jdlib.security.audit`) in the caller's
transaction and refuses a row that would be mis-attributed: an event naming
another tenant, or another actor id or actor kind, than the ambient one raises
`ValueError` rather than being written — a mis-attributed audit row points an
investigation at the wrong tenant or blames the wrong principal, which is worse
than a missing row. The actor is taken from the most specific bound context (the
request's `SecurityContext` when there is one, else the `TenantContext`,
`_ambient_actor`, `audit_recorder.py:22-34`), and an event that names no actor
is attributed the same way the tenant is. The timestamp is corroborated rather
than trusted: `occurred_at` must sit within `MAX_TIMESTAMP_SKEW` (one minute,
`audit_recorder.py:19`) of the recorder's clock, so request-derived data cannot
backdate, postdate or replay an entry. Reading history is not writing it —
`export` rebuilds envelopes from stored rows with their original timestamps
(`docs/security/audit-hardening.md`).

---

### 8.14 Tenant-plane purge (`TenantPlanePurger`)

**Overview.** For shared placement, "purge" means deleting every tenant row
from the shared tables; for schema/database placement the strategy drops the
namespace/database instead. `TenantPlanePurger` implements the former.

**Public API.** `TenantPlanePurger(session_factory, *, factory: ContextFactory,
rls: RlsConfig | None = None)` with `purge(tenant: TenantRecord) -> dict[str,
int]`.

**Flow** (`control/purge.py:15-61`): dynamically import the framework tenant
model modules; walk `TenantRouted.__subclasses__()` into a table map; derive
child-first order from `TenantBase.metadata.sorted_tables` (reverse); obtain a
system context via `factory.for_system(tenant, purpose="tenant.purge",
issuer=PRIVILEGE_ISSUER)`; when RLS is enabled set `app.tenant_id`; delete every
registered tenant-row class through `TenantSession.delete_where`; commit once;
return per-table row counts.

`TenantRegistry.deprovision` **requires** a purger for shared placement on
non-archive modes and fails closed when it is missing
(`src/jdlib/control/registry.py:512-544`).

---

### 8.15 Schema metadata lint

**Overview.** `jdlib.lint` statically validates SQLAlchemy metadata against the
relational contract before it ever reaches a database.

**Public API.**

```python
@dataclass(frozen=True)
class LintIssue:                  # lint.py:21-25
    rule: str
    table: str
    message: str

def lint_metadata(controls: list[MetaData], rls_enabled: bool = False) -> list[LintIssue]
def assert_clean(controls: list[MetaData], rls_enabled: bool = False) -> None  # raises SchemaLintError
```

**Implemented rules (12 of the L1–L19 ids referenced in the design docs):**

| Rule | Check | Message |
|---|---|---|
| L1 | tenant-scoped table PK lacks `tenant_id` | `primary key does not include tenant_id` |
| L4 | `tenant_id` in PK but not first | `primary key does not lead with tenant_id` |
| L9 | tenant-scoped `tenant_id` is nullable | `tenant_id is nullable` |
| L2 | tenant→tenant FK omits `tenant_id` | `FK {name} omits tenant_id` |
| L3 | FK crosses planes (`table.schema != referred.schema`) | `FK {name} crosses planes` |
| L6 | table transitively reachable from `tenants` via `ondelete="CASCADE"` | `cascade path from tenants` |
| L11 | tenant-scoped model is not `TenantOwned` | `tenant-scoped model is not TenantOwned` |
| L12 | unique constraint/index lacks `tenant_id` (unless whitelisted) | `unique … is not tenant-scoped` |
| L13 | with `rls_enabled=True`, a schema-less table is not RLS-eligible | `tenant-plane table is not RLS-eligible` |
| L15 | `team_id` present without the check + composite team FK | `team ownership constraints missing` |
| L17 | schema-less known model is not `TenantRouted` | `tenant-plane model must be TenantRouted` |
| L19 | `jd_control` model is `TenantRouted` | `control-plane model must not be TenantRouted` |

**Not implemented** (named in `docs/jdlib/03-isolation-invariants.md` but never
emitted by `lint.py`): **L5, L7, L8, L10, L14, L16, L18**. There is no L20+.

Other constants: `GLOBAL_UNIQUE_WHITELIST` allows
`("api_keys","uq_api_keys_key_prefix")`, `("invitations",
"uq_invitations_token_id")`, `("tenants","uq_tenants_slug")`;
`TENANT_ID_REFERENCE_ONLY = {"platform_audit_events"}`; tables named
`alembic_version*` are skipped. Because L1 and L4 share an `elif` chain, one
call never emits both for the same table.

---

### 8.16 Secrets

**Overview.** Database-per-tenant targets are opaque handles resolved to full
DSNs by a consumer-supplied provider.

```python
class SecretProvider(Protocol):                       # persistence/secrets.py:7-8
    def resolve(self, handle: str) -> str: ...

class MemorySecretProvider:                          # :11-19  (copies mapping)
class EnvSecretProvider:                             # :22-31  (prefix "JDLIB_TENANT_DB_")
```

`EnvSecretProvider` computes `prefix + handle.upper().replace("-", "_")`, so
handle `db-acme` resolves to `JDLIB_TENANT_DB_DB_ACME`; a missing variable
raises `KeyError`, which `DatabasePerTenantStrategy._resolve` converts to
`StrategyCapabilityError("no secret for database handle {handle}")`.

**Rotation contract (documented behavior):** the resolved DSN is retained by
the cached `AsyncEngine`; changing the provider value does not hot-reload a
cached engine. The caller must `await strategy.invalidate(handle)` after
rotation; `dispose()` clears everything.

---

### 8.17 UUIDv7 generation

`jdlib._uuid.uuid7()` (`src/jdlib/_uuid.py:8-14`) builds a UUIDv7 from
`int(time.time() * 1000)` in the top 48 bits, `os.urandom(16)` for randomness,
version bits `0x70`, and RFC 4122 variant bits `0x80`. It is the application-side
ID default for all control and tenant models (`control/models.py`,
`models/org.py`, `models/audit.py`, `authz/access.py`).

Properties: lexically ordered across **different** milliseconds; **no**
same-millisecond monotonic counter, no lock, no clock-rollback guard. The module
is private (leading underscore) and not re-exported.

---

### 8.18 Testing kit (`jdlib.testing`)

**Public API** (`testing/__init__.py:1-13`): exactly three assertion helpers.

```python
async def assert_scoped_count(session_factory, context, model, expected: int) -> None
async def assert_tenant_isolated(session_factory, context_a, context_b, model, **values) -> uuid.UUID
async def assert_cross_tenant_write_rejected(session_factory, context_a, model, **values) -> None
```

Semantics: `assert_scoped_count` counts visible rows through a new
`TenantSession`; `assert_tenant_isolated` creates+commits a row for tenant B and
requires tenant A to see zero rows and `None` for B's id (returns the created
id); `assert_cross_tenant_write_rejected` requires
`CrossTenantReferenceError` on flush and raises `AssertionError` if the flush
succeeds.

**Pytest plugin** (`testing/pytest_plugin.py`, autoloaded via
`[project.entry-points.pytest11]`, `pyproject.toml:36-37`):

| Fixture | Scope | Behavior |
|---|---|---|
| `jdlib_database_url` | session | `JDLIB_TEST_DATABASE_URL`; **skips** the test when unset |
| `jdlib_schema` | session | `JDLIB_TEST_SCHEMA`, default `jdlib_test` |
| `jdlib_models` | function | tuple of model modules (`jdlib_test_models()` defaults to org/settings/audit); override to extend |
| `jdlib_engine` | function | async engine (via `pytest_asyncio` if installed, else a skipping sync fixture) that imports the model modules, converts the DSN to asyncpg, sets `search_path`, creates the schema and `TenantBase` tables, and disposes at teardown (it does **not** drop them) |
| `jdlib_session_factory` | function | `async_sessionmaker(engine, expire_on_commit=False)` |

`pytest_asyncio` is imported inside a `try/except ImportError` at module level
(`testing/pytest_plugin.py:19-21`); the plugin is never imported by
`import jdlib`.

---

### 8.19 FastAPI integration

**Public API.** `JdlibContainer`, `install`, `get_context`, `get_uow`,
`require` (§6.2).

`install` (`integrations/fastapi.py:41-58`) optionally stores the container on
`app.state.jdlib_container`, adds `TenantMiddleware`, and registers
`_handle_jdlib_error` for `JdlibError`. It does **not** construct any
authenticator, PDP, registry, or context factory.

`get_context` returns `current_tenant()`. `get_uow` yields
`container.uow_factory()` (annotated `UnitOfWork`; entering it yields a
`TenantSession`). `require(permission, target_factory=None)` returns a FastAPI
dependency that opens **its own** `uow_factory()` transaction, builds the
target (`tenant_target()` by default, otherwise `target_factory(request)`), and
calls `container.enforcer.require(...)`. `_container` raises
`RuntimeError("jdlib container is not installed on the app")` when missing.
`_handle_jdlib_error` returns `JSONResponse(status_code=http_status_for(exc),
content={"error": type(exc).__name__, "detail": str(exc)})`.

**Documented TOCTOU (module docstring, `integrations/fastapi.py:1-12`):** the
guard authorizes in its own unit of work — so `RegistryWriteFence` applies to
guarded reads too (a guarded read during a relocation quiesce fails with 423) —
but the handler's own session does not re-validate the guard's decision.

---

### 8.20 Typer CLI

**Public API.** `app` (`jdlib.integrations.cli`). Six Typer app objects:
`app`, `tenant_app`, `db_app`, `rls_app`, `schema_app`, `security_app`
(`integrations/cli.py:52-62`). Shared options: `--database-url` (env
`JDLIB_CONTROL_DSN`), `--shared-schema` (default `public`), `--json`.

| Group | Command | Options/arguments |
|---|---|---|
| `tenant` | `create` | `--slug`, `--name`, `--strategy` (default `shared`), `--target-handle` (default `default`), `--region`, `--shared-schema`, `--json` |
| `tenant` | `provision` | positional `<tenant_id: UUID>` |
| `tenant` | `list` | inner-joins tenants and placements (a tenant without a placement is omitted) |
| `db` | `upgrade-control` | implicit `head` |
| `db` | `upgrade-tenants` | iterates registered tenants sequentially |
| `rls` | `install` | `--schema`, `--app-role` |
| `rls` | `verify` | `--schema`, `--app-role` |
| `schema` | `lint` | `--rls/--no-rls`; **no** database/shared-schema options |
| `security` | `posture` | `--environment`, `--database-url` + `--schema` (live evidence), `--branch` (default `tenant`), `--policy-directory`, `--pdp-kind` (default `cerbos`), `--json`; **exits 1 when any control FAILs** (§8.22) |
| `security` | `evidence` | the same options; prints the evidence records behind the report (`--json` emits the list) |
| `security` | `compliance` | `--framework`, `--environment`, `--json`; the register and its framework mappings plus the posture counts |

The CLI registers only `SharedSchemaStrategy` and `SchemaPerTenantStrategy`
(`integrations/cli.py:115-127`); database placement requires programmatic
wiring (`README.md:362-365`). It cannot suspend/resume/archive/deprovision,
manage identities/roles/grants/invitations, choose a revision, or downgrade.
The `security` group is read-only reporting: it assesses the profile the
operator declares (`--environment`) rather than a deployment's private settings,
`--database-url` without `--schema` is refused, and an unknown environment,
branch or framework is a `BadParameter`. `JdlibError` and SQLAlchemy errors
print `error: …` to stderr with exit code 1; unexpected exceptions are not
normalized. There is no `[project.scripts]` entry — consumers expose `app`
themselves (`README.md:69-72`).

---

### 8.21 Internal component architecture

```mermaid
graph TB
    subgraph Request["Request path"]
        MW["TenantMiddleware"]
        AUTHN["CompositeAuthenticator<br/>Oidc + ApiKey"]
        RES["ResolverChain"]
        CF["ContextFactory"]
    end

    subgraph AuthzPath["Decision path"]
        ENF["Enforcer"]
        PDP["DefaultPDP"]
        CACHE["AuthzCache (request-scoped)"]
        SCOPES["ScopeResolver"]
        READER["ControlAccessReader"]
        CAT["PermissionCatalog"]
        RTT["ResourceTypeRegistry"]
    end

    subgraph DataPath["Data path"]
        UOW["UnitOfWork"]
        FENCE["RegistryWriteFence"]
        TS["TenantSession"]
        EVT["do_orm_execute + before_flush"]
        RAW["RawSqlValidator (pglast)"]
        REPO["TenantRepository"]
        ROUTER["SessionRouter"]
    end

    subgraph ControlPath["Control path"]
        REG["TenantRegistry"]
        CP["ControlPlaneSession"]
        AUDIT["DatabaseAuditSink"]
        MIG["MigrationRunner"]
        STRATS["IsolationStrategy map"]
    end

    MW --> AUTHN
    MW --> RES
    MW --> CF
    CF --> REG
    ENF --> PDP
    PDP --> CACHE
    PDP --> SCOPES
    PDP --> READER
    PDP --> CAT
    SCOPES --> RTT
    UOW --> FENCE
    UOW --> TS
    TS --> EVT
    TS --> RAW
    REPO --> TS
    ROUTER --> STRATS
    REG --> CP
    REG --> AUDIT
    REG --> MIG
    REG --> STRATS
    READER --> CP
```

---

### 8.22 Compliance evidence and posture (`jdlib.security.compliance`)

**Overview.** The compliance surface (phase 9; directive §9.1–§9.5) answers
"which technical controls does this library implement, what evidence stands
behind that claim, and are they in force here" — and answers in readiness
language throughout. A `ControlMapping` names where a control *belongs* in a
framework; it is never an audit result, and the package docstring says so. Three
properties are enforced by tests because each decays silently: **no silent
partials** (a status other than `IMPLEMENTED`/`NOT_APPLICABLE` must carry a
`status_note`), **every cited `evidence_sources` path must exist on disk**, and
**at least three gaps must be recorded** so the register cannot quietly become a
wish list. The register's own gaps are in the register, not omitted from it
(`docs/security/compliance-evidence.md`).

**The registry — 19 controls over 7 framework families.** `CONTROL_REGISTRY`
(`controls.py:759-761`) is a frozen `Mapping[str, Control]`; `Control` carries
`control_id`, `title`, `description`, `category`, `implementation_status`,
`mappings`, `evidence_requirements`, `evidence_sources`, `technical_owner`,
`verification_method` and an optional `status_note`. Control ids are shaped
`JDL-…` (`JDL-AUTHN-01`, `JDL-ISO-01`, `JDL-SUPPLY-01`, …) and map onto
`ControlFramework` members — SOC 2, ISO/IEC 27001, NIST CSF, NIST SP 800-53,
OWASP ASVS, OWASP API Security Top 10, CIS — the seven families
`frameworks_in_use()` returns. At this revision the register holds 19 controls:
15 `IMPLEMENTED`, 2 `PARTIAL` (Tyk plugin execution; pipeline security), 1
`NOT_IMPLEMENTED` with its reason (tamper-evident audit storage — a deployment
responsibility, not a library one) and 1 `NOT_APPLICABLE` (replay protection for
a stateless validator). `control_by_id`, `controls_for_framework` and
`frameworks_in_use` are the lookup helpers (§26.6 records the run that confirmed
these counts).

**Evidence (directive §9.3).** `SecurityEvidence` is a frozen dataclass that
makes the five required properties structure rather than convention:
`observations` (a flat mapping of JSON scalars, passed through the **same**
sanitiser as audit metadata — `jdlib.security.audit.audit_metadata` — so a
credential-shaped value is redacted, a credential-named key is redacted whole,
and a nested or oversized value is refused rather than smuggled into a report),
`collected_at` (from an injected clock), `collected_by` (cannot be blank),
`reproducible` (the command or procedure that regenerates the observation) and
`control_id`/`subject`; `repr` prints observation *keys*, never values. Four
collectors ship in `evidence.py`: `collect_configuration_evidence` (reads the
fixed allow-list `CONFIGURATION_EVIDENCE_KEYS`, 16 keys, so a future field
cannot arrive in a report unreviewed), `collect_migration_evidence` (one head per
branch of `MIGRATION_BRANCHES = ("control", "tenant")`, refusing a branch with
two heads or a revision file with no identifier), `collect_policy_evidence`
(names and counts of policy files only — a policy body is a deployment's
business and is never read) — and two session-backed collectors in
`evidence`'s sibling `session.py`: `collect_isolation_evidence` (the
PostgreSQL catalog, through `inspect_rls`, §8.12) and
`collect_schema_revision_evidence` (the revision a live schema has applied,
against the checkout's expected head; a missing revision table is an observation,
not an error). A collector that cannot reach its subject raises: "no evidence"
is a state a report may describe, but an assumed state is not.

**Posture (directive §9.4).** `evaluate_posture(config, *, evidence=(), rules=None,
clock=None, environment=None)` (`posture.py:667-716`) evaluates **every** control
in the registry exactly once and returns a `PostureReport` — findings in
deterministic order, `counts`, `worst_outcome`, `is_ready`, `failures` and
`as_dict()`; a registry control with no rule raises. The four outcomes are
`PASS` / `WARN` / `FAIL` / `NOT_APPLICABLE` with a `Severity` per finding, and
the semantics are fixed in the module rather than left to each rule: `PASS` is a
control in force — either a gate inside a code path a caller cannot route around
or a state something actually observed; `WARN` is in force but unverified here
(no evidence, or incomplete evidence, and the reason names what is missing), or
switched off in `development`, the profile that declares itself unsafe on
purpose; `FAIL` is a control that should be in force and is absent, disabled or
contradicted; `NOT_APPLICABLE` is a subject this deployment does not have. A
finding needs a reason of at least 20 characters, must name a known control, and
cannot cite another control's evidence; serialization carries outcomes, reasons
and evidence *summaries* — never observation values. `POSTURE_RULES` covers the
registry exactly, and `rules=` exists so a caller (and the tests) can document
what a missing rule would look like.

**Import isolation.** The namespace is additive by construction: the security
core's public surface is pinned by an exact-equality test, so new compliance API
lives in a submodule rather than in `jdlib.security`. Importing
`jdlib.security.compliance` pulls no optional dependency and nothing from the
persistence layer; `compliance/session.py` is the only module in the namespace
that imports it (`jdlib.persistence.strategies.rls`, `jdlib.models.base`), and
the CLI imports that module explicitly (§8.20). A posture report over a
configuration therefore needs no database.

**Tests.** 65 unit tests — 9 (`test_compliance_controls.py`), 12
(`test_compliance_evidence.py`), 31 (`test_compliance_posture.py`), 13
(`tests/unit/test_cli_security.py`) — plus 6 live-collector tests on real
PostgreSQL (`tests/integration/test_compliance_live_collectors.py`). The phase
document also records a bug the phase found in itself: the audit-posture rule
selected its configuration section by string, silently read the wrong section and
would have passed a deployment with the audit trail switched off; it now takes
the section name and uses `getattr`, with the regression test
(`docs/security/compliance-evidence.md` §4).

---

## 9. Runtime and Execution Model

### 9.1 Import-time behavior

* `import jdlib` executes **eager** imports of exactly eight modules'
  symbols (`src/jdlib/__init__.py:1-9`) plus `__all__` and `__version__`.
* No lazy-import machinery (`__getattr__`, import maps) exists.
* `fastapi`, `typer`, and `pytest` are **not** imported as a result of
  `import jdlib` — asserted in a subprocess by
  `tests/unit/test_public_api.py:46-59` and independently verified.
* `jdlib.testing.pytest_plugin` is loaded only by pytest through the `pytest11`
  entry point, never by package import.
* Importing `jdlib.models.*`/`jdlib.control.*` modules registers SQLAlchemy
  models on `TenantBase.metadata` / `ControlBase.metadata`. This is the only
  import-time side effect with architectural meaning: **model discovery is
  import-driven** (`tenant_table_map()` walks
  `TenantRouted.__subclasses__()`, `persistence/models.py:11-29`).
* `jdlib.models` and `jdlib.control` are namespace-package portions (no
  `__init__.py`); `jdlib.authz`, `jdlib.authn`, `jdlib.persistence`,
  `jdlib.tenancy`, and `jdlib.persistence.strategies` have empty initializers
  with no re-exports.

### 9.2 Initialization order in a real application

```text
1. TenancyConfig()                     # env + validation, no I/O
2. create_async_engine(control_dsn)    # CONSUMER creates engines; jdlib has no engine factory
3. async_sessionmaker(...)             # consumer
4. DatabaseAuditSink(sessions)         # audit
5. PrivilegeAuditAdapter(audit)        # PrivilegeAudit port
6. MigrationRunner(control_dsn)        # migrations
7. Isolation strategies                # consumer supplies engines / secrets
8. TenantRegistry(...)                 # control-plane authority
9. ControlAccessReader / PermissionCatalog / ResourceTypeRegistry
10. ScopeResolver + DefaultPDP (+ AuthzCache)  # request-scoped!
11. ContextFactory(...)                # request-time context builder
12. build_authenticator(...)           # authn composition
13. install(app, factory, chain, principal_provider, container)
```

Steps 1–2 are consumer responsibilities: **the library contains no engine or
session factory.** `SharedSchemaStrategy(engine, …)` and
`SchemaPerTenantStrategy(engine, runner)` take prebuilt engines;
`DatabasePerTenantStrategy` creates engines itself from resolved DSNs with no
pool arguments (`create_async_engine(dsn)`, `strategies/database.py:101-120`).

### 9.3 Lazy initialization

| Object | Lazy? | Trigger |
|---|---|---|
| Database strategy tenant engine | yes | first `session()`/`provision()` for a handle |
| Database strategy admin engine | yes | first `provision()`/`deprovision()` |
| `ContextFactory` clock | yes | `clock or SystemClock()` at construction |
| `EnvelopeCodec` key bytes | no | unwrapped in the constructor |
| `JdlibCache`/PDP cache | created by consumer | README builds a fresh PDP per guard evaluation |
| Alembic `Config` | yes | each `_config()` call, in memory |

### 9.4 Runtime state and lifecycle

| Object | State | Reset/cleanup |
|---|---|---|
| `_CTX` ContextVar | per-task tenant context | reset by `context_scope` `finally` |
| `TenantSession` | wraps an `AsyncSession`; context stored in `session.info["jdlib_context"]` | `close()`; `__aexit__` closes only |
| `UnitOfWork` | ephemeral per `async with` | commit/rollback + close |
| `ControlPlaneSession` | wraps an `AsyncSession` | `__aexit__` closes only (never commits automatically) |
| `DatabasePerTenantStrategy` | `OrderedDict` engine cache + admin engine | `dispose()`; `invalidate(handle)` |
| `AuthzCache` | memo + permanent dirty flag | per request (construct per request) |
| `JwksCache` | JWKs by `kid` with TTL | TTL/`min_refresh_interval` |
| `TenantRegistry` | none beyond injected collaborators | none needed |

### 9.5 Async, threading, and event loops

* The library is **async-first** (`AsyncSession`, `async def` throughout
  authn/authz/control/persistence request paths).
* Exceptions that are synchronous by design: `MigrationRunner` (Alembic +
  sync psycopg) and all CLI commands.
* **No** threads, thread pools, `threading.Lock`, `asyncio.Lock`,
  `asyncio.Semaphore`, `multiprocessing`, or background tasks exist in
  production source. The only concurrency primitives are:
  * the `contextvars.ContextVar` (§9.4),
  * PostgreSQL transaction advisory locks in the registry and two
    `AccessControl` methods,
  * `asyncio.sleep()` for RLS DDL retry backoff,
  * database constraints/conditional updates for race safety
    (`INSERT … ON CONFLICT DO NOTHING RETURNING`, conditional invitation
    claim, partial unique indexes).
* Concurrency safety therefore rests on PostgreSQL plus task-local contexts,
  not on in-process locks.

### 9.6 Resource management rules

1. `UnitOfWork` owns the tenant transaction: commit on success, rollback on
   exception, always close.
2. `ControlPlaneSession` never commits implicitly — the caller commits.
3. `DatabaseAuditSink` closes only sessions it created; caller-supplied
   sessions are flushed, never closed or committed.
4. `DatabasePerTenantStrategy.dispose()` must be called during application
   shutdown to dispose tenant and admin engines.
5. `TenantSession.__aexit__` closes but does not commit (`session.py:274-290`).

### 9.7 Runtime lifecycle diagram

```mermaid
sequenceDiagram
    autonumber
    participant P as Process
    participant App as Consumer app
    participant J as jdlib
    participant DB as PostgreSQL

    P->>App: import jdlib (eager, no optional deps)
    App->>J: TenancyConfig()
    App->>App: create_async_engine + async_sessionmaker
    App->>J: DatabaseAuditSink / MigrationRunner / strategies / TenantRegistry
    App->>J: install(app, ContextFactory, ResolverChain, principal_provider, container)
    App->>DB: MigrationRunner.upgrade_control() [sync]
    loop every HTTP request
        App->>J: TenantMiddleware → authenticate → resolve → context_scope
        J->>DB: entitlement + servability reads
        J->>App: handler runs with TenantContext
        App->>J: UnitOfWork → TenantSession → scoped SQL
        J->>DB: tenant-scoped statements
    end
    P->>App: shutdown
    App->>J: strategy.dispose() (engines), session factories disposed
```

---

## 10. Data Architecture

### 10.1 Two planes

```mermaid
erDiagram
    subgraph CONTROL["jd_control (control plane — global metadata)"]
        TENANTS["tenants (id, slug UNIQUE, name, status, parent_tenant_id)"]
        PLACEMENTS["tenant_placements (tenant_id PK, strategy, target_handle, region)"]
        MIGSTATE["tenant_migration_states (tenant_id PK, current_version, desired_version, status, last_error)"]
        RELOC["tenant_relocations (tenant_id, id, phase, from/to …)"]
        USERS["users (id, email CITEXT, status …)"]
        IDLINKS["identity_links (issuer, subject) UNIQUE"]
        OPERATORS["platform_operators (user_id PK, level)"]
        SACCOUNTS["service_accounts (tenant_id, id)"]
        APIKEYS["api_keys (tenant_id, id, key_prefix UNIQUE, hash, scopes)"]
        MEMBERSHIPS["memberships (tenant_id, id, user_id)"]
        ROLES["roles (tenant_id, id, name)"]
        ROLEPERMS["role_permissions (tenant_id, role_id, permission_code)"]
        BINDINGS["role_bindings (tenant_id, id, role_id, principal_*, scope_*)"]
        GRANTS["resource_grants (tenant_id, id, resource_*, principal_*, permission_code)"]
        INVITES["invitations (tenant_id, id, email, token_id UNIQUE, token_hash, status)"]
        AUDIT["platform_audit_events (id, tenant_id?, actor_*, action, metadata, severity)"]
    end

    subgraph TENANT["tenant plane (unqualified, resolved by search_path)"]
        ORGS["organizations (tenant_id, id)"]
        TEAMS["teams (tenant_id, id, organization_id)"]
        SETTINGS["tenant_settings (tenant_id, key)"]
        TAUDIT["audit_events (tenant_id, id)"]
    end

    TENANTS ||--|| PLACEMENTS : "one placement"
    TENANTS ||--o| MIGSTATE : "migration state"
    TENANTS ||--o{ RELOC : "relocations"
    TENANTS ||--o{ SACCOUNTS : "owns"
    SACCOUNTS ||--o{ APIKEYS : "issues"
    TENANTS ||--o{ MEMBERSHIPS : "has"
    USERS ||--o{ MEMBERSHIPS : "joins"
    USERS ||--o| IDLINKS : "links identity"
    USERS ||--o| OPERATORS : "may be"
    TENANTS ||--o{ ROLES : "defines"
    ROLES ||--o{ ROLEPERMS : "grants"
    ROLES ||--o{ BINDINGS : "bound at scope"
    TENANTS ||--o{ GRANTS : "resource grants"
    TENANTS ||--o{ INVITES : "invites"
    TENANTS ||--o{ ORGS : "tenant org tree"
    ORGS ||--o{ ORGS : "parent"
    ORGS ||--o{ TEAMS : "contains"
    TEAMS ||--o{ TAUDIT : "tenant rows"
    SETTINGS ||--|| TAUDIT : "tenant rows"
```

There are **no** foreign keys between the control plane and the tenant plane
(lint rule L3 enforces this: `FK {name} crosses planes`).

### 10.2 Control-plane model table (16 tables + `alembic_version`)

| Table | PK | Notable columns / constraints |
|---|---|---|
| `jd_control.tenants` | `id` | `slug` globally unique, `status` check, `slug` format check, nullable self-FK `parent_tenant_id`, suspension/archive timestamps |
| `jd_control.tenant_placements` | `tenant_id` | one authoritative placement; `strategy` check; opaque `target_handle`; `region` |
| `jd_control.tenant_migration_states` | `tenant_id` | `current_version`, `desired_version`, `status`, `last_error` |
| `jd_control.tenant_relocations` | `(tenant_id, id)` | from/to strategy+handle+region, `phase`, phase timestamps, partial unique `uq_tenant_relocations_active` |
| `jd_control.users` | `id` | CITEXT `email` with partial unique non-null index `uq_users_email`, display name, locale, status |
| `jd_control.identity_links` | `id` | FK `users.id`, `issuer`, `subject`, unique `(issuer, subject)`, login timestamps |
| `jd_control.platform_operators` | `user_id` | FK `users.id`, `level`, granted-by UUID |
| `jd_control.service_accounts` | `(tenant_id, id)` | tenant FK, name, status, unique `(tenant_id, name)` |
| `jd_control.api_keys` | `(tenant_id, id)` | composite FK to service account, globally unique `key_prefix`, hash, nullable `TEXT[]` scopes, status, expiry/last-used/revocation |
| `jd_control.memberships` | `(tenant_id, id)` | user FK, status, joined/suspended, unique `(tenant_id, user_id)` |
| `jd_control.roles` | `(tenant_id, id)` | name, description, `is_system`, unique `(tenant_id, name)` |
| `jd_control.role_permissions` | `(tenant_id, role_id, permission_code)` | composite FK to role with cascade; permission codes are **strings, not FKs** |
| `jd_control.role_bindings` | `(tenant_id, id)` | role FK, polymorphic `principal_type`/`principal_id`, `scope_type`/`scope_id`, creator, `UNIQUE NULLS NOT DISTINCT` across tenant/role/principal/scope |
| `jd_control.resource_grants` | `(tenant_id, id)` | `resource_type`/`resource_id` and `principal_type`/`principal_id` are **logical** (no FKs), `permission_code`, creator, uniqueness preventing duplicate exact grants |
| `jd_control.invitations` | `(tenant_id, id)` | CITEXT email, scope, role FK, unique `token_id`, `token_hash`, status, expiry/accepted/revoked, partial unique pending invitation |
| `jd_control.platform_audit_events` | `id` | nullable `tenant_id` **without FK**, actor, action, target, JSONB `metadata`, `ip`, request/correlation/trace ids, `severity`, `occurred_at` |
| `jd_control.alembic_version` | `version_num` | created by Alembic with `version_table_schema="jd_control"` |

All control IDs default application-side to `uuid7()`.

### 10.3 Tenant-plane models

```text
TenantBase(DeclarativeBase)        # metadata.schema = None (search_path-resolved)
 ├── TenantOwned                    # tenant_id: UUID PK, non-null, sorted first
 │    └── TenantRouted              # marker: eligible for scoping/RLS
 ├── Timestamped                    # created_at/updated_at timestamptz, server_default now()
 ├── SoftDelete                     # deleted_at timestamptz NULL
 ├── OwnableByOrg                   # organization_id UUID NULL
 └── OwnableByTeam                  # team_id UUID NULL

Concrete shipped models:
 Organization(TenantBase, TenantRouted, Timestamped, SoftDelete)   # "organizations"
 Team(TenantBase, TenantRouted, Timestamped, SoftDelete)           # "teams"
 TenantSetting(TenantBase, TenantRouted)                           # "tenant_settings"
 AuditEvent(TenantBase, TenantRouted)                              # "audit_events"
```

`ownership_constraints()` (`models/base.py:56-74`) contributes:

```sql
CHECK (team_id IS NULL OR organization_id IS NOT NULL)          -- ck_…_team_requires_org
FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations(tenant_id, id)   ON DELETE RESTRICT
FOREIGN KEY (tenant_id, team_id, organization_id) REFERENCES teams(tenant_id, id, organization_id) ON DELETE RESTRICT
```

`TenantSetting` is the only shipped model **without** `Timestamped` (it has
`updated_at` and `updated_by` only). `AuditEvent.metadata_json` maps to the SQL
column `metadata`.

### 10.4 Value objects (non-ORM)

| Type | Location | Fields | Validation |
|---|---|---|---|
| `Principal` | `context.py:42-50` | `kind`, `id`, `user_id`, `tenant_id`, `api_key_id`, `scopes`, `operator_level` | none at construction |
| `PrivilegeContext` | `context.py:53-60` | `kind`, `capability`, `justification`, `actor`, `issued_at`, `expires_at` | TTL/justification rules enforced by `ContextFactory` |
| `TenantContext` | `context.py:63-72` | see §7.1 | none at construction |
| `TenantRef` / `TenantRecord` | `context.py:75-87` | `id`/`slug`; record adds `status`, `strategy`, `target_handle` | slug/UUID normalization in `_slug_ref` |
| `TenantContextEnvelope` | `context.py:375-384` | identity + request ids + `issued_at` + `signature` | HMAC + TTL on decode |
| `Decision` / `MatchedRule` | `authz/pdp.py:18-27` | `allowed`, `reason`, `matched` | — |
| `Binding` | `authz/reader.py:16-19` | `role_id`, `scope_type`, `scope_id` | — |
| `ScopeRef` / `ResourceRef` | `authz/scopes.py:15-24` | `type`,`id` / `resource_type`,`resource_id` | non-tenant `ScopeRef` without id raises `ValueError` in `ScopeResolver` |
| `ResourceTypeDefinition` | `authz/resource_types.py:9-15` | `resource_type`, `model`, `tenant_owned`, `tenant_routed`, `permission_namespace` | validated at `register` |
| `Permission` | `authz/permissions.py:9-14` | `code`, `namespace`, `allowed_scopes`, `description` | duplicate code → `ValueError` |
| `StrategyCapabilities` | `strategies/base.py:13-16` | `supports_rls`, `supports_ddl` | — |
| `RequestInfo` | `tenancy/resolution.py:14-21` | `headers`, `query`, `path`, `host`, `claims` | header keys must be lowercase (ASGI convention) |
| `CompiledRawSql` | `persistence/rawsql.py:36-39` | `sql`, `binds` | — |
| `ParsedApiKey` | `authn/apikey.py:23-26` | `key_prefix`, `secret` | token must have exactly 3 segments |
| `IdentityClaims` | `authn/oidc.py:127-132` | `issuer`, `subject`, `email`, `email_verified` | `sub` mandatory |
| `LintIssue` | `lint.py:21-25` | `rule`, `table`, `message` | — |
| `JdlibContainer` | `integrations/fastapi.py:32-38` | `session_factory`, `uow_factory`, `enforcer` | frozen |
| `ContextConfig` etc. | `config.py:10-78` | pydantic models | see §12 |

### 10.5 Enumerations

| Enum | Location | Members |
|---|---|---|
| `TenantStatus` | `control/enums.py` | `provisioning, active, suspended, archived, deprovisioning, deleted` |
| `PlacementStrategy` | `control/enums.py` | `shared, schema, database` |
| `MigrationStatus` | `control/enums.py` | `pending, running, success, failed, blocked` |
| `RelocationPhase` | `control/enums.py` | `pending, provisioning, copying, verifying, flipping, post_flip_verification, completed, failed, rolled_back` |
| `OperatorLevel` | `control/enums.py` | `support, operator, admin` |
| `PrincipalType` | `control/enums.py` | `user, service_account` |
| `ScopeType` | `control/enums.py` | `tenant, org, team` |
| `MembershipStatus` | `control/enums.py` | `active, suspended, deleted` |
| `InvitationStatus` | `control/enums.py` | `pending, accepted, expired, revoked` |
| `ApiKeyStatus` | `control/enums.py` | `active, revoked, expired` |
| `ActorType` | `control/enums.py` | `user, service_account, platform_operator, system` |
| `AuditSeverity` | `control/enums.py` | `info, warning, critical` |
| `DeprovisionMode` | `strategies/deprovision.py` | `archive, purge, destroy` |
| `PrincipalKind` | `context.py:30-33` | `user, service_account, platform_operator` |
| `PrivilegeKind` | `context.py:36-39` | `operator, system, test` |
| `ResolverName` | `config.py:10-15` | `jwt_claim, subdomain, path, header, api_key` |
| `RawSqlMode` | `persistence/rawsql.py:31-33` | `tenant_bound, privileged` |

All are `StrEnum`, so their values serialize directly to text in SQL
CHECK constraints (via `sql_in`).

### 10.6 Serialization formats

| Format | Where | Notes |
|---|---|---|
| SQLAlchemy Core/ORM | everywhere | primary persistence format |
| JSON (JSONB columns) | `PlatformAuditEvent.metadata`, `AuditEvent.metadata`, `TenantSetting.value` | `metadata` is a reserved-ish name, hence the `metadata_json` attribute |
| Compact sorted JSON + HMAC | `EnvelopeCodec` | `sort_keys=True`, `separators=(",", ":")`, unpadded base64url |
| `TEXT[]` | `ApiKey.scopes` | nullable; `NULL` means "no narrowing" |
| CITEXT | `users.email`, `invitations.email` | case-insensitive uniqueness via the `citext` extension created by the control baseline |
| INET | `AuditEvent.ip`, `PlatformAuditEvent.ip` | nullable, no ORM helper is provided |

### 10.7 Naming conventions

Control plane (`control/base.py:6-21`):

```python
{"ix": "ix_%(table_name)s_%(column_0_N_name)s",
 "uq": "uq_%(table_name)s_%(column_0_N_name)s",
 "ck": "ck_%(table_name)s_%(constraint_name)s",
 "fk": "fk_%(table_name)s_%(column_0_N_name)s",
 "pk": "pk_%(table_name)s"}
```

Tenant plane (`models/base.py:13-14`) uses the same convention object with
unqualified tables. Partial unique indexes are declared explicitly in models
(e.g. `uq_organizations_tenant_id_slug` where `deleted_at IS NULL`).

---

## 11. Dependency Architecture

### 11.1 Runtime dependencies (all lower-bound-only, `pyproject.toml:10-21`)

| Package | Why | Where used | Coupling | Replaceable? |
|---|---|---|---|---|
| `sqlalchemy[asyncio]>=2.0.30` | ORM/Core, async sessions, events, metadata, engines | everywhere (`control/models.py`, `persistence/session.py`, `authz/*`, `control/purge.py`, strategies) | very tight (event API, `with_loader_criteria`, `execution_options`) | no |
| `pydantic>=2.7` | models, validators, `SecretStr` | `config.py`, `jdlib/testing` typing | moderate | no |
| `pydantic-settings>=2.3` | env-driven `TenancyConfig` | `config.py:70-78` | tight to the settings base class | partially (swap for a hand-written loader) |
| `alembic>=1.13` | programmatic migrations, `env.py`, revisions | `migrations/runner.py`, `migrations/*/env.py` | moderate (`Config`, `command.upgrade`) | theoretically, at high cost |
| `asyncpg>=0.29` | asyncpg DSN/driver | used through DSNs, not imported | driver-level (SQLAlchemy dialect) | yes (any asyncpg-compatible DSN) |
| `psycopg[binary]>=3.2` | **sync** driver for Alembic and tests | `_sync_url` normalization, integration fixtures | driver-level | yes |
| `pglast>=6.0` | real PostgreSQL AST for raw SQL proof | `persistence/rawsql.py` | tight to `parse_sql` node shapes | no (semantics depend on it) |
| `pyjwt[crypto]>=2.8` | JWT signature/claims verification, JWK parsing | `authn/oidc.py` | moderate | yes (another OIDC library) |
| `argon2-cffi>=23.1` | Argon2id password hashing for API keys and invitation secrets | `authn/apikey.py`, `authz/access.py` | tight to two helpers | yes |
| `httpx>=0.27` | JWKS fetch | `authn/wiring.py:20-27` | light | yes |

Neither `asyncpg` nor `psycopg` is imported by any `jdlib.*` module; they are
referenced only through DSN strings.

### 11.2 Optional extras

| Extra | Contents | Enables |
|---|---|---|
| `fastapi` | `fastapi>=0.111` | `jdlib.integrations.fastapi` |
| `cli` | `typer>=0.12` | `jdlib.integrations.cli` |
| `http` | `httpx>=0.27` | the real HTTP transports of `jdlib.security.authn.provider` / `jdlib.security.authz.cerbos` (added by phase 2; `httpx` is already a core dependency, so the extra exists to let a consumer state the requirement explicitly) |
| `dev` | the above plus `httpx>=0.27`, `pytest>=8.2`, `pytest-asyncio>=0.23`, `ruff>=0.5`, `mypy>=1.10`, `testcontainers[postgres]>=4.5` | development, lint, type check, integration tests |

There are no `test`, `lint`, `typing`, or `all` extras.

### 11.3 Development/testing dependencies

`pytest` and `pytest-asyncio` (auto mode), `testcontainers[postgres]` (the
`postgres:16` integration container), `ruff`, `mypy --strict`. Starlette is
imported directly by `integrations/fastapi.py` but is not declared in
`pyproject.toml` — it arrives transitively through FastAPI
(**accuracy note**: an undeclared direct import).

### 11.4 Dependency architecture diagram

```mermaid
graph TB
    subgraph JD["jdlib"]
        CORE["core modules"]
        ADAPT["integrations + migrations"]
    end

    subgraph RT["runtime deps"]
        SA["sqlalchemy[asyncio]"]
        PD["pydantic / pydantic-settings"]
        AL["alembic"]
        PGLAST["pglast"]
        JWT["pyjwt[crypto]"]
        ARG["argon2-cffi"]
        HTTPX["httpx"]
        ASY["asyncpg / psycopg"]
    end

    subgraph OPT["optional extras"]
        FA["fastapi (+starlette)"]
        TYP["typer"]
    end

    subgraph DEV["dev extra"]
        PT["pytest / pytest-asyncio"]
        TC["testcontainers[postgres]"]
        RF["ruff"]
        MY["mypy"]
    end

    CORE --> SA
    CORE --> PD
    CORE --> PGLAST
    CORE --> JWT
    CORE --> ARG
    CORE --> HTTPX
    ADAPT --> AL
    ADAPT --> SA
    ADAPT --> FA
    ADAPT --> TYP
    CORE -.DSNs.-> ASY
    ADAPT -.sync driver.-> ASY
    PT --> TC
    PT --> MY
    PT --> RF
```

### 11.5 Behavior when a dependency is unavailable

* Optional integration missing → `ImportError` **only** when importing
  `jdlib.integrations.fastapi` or `jdlib.integrations.cli`; the core package and
  its 13 exports remain importable (guarded by
  `tests/unit/test_public_api.py:46-59`).
* `pytest_asyncio` missing → the plugin substitutes a **skipping** synchronous
  `jdlib_engine` fixture (`testing/pytest_plugin.py:53-59`).
* Core runtime dependency missing → immediate `ImportError`; there are no
  lazy fallbacks.
* No dependency is vendored, patched, or re-implemented.

---

## 12. Configuration Architecture

### 12.1 Configuration model

`TenancyConfig(BaseSettings)` with
`SettingsConfigDict(env_prefix="JDLIB_", env_nested_delimiter="__")`
(`src/jdlib/config.py:70-78`). There is **no** singleton, no `get_settings()`,
no `.env` file support, and no custom settings source.

```text
TenancyConfig
 ├── control_dsn: SecretStr | None = None
 ├── context: ContextConfig
 │    ├── signing_key: SecretStr                      (required)
 │    ├── envelope_ttl: timedelta = 5 minutes
 │    ├── operator_ttl: timedelta = 30 minutes
 │    └── allow_test_contexts: bool = False
 ├── resolvers: ResolverConfig = ResolverConfig()
 │    ├── order: list[ResolverName] = [JWT_CLAIM, SUBDOMAIN, PATH, HEADER, API_KEY]
 │    ├── base_domain: str | None = None
 │    ├── path_prefix: str = "/t/"                    (validator: must start with "/")
 │    ├── header_name: str = "X-Tenant-Slug"
 │    └── jwt_claim: str = "tid"
 ├── oidc: OidcConfig | None = None
 │    ├── issuer: str                                  (required when present)
 │    ├── audience: str                                (required when present)
 │    ├── algorithms: list[str] = ["RS256"]
 │    ├── jwks_url: str | None = None
 │    ├── jwks_ttl: timedelta = 1 hour
 │    ├── leeway: timedelta = 60 seconds
 │    └── email_trusted: bool = False
 │        + resolved_jwks_url(): jwks_url or issuer.rstrip("/") + "/.well-known/jwks.json"
 ├── api_keys: ApiKeyConfig = ApiKeyConfig()
 │    └── prefix: str = "jd"
 └── rls: RlsConfig = RlsConfig()
      ├── enabled: bool = False
      └── app_role: str | None = None                  (configured but unused by the strategy)
```

### 12.2 Environment variables (documented patterns)

| Variable | Field | Example |
|---|---|---|
| `JDLIB_CONTROL_DSN` | `control_dsn` | `postgresql+psycopg://user:pass@host:5432/app` |
| `JDLIB_CONTEXT__SIGNING_KEY` | `context.signing_key` | `$(openssl rand -hex 32)` |
| `JDLIB_RESOLVERS__ORDER` | `resolvers.order` | list parsed by pydantic-settings |
| `JDLIB_RESOLVERS__BASE_DOMAIN` | `resolvers.base_domain` | `example.com` |
| `JDLIB_OIDC__ISSUER` | `oidc.issuer` | `https://login.example.com/` |
| `JDLIB_OIDC__AUDIENCE` | `oidc.audience` | `my-api` |
| `JDLIB_RLS__ENABLED`, `JDLIB_RLS__APP_ROLE` | `rls.*` | `true`, `jdlib_app` |
| `JDLIB_TENANT_DB_<HANDLE>` | `EnvSecretProvider` (not `TenancyConfig`) | handle `db-acme` ⇒ `JDLIB_TENANT_DB_DB_ACME` |
| `JDLIB_TEST_DATABASE_URL`, `JDLIB_TEST_SCHEMA` | pytest plugin | integration/plugin fixtures |
| `TESTCONTAINERS_HOST_OVERRIDE` | testcontainers (not read by jdlib) | `127.0.0.1` for Docker Desktop |

### 12.3 Configuration flow

```text
process environment ──(JDLIB_ prefix, __ nesting)──► TenancyConfig (validated)
                                                        │
        ┌───────────────────────┬───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼                       ▼
  EnvelopeCodec        ResolverConfig/            SharedSchemaStrategy     API key prefix
  (signing key, TTLs)  build_chain()               rls.enabled → per-tx     (ApiKeyConfig)
                                                 set_config('app.tenant_id')
```

`ContextFactory` receives only `config.context`; strategies receive only the
pieces they need (`SharedSchemaStrategy(rls=…)`, `MigrationRunner(url)`,
`ApiKeyAuthenticator(config=ApiKeyConfig…)`).

### 12.4 Secret handling

* `SecretStr` for `control_dsn` and `context.signing_key`; never rendered in
  `repr` (`tests/unit/test_config.py:48-51`).
* Explicit unwrapping: `config.control_dsn.get_secret_value()`,
  `config.signing_key.get_secret_value().encode()` (`context.py:389-390`).
* API key and invitation secrets are stored as Argon2id hashes; the plaintext
  API key secret and invitation secret are never persisted.
* Envelope HMAC key, JWKS, and DSNs are never logged (there is no logging in the
  library at all — §14).
* **Consumer responsibility:** production secret storage/rotation, `SecretProvider`
  implementations, and key management for the envelope signing key.

---

## 13. Error and Exception Architecture

### 13.1 Hierarchy (28 subclasses of `JdlibError` in this module, 27 exported; 31 package-wide)

```text
Exception
└── JdlibError
    ├── MissingTenantContext
    ├── TenantNotFound
    ├── TenantAccessDenied
    ├── TenantSuspended
    ├── TenantNotWritable
    ├── CrossTenantReferenceError
    ├── UnscopedBulkOperation
    ├── InvalidReference
    ├── InvalidResourcePermission
    ├── UnknownResourceType
    ├── UnknownPermission
    ├── RoleScopeMismatch
    ├── AuthenticationError
    │   ├── InvalidToken
    │   ├── ExpiredToken
    │   └── UnknownPrincipal
    ├── AuthorizationError
    │   ├── PermissionDenied
    │   ├── AuthorizationUnavailable
    │   └── RoleEscalationBlocked
    ├── StrategyCapabilityError
    ├── PoolCapacityError
    ├── TenantOperationInProgress
    ├── RelocationPhaseError
    ├── UnscopedRawSql
    ├── SchemaLintError
    ├── ProvisioningError
    └── MigrationError
```

`errors.__all__` lists 27 subclasses (not the base class). A 28th,
`AuthorizationUnavailable` (`errors.py:81-91`, added by the security programme's
error-response work), is defined alongside them but is not in
`jdlib.errors.__all__`; it is re-exported through `jdlib.security`
(`security/errors.py:220`), mapped to `503`/retryable there, and raised by the
authorization enforcement point when a decision could not be taken (§8.22's
neighbours; `docs/security/error-responses.md` §4). Only `TenantNotFound`,
`CrossTenantReferenceError`, and `SchemaLintError` define custom constructors;
`SchemaLintError.issues` is the only custom attribute.

### 13.2 Where each error is raised

| Error | Raised by |
|---|---|
| `MissingTenantContext` | `current_tenant`, `current_principal`, `current_privilege`, `scoped_key`, `TenantSession.__init__`/events, `TenantAuditRecorder.record`, `DefaultPDP` (missing session) |
| `TenantNotFound` | `ContextFactory._resolve_tenant`, `TenantMiddleware` (unresolved ref), `ContextPropagator`, `RegistryWriteFence` |
| `TenantAccessDenied` | service-account tenant-pin mismatch, entitlement failure, job entitlement re-check |
| `TenantSuspended` | `TenantRegistry.assert_servable` failed predicate |
| `TenantNotWritable` | `RegistryWriteFence.assert_writable` |
| `CrossTenantReferenceError` | `TenantSession.before_flush` (stamp mismatch or `tenant_id` mutation) |
| `UnscopedBulkOperation` | `do_orm_execute` DML gate |
| `InvalidReference` | `AccessControl` scope/resource validation for deleted or cross-tenant targets |
| `InvalidResourcePermission`, `UnknownResourceType`, `UnknownPermission`, `RoleScopeMismatch` | `ResourceTypeRegistry`, `PermissionCatalog`, `AccessControl` scope compatibility |
| `AuthenticationError` + subclasses | `TenantMiddleware` (no credentials), `EnvelopeCodec` (bad/expired token), `ContextFactory` (inactive principal), `ContextPropagator` |
| `AuthorizationError` + subclasses | `Enforcer.require` denial (`PermissionDenied`), anti-escalation (`RoleEscalationBlocked`), missing `ScopeLookup`/`ResourceLookup`, operator/system/test context denials, privileged raw SQL without capability |
| `StrategyCapabilityError` | strategy missing engine/handle/secret/database name, unknown strategy in `SessionRouter`, `verify_rls` failures |
| `PoolCapacityError` | database strategy eviction with all engines checked out |
| `TenantOperationInProgress` | illegal lifecycle transition |
| `UnscopedRawSql` | `RawSqlValidator` and `TenantSession.raw_sql` path |
| `SchemaLintError` | `assert_clean` |
| `ProvisioningError` | registry create validation, migration schema validation, `create` normalization failures |
| `MigrationError` | migration failures surfaced by consumers/strategies |
| `RelocationPhaseError` | reserved for relocation flows (no shipped caller) |

### 13.3 Error-to-HTTP status mapping

`src/jdlib/tenancy/middleware.py:26-42`; ordered `isinstance` match, default 500:

| Exception (first match wins) | Status |
|---|---|
| `AuthenticationError` (incl. `InvalidToken`, `ExpiredToken`, `UnknownPrincipal`) | 401 |
| `AuthorizationError` (incl. `PermissionDenied`, `RoleEscalationBlocked`) | 403 |
| `TenantNotFound` | 404 |
| `TenantAccessDenied` | 404 |
| `TenantSuspended` | 423 |
| `TenantNotWritable` | 423 |
| `CrossTenantReferenceError` | 409 |
| `InvalidReference` | 409 |
| any other `JdlibError` | 500 |

Notable consequences (verified): `UnknownPermission`, `UnknownResourceType`,
`InvalidResourcePermission`, `RoleScopeMismatch`, and `MissingTenantContext`
map to **500**; no `WWW-Authenticate` header is added; error bodies are
`{"error": "<ClassName>", "detail": "<message>"}` from both the middleware and
the FastAPI handler.

```mermaid
graph TD
    RAISE["JdlibError raised anywhere"] --> MAP["http_status_for(exc)"]
    MAP --> S401{"AuthenticationError?"} -->|yes| H401["401"]
    MAP --> S403{"AuthorizationError?"} -->|yes| H403["403"]
    MAP --> S404{"TenantNotFound / TenantAccessDenied?"} -->|yes| H404["404"]
    MAP --> S423{"TenantSuspended / TenantNotWritable?"} -->|yes| H423["423"]
    MAP --> S409{"CrossTenantReferenceError / InvalidReference?"} -->|yes| H409["409"]
    MAP --> H500["500"]
    H401 --> BODY["JSON: {error, detail}"]
    H403 --> BODY
    H404 --> BODY
    H423 --> BODY
    H409 --> BODY
    H500 --> BODY
```

### 13.4 Wrapping and propagation rules

* **Library code never wraps driver errors into `JdlibError`.** SQLAlchemy /
  asyncpg exceptions propagate untouched (e.g. `DatabasePerTenantStrategy`
  re-raises the original migration exception after recording failed state).
* `RawSqlValidator` is the one place that normalizes: compiler failures →
  `UnscopedRawSql("raw SQL could not be compiled")`, parser failures →
  `UnscopedRawSql("raw SQL could not be parsed")`, always chained `from` the
  cause.
* `SecretProvider.resolve` `KeyError` → `StrategyCapabilityError` chained
  `from exc`.
* `PlacementStrategy(strategy)` failures → `ProvisioningError` chained
  `from exc`.
* Only `JdlibError` crosses module boundaries by contract
  (`README.md:389-390`); adapters are expected to map driver exceptions.
* `jdlib.integrations.cli._run`/`_run_sync` normalize `JdlibError` and
  SQLAlchemy errors to stderr + exit 1; unexpected exceptions are not
  normalized.

---

## 14. Logging and Observability

### 14.1 What is implemented

| Mechanism | Status | Evidence |
|---|---|---|
| Audit events (platform) | **Implemented** | `jd_control.platform_audit_events` + `DatabaseAuditSink` |
| Audit events (tenant) | **Implemented** | `audit_events` + `TenantAuditRecorder` |
| Authentication failure records | **Implemented** | `record_authn_failure` → `authn.failed` |
| Privilege issuance records | **Implemented** | `PrivilegeAuditAdapter` → `privilege.{operator,system,test}` |
| Raw-SQL execution records (privileged only) | **Implemented** | `RawSqlAuditor.record_raw_sql`; ordinary tenant-bound raw SQL is **not** audited |
| `request_id` | **Implemented** | generated per request (`uuid4().hex`) |
| `correlation_id` | **Implemented** | from `x-correlation-id`, defaulting to `request_id` |
| `trace_id` | **Implemented** | strict W3C `traceparent` parse (`jdlib.security.tracing.request_ids_from_headers`), carried into logs and audit rows |
| W3C `traceparent` propagation | **Implemented** | parsed strictly and re-rendered by `format_traceparent`; spans are emitted through a caller-supplied OpenTelemetry-compatible tracer, with no SDK dependency in the library |
| Signed cross-hop context | **Implemented** | `EnvelopeCodec` (identity + request ids + signature) |
| Structured security logs | **Implemented** | `jdlib.security.telemetry.security_log_record` — fixed field set (`LOG_FIELDS`), redaction-enforced, identifiers filled from the ambient security context (phase 7; `docs/security/observability-hardening.md` §1) |
| Security metrics | **Implemented** | `SecurityMetrics` with a bounded label allow-list (`BOUNDED_LABELS`, `FORBIDDEN_LABELS`, `KNOWN_METRICS`); a smuggled identifier label is refused with `MetricLabelError` (phase 7, §2) |
| Telemetry failure isolation | **Implemented** | `safe_emit` swallows a telemetry error and reports it once, so a collector outage cannot disable security (phase 7, §3) |
| Security spans | **Implemented** | `SecuritySpan` / `security_span` — duck-typed against the OpenTelemetry API; span failures are swallowed in both directions (phase 7, §4) |
| Security audit events | **Implemented** | `jdlib.security.audit` vocabulary + envelope, with producers for authorization decisions, privilege issuance, raw SQL and control-plane actions; `TenantAuditRecorder.record_security` persists them in the caller's transaction (§8.13) |

### 14.2 What is explicitly absent (revised — phase 7)

The pre-hardening text of this section said "no logging at all" and "no
metrics"; that is no longer true, and the phase 7 surface is **Implemented**
above. What remains absent:

* **No logger configuration and no handler.** The library builds a structured
  security record and leaves emission to the application's logging setup. The
  only `logging` use in `src/jdlib` is one lazy `getLogger(...).warning` call in
  `security/telemetry.py:264-266`, which reports a swallowed `safe_emit`
  failure once.
* **No metrics backend and no SDK dependency** — no Prometheus exposition, no
  OpenTelemetry SDK import (the span layer is duck-typed and the application
  supplies any tracer), no health endpoint.
* **No log shipping, rotation, sampling or dashboards.**
* **No debug utilities.**

Consequence: operational visibility is built by the consumer from the audit
tables, the structured security records, the metric surface and the CLI `--json`
output, joined by the request/correlation/trace ids in `TenantContext`.

### 14.3 Audit event vocabulary (platform)

| Producer | Action(s) |
|---|---|
| `TenantRegistry` | `tenant.created`, provisioning/migration success and failure, suspension/resume/archive events, deprovision counts |
| `AccessControl` | `role.created`, `role.permissions_changed`, `role.deleted`, `binding.created`, `binding.removed`, `grant.created`, `grant.revoked`, `resource.owner_changed`, `team.moved`, `invitation.created`, `invitation.revoked`, `invitation.accepted` |
| authn | `authn.failed` |
| privilege issuance | `privilege.operator`, `privilege.system`, `privilege.test` |
| raw SQL | consumer-supplied `RawSqlAuditor` (library ships only the no-op default) |

Tenant-plane `AuditEvent.action` is free-form; the shipped writers are
`TenantAuditRecorder.record` (which the consumer calls) and
`TenantAuditRecorder.record_security`, which writes the security-event envelope
into the same table (§8.13).

The security programme added a **frozen vocabulary** for security events:
`jdlib.security.audit.SecurityEventType` holds 36 members — the directive's 34
event names plus the two audit-access events (`AUDIT_READ_DENIED`,
`AUDIT_EXPORTED`) — grouped by category (authentication, authorization,
tenancy, privilege, security), with `SecurityAuditEvent` as the envelope and
producers that include the authorization enforcement point
(`authorization_audit_observer`), the privilege and raw-SQL adapters, and the
control-plane adapters (`jdlib.security.audit.adapters`). A test asserts the
vocabulary is exactly the intended list, because evidence mappings and
dashboards key off these strings; `docs/security/audit-hardening.md` is the
reference, including its integrity evaluation and recorded residual risk.

### 14.4 Correlation model

```mermaid
graph LR
    IN["incoming headers"] --> RID["request_id = uuid4().hex"]
    IN --> CID["correlation_id = x-correlation-id or request_id"]
    IN --> TID["trace_id = traceparent[1] if 32 hex"]
    RID --> TC["TenantContext"]
    CID --> TC
    TID --> TC
    TC --> PA["platform_audit_events.request/correlation/trace"]
    TC --> TA["audit_events.request/correlation/trace"]
    TC --> ENV["EnvelopeCodec (signed, carried to workers)"]
```

`DatabaseAuditSink` fills the three columns from `current_tenant()` when a
context is active and leaves them `NULL` otherwise
(`src/jdlib/control/audit.py:19-24`); it never synthesizes ids.

---

## 15. Security Architecture

### 15.1 JDLib responsibility

| Control | Mechanism | Location |
|---|---|---|
| Fail-closed tenant access | `MissingTenantContext` everywhere; no default tenant | `context.py:113-117`, `session.py:265-272` |
| Read scoping | `with_loader_criteria` per trusted mapper, aliases included | `session.py:117-211` |
| Query-shape rejection | text, literal columns, bare tables, raw aliases, `FromStatement`, unscoped bulk DML | `session.py:109-224` |
| Write ownership | stamping, `tenant_id` immutability, cross-tenant rejection | `session.py:226-253` |
| Soft-delete protection | hard delete of `SoftDelete` models requires a privilege | `session.py:245-253` |
| Raw SQL proof | pglast AST, per-relation bound predicate, no OR/NOT/subquery/CTE | `rawsql.py:179-256` |
| Privileged raw SQL | explicit capability (`tenant.raw_sql` / `platform.raw_sql`) + audit | `session.py:335-363` |
| Tenant pinning | API keys resolve to `principal.tenant_id`; equality enforced in `ContextFactory` and re-checked in jobs | `context.py:240-244`, `jobs.py:40-68` |
| Key-scope narrowing | `principal.scopes` intersected (never widened) | `pdp.py:130-138` |
| Anti-escalation | actor must already hold every permission it grants/binds; `owner` requires the full catalog | `access.py:236-464` |
| Last-owner protection | refuses removing the last `owner` binding (under advisory lock) | `access.py:466-513` |
| Invitation secrets | Argon2id hashes; lookup id separated from secret; single-use conditional claim | `access.py:102-117, 920-1027` |
| Identity verification | OIDC signature/issuer/audience/algorithm/time; API-key prefix scoping; no token material in audit metadata | `oidc.py:82-124`, `apikey.py:61-103` |
| Context signing | HMAC-SHA256 + TTL + future-timestamp rejection | `context.py:387-438` |
| Privileged access | `PrivilegeContext` with capability, justification, expiry, and **liveness enforced at every gate** (§8.1); `for_system`/`for_test` gated by a private sentinel | `context.py:254-372`, `persistence/session.py:258-276` |
| Write admission | `RegistryWriteFence` blocks writes (and guarded reads) while unservable | `registry.py:636-652` |
| Schema invariants | 12 lint rules incl. cascade-path and cross-plane FK bans | `lint.py:71-194` |
| RLS | `ENABLE` + `FORCE` + `NOBYPASSRLS` verification; transaction-local `app.tenant_id`; one shared catalogue inspection behind the guard and the evidence | `strategies/rls.py:54-197`, `shared.py:33-53` |
| Secret redaction | `SecretStr` config, Argon2 at rest, DSNs never logged; one canonical redaction pattern set behind error responses, audit metadata, telemetry and evidence | `config.py`, `authn/apikey.py`, `authz/access.py`, `security/redaction.py` |
| Security audit trail | frozen `SecurityEventType` vocabulary + `SecurityAuditEvent` envelope, fail-closed attribution, clock-corroborated timestamps | `security/audit/`, `models/audit_recorder.py:66-117` |
| Compliance readiness | 19-control register mapped onto 7 framework families; posture over a declared configuration and observed evidence; `posture` exits non-zero on FAIL | `security/compliance/` (§8.22) |
| CI supply chain | pinned pip-audit / gitleaks (full history) / bandit / CycloneDX / build gates, every one build-failing | `.github/workflows/ci.yml`, `docs/security/ci-security.md` (§19.6) |
| Identifier safety | driver-level quoting for schema names; handle regexes; `%` doubling in Alembic URLs | `schema.py:16-23,67-84`, `database.py:18-43`, `runner.py:35-52` |
| Error non-disclosure | unentitled caller for a suspended tenant gets 404, not 423 | `context.py:232-252` |

### 15.2 Consumer responsibility (jdlib does **not** provide these)

* **Transport security** — TLS termination, HSTS, secure cookies.
* **Credential issuance** — no user store, password auth, MFA, session
  issuance, refresh-token rotation.
* **API key generation/rotation/revocation service** — only parsing, hashing,
  and verification ship.
* **Invitation delivery** — `invite` returns a plaintext token; sending it is
  the consumer's job.
* **Rate limiting, quotas, bot protection.**
* **Secret storage/rotation** — the consumer implements `SecretProvider`,
  stores `JDLIB_CONTEXT__SIGNING_KEY`, and calls `invalidate(handle)`.
* **Operator authorization** — `OperatorAuthorizer` is a port with **no shipped
  implementation** (README example denies everything).
* **Membership management, user provisioning, role seeding** — not shipped
  (`SeedHook` is a port; the README quickstart does not seed roles).
* **Scope/resource existence lookups** — `ScopeLookup`/`ResourceLookup` are
  ports; omitting them makes the related `AccessControl` operations fail
  closed.
* **Application resource-type registration** — consumers must register their
  own `ResourceTypeDefinition`s.
* **DDL/DML hardening, database role separation** beyond what RLS helpers and
  the `NOBYPASSRLS` check enforce; PostgreSQL superuser/owner caveats are
  documented for RLS only.
* **Certification and audit results** — the compliance surface maps technical
  controls to framework references, collects evidence and reports readiness; it
  is not an audit result, and installing the library does not make an
  organisation certified or compliant (`docs/security/compliance-evidence.md`,
  `docs/compliance/README.md`).
* **Backups, HA, connection proxying, observability pipelines.**

### 15.3 Threat-oriented notes (evidence-based)

| Threat | Mitigation | Residual risk (documented) |
|---|---|---|
| Forged tenant context | context is only created by `ContextFactory`; cross-hop contexts must carry a valid HMAC envelope | a consumer that constructs `TenantContext` by hand bypasses the factory (dataclass is public) |
| Cross-tenant raw SQL | AST proof per relation, no OR/NOT/subquery/CTE, no unknown relations | set-operation handling is implicit rather than explicit; `platform.raw_sql` skips tenant proof by design |
| Bulk DML escape | unscoped bulk rejected; `update_where`/`delete_where` append the predicate | execution-option markers are trusted; a consumer that sets `jdlib_scoped=True` manually can bypass the predicate (convention-enforced, not capability-secure) |
| Stale authorization | request-scoped cache; invalidation before mutations; cross-hop re-authorization | `AccessControl` mutations authorize in a separate transaction from the PDP read; `fastapi.require` has a documented TOCTOU window vs the handler session |
| Privilege abuse | audited, TTL-bounded, capability-bearing; sentinel-gated system/test issuance | `NullPlatformAudit` raises (good), but a consumer that supplies an async no-op audit sink silently disables privilege records |
| RLS bypass | FORCE + `NOBYPASSRLS` + superuser/bypass checks in `verify_rls` | the strategy does not enforce the runtime role; an engine connected as owner/superuser bypasses policies (`tests/integration/test_rls_db.py` covers these negatives) |
| Cross-tenant FK/reference | composite tenant FKs, `RESTRICT`, lint L2/L3/L15 | `ResourceGrant` and `RoleBinding` principal/resource references are logical, validated only through injected lookups |
| Deleted-tenant data leakage | `PlatformAuditEvent.tenant_id` intentionally has no FK so audit history survives deletion; row data is purged by strategies/purger | none observed |

### 15.4 Security-hardening programme (phases 1–11)

The security work after `a30601d` was delivered as a numbered programme. Each
phase has one document under `docs/security/`, and each document carries its own
`Status:` line, the tests behind its claims and the gaps it did not close. The
phase numbers are the programme's own; they are unrelated to the foundation
phases in `docs/superpowers/plans/`.

| Phase | Document | What it added |
|---|---|---|
| 1 | `security-core.md` | `jdlib.security` — `SecurityContext`, `SecurityConfig`, the error model, the ports |
| 2 | `authentication-hardening.md` | JWKS hardening, algorithm policy, `JwtTokenValidator`, outbound token provider, ZITADEL adapter, service identities |
| 3 | `authorization-hardening.md` | decision model, PDP port, fail-closed Cerbos adapter, `AuthorizationPEP` |
| 4 | `gateway-hardening.md` | gateway adapters and trust rules (Kong 3.6 verified; the Tyk live path is not verified) |
| 5 | `error-responses.md` | stable codes, HTTP mapping, safe envelope, `WWW-Authenticate`, the 403 → 503 change |
| 6 | `audit-hardening.md` | security event vocabulary, envelope, emitters, audit access and export, integrity evaluation |
| 7 | `observability-hardening.md` | structured logs, bounded metrics, telemetry failure isolation, spans, collector verification |
| 8 | `adversarial-review.md` | the adversarial pass, and the privilege-liveness and audit-corroboration fixes (§8.1, §8.13) |
| 9 | `compliance-evidence.md` | the control register, evidence, posture and the `security` CLI (§8.22) |
| 10 | `ci-security.md` | the `security` CI job's five gates (§19.6) |
| 11 | (this revision) | the documentation sweep: `CHANGELOG.md`, `SECURITY.md`, the indexes, and this synchronisation (§26.6) |

Verification status is per document and deliberately uneven: Kong 3.6 is the
verified gateway while the Tyk plugin path is not infrastructure-verified
(§19.7). Nothing in this set is a certification, an audit result, or a
substitute for one.

---

## 16. Performance and Concurrency

### 16.1 Execution model

* Async-first: `AsyncSession` everywhere on the request path.
* Synchronous by design: `MigrationRunner` and the CLI (Alembic + psycopg).
* No threads, no multiprocessing, no background tasks, no in-process locks
  (§9.5).

### 16.2 Connection pooling

| Placement | Pool model | Notes |
|---|---|---|
| shared | one engine/pool supplied by the consumer | no pool parameters set by jdlib |
| schema | one engine/pool; per-transaction `SET search_path`; `RESET search_path` on checkin | search_path is re-asserted on every `after_begin` |
| database | **one engine per handle**, cached in an `OrderedDict`, capped by `max_targets=32`; idle-only LRU eviction; `PoolCapacityError` when all cached engines are checked out | `max_targets` bounds **engines**, not connections |

**Not present in source:** no `pool_size`, `max_overflow`, `pool_timeout`,
`pool_recycle`, `pool_pre_ping`, `poolclass`, `connect_args`, or
`statement_timeout` configuration anywhere in production code. The only
timeout-like setting is RLS DDL's `SET LOCAL lock_timeout = '5s'`. The design
document sketches a `PoolConfig` (`docs/jdlib/07-implementation-design.md:226-238`)
but `TenancyConfig` has no `pools` field — **configured nowhere, implemented
nowhere**.

### 16.3 Concurrency model

| Concern | Mechanism | Location |
|---|---|---|
| Cross-request/task isolation | `contextvars.ContextVar` | `context.py:99-110` |
| Lifecycle serialization | `pg_advisory_xact_lock(hashtextextended(key, 0))` on tenant / tenant-slug / tenant-handle | `registry.py:285-304` |
| Owner-count race | advisory lock inside `unbind_role` | `access.py:466-513` |
| Invitation re-issue/claim | advisory lock in `invite`; atomic conditional update in `accept_invitation` | `access.py:851, 920-1027` |
| Grant idempotency under races | `INSERT … ON CONFLICT DO NOTHING RETURNING` | `access.py:540-624` |
| One active relocation | partial unique index | `control/models.py:107-145` |
| Engine-cache invalidation race | generation counter re-check after the eviction `await` | `strategies/database.py:101-153` |
| DDL lock contention | RLS DDL retry (3 attempts, 5 s lock timeout) | `strategies/rls.py:78-105` |

**Stateless vs. stateful classes:**

| Kind | Examples |
|---|---|
| Stateless (safe to share) | `PermissionCatalog`, `ResourceTypeRegistry`, `ScopeResolver`, `RawSqlValidator`, `MigrationRunner` (after construction), `DefaultPDP` when paired with a per-request cache, `ContextFactory`, `TenantRegistry`, `AccessControl` (aside from injected collaborators) |
| Stateful per request/task | `TenantContext` (immutable), `TenantSession` (one session), `AuthzCache` (must be request-scoped), `EnvelopeCodec` (stateless apart from the key) |
| Stateful per process | `DatabasePerTenantStrategy` (engine caches), `JwksCache` (JWK TTL) |
| Not thread-safe / not lock-protected | `DatabasePerTenantStrategy` cache/invalidate/dispose/admin-engine lazy init; `JwksCache` concurrent refresh |

### 16.4 Caching and memoization

| Cache | Scope | Invalidation |
|---|---|---|
| `AuthzCache` | per request (by contract) | `invalidate()` is one-way and permanent for the instance |
| Database engine cache | per strategy instance | `invalidate(handle)`, `dispose()`, idle LRU eviction |
| JWK cache | per `JwksCache` instance | TTL or unknown-`kid` refresh with a 1 s floor |
| No ORM identity caching | — | `expire_on_commit=False` is the consumer's choice; the README sets it |

### 16.5 Known hot spots and costs (evidence-based)

* `DefaultPDP.evaluate` performs several control-plane queries per decision
  (principal, tenant status, membership, scope chain, bindings, role
  permissions, grants), mitigated only by the request-scoped memo.
* `ScopeResolver.chain` walks parent organizations row by row (one query per
  ancestor, cycle-safe).
* `RawSqlValidator` parses SQL with libpg_query on every raw call; `TenantSession`
  rejects `TextClause` in the ORM path, so this cost applies only to explicit
  `raw_sql` use.
* `install_rls`/`verify_rls` issue several statements per eligible table.
* `tenant_table_map()` re-walks subclasses and re-imports model modules on
  invocation (called by `RawSqlValidator` defaults and the purger).
* `uuid7()` allocates 16 random bytes per id (`os.urandom`) — cheap but not
  monotonic within a millisecond.

---

## 17. Extensibility and Plugin Architecture

`jdlib` is extended almost entirely by **implementing a Protocol and injecting
it**. There is no plugin discovery, entry-point registry (besides pytest), or
hook system.

### 17.1 Extension points

| Interface | Abstract? | Built-in implementations | Consumer example |
|---|---|---|---|
| `Authenticator` (`authn/base.py:10-11`) | Protocol | `OidcAuthenticator`, `ApiKeyAuthenticator`, `CompositeAuthenticator` | custom SAML/basic auth composed via `CompositeAuthenticator` |
| `TenantResolver` (`tenancy/resolution.py:24-27`) | Protocol | 5 resolvers | host/cookie/query-string tenant resolution |
| `IsolationStrategy` (`strategies/base.py:19-37`) | Protocol (not `runtime_checkable`) | 3 strategies | a Redis/Kafka-sharded or "schema with pooling proxy" placement |
| `AccessReader` (`authz/reader.py:28-52`) | Protocol | `ControlAccessReader` | cache-backed or replicated authorization reads |
| `PolicyDecisionPoint` (`authz/pdp.py:30-39`) | Protocol | `DefaultPDP` | OPA/Cedar/Casbin-backed PDP |
| `PlatformAudit` (`control/audit.py:27-37`) | Protocol | `DatabaseAuditSink`, `CompositeAuditSink`, `RecordingPlatformAudit` | shipping audit to a SIEM/S3 |
| `PrivilegeAudit` (`context.py:155-164`) | Protocol | `PrivilegeAuditAdapter` | custom privilege ledger |
| `WriteFence` (`persistence/models.py:32-33`) | Protocol | `RegistryWriteFence`, `NullWriteFence` | an app-specific freeze/quiesce signal |
| `SecretProvider` (`persistence/secrets.py:7-8`) | Protocol | `MemorySecretProvider`, `EnvSecretProvider` | Vault/AWS Secrets Manager lookup |
| `SeedHook` (`control/registry.py:72-78`) | Protocol | `_NoopSeedHook` default | per-tenant role/resource seeding |
| `ScopeLookup` / `ResourceLookup` (`authz/access.py:53-82`) | Protocol callables | **none** | wire org/team/resource existence into `AccessControl` |
| `PrincipalDirectory` / `TenantDirectory` / `EntitlementChecker` / `ServabilityChecker` / `OperatorAuthorizer` (`context.py:135-152`) | Protocols | 3 adapters + `TenantRegistry` | custom identity/entitlement/operator systems |
| `RawSqlAuditor` (`persistence/session.py:26-29`) | Protocol | `_NoopRawSqlAuditor` | record all raw SQL (not just privileged) |
| `RawSqlValidator` (`persistence/session.py:272`) | concrete, injectable | default `RawSqlValidator` | stricter/looser structural rules per app |
| `TenantBase` mixins | declarative | `TenantOwned`, `TenantRouted`, `Timestamped`, `SoftDelete`, `OwnableByOrg`, `OwnableByTeam` | application models |
| `ownership_constraints()` | function | — | composes check + composite FKs |
| `PermissionCatalog.register` | registry method | 13 built-ins | application permission codes |
| `ResourceTypeRegistry.register` | registry method | empty | application resource types |
| `Permission` | dataclass | built-ins | custom namespace/codes |
| `ResolverChain` / `build_chain` | composition | 5 resolvers | custom resolution order |
| `CompositeAuditSink` / `CompositeAuthenticator` | composition | — | fan-out policies |
| `TenantMiddleware` + `install` | composition | — | adding consumer ASGI middleware around the pipeline |
| Alembic env + `emit_rls_policies` | integration hook | — | consumer migrations that create tables and then emit policies |

### 17.2 Practical examples

**Custom authenticator:**

```python
from jdlib.authn.base import Authenticator
from jdlib.authn.composite import CompositeAuthenticator
from jdlib.context import Principal, PrincipalKind
from jdlib.tenancy.resolution import RequestInfo

class BasicAuthenticator:
    def __init__(self, lookup): self._lookup = lookup

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        user_id = self._lookup(request.headers.get("authorization", ""))
        if user_id is None:
            return None
        return Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)

authenticator = CompositeAuthenticator([BasicAuthenticator(lookup), oidc, api_key])
```

**Custom isolation strategy:**

```text
IsolationStrategy (Protocol)
 ├── built-in: SharedSchemaStrategy
 ├── built-in: SchemaPerTenantStrategy
 ├── built-in: DatabasePerTenantStrategy
 └── consumer: MyStrategy
      ├── name = "mystrategy"
      ├── capabilities = StrategyCapabilities(supports_rls=False, supports_ddl=True)
      ├── session(tenant) -> AsyncSession
      ├── provision(tenant) / migrate(tenant, runner) / deprovision(tenant, mode)
      └── migration_schema(tenant) -> str
```

Register it by extending `TenantPlacement`/`PlacementStrategy` data and passing
it in the `strategies` mapping to `TenantRegistry`; `SessionRouter` will
dispatch by `tenant.strategy` (`README.md:378-380`).

**Custom PDP:**

```python
class ExternalPDP:  # satisfies PolicyDecisionPoint
    def __init__(self, client): self._client = client

    async def evaluate(self, principal, permission, target, context, *, session) -> Decision:
        allowed = await self._client.check(
            subject=str(principal.id), action=permission,
            tenant=str(context.tenant_id), target=target)
        return Decision(allowed=allowed, reason="allowed" if allowed else "no_allow", matched=())

enforcer = Enforcer(ExternalPDP(client))
```

**Custom audit fan-out and privilege bridging:**

```python
audit = CompositeAuditSink(DatabaseAuditSink(sessions), ShipToSiem(...))
context_factory = ContextFactory(..., audit=PrivilegeAuditAdapter(audit))
```

**Consumer models:**

```python
from sqlalchemy.orm import Mapped, mapped_column
from jdlib.models.base import (
    OwnableByOrg, OwnableByTeam, SoftDelete, TenantBase, TenantRouted, Timestamped,
    ownership_constraints,
)

class Invoice(TenantBase, TenantRouted, Timestamped, SoftDelete,
              OwnableByOrg, OwnableByTeam):
    __tablename__ = "invoices"
    __table_args__ = ownership_constraints()
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    number: Mapped[str]
```

(`tests/support/invoice.py:20-52` is the executable reference implementation of
this pattern, including the composite FK to a `LineItem`.)

### 17.3 Extension limitations

* Protocols are **not** `@runtime_checkable`, so `isinstance` checks against
  them are not available.
* `IsolationStrategy` has no `health_check`/`invalidate`/`dispose` in the
  protocol, so strategies with caches (like the database strategy) expose
  extra methods the registry/router never call.
* No middleware/hook pipeline around the request path other than composing
  `TenantMiddleware` with other ASGI middleware.
* No plugin entry points other than the `pytest11` plugin.

---

## 18. Packaging and Distribution

### 18.1 Build configuration

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "jdlib"
version = "0.1.0"
description = "Reusable multi-tenant foundation"
requires-python = ">=3.12"
dependencies = [
  "alembic>=1.13", "argon2-cffi>=23.1", "asyncpg>=0.29", "httpx>=0.27",
  "pglast>=6.0", "psycopg[binary]>=3.2", "pydantic>=2.7",
  "pydantic-settings>=2.3", "pyjwt[crypto]>=2.8", "sqlalchemy[asyncio]>=2.0.30",
]

[project.optional-dependencies]
dev     = ["fastapi>=0.111", "httpx>=0.27", "mypy>=1.10", "pytest>=8.2",
           "pytest-asyncio>=0.23", "ruff>=0.5", "testcontainers[postgres]>=4.5",
           "typer>=0.12"]
fastapi = ["fastapi>=0.111"]
cli     = ["typer>=0.12"]
http    = ["httpx>=0.27"]

[project.entry-points.pytest11]
jdlib = "jdlib.testing.pytest_plugin"

[tool.hatch.build.targets.wheel]
packages = ["src/jdlib"]
```

Source: `pyproject.toml:1-42` (64 lines total).

### 18.2 Packaging facts and gaps

| Aspect | Value | Note |
|---|---|---|
| Backend | hatchling | no version pin |
| Wheel contents | `src/jdlib` only | `tests/`, `docs/`, `.github/` are **not** packaged |
| `py.typed` | present (`src/jdlib/py.typed`, empty) | PEP 561; no explicit package-data rule (hatchling includes package files) |
| sdist target | not configured | hatchling's default applies |
| Entry points | `pytest11` only | **no console script**; consumers expose `jdlib.integrations.cli:app` themselves |
| Version source | hard-coded in `pyproject.toml:7` and `__init__.py:27` | duplicated, not dynamic |
| Optional extras | `fastapi`, `cli`, `http` | `http` (`httpx>=0.27`) was added by phase 2; `httpx` is also a core dependency |
| `readme`, `license`, `authors`, `classifiers`, `keywords`, `urls` | **absent** | a `LICENSE` file does not exist either |
| Lock files | none (`uv.lock`, `poetry.lock`, `requirements*.txt` all absent) | reproducibility is left to the consumer |
| Dependency bounds | lower bounds only | no upper bounds; resolver picks the latest compatible |

### 18.3 Tool configuration

| Tool | Configuration |
|---|---|
| pytest | `asyncio_mode = "auto"`, `testpaths = ["tests"]`, markers `unit` / `integration` / `infra` / `e2e` (`pyproject.toml:44-52`) |
| ruff | `line-length = 100`, `target-version = "py312"`, `select = ["E","F","I","UP","B","SIM"]` (`pyproject.toml:54-59`) |
| mypy | `python_version = "3.12"`, `strict = true`, `files = ["src/jdlib"]` (`pyproject.toml:61-64`) |
| coverage / tox / nox / black / isort / pyright / pylint | **absent**; `bandit` is not configured in `pyproject.toml` either — it runs only in CI (§19.6) |

### 18.4 Installation

```bash
pip install jdlib
pip install "jdlib[fastapi]"   # FastAPI integration
pip install "jdlib[cli]"       # Typer CLI
pip install -e ".[dev]"        # from a checkout: tests, lint, type check
```

### 18.5 Distribution workflow

**Not present.** There is no publish/release workflow and no twine/uv-publish
configuration. The CI `security` job now builds a wheel and smoke-installs it
into a clean environment (§19.6), but nothing tags or uploads a release, and
there is no PyPI metadata beyond the name/version. Distribution status on PyPI
is **Unknown / Requires Confirmation** (the README documents
`pip install jdlib`, but no publishing automation exists in the repository).

### 18.6 Versioning policy

Version `0.1.0`; the working tree now carries a `CHANGELOG.md` (phase 11) that
records the security-hardening programme as **unreleased** changes, but there
are no tags documented in-repo, no published release, and no deprecation policy.
Compatibility guarantees: **Unknown / Requires Confirmation**. The design docs
describe a frozen public API, which is the only observable compatibility
contract
(`docs/superpowers/plans/2026-09-21-jdlib-integrations-phase-6.md:364-382`).

### 18.7 Packaging flow

```mermaid
graph LR
    SRC["src/jdlib (104 .py + 2 .mako + py.typed)"] --> HATCH["hatchling build backend"]
    PYPROJ["pyproject.toml<br/>metadata + deps + extras"] --> HATCH
    HATCH --> WHEEL["wheel: jdlib/… (py.typed included)"]
    HATCH --> SDIST["sdist (hatchling default)"]
    WHEEL --> INST["pip install jdlib[fastapi|cli]"]
    SDIST --> INST
    INST --> EP["pytest11 entry point auto-loads jdlib.testing.pytest_plugin"]
    WHEEL -.not included.-> T["tests/ docs/ .github/"]
```

---

## 19. Testing Architecture

### 19.1 Suite shape

**At `a30601d` (the pre-hardening baseline):**

| Metric | Value |
|---|---|
| Total passing tests | **568** (`pytest -q -W error`, fresh PostgreSQL 16) |
| Test-function definitions | 527 (268 unit + 259 integration) |
| Unit files | 36 modules, 4,587 lines |
| Integration files | 26 test modules + `conftest.py` + `rls_support.py` + `strategy_support.py`, 8,258 lines |
| Support (fakes/fixtures) | 3 files, 178 lines |
| Parametrized tests | 7 functions; a 4-case `matrix` fixture yields 24 nominal cases from 6 test definitions |
| Warnings policy | `-W error` in the verification run; any warning is a failure |

**At `4d113e5`, re-verified for this revision (§26.6):**

| Metric | Value |
|---|---|
| Total passing tests | **1,215** (`pytest -q -W error`, real PostgreSQL 16 via testcontainers, 71.87 s) |
| Skipped | **6**, all in `tests/infra/test_tyk_infra.py` (§19.7) |
| Test-function definitions | 1,019 (677 unit + 307 integration + 35 infra) |
| Unit | 66 modules (37 top-level + 29 under `unit/security/`), 11,650 lines |
| Integration | 33 test modules + `conftest.py` + `rls_support.py` + `strategy_support.py`, 9,824 lines |
| Infra | 5 modules, 1,589 lines — live Kong, Cerbos, ZITADEL and OpenTelemetry harnesses |
| Support (fakes/fixtures) | 3 files, 178 lines |
| Warnings policy | `-W error` in the verification run; any warning is a failure |

Without the `JDLIB_INFRA_*` settings the infrastructure classes skip themselves
and the same suite reports 1,190 passed, 31 skipped — the difference is exactly
those classes (Kong 9, Cerbos 12, ZITADEL 4, Tyk 6), each skip naming the
variable it wants.

### 19.2 Architecture of the suite

```mermaid
graph TB
    TS["tests/"] --> U["unit/ (677 defs)"]
    TS --> I["integration/ (307 defs)"]
    TS --> N["infra/ (35 defs)"]
    TS --> S["support/ (fakes + consumer Invoice model)"]

    U --> U1["enforcement units: session, rawsql, pdp, guards, context, envelopes, strategies, lint, config, errors, uuid"]
    U --> U2["unit/security/: authn, authz, gateway, audit, telemetry, tracing, replies, compliance"]
    I --> I1["real PostgreSQL 16 via testcontainers or JDLIB_TEST_DATABASE_URL"]
    I1 --> I2["conftest: postgres_url, control_engine, control_metadata, async_engine, session_factory, control_session_factory"]
    I2 --> I3["registry/lifecycle, access control, authn, RLS, purge, migrations, strategy matrix, FastAPI/CLI e2e, security-audit persistence, compliance collectors"]
    N --> N1["live Kong 3.6, Cerbos, ZITADEL, OpenTelemetry collector; Tyk harness skipped without a coprocess runtime"]
    S --> S1["FrozenClock, StaticPrincipals, DictTenants, ServabilityStub, EntitlementsStub, ServiceAccountEntitlementsStub, OperatorsStub, RecordingPrivilegeAudit, Invoice/LineItem"]
```

### 19.3 Fixtures and test doubles

`tests/integration/conftest.py:14-84` provides: `postgres_url` (session;
`JDLIB_TEST_DATABASE_URL` or a `postgres:16` testcontainer), `control_engine`
(creates `jd_control` + `jt_test` schemas and enables `citext`),
`control_metadata`, `async_engine` (function; `search_path=jt_test`, tenant
tables created), `session_factory`, `control_session_factory`. Additional
fixtures: `matrix` (4 strategies), `rls_app_role` (a `NOBYPASSRLS` role),
`rls_engine`, `tenant_metadata`, `rls_app_engine`, `make_strategy`.

`tests/support/context_fakes.py` supplies the port doubles listed in §7.1.
`tests/support/invoice.py` is a realistic consumer model (composite FK,
partial unique index, ownership constraints) used as a schema fixture.

### 19.4 Which components are covered

| Component | Representative tests |
|---|---|
| Session scoping (core contract) | `integration/test_session_isolation.py` (39 defs: scoped reads, entity-less counts, table/text/literal/alias/`FromStatement` rejection, joins, cross-tenant `get`, stamping, immutability, unscoped bulk, soft/hard delete) |
| Strategy independence | `integration/test_strategy_matrix.py` (identical assertions for shared, shared-rls, schema, database) |
| Raw SQL proof | `unit/test_rawsql.py` (24 defs) + `unit/test_session.py` |
| Authorization | `unit/test_pdp.py`, `unit/test_guards.py`, `unit/test_permissions.py`, `unit/test_resource_types.py`, `integration/test_access_*.py`, `integration/test_role_action_matrix.py`, `integration/test_scopes.py`, `integration/test_pdp_control_reader.py` |
| Authentication | `unit/test_oidc_*.py`, `unit/test_apikey_parser.py`, `integration/test_apikey_auth.py`, `integration/test_oidc_linking.py`, `integration/test_authn_composite.py`, `integration/test_auth_wiring.py` |
| Lifecycle | `integration/test_registry.py` (46 defs incl. races), `test_registry_models.py`, `test_tenant_purge.py` |
| Strategies/RLS | `integration/test_schema_strategy_db.py`, `test_database_strategy_db.py`, `test_rls_db.py`, `unit/test_strategy_lifecycle.py`, `unit/test_database_strategy.py` |
| Migrations | `integration/test_migrations.py` |
| Context/envelopes/jobs | `unit/test_context_factory.py`, `test_context_values.py`, `test_envelope.py`, `test_jobs.py`, `integration/test_auth_wiring.py` |
| HTTP surface | `unit/test_middleware.py`, `integration/test_fastapi_integration.py` |
| Metadata invariants | `unit/test_lint.py` (15 defs, one per implemented rule) |
| Public API boundary | `unit/test_public_api.py` (exact `__all__`, version, no optional imports) |
| Audit | `unit/test_platform_audit_sinks.py`, `integration/test_audit_sinks.py` |
| CLI | `unit/test_cli.py`, `integration/test_cli_integration.py` |
| Test kit | `unit/test_testing_kit.py` |
| Security core | `unit/security/test_security_context.py`, `test_security_config.py`, `test_security_errors.py`, `test_security_interfaces.py`, `test_security_public_surface.py` (exact security surface), `test_error_responses.py` |
| Security authn | `unit/security/test_jwt_validator.py`, `test_jwks_hardening.py`, `test_token_provider.py`, `test_zitadel_adapter.py`, `test_service_identity.py`; `integration/test_authn_composite.py`, `test_authn_http_integration.py` |
| Security authz | `unit/security/test_authz_decision.py`, `test_authz_pep.py`, `test_cerbos_pdp.py`; `tests/infra/test_cerbos_infra.py` (12 defs) |
| Gateway | `unit/security/test_gateway_adapters.py`; `tests/infra/test_kong_infra.py` (9 defs) |
| Security audit | `unit/security/test_audit_events.py`, `test_audit_emitters.py`, `test_audit_access_export.py`, `test_audit_adapters.py`, `test_audit_control_adapters.py`; `integration/test_security_audit_persistence.py`, `test_audit_isolation_export.py`, `test_audit_raw_sql_refusal.py` |
| Telemetry and tracing | `unit/security/test_telemetry.py`, `test_tracing.py`; `tests/infra/test_otel_infra.py` (4 defs) |
| Compliance and the security CLI | `unit/security/test_compliance_controls.py` (9), `test_compliance_evidence.py` (12), `test_compliance_posture.py` (31); `unit/test_cli_security.py` (13); `integration/test_compliance_live_collectors.py` (6, real PostgreSQL) |
| Adversarial regressions | `unit/security/test_adversarial.py`, `test_adversarial_privilege.py`, `test_adversarial_service_identity.py`, `test_adversarial_audit_integrity.py` |
| Live infrastructure | `tests/infra/` — Kong 3.6 (9), Cerbos (12), ZITADEL (4), OpenTelemetry collector (4), Tyk (6; skipped without a JavaScript/coprocess runtime) |

### 19.5 Concurrency and security regression tests

Provisioning serialization, distinct-tenant parallelism, deprovision
state-change and child-insert races (`test_registry.py:493-529, 826-888`),
concurrent idempotent grant insert, concurrent invitation claim, owner-count
race under the advisory lock, OIDC identity-link and deleted-user races,
database-pool invalidation during eviction, and real checked-out-pool cap
behavior. Security regressions include all eight historical cross-tenant read
paths, raw-DML `tenant_id` mutation, the API-key scope-escalation fix, the
non-member 423 existence leak, un-audited privileged contexts, and the
API-key tenant-pin bypass.

### 19.6 CI

`.github/workflows/ci.yml` defines **two** jobs, both on `ubuntu-latest` and
both build-failing:

* `test` (pre-existing): `actions/checkout@v4` → `actions/setup-python@v5`
  (3.12) → `pip install -e ".[dev]"` → `ruff check .` → `mypy src/jdlib` →
  `pytest -q`. No matrix, no PostgreSQL service; integration tests rely on the
  runner's Docker for testcontainers.
* `security` (phase 10; `docs/security/ci-security.md`): five gates, each of
  which fails the build on its own — `pip-audit` against the installed
  environment; `gitleaks` over the **full history**, so an old leak is still a
  finding; `bandit -ll` over `src/jdlib`; a CycloneDX SBOM of the installed
  environment written as a build artefact; and a build + clean-install smoke
  test (wheel built, installed into a fresh environment, `import jdlib` and the
  CLI help checked, so a packaging mistake cannot ship silently).

The gates are deterministic and deliberately shallow: they are a floor under
review, not a substitute for it, and the phase document records what each one
does and does not catch.

### 19.7 Known test gaps

* No coverage tooling or threshold is configured; coverage is **Unknown /
  Requires Confirmation**.
* `tests/isolation/` (proposed in `docs/jdlib/03-isolation-invariants.md:263-293`)
  does not exist; isolation coverage is distributed across the suites above.
* Relocation phases have schema support and lint/servability integration but no
  executed relocation workflow, because relocation is not implemented (§23).
* `examples/` is absent, so no example-driven smoke test exists.

---

## 20. Consumer Integration

### 20.1 Integration shape

```mermaid
graph TB
    subgraph App["Consumer application"]
        CFG["TenancyConfig (JDLIB_* env)"]
        ENG["create_async_engine + async_sessionmaker"]
        WIR["Wiring module: registry, strategies, PDP, adapters"]
        APP["FastAPI app + routes"]
        JOB["Background job handlers"]
    end

    subgraph JDL["jdlib"]
        MW["TenantMiddleware"]
        CF["ContextFactory"]
        REPO["TenantRepository / UnitOfWork"]
        AC["AccessControl"]
        REG["TenantRegistry"]
        CLI["Typer CLI (own entry point)"]
    end

    CFG --> ENG
    ENG --> WIR
    WIR --> CF
    WIR --> REPO
    WIR --> AC
    WIR --> REG
    APP --> MW
    MW --> CF
    APP --> REPO
    JOB --> ENV["EnvelopeCodec / tenant_job"]
    CLI -.operators.-> REG
```

### 20.2 Minimal lifecycle

1. **Install** `jdlib` (+ extras).
2. **Configure** via `JDLIB_*` env or `TenancyConfig(...)`; the context signing
   key is mandatory.
3. **Create engines** — the consumer owns engine/pool configuration; jdlib has
   no factory.
4. **Migrate** the control plane: `MigrationRunner(url).upgrade_control()` or
   `jdlib db upgrade-control`.
5. **Provision tenants** with `TenantRegistry.create(...)` +
   `.provision(id)` (or `jdlib tenant create` / `jdlib tenant provision`).
6. **Wire** `ContextFactory`, resolver chain, authenticator, container, and
   `install(app, …)`.
7. **Access data** through `UnitOfWork` + `TenantRepository`; guard routes with
   `require(...)`.
8. **Operate** through the CLI (own entry point) and `AccessControl`.
9. **Propagate** context to workers with `EnvelopeCodec.encode` /
   `tenant_job(propagator)`.
10. **Test** with `jdlib.testing` assertions and the `jdlib_*` fixtures.
11. **Shut down** by disposing engines and calling `strategy.dispose()`.

### 20.3 Recommended patterns (from README/design docs)

* **Request-scoped PDP.** Never build one `DefaultPDP`/`AuthzCache` at import
  time and share it across requests; build a fresh PDP per guard evaluation
  (`README.md:220-222`, example at `README.md:150-159`).
* **Hybrid placement routing.** In `uow_factory`, branch on
  `context.strategy` via `SessionRouter` so application code above the session
  factory never changes (`README.md:216-218, 267-269`).
* **Privilege audit bridging.** Pass `PrivilegeAuditAdapter(audit)` to
  `ContextFactory`, not the raw `PlatformAudit` (`README.md:233-235`).
* **Operator denial by default.** The README's `OperatorAuthorizer` returns
  `False` — privileged access stays off until a real directory is wired.
* **CLI secret limitation.** Provisioning `database` placement needs the
  database strategy plus a `SecretProvider` registered programmatically
  (`README.md:362-365`).
* **RLS role requirements.** Pass `rls=config.rls` to `SharedSchemaStrategy`;
  the runtime role must be `NOBYPASSRLS`, not the owner, not a superuser
  (`README.md:300-318`).

### 20.4 Error handling in a consumer app

```text
JdlibError inside a route/dependency  → FastAPI _handle_jdlib_error → mapped JSON
JdlibError before the route (authn, resolution, context) → TenantMiddleware → mapped JSON
Driver/SQLAlchemy errors              → propagate (consumer must map them)
Guarded denial                          → PermissionDenied → 403
Non-servable tenant                    → TenantSuspended/TenantNotWritable → 423
Unknown principal                      → UnknownPrincipal → 401
```

### 20.5 Cleanup responsibilities

| Resource | Owner | Cleanup |
|---|---|---|
| tenant session/transaction | `UnitOfWork` | automatic commit/rollback/close |
| control session | `ControlPlaneSession` | caller closes (and commits) |
| tenant/admin engines (database strategy) | strategy | `await strategy.dispose()` |
| consumer engines | consumer | `engine.dispose()` |
| authz cache | consumer | per-request instance; nothing to clean |
| JWK cache | consumer | `JwksCache` per process; TTL-based |

---

## 21. End-to-End Workflows

### 21.1 Authenticated HTTP request → scoped read

1. **Start:** client sends `Authorization: Bearer <oidc|jd.key.secret>` plus
   `X-Tenant-Slug: acme`.
2. **Public API:** `TenantMiddleware.__call__` (installed by
   `jdlib.integrations.fastapi.install`).
3. **Validation:** `_request_info` (lowercased headers, parsed query, empty
   claims); `CompositeAuthenticator.authenticate`; `ResolverChain.resolve` →
   `HeaderResolver` → `TenantRef(slug="acme")`.
4. **Internal processing:** `ContextFactory.for_principal` performs
   principal-active → tenant lookup → service-account pin → entitlement →
   servability checks and builds the context; `context_scope` installs it.
5. **Collaborators:** authenticator, `AccessReader` (via adapters),
   `TenantRegistry.find`, `RegistryWriteFence` predicate.
6. **External calls:** 2–4 control-plane queries (identity, tenants, membership).
7. **Transformation:** `TenantRef` → `TenantRecord` → `TenantContext`.
8. **Data access:** handler opens `UnitOfWork`; `TenantRepository.list()`
   triggers `with_loader_criteria`; SQL includes `WHERE tenant_id = $1`.
9. **Error handling:** any `JdlibError` before the route is mapped to JSON; a
   denial inside a guard raises `PermissionDenied` → 403.
10. **Result:** JSON response; context reset on the way out.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant MW as TenantMiddleware
    participant AU as CompositeAuthenticator
    participant CF as ContextFactory
    participant AR as ControlAccessReader
    participant REG as TenantRegistry
    participant H as Handler
    participant U as UnitOfWork/TenantSession
    participant DB as PostgreSQL

    C->>MW: GET /invoices (Bearer …, X-Tenant-Slug: acme)
    MW->>AU: authenticate(RequestInfo)
    AU->>DB: api_keys/users/identity_links
    AU-->>MW: Principal(USER)
    MW->>MW: ResolverChain → TenantRef(slug=acme)
    MW->>CF: for_principal(principal, ref, request_id, correlation_id, trace_id)
    CF->>AR: principal_active / membership_active
    CF->>REG: find(TenantRef) + assert_servable
    REG->>DB: tenants + migration_state + relocations
    CF-->>MW: TenantContext
    MW->>H: with context_scope(context)
    H->>U: async with UnitOfWork(...) as session
    U->>DB: fence.assert_writable (control reads)
    H->>U: TenantRepository(session, Invoice).list()
    U->>DB: SELECT … FROM invoices WHERE tenant_id = $1
    DB-->>H: rows
    H-->>C: 200 JSON
    U->>DB: COMMIT
    MW->>MW: context reset
```

### 21.2 Tenant provisioning (schema placement)

1. **Start:** `registry.create(slug="acme", name="Acme Inc",
   strategy=PlacementStrategy.SCHEMA, target_handle="t_acme")`.
2. **Validation:** strategy normalization; handle regex
   `^t_[a-z0-9][a-z0-9_]{0,50}$`; slug advisory lock; idempotency check (an
   existing slug with identical strategy/handle/region returns the existing
   tenant); handle advisory lock rejects a handle already used by another
   schema tenant.
3. **Internal processing:** insert `Tenant`, `TenantPlacement`,
   `TenantMigrationState(status=pending, desired_version="0001_tenant_baseline")`.
4. **Collaborators:** `ControlPlaneSession`, `PlatformAudit`.
5. **External call:** one control transaction; audit row flushed in the same
   transaction (`session=…`).
6. **Then:** `registry.provision(tenant.id)` → tenant advisory lock →
   `SchemaPerTenantStrategy.provision` (`CREATE SCHEMA IF NOT EXISTS t_acme`) →
   migration state `running` → `strategy.migrate` →
   `MigrationRunner.upgrade_tenant("t_acme")` → optional `SeedHook.seed` →
   `tenant_version("t_acme") == "0001_tenant_baseline"` → status `active` →
   audit → commit.
7. **Transformation:** `TenantRecord` carries `strategy` + `target_handle`;
   `SessionRouter` maps that to sessions later.
8. **Error handling:** any failure commits `migration_state=failed` +
   `last_error`, audits `tenant.migration.failed`, and re-raises; the tenant
   stays `provisioning` and therefore unservable.
9. **Result:** an active, servable tenant with its schema migrated.

### 21.3 Guarded write (FastAPI `require` + `get_uow`)

1. **Start:** `Depends(require("resource:create"))` on a route.
2. **Validation:** `require` opens its own `uow_factory()`; the
   `RegistryWriteFence` runs (so a relocating tenant yields 423 even for a
   guarded read); the target defaults to `tenant_target()`.
3. **Internal processing:** `Enforcer.require` → `DefaultPDP.evaluate`:
   catalog validation → principal → tenant → membership → scope chain →
   bindings → role permissions → key-scope intersection.
4. **Collaborators:** `ControlAccessReader`, `ScopeResolver`,
   `PermissionCatalog`, `AuthzCache`.
5. **External calls:** the control-plane reads above (memoized per request).
6. **Transformation:** `Decision(allowed, reason, matched)`; denial raises
   `PermissionDenied(f"resource:create: {reason}")`.
7. **Handler:** `get_uow` yields a **new** `UnitOfWork`; the handler writes via
   `TenantRepository`/`TenantSession`; `before_flush` stamps `tenant_id`.
8. **Error handling:** denial → 403; cross-tenant stamp → `CrossTenantReferenceError`
   → 409; unscoped bulk DML → `UnscopedBulkOperation` → 500.
9. **Result:** the row is committed in the handler's transaction. The guard's
   decision is **not** revalidated in that transaction (documented TOCTOU).

### 21.4 Database-placement request and engine-cache pressure

```mermaid
sequenceDiagram
    autonumber
    participant H as Handler
    participant RO as SessionRouter
    participant SD as DatabasePerTenantStrategy
    participant SP as SecretProvider
    participant CA as OrderedDict engine cache
    participant DB as Tenant database / admin DB

    H->>RO: session(tenant_record)
    RO->>SD: session(tenant)
    SD->>SD: validate_database_handle(target_handle)
    SD->>SP: resolve("db-initech")
    SP-->>SD: postgresql+asyncpg://…/initech
    SD->>CA: lookup handle
    alt cache miss
        SD->>CA: evict_idle (first engine with pool.checkedout()==0)
        alt all engines checked out
            CA-->>SD: none idle
            SD-->>H: PoolCapacityError
        else idle engine found
            CA-->>SD: evicted engine
            SD->>DB: engine.dispose()
        end
        SD->>DB: create_async_engine(dsn)
        SD->>CA: insert (LRU order)
    end
    SD-->>H: AsyncSession
```

### 21.5 Async job with signed envelope

Covered by the diagram in §8.3. In sequence: request handler encodes a
`TenantContext`; a queue stores the token; `tenant_job` reconstructs and
**re-validates** principal activity, tenant existence, entitlement, and
servability; the handler runs under a fresh context; failures
(`InvalidToken`/`ExpiredToken`/`UnknownPrincipal`/`TenantNotFound`/
`TenantAccessDenied`/`TenantSuspended`) occur **before** the handler is entered.

### 21.6 Deprovision (purge/destroy) with child-first ordering

1. `registry.deprovision(tenant_id, mode=DeprovisionMode.PURGE)`.
2. Requires `archived` (or already `deprovisioning`), commits `deprovisioning`,
   then releases and re-acquires the advisory lock and re-reads with
   `populate_existing=True` to detect superseded state.
3. Re-checks children (`parent_tenant_id`).
4. Deletes control access rows in `_ACCESS_ROW_DELETION_ORDER`.
5. Calls `strategy.deprovision`: `DROP SCHEMA … CASCADE` (schema) or terminate
   backends + `DROP DATABASE IF EXISTS` (database); shared placement instead
   requires the configured `TenantPlanePurger`.
6. `TenantPlanePurger` (shared) obtains a system privilege, walks
   `sorted_tables` in reverse for child-first deletion, deletes through
   `TenantSession.delete_where`, commits once, and returns row counts.
7. Marks the tenant `deleted` and audits counts. The tenant, placement,
   migration state, relocations, global users, and platform audit rows are
   retained.

### 21.7 Invitation acceptance

```mermaid
sequenceDiagram
    autonumber
    participant U as Invitee
    participant AC as AccessControl
    participant PG as jd_control
    participant B as Binding writer
    participant A as PlatformAudit
    participant C as AuthzCache

    U->>AC: accept_invitation(token, user_id=…)
    AC->>AC: parse inv_<id>_<secret>
    AC->>PG: load invitation by token_id
    AC->>AC: verify Argon2 hash, status=pending, not expired
    AC->>PG: conditional claim UPDATE … WHERE status='pending' RETURNING
    AC->>AC: re-validate scope + role/permission compatibility
    alt active membership exists
        AC->>B: ensure role binding exists
    else new membership
        AC->>PG: insert membership + role binding
    end
    AC->>C: cache.invalidate()
    AC->>A: invitation.accepted
    AC->>PG: COMMIT
    AC-->>U: Membership
```

### 21.8 Security posture run (`jdlib security …`)

The operator-facing workflow behind the `security` CLI group (§8.20) and the
compliance package (§8.22) — the same call a pipeline can gate on:

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator / CI
    participant CLI as jdlib security posture
    participant CFG as Declared profile
    participant CO as Evidence collectors
    participant REG as CONTROL_REGISTRY (19 controls)
    participant RP as PostureReport

    OP->>CLI: posture --environment production --database-url … --schema …
    CLI->>CFG: _declared_config(environment) (BadParameter on an unknown profile)
    CLI->>CO: configuration, migration (+ policy-directory) evidence
    CLI->>CO: isolation + schema-revision evidence (only with --database-url and --schema)
    CLI->>REG: evaluate_posture(config, evidence=…, environment=…)
    REG->>RP: one finding per control — outcome, severity, reason, evidence summary
    RP-->>OP: table or --json; exit 1 when any control FAILs
```

`jdlib security evidence` runs the same collection without the verdict, and
`jdlib security compliance` reports the register itself (optionally filtered by
`--framework`) with the posture counts for the declared profile. All three are
read-only; none of them needs a database unless a live collector was asked for.

---

## 22. Architectural Decisions

For each decision: problem, decision, reason (with evidence), alternatives,
trade-offs, consequences. Where the repository does not state a rationale, it
is marked as not evident.

### 22.1 Two data planes instead of one schema per tenant only

* **Problem:** tenant metadata and tenant data have different lifecycles and
  different access rules.
* **Decision:** a global `jd_control` schema plus unqualified tenant-plane
  tables resolved by `search_path` (`control/base.py:6-21`,
  `models/base.py:13-14`).
* **Reason (evidenced):** `docs/jdlib/02-relational-schema.md` freezes this and
  lint L3/L19 actively prevent cross-plane FKs and misrouted models.
* **Alternatives:** single schema with a `tenants` table (rejected: RLS/purge
  and audit survival become harder).
* **Trade-off:** two metadata roots, two migration chains, and two engines in
  some deployments.
* **Consequences:** `ControlPlaneSession` is a separate wrapper; the purge path
  must move between planes; `PlatformAuditEvent.tenant_id` intentionally has no
  FK.

### 22.2 Composite `(tenant_id, id)` identity and composite tenant FKs

* **Problem:** single-column UUID PKs make cross-tenant references possible at
  the database level.
* **Decision:** every tenant-scoped table leads its PK with `tenant_id`; FKs
  between tenant tables include `tenant_id` (`models/base.py:17-27`,
  `ownership_constraints()`).
* **Reason (evidenced):** invariants I3/I4; lint L1/L2/L4.
* **Consequences:** `TenantSession.get` must use composite keys; repository
  and raw-SQL proofs can rely on `tenant_id` being part of identity; consumers
  write composite FKs themselves.

### 22.3 Enforce scoping with SQLAlchemy events, not a custom session/mapper

* **Problem:** a bespoke ORM layer would be invasive and easy to bypass.
* **Decision:** wrap the consumer's own `AsyncSession` with `TenantSession` and
  register `do_orm_execute` + `before_flush` per instance
  (`persistence/session.py:109-254`).
* **Reason (evidenced):** the design docs require every path to be scoped; event
  hooks reach ORM selects, relationship loads, and flushes without replacing
  SQLAlchemy.
* **Alternatives:** global mapper events (rejected: cross-instance leakage),
  row-level security only (rejected: not available for schema/database
  placement, and still needs logical checks).
* **Trade-off:** untrusted query shapes must be rejected rather than rewritten;
  the DML gate trusts execution-option markers.
* **Consequences:** bare tables, raw aliases, text, and `FromStatement` are
  refused; consumers must go through entities (or `raw_sql`).

### 22.4 Prove raw SQL structurally with libpg_query

* **Problem:** regex/string inspection of SQL is unsound.
* **Decision:** `pglast.parse_sql` + per-relation predicate proof
  (`persistence/rawsql.py`).
* **Reason (evidenced):** `docs/jdlib/03-isolation-invariants.md:177-233` freezes
  the per-statement proof table; `pglast` is a declared runtime dependency.
* **Alternatives:** prepared-statement-only access, a query DSL, or regex
  (rejected as unsound).
* **Trade-off:** CTEs, subqueries, `OR`/`NOT`, and set operations are rejected
  even when a human could prove them; one parse per call.
* **Consequences:** the raw-SQL surface is intentionally small.

### 22.5 Placement as data with a strategy protocol

* **Problem:** code branching per tenant would make hybrid deployments
  impossible and force application changes.
* **Decision:** `PlacementStrategy` in `tenant_placements`, an
  `IsolationStrategy` protocol, and a `SessionRouter` that dispatches on
  `tenant.strategy` (`README.md:271-298`).
* **Reason (evidenced):** `docs/jdlib/06-strategy-matrix.md`; the README states
  "Placement is data, not code".
* **Trade-off:** every strategy must implement six protocol members; the
  protocol has no health-check member.
* **Consequences:** application code is placement-agnostic; the registry is
  strategy-aware; per-strategy quirks (e.g. the version-check nuance in §23)
  are possible.

### 22.6 A single servability predicate shared by reads and writes

* **Problem:** divergent "is this tenant usable?" logic caused leaks and
  availability bugs during development.
* **Decision:** one helper (`registry.py:124-140`) used by
  `assert_servable` (raises `TenantSuspended`) and `RegistryWriteFence`
  (raises `TenantNotWritable`) (`docs/jdlib/05-tenant-lifecycle.md:73-101`).
* **Consequences:** a relocation quiesce blocks reads and writes consistently
  (a guarded read can return 423).

### 22.7 PostgreSQL advisory locks for lifecycle serialization

* **Problem:** multi-process idempotency for create/provision/deprovision.
* **Decision:** `pg_advisory_xact_lock(hashtextextended(key, 0))` with
  tenant/slug/handle key namespaces (`registry.py:285-304`).
* **Alternatives:** `SELECT … FOR UPDATE` on tenant rows (rejected: the row
  often does not exist yet at create time), a distributed lock service
  (rejected: external dependency).
* **Trade-off:** lock scope is transaction-scoped; work that must happen
  outside the lock (database drops) is re-validated after re-acquiring the
  lock.

### 22.8 Request-scoped authorization cache with one-way invalidation

* **Problem:** a shared cache risks cross-request staleness; a re-enabling
  cache risks post-mutation staleness.
* **Decision:** `AuthzCache` is per request; `invalidate()` permanently
  disables it for that instance (`authz/cache.py:6-19`); `AccessControl`
  invalidates before every attempt; the scope-chain key omits the tenant id.
* **Reason (evidenced):** the README explicitly forbids sharing a PDP/cache
  across requests.
* **Consequences:** correctness over hit rate — after any mutation the rest of
  the request is uncached.

### 22.9 Additive, allow-only RBAC with scope-checked permissions

* **Problem:** deny rules are hard to reason about and easy to get wrong.
* **Decision:** effective authority = union of role permissions across the
  scope chain + exact-resource grants, intersected (never widened) by API-key
  scopes; `Permission.allowed_scopes` constrains where a permission may be
  bound (`pdp.py:77-150`, `permissions.py`).
* **Reason (evidenced):** `docs/jdlib/04-authorization-model.md:62-112`.
* **Consequences:** no deny semantics; the PDP is a deterministic pure-ish
  function over SQL reads.

### 22.10 AccessControl authorizes mutations from tenant-scope bindings, not the PDP

* **Problem:** mutation-time authorization needs the actor's *global* authority
  to create a role, not a target-scoped decision.
* **Decision:** `actor_permissions` reads tenant-scope bindings only and
  applies subset/anti-escalation checks (`access.py:149-175`).
* **Rationale not evident from the source code** beyond the design docs'
  anti-escalation sections.
* **Consequences:** mutation checks are cheaper but do not re-verify
  principal/tenant/membership activity at write time.

### 22.11 Privileged access is a context, not a flag

* **Problem:** "admin mode" booleans are unauditable and unbounded.
* **Decision:** `PrivilegeContext(kind, capability, justification, actor,
  issued_at, expires_at)` inside the tenant context; issuance goes through
  `ContextFactory` and is audited; `for_system`/`for_test` require the
  module-private issuer sentinel (`context.py:254-372`).
* **Consequences:** any consumer code reading `current_tenant().privilege` can
  see why elevated access was granted; expiry is stored but **not** re-checked
  by `TenantSession` (the trust is bounded by TTL and context lifetime).

### 22.12 Signed minimal envelopes instead of serialized contexts

* **Problem:** a `TenantContext` cannot be trusted across a queue boundary.
* **Decision:** HMAC-signed JSON containing only identity + request ids, TTL
  validated, then full re-authorization on arrival
  (`context.py:375-438`, `tenancy/jobs.py:24-81`).
* **Consequences:** scopes/permissions are never carried; revocation takes
  effect at the next hop because activity/entitlement/servability are
  re-checked.

### 22.13 Programmatic Alembic with no `alembic.ini`

* **Problem:** two independent chains (control and tenant) cannot be expressed
  by one ini file, and tenant targets are per-request secrets.
* **Decision:** in-memory `alembic.Config` per call, `script_location` set to
  the plane directory, URL injected with `%` doubling
  (`migrations/runner.py:35-52`); the unusable ini template was removed.
* **Consequences:** consumers cannot shell out to `alembic` with a shipped
  ini; the CLI exposes `db upgrade-control` / `db upgrade-tenants` instead.

### 22.14 Ownership is org/team placement; exact access is a grant

* **Problem:** the design documents speak of "ownership" ambiguously.
* **Decision:** `OwnableByOrg`/`OwnableByTeam` with composite FKs plus
  `ResourceGrant` for exact resource permissions; `ScopeResolver` treats
  hierarchy as implicit downward inheritance (`models/base.py`,
  `authz/scopes.py`).
* **Consequences:** there is no `own` scope; per-resource access is explicit and
  auditable via grants.

### 22.15 The CLI is an operator subset, not an API surface

* **Decision:** five command groups (`tenant`, `db`, `rls`, `schema`,
  `security`), shared+schema strategies only, `--json` everywhere
  (`README.md:350-365`, `integrations/cli.py`). The `security` group (phase 9)
  is read-only reporting: it assesses a declared configuration and lists
  evidence — it never mutates a deployment.
* **Reason (evidenced):** the phase-6 plan records this as an accepted scope
  deviation.
* **Consequences:** database placement and all identity/RBAC management are
  programmatic only.

### 22.16 No in-process locks anywhere

* **Decision:** concurrency correctness is delegated to PostgreSQL (advisory
  locks, constraints, conditional updates) and to task-local contexts.
* **Rationale not evident from the source code**, though it is consistent with
  the multi-process-first posture of the advisory-lock design.
* **Consequences:** the database engine cache and the JWK cache have known
  unprotected windows (§23).

---

## 23. Current Limitations

### 23.1 Architectural limitations

1. **Relocation is not implemented as an API.** `TenantRelocation` and
   `RelocationPhase` exist in the schema and the servability predicate, and
   `docs/jdlib/05-tenant-lifecycle.md:175-276` documents the phases, but
   `TenantRegistry` has no `relocate`/`resume_relocation`/`rollback_relocation`
   (`docs/jdlib/07-implementation-design.md:437-456` sketches them). The phase
   workflow is manual/operational. `RelocationPhaseError` is defined but has
   no shipped caller.
2. **Database-placement version verification nuance.** After
   `DatabasePerTenantStrategy.migrate` (which migrates the *tenant* database
   through `runner.upgrade_tenant_url`), the registry's post-migration check
   calls `self._runner.tenant_version(strategy.migration_schema(record))`
   (`registry.py:329-338`), where `migration_schema` returns `"public"` and the
   runner is bound to the control/base DSN. The check therefore verifies the
   base database's `public` version rather than the tenant database's.
   *(Observed from source; the shipped test suite exercises per-strategy
   migration success separately.)*
3. **`migrate()` has no lifecycle eligibility check** — unlike `provision`, it
   runs for any status and, on failure, suspends an active tenant
   (`registry.py:367-407`).
4. **No engine/pool configuration surface.** No `PoolConfig`, pool sizing,
   timeouts, `pool_pre_ping`, or `statement_timeout` anywhere (§16.2);
   consumers must configure engines themselves.
5. **Synchronous migrations inside async flows.** `MigrationRunner` is
   synchronous and is called from `async` registry/strategy methods, so
   provisioning and migration block the event loop.
6. **One-way cache invalidation** makes `AuthzCache` permanently uncached after
   any attempted mutation (§7.4).

### 23.2 API limitations

* `TenantContext` can be constructed directly by consumer code; only convention
  (and cross-hop HMAC) protects the factory invariant.
* `privilege.expires_at` is stored but not re-evaluated by `TenantSession`; an
  expired privilege inside a long-lived context remains effective.
* `requires` reads the session only from `kwargs["session"]`; positional or
  renamed parameters silently produce `MissingTenantContext`
  (`authz/guards.py:34-52`).
* `fastapi.require` authorizes in a separate transaction from the handler
  (documented TOCTOU, `integrations/fastapi.py:1-12`).
* `AccessControl` methods accept both `actor_id` and `actor_principal` without
  verifying they are the same principal; `actor_type` is never passed, so
  `DatabaseAuditSink` records non-null actors as `"user"`.
* `accept_invitation` does not verify the invitation email against the
  accepting identity.
* `grant_resource` does not validate grantee activity; `revoke_grant` does not
  require holding the granted permission; the last-owner count is not filtered
  by active principals.
* `bind_role` validation and insertion use two control sessions, so a
  validation-to-write window exists (fail-closed at read time).
* Bulk `revoke`/role-permission replacement are not exposed as operations
  (only single-row grant revoke and full role permission replacement exist).
* No API-key issuance/revocation, membership management, or user-management
  service (`member:manage` exists in the catalog but no shipped mutation API).
* No `own`/`all`/`ancestor` scopes, no deny rules, no ABAC conditions.
* `ResolverChain` returns the first match and does not compare conflicts.
* The built-in middleware passes `claims={}`, so the default
  `JwtClaimResolver` is inert through that path (§8.2).

### 23.3 Performance limitations

* `DefaultPDP` issues several control-plane queries per decision (mitigated by
  request-scoped memoization only).
* `ScopeResolver.chain` queries each organization ancestor individually.
* `RawSqlValidator` parses every raw statement; the ORM path already rejects
  text, so this is confined to explicit raw SQL.
* `DatabasePerTenantStrategy` creates engines with default SQLAlchemy pools and
  no recycling/pre-ping; cache pressure yields `PoolCapacityError` rather than
  waiting.
* `tenant_table_map()` re-imports model modules and re-walks subclasses on
  every call.
* `uuid7()` is non-monotonic within a millisecond, so UUID ordering is only
  meaningful across milliseconds.

### 23.4 Dependency limitations

* `starlette` is imported directly by `integrations/fastapi.py` but is not
  declared in `pyproject.toml` (it arrives transitively via FastAPI).
* No upper bounds on any dependency; lower bounds only.
* `pglast>=6.0` message text for rejected set operations is version-dependent.
* No `uv.lock`/`poetry.lock`; builds are not reproducible from the repository.
* `httpx` JWKS fetch has no explicit timeout.
* `JwksCache` has no refresh lock (thundering-herd risk on unknown `kid`).
* `asyncpg`/`psycopg` are only referenced through DSNs, so a DSN naming a
  missing driver fails at engine creation time.

### 23.5 Testing gaps

* No coverage tooling or threshold; coverage is unknown.
* No executed relocation workflow test (relocation is unimplemented).
* No `examples/` directory and no example-driven smoke test.
* CI has no matrix (single Python 3.12) and no dedicated PostgreSQL service
  (relies on testcontainers + runner Docker).
* The `tests/isolation/` layout proposed in the design docs does not exist;
  isolation tests are spread across suites.
* The database-placement registry version-check nuance (§23.1.2) is not covered
  by a test that asserts the tenant database's version is what the registry
  checked.

### 23.6 Documentation gaps

* `pyproject.toml` declares no `readme`, `license`, `authors`, `classifiers`,
  `keywords`, or `urls`; no `LICENSE`, `CHANGELOG`, `CONTRIBUTING.md`, or
  `SECURITY.md` exist.
* Design docs `07-implementation-design.md` drift from the shipped tree: it
  names modules that do not exist (`persistence/events.py`,
  `authz/ownership.py`, an `audit/` package, `testing/fixtures.py`,
  `testing/fakes.py`) and registry relocation methods that do not exist; the
  frozen spec's abbreviated public-API list omits names that the real
  `__all__` contains. Source and `tests/unit/test_public_api.py` are
  authoritative.
* The spec still refers to "L1–L19" while only 12 rule ids are implemented
  (§8.15); `docs/jdlib/03-isolation-invariants.md` also mentions an `L5` rule
  that is not emitted.
* No operator runbook (backup/rotation/incident) accompanies the audit and RLS
  features; no logging/metrics guidance because none exists (§14).

### 23.7 Extensibility limitations

* Protocols are not `@runtime_checkable`; structural checks are unavailable.
* `IsolationStrategy` lacks `health_check`/`invalidate`/`dispose` members, so
  cache-owning strategies expose methods the framework never calls.
* No plugin/hook discovery; only the `pytest11` entry point exists.
* `PlatformAudit` has no target/IP/severity parameters, so rich audit events
  require a custom sink rather than the shipped one.

---

## 24. Future Architecture (Proposed / Not Currently Implemented)

**Everything in this section is proposed or documented-but-unbuilt. None of it
exists in the current source.** The only externally sourced proposals are those
recorded in the repository's design documents; each is labeled accordingly.

### 24.1 Documented in the design docs, not implemented

| Proposal | Design reference | Status |
|---|---|---|
| `TenantRegistry.relocate`, `resume_relocation`, `rollback_relocation` with the eight `RelocationPhase`s | `docs/jdlib/05-tenant-lifecycle.md:175-276`; `07-implementation-design.md:437-456` | schema + servability support exist; no code |
| `PoolConfig(...)` with health-check intervals | `docs/jdlib/07-implementation-design.md:226-238` | no config field, no code |
| `tests/isolation/` dedicated suite layout | `docs/jdlib/03-isolation-invariants.md:263-293` | suite distributed elsewhere |
| Rules L5, L7, L8, L10, L14, L16, L18 | `docs/jdlib/03-isolation-invariants.md` | not emitted by `lint.py` |
| Hybrid placement helper abstractions | `docs/jdlib/06-strategy-matrix.md:163-173` | expressible today with `SessionRouter` in consumer code; no helper ships |
| 503 semantics for mandatory-audit failure paths | `docs/jdlib/03-isolation-invariants.md:247-261` | no mapping exists (all unlisted errors are 500) |

### 24.2 Reasonable next steps implied by the code (suggestions, not requirements)

These are not demanded by the repository; they are the smallest changes that
would close the limitations in §23.

1. Make the registry's post-migration version check placement-aware
   (`tenant_version_url` for database placement) — closes §23.1.2.
2. Add an `asyncio.Lock` (or per-handle lock) around the database engine cache
   and `dispose()` — closes the unprotected windows in §16.3.
3. Add a `pool` configuration block to `TenancyConfig` and pass it to
   `create_async_engine` / consumer engine helpers.
4. Re-check `privilege.expires_at` inside `TenantSession` event hooks.
5. Populate `RequestInfo.claims` in the middleware from the authenticated
   principal/identity link so the default JWT-claim resolver works.
6. Pass `actor_type` from `AccessControl` (it already receives
   `actor_principal`) so audit records distinguish service accounts.
7. Add coverage tooling, a CI matrix (3.12/3.13), and a PostgreSQL service
   container in CI.
8. Publish metadata (`readme`, `license`, `classifiers`) and a build/publish
   workflow; add a lock file.
9. Ship an `examples/` application (FastAPI + CLI + tests) as an executable
   contract.
10. Implement relocation as registry methods with phase transitions, audit
    events, and servability integration.

---

## 25. Complete Architecture Diagrams

### 25.1 System context

```mermaid
graph TB
    User["End user / operator"] --> App["Consumer FastAPI app"]
    App --> JDL["jdlib 0.1.0"]
    JDL --> PG[("PostgreSQL 15+")]
    JDL --> IDP["OIDC issuer"]
    App -.pytest.-> Plugin["jdlib.testing.pytest_plugin"]
    Plugin --> PG
    Ops["Operator"] --> CLI["Consumer-exposed Typer CLI"]
    CLI --> JDL
```

### 25.2 Package architecture

```mermaid
graph TB
    JD["jdlib (top-level: 13 exports)"]
    JD --> A["authn (6)"]
    JD --> B["authz (9)"]
    JD --> C["control (7)"]
    JD --> D["persistence (15)"]
    JD --> E["tenancy (4)"]
    JD --> F["models (5)"]
    JD --> G["migrations (8)"]
    JD --> H["integrations (3)"]
    JD --> I["testing (3)"]
    JD --> R["config / context / errors / lint / _uuid (5 root modules)"]
```

### 25.3 Module dependency graph

See the full `graph LR` in [§5.2](#52-module-dependency-graph-verified-static-imports).

### 25.4 Public API flow

```mermaid
graph LR
    U["Consumer"] --> CTX["current_tenant()"]
    CTX --> UOW["UnitOfWork"]
    UOW --> TS["TenantSession"]
    TS --> REPO["TenantRepository"]
    U --> REG["TenantRegistry"]
    U --> AC["AccessControl"]
    AC --> G["requires / authorize → Enforcer → DefaultPDP"]
    G --> TS
```

### 25.5 Internal component architecture

See the `graph TB` in [§8.21](#821-internal-component-architecture).

### 25.6 Important feature flows

* Context creation: [§8.1](#81-tenant-context-and-contextfactory)
* Request pipeline: [§8.2](#82-tenant-resolution-and-the-asgi-middleware)
* Cross-hop: [§8.3](#83-signed-envelopes-and-background-jobs)
* Provisioning: [§8.4](#84-control-plane-tenantregistry-and-the-lifecycle-state-machine)
* Raw SQL: [§8.7](#87-raw-sql-validation-rawsqlvalidator)
* Authentication: [§8.8](#88-authentication-jdlibauthn)
* Decisioning: [§8.9](#89-authorization-decisioning-jdlibauthz-pdp-guards-cache)

### 25.7 Sequence diagrams

Request (§21.1), provisioning (§8.4), raw SQL (§8.7), OIDC (§8.8), database
routing (§21.4), invitations (§21.7), and job propagation (§8.3).

### 25.8 Data model

See the ERD in [§10.1](#101-two-planes) and the table inventories in
§10.2–§10.5.

### 25.9 Dependency architecture

See [§11.4](#114-dependency-architecture-diagram).

### 25.10 Runtime lifecycle

See [§9.7](#97-runtime-lifecycle-diagram).

### 25.11 Error/exception flow

See [§13.3](#133-error-to-http-status-mapping).

### 25.12 Consumer integration

See [§20.1](#201-integration-shape).

### 25.13 Packaging/distribution flow

See [§18.7](#187-packaging-flow).

---

## 26. Accuracy and Verification Notes

### 26.1 What was inspected

* All 64 Python modules under `src/jdlib` (plus 2 Mako templates and
  `py.typed`), including complete import graphs (module-level and
  function-local).
* `pyproject.toml` (56 lines, read in full), `.github/workflows/ci.yml`,
  `.gitignore`, `README.md` (390 lines, read in full).
* All 68 tracked test files: unit inventory (36 modules), integration inventory
  (26 modules + 3 support modules), fixtures, strategy matrix, and the
  security/concurrency regression tests.
* All 17 documentation files: 6 in `docs/jdlib/`, 1 spec, 9 plans, plus
  `README.md`.
* Absence checks for `examples/`, Docker/compose, Makefile/tox/nox, lock
  files, `setup.py`/`setup.cfg`, `requirements*.txt`, `LICENSE`, `CHANGELOG`,
  `CONTRIBUTING.md`, `SECURITY.md`, pre-commit, and agent-instruction files.

### 26.2 What was verified by execution

* `pytest -q -W error` → **568 passed** on a fresh `postgres:16` testcontainer
  at commit `a30601d`.
* `ruff check .` → all checks passed; `mypy src/jdlib` → no issues in 64 files
  (strict mode).
* `import jdlib` → version `0.1.0`, 13 exports, and **no** `fastapi`, `pytest`,
  or `typer` in `sys.modules` (subprocess check, matching
  `tests/unit/test_public_api.py`).
* Import graph: no cycles; `jdlib.models`/`jdlib.control` have no
  `__init__.py`; other subpackage initializers are empty.
* `.github` contains exactly one workflow; remote and local `main` were
  identical at the time of writing.

### 26.3 Known documentation-vs-source drift (resolved in favor of source)

| Design-doc claim | Shipped reality |
|---|---|
| `persistence/events.py`, `authz/ownership.py`, `audit/` package, `testing/fixtures.py`, `testing/fakes.py` | do not exist; responsibilities live in `persistence/session.py`, `control/audit.py`, `models/audit_recorder.py`, `control/purge.py`, `testing/assertions.py`, `testing/pytest_plugin.py` |
| `TenantRegistry.relocate` / `resume_relocation` / `rollback_relocation` | absent |
| `PoolConfig` | absent |
| Public API list in the frozen spec | `src/jdlib/__init__.py:11-25` plus `tests/unit/test_public_api.py` are authoritative (13 names) |
| "L1–L19" | 12 implemented rule ids (L1, L2, L3, L4, L6, L9, L11, L12, L13, L15, L17, L19) |
| `AuditSink` / `PlatformAuditSink` names in older text | shipped names are `PlatformAudit` and `DatabaseAuditSink` |
| `tests/isolation/` layout | absent; distributed suites |
| 503 audit-failure status | no mapping (500) |

### 26.4 Explicit "Unknown / Requires Confirmation" items

* PyPI publication status and any external deployment of `jdlib`.
* Whether the design docs' original motivation statements were authored or
  reviewed by a particular party.
* Exact `pglast` version installed in any given environment, and therefore the
  exact exception text for rejected set operations.
* Whether the design docs' original motivation statements were authored or
  reviewed by a particular party.
* Whether the `MemorySecretProvider`/`EnvSecretProvider` defaults are intended
  for production (README points consumers at custom providers).
* Coverage percentage (no tooling configured).
* Whether GitHub-hosted runners can start testcontainers in the CI job (no
  service container is declared; the job relies on runner Docker).

### 26.5 Uncertain items deliberately not claimed

* No claim is made that any consumer application exists or that the library is
  deployed anywhere.
* No claim is made about performance characteristics beyond what the code
  structure implies (no benchmarks exist in the repository).
* No claim is made about SemVer or backward-compatibility policy (no CHANGELOG
  or policy document exists).

---

## 27. Final Architecture Summary

### 27.1 Architecture at a glance

```text
Consumer FastAPI app / CLI / jobs
        │  import + wiring (no engine factory inside jdlib)
        ▼
Public API: TenancyConfig · ContextFactory · TenantContext · current_tenant
            UnitOfWork · TenantRepository · TenantRegistry · AccessControl
            requires/authorize · JdlibError/errors
        ▼
Core architecture: ContextFactory checks (principal → tenant → pin →
                    entitlement → servability) · ContextVar context
                    TenantSession SQLAlchemy event enforcement
                    RawSqlValidator (pglast AST proof)
                    DefaultPDP (6-gate precedence) + request-scoped AuthzCache
                    TenantRegistry advisory-locked lifecycle + servability
        ▼
Feature modules: context/envelopes/jobs · resolution/middleware ·
                 isolation strategies (shared/schema/database) · RLS ·
                 migrations · audit (platform + tenant) · purge · lint ·
                 authn (OIDC/API key) · access control · testing kit
        ▼
Adapters: FastAPI (install/dependencies/JSON errors) · Typer CLI ·
           Alembic programmatic runner · PlatformAudit/SecretProvider/
           OperatorAuthorizer/ScopeLookup/ResourceLookup (consumer ports)
        ▼
External dependencies: PostgreSQL 15+ (control `jd_control` schema + tenant
                       planes) · asyncpg (async) / psycopg (sync) ·
                       OIDC issuer + JWKS via httpx · libpg_query (pglast) ·
                       Argon2-cffi · FastAPI/Starlette · Typer
```

### 27.2 Core modules

`context.py` (identity/authority/envelopes), `errors.py` (27-error hierarchy),
`config.py` (pydantic-settings), `lint.py` (12 metadata invariants),
`control/registry.py` (lifecycle authority), `persistence/session.py`
(tenant-scoped session), `persistence/rawsql.py` (raw-SQL proof),
`persistence/uow.py` (write admission + transaction), `authz/pdp.py`
(decisions), `authz/access.py` (mutations), `authn/*` (identity),
`persistence/strategies/*` (placement), `migrations/runner.py` (schema
evolution), `control/audit.py` + `models/audit_recorder.py` (audit).

### 27.3 Core abstractions

`TenantContext` · `Principal` · `PrivilegeContext` · `TenantRecord` ·
`TenantSession` · `UnitOfWork` · `TenantRepository` · `SessionRouter` ·
`TenantRegistry` · `RegistryWriteFence` · `IsolationStrategy` ·
`RawSqlValidator` · `Decision`/`MatchedRule` · `AuthzCache` ·
`AccessReader`/`ControlAccessReader` · `AccessControl` · `EnvelopeCodec` ·
`ContextPropagator` · `PermissionCatalog` · `ResourceTypeRegistry` ·
`ScopeResolver` · `MigrationRunner` · `PlatformAudit` · `TenantAuditRecorder`.

### 27.4 Main public APIs (13)

`AccessControl` · `ContextFactory` · `JdlibError` · `TenancyConfig` ·
`TenantContext` · `TenantRegistry` · `TenantRepository` · `UnitOfWork` ·
`authorize` · `current_principal` · `current_tenant` · `errors` · `requires`
— plus the de facto submodule surface in §6.2 (FastAPI `install`, Typer `app`,
strategies, `MigrationRunner`, `DefaultPDP`, `ControlAccessReader`,
`DatabaseAuditSink`, resolvers, `tenant_job`, `jdlib.testing` assertions and
fixtures).

### 27.5 Major features

Request-scoped tenant context; five resolver strategies; signed envelopes with
re-authorization; three isolation strategies plus RLS; fail-closed
tenant-scoped sessions and repositories; structural raw-SQL proof; scoped RBAC
(roles/bindings/grants/invitations/ownership); OIDC + API-key authentication;
tenant lifecycle (create/provision/migrate/suspend/resume/archive/deprovision)
with advisory locking and a single servability predicate; programmatic Alembic
for two planes; platform and tenant audit with caller-transaction participation;
tenant-plane purge; schema lint; consumer testing kit; FastAPI and Typer
integrations.

### 27.6 Important dependencies

`sqlalchemy[asyncio]` (core), `pydantic`/`pydantic-settings` (config),
`alembic` (migrations), `pglast` (SQL proof), `pyjwt[crypto]` + `httpx`
(OIDC), `argon2-cffi` (secret hashing), `asyncpg` (async driver) and
`psycopg` (sync driver), optional `fastapi` and `typer`.

### 27.7 Extension points

`Authenticator` · `TenantResolver` · `IsolationStrategy` · `AccessReader` ·
`PolicyDecisionPoint` · `PlatformAudit` · `PrivilegeAudit` · `WriteFence` ·
`SecretProvider` · `SeedHook` · `ScopeLookup`/`ResourceLookup` ·
`PrincipalDirectory`/`TenantDirectory`/`EntitlementChecker`/
`ServabilityChecker`/`OperatorAuthorizer` · `RawSqlAuditor` · injectable
`RawSqlValidator` · model mixins + `ownership_constraints()` ·
`PermissionCatalog.register` · `ResourceTypeRegistry.register` ·
`CompositeAuthenticator`/`CompositeAuditSink` · `tenant_job`.

### 27.8 Main runtime flows

1. **Request:** ASGI middleware → authenticate → resolve tenant → context
   checks → `context_scope` → handler → `UnitOfWork` → scoped SQL → reset.
2. **Provisioning:** advisory lock → validate/idempotency → control rows +
   audit → strategy provision → migrations → seed → version check → activate.
3. **Decision:** guard → `Enforcer` → PDP (6 gates) → `Decision` or
   `PermissionDenied`.
4. **Cross-hop:** encode → queue → decode → re-validate → run under a fresh
   context.
5. **Deprovision:** lock → state recheck → control-row deletion in order →
   strategy drop or tenant-plane purge → mark deleted → audit counts.

### 27.9 Known limitations (summary)

Relocation is not an implemented API (§23.1.1); the database-placement
registry version check reads the base database (§23.1.2); `migrate()` has no
status gate (§23.1.3); no engine/pool configuration exists (§23.1.4);
migrations are synchronous inside async flows (§23.1.5); cache invalidation is
one-way (§23.1.6); privilege expiry is not re-checked per statement (§23.2);
`fastapi.require` has a TOCTOU window (§23.2); audit actor typing collapses
non-null actors to `"user"` (§23.2); the built-in middleware does not populate
JWT claims for the default resolver (§23.2); `IsolationStrategy` lacks
`health_check`/`invalidate`/`dispose` (§23.7); no logging/metrics/tracing
exists (§14.2); packaging lacks readme/license/classifiers, a console script, a
publish workflow, and a lock file (§18.2).

---

*End of document. Derived from `jdlib` at commit `a30601d`; every claim is
traceable to the file references given inline. For anything not determinable
from the repository, this document says so explicitly.*





