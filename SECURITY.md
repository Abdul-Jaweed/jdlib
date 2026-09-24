# Security policy

JDLib is a multi-tenant data-access library: it authenticates principals, decides
authorization, binds tenant context, enforces tenant isolation in the database,
records an audit trail and emits security telemetry. This document says what it
guarantees, what it deliberately leaves to a deployment, and how to report a
problem in it.

## Supported versions

The project has not published a release. The `main` branch is the development
line and the only version that receives security fixes; commit history on `main`
is the record of what changed and why.

## Reporting a vulnerability

Report privately, not in a public issue: use this repository's **Security →
Report a vulnerability** (GitHub private vulnerability reporting). If that is not
available to you, open an issue that says only that you have a security report
and asks for a private channel — do not include a working exploit, credentials or
a reproduction against anyone else's system.

A useful report contains: the affected file or component, the version/commit, what
an attacker gains, and the smallest reproduction you can give us. Please give us a
reasonable window to fix it before public disclosure.

This is a development project without a support contract, so no response-time
guarantee is offered. Reports are handled on a best-effort basis, and confirmed
issues are fixed on `main` with a regression test that fails without the fix.

## What this library is responsible for

In scope, and covered by this project's tests (unit, integration against real
PostgreSQL, and infrastructure tests against Cerbos, Kong, ZITADEL and an
OpenTelemetry collector):

* **Authentication** of inbound credentials — token validation against issuer,
  audience, algorithm and expiry including JWKS rotation and outage behaviour —
  and service-to-service identity.
* **Authorization** — the policy decision point and the enforcement point,
  including failing closed when the engine is unavailable or slow.
* **Tenant isolation** — tenant resolution, the bound tenant context, row-level
  security in PostgreSQL, and the refusal of raw SQL or bulk operations that are
  not bound to a tenant.
* **Privilege liveness** — a time-boxed privilege cannot authorize work after it
  expires.
* **Audit** — event vocabulary, fail-closed actor attribution, timestamp
  corroboration, and separate authorization for reading and exporting the trail.
* **Secret safety** — one redaction path covering errors, logs, spans and audit
  metadata.
* **Gateway trust** — verified identity assertions from the supported gateways,
  including the signature and replay-window checks on the identity envelope.
* **Compliance surface** — the control register, evidence collection, posture
  reporting and the `jdlib security` commands.

Documentation for each is indexed in [docs/security/README.md](docs/security/README.md).

## What is out of scope

Report these to the operator of the deployment, not here. The library cannot fix
them, and several are controls it deliberately does not implement:

* The consumer application built on JDLib (routes, business rules, data it
  chooses to log), and its choice of which endpoints to protect.
* Deployment configuration: environment profiles, network boundaries, secrets
  management, database roles and their privileges, backup and retention.
* Operating the gateway (Kong/Tyk), the identity provider (ZITADEL), the policy
  engine (Cerbos) and the telemetry pipeline — including their availability.
  JDLib's obligation is to fail safely when they are unavailable, which is tested.
* **Tamper-evident audit storage.** An actor with database access can rewrite
  history; the library records the trail, it does not make it tamper-proof. Per
  `docs/security/audit-hardening.md`, that control belongs to the deployment.
* A stolen bearer token being replayed within its lifetime. This validator keeps
  no server-side session, so token lifetime and audience checks are what bound it,
  and the register records the control as not applicable.

## Known limitations

* **Tyk plugin execution is not infrastructure-verified.** The Tyk adapter is
  unit-tested, but the six tests in `tests/infra/test_tyk_infra.py` skip because
  the Tyk 5.3.1 OSS image has no JavaScript/coprocess runtime. Those skips are a
  documented engine limitation and are never reported as passes. Kong 3.6 is the
  gateway verified end to end; see `docs/security/gateway-hardening.md`.
* Compliance language is readiness language. The control register records what is
  implemented, partial, not implemented and not applicable — including the gaps —
  and installing JDLib does not make an organisation certified or compliant. See
  `docs/security/compliance-evidence.md`.
* Sanitization is pattern-based. The redaction path removes credential-shaped
  values; it is a strong default, not a proof. Do not pass secret material into
  the library's own fields.

## Working on security in this repository

The gate is `.venv/Scripts/python.exe -m pytest -q -W error`, `ruff check .` and
`mypy src/jdlib`; CI adds dependency scanning, full-history secret scanning,
static analysis, an SBOM and a packaging smoke test
(`docs/security/ci-security.md`). Contribution rules — including the rule that a
new skip or a new suppression needs a documented reason and that published
history is never rewritten — are in [CONTRIBUTING.md](CONTRIBUTING.md).
