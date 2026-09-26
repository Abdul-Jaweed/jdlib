# Introduction

## What JDLib is

A library that puts one enforced surface in front of a multi-tenant application's data: it verifies
the credential, decides which tenant the caller belongs to, asks a policy engine whether the action
is allowed, runs the operation inside a tenant-bound session that the database itself constrains,
and records what happened in one audit vocabulary.

It is a library, not a service. It does not run your application, hold your policies, or decide what
your tenants may do — it makes the *mechanism* of those decisions the same everywhere, so a
decision cannot differ by protocol, by surface, or by whoever wrote the route.

## Why it exists

Every application that serves more than one customer writes the same six things: authentication,
tenant resolution, authorization, tenant-scoped data access, audit, and the reliability around all
of it. Written by hand, they are written once per team, per surface, per release — and the failure
mode is not a bug in any of them, it is that one call path forgot one of them.

JDLib's answer is to make each of those a seam with a single implementation:

| The problem | What the library provides |
|---|---|
| A credential is parsed in a request handler | `build_authenticator` verifies it and produces a `SecurityContext` |
| The tenant comes from a header the caller controls | a resolver chain decides it, and the context is the only source |
| An authorization check is a code path someone can forget | `require("...")` declares it on the route; the PEP runs it before the handler |
| A forgotten `WHERE tenant_id = ...` is a disclosure | the repository is tenant-bound **and** row-level security enforces it in the database |
| Every layer invents an error shape | one envelope, and a 5xx never echoes its own text |
| A denial leaves no trace | one audit vocabulary, written for the decision and not for the data |
| A failing dependency becomes an outage | breaker, retry budget, concurrency gate and a drain, with `/readyz` that tells the truth |

## What it does not do

* **It does not decide policy.** A policy engine answers; JDLib asks the question, refuses on a
  degraded answer, and records the decision. Your policies are yours.
* **It does not provision your infrastructure.** The operator steps (migrations, tenant creation,
  schema declaration) are commands you run; the library gives them an idempotent shape.
* **It does not make you compliant.** It provides controls and the evidence for them; the compliance
  surface says so in its own first paragraph.
* **It does not hide your database.** PostgreSQL and Neo4j are visible in the design, because a
  library that hides its storage cannot make promises about isolation.

## Who this documentation is for

| Reader | Start at |
|---|---|
| a developer writing the first application | [Installation](installation.md) → [Quickstart](quickstart.md) → [First application](first-application.md) |
| a developer adding JDLib to an existing application | [Configuration](configuration.md) → [Features](../jdlib/features/README.md) |
| an architect | [Architecture](../jdlib/architecture.md) → the [long-form reference](../architecture/long-form-reference.md) |
| a security engineer | [Security model](../jdlib/security-model.md) → [Threat model](../threat-model/README.md) |
| an operations engineer | [Operations](../operations/README.md) → [Production readiness](../jdlib/production-readiness.md) |

## Where the evidence is

Every claim in this site is either cited to a test or labelled as a design statement. The
documentation inventory records, per public namespace, which pages document it and how many test
files hold it, and the [feature matrix](../jdlib/examples/feature-matrix.md) carries a `file:line`
for every seam, every use in the examples, and the test that asserts it. If a page here says
something is verified, that is what "verified" means in this repository.
