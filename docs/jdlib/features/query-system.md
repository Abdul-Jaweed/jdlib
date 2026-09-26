---
guide: query-system
authority: docs/jdlib/query-system.md
modules:
  - src/jdlib/query/__init__.py
  - src/jdlib/query/ast.py
  - src/jdlib/query/compiler.py
  - src/jdlib/query/dialect.py
  - src/jdlib/query/errors.py
  - src/jdlib/query/safety.py
  - src/jdlib/query/specification.py
exports:
  - QueryCompiler
  - CompiledQuery
  - Filter
  - Predicate
  - OPERATORS
  - TENANT_PARAMETER
  - IdentifierPolicy
  - CrossTenantQueryError
  - QueryComplexityError
example:
  - examples/enterprise/app/repositories/resources.py
test_files:
  - tests/unit/test_query_compiler.py
---
# The query system

> **Design authority:** [`docs/jdlib/query-system.md`](../query-system.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

A small, closed query language: predicates and filters that compile to a dialect's SQL, with identifiers checked against an allow-list and the tenant supplied by the framework rather than the caller.

## Why it exists

Hand-written SQL in an application is where tenant filters get forgotten and identifiers get interpolated. A compiler that takes a *specification* makes both impossible by construction.

## When to use it

When an application needs to filter or sort tenant data by input it did not author -- a search box, a report, a saved view. Use it for the parts a caller can influence.

## When not to use it

For a fixed query an application owns end to end (a by-id read, a known report): write the ORM statement. And never as a general-purpose SQL surface -- the language is deliberately not one (ADR-1).

## How it works

`Filter`/`Predicate` build a small AST (`query/ast.py`); `QueryCompiler` walks it with a `QueryDialect` (`PostgresDialect`, `MysqlDialect`), emitting bound parameters for values and quoting identifiers that pass `IdentifierPolicy`. The tenant is not a field a caller can set: the compiled statement takes it from `TENANT_PARAMETER`, which the repository binds from the context.

## Architecture

`query/ast.py` (the nodes), `query/compiler.py` (the walk), `query/dialect.py` (per-database SQL), `query/safety.py` (identifier policy, operator allow-list), `query/specification.py` (what a caller may ask for). `jdlib.persistence.TenantRepository` is what runs the result.

## Example

`examples/enterprise/app/repositories/resources.py` builds its list query through the compiler, so the tenant predicate comes from the session's binding and the sort/filter a route accepts is a specification rather than a string.

## Security

Two refusals are structural: an identifier that is not on the allow-list never reaches the SQL (`IdentifierPolicy`), and a specification that tries to name another tenant raises `CrossTenantQueryError`. Complexity is bounded (`QueryComplexityError`) so a caller cannot turn a filter into a scan.

## Reliability

Compilation is pure and cheap; the failure modes are typed errors rather than exceptions from the driver, so a bad specification is a 4xx and not a 500.

## Observability

The compiler's output carries the parameter count and the tables it touched, which is what a span records about a slow query without logging the SQL.

## Audit

A refused specification is a security event (`UnscopedRawSql`-class refusals are audited), so an attempt to widen a query is visible in the trail.

## Configuration

Nothing to configure: the dialect is chosen by the repository from the connection, and the allow-list comes from the models the application declares.

## Testing

`tests/unit/test_query_compiler.py` covers the compiler and the dialects; the example's live layer exercises the compiled list query against PostgreSQL.

## Common mistakes

Interpolating a column name from input; treating the compiler as a general SQL builder; forgetting that the tenant predicate is added by the repository, not the caller; letting an unbounded IN list through.

## Production checklist

Keep the identifier allow-list tight; log refusals, not SQL; bound the complexity limits to what the database can serve; and check the compiled plan for the queries your busiest route runs.
