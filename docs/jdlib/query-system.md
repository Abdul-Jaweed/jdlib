---
page: query-system
sources:
  - src/jdlib/query
  - src/jdlib/persistence/rawsql.py
  - docs/jdlib/capabilities/query.md
---
# Query system

Two things exist and they are not interchangeable:

1. **The tenant plane** is queried through `TenantRepository` and the raw-SQL guard. This is the
   only path to tenant-routed rows.
2. **The compiler** (`jdlib.query`) exists for engines without an ORM, and refuses tenant-plane
   tables outright (ADR-1). Full page: [`capabilities/query.md`](capabilities/query.md).

## Why both

The repository is an ORM path with RLS underneath it; the compiler is a specification-to-SQL path
for analytical engines that have no ORM to route through. Letting the compiler reach the tenant
plane would create a second, weaker path to the same rows - so the policy declares the tenant
plane and the compiler refuses it, and a test asserts that refusal for `projects`, `tasks` and the
audit tables.

## The compiler's contract

- The allow-list is enforced at **parse** time: an unknown table, column or operator is refused
  before anything is rendered or connected.
- Values are **never** text: they are bound parameters, and `CompiledQuery.__repr__` redacts them.
- The **scope predicate is the compiler's**: a caller's own `tenant_id` filter is ANDed with it,
  not substituted for it.
- Complexity is bounded: column count, filter count, IN-list size, page size.

## Evidence

A live test runs the compiled statement through the connector against a real database and asserts
that tenant A sees only tenant A's rows and that a cross-tenant filter returns nothing.
