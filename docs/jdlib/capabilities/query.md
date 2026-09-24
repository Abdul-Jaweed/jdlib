---
capability: query
namespace: jdlib.query
errors_module: jdlib.query.errors
modules:
  - src/jdlib/query/ast.py
  - src/jdlib/query/compiler.py
  - src/jdlib/query/dialect.py
  - src/jdlib/query/errors.py
  - src/jdlib/query/safety.py
  - src/jdlib/query/specification.py
exports:
  - CompiledQuery
  - IdentifierPolicy
  - QueryCompiler
  - QuerySpecification
  - parse_specification
refusals:
  - QueryParseError
  - QueryComplexityError
  - CrossTenantQueryError
  - TenantPlaneQueryError
test_files:
  - tests/unit/test_query_compiler.py
test_functions: 26
---
# Query compilation: a specification, never SQL text

## What it is

A caller sends a specification - a table, columns, filters, ordering, a page - and gets back one
value that holds the statement **and** its parameters together:

```python
compiler = QueryCompiler(policy=IdentifierPolicy(tables={...}, tenant_scoped=("events",),
                                                tenant_plane=("projects",)), tracer=tracer)
compiled = compiler.compile(spec, context=security_context)
compiled.text          # SELECT "id", "kind" FROM "events" WHERE "tenant_id" = :jdlib_tenant ...
compiled.parameters    # {'jdlib_tenant': '...', 'jdlib_p0': 'hire', 'jdlib_limit': 50}
```

They are one value because they are useless apart: text without parameters cannot run, and
parameters without text have no meaning. A caller therefore cannot execute the statement with
values interpolated or reuse the parameters against different SQL.

## The decisions that carry weight

**The allow-list runs at parse time.** An identifier that reaches SQL is an identifier that was
trusted, and the only way to trust one is to have written it down - so an unknown table, an
unknown column, an unknown operator or a hostile identifier is refused *before* anything is
rendered or connected. Adversarial cases include SQL fragments, comment openers, case confusion,
trailing whitespace, embedded NUL, dotted qualification, `*`, casts and Cyrillic homoglyphs.

**Values are never text.** A hostile value appears in `parameters` and never in `text`, and
`CompiledQuery.__repr__` renders `values=[REDACTED]`.

**The scope predicate is the compiler's.** A caller who filters on `tenant_id` gets the filter
*and* the scope predicate - two predicates, the caller's value bound - rather than a replaced
scope. This is asserted live, against a real database, returning zero rows for the other tenant.

**The tenant plane is refused, not merely discouraged** (ADR-1): the tenant plane keeps exactly
one path, the repository.

## Evidence

26 test functions across `tests/unit/test_query_compiler.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_query_compiler.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

## Limits

One table per specification, no joins and no subqueries - a limitation that is a design decision
rather than a backlog item: every construct that would let a caller express a data source the
allow-list does not name is a construct that moves the trust boundary.

## Limits on dialects

`PostgresDialect` and `MysqlDialect` exist; the compiler is dialect-parameterised rather than
dialect-specific, and only PostgreSQL is exercised against a server.
