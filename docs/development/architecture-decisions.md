# Architecture decisions

The decisions that shaped this library, with the reasoning and where each one is recorded. A decision
that is only in someone's head is re-litigated every quarter.

## One source for the tenant

**Decision.** The tenant is resolved once, recorded in `SecurityContext`, and read from there.
**Why.** Every alternative — a header, a path segment, a body field, a per-layer lookup — is a second
source, and two sources disagree exactly when it matters.
**Where.** [`jdlib/security-model.md`](../jdlib/security-model.md), the resolver order in
`jdlib.tenancy.resolution`; the assertion in the enterprise example's tenant-isolation suite.

## Denial is non-execution

**Decision.** The PEP runs before the handler or the tool body; a denial means the body never ran.
**Why.** A check inside a handler is a code path someone can forget, and a denial that half-ran is
worse than an error.
**Where.** `jdlib.security.authz.pep`; the security layers measure denial as non-execution, with an
allowing control in the same test.

## A degraded dependency is a refusal

**Decision.** An unreachable or unreadable decision point is treated as a denial, not as an allow.
**Why.** The alternative makes an outage into a permission — the one failure mode where the security
system silently stops being one.
**Where.** `jdlib.security.authz.pep`, `jdlib.security.authz.decision`.

## Isolation is enforced twice

**Decision.** The unit of work is tenant-bound *and* the database's row-level security applies to the
application role.
**Why.** The first is discipline, the second is enforcement. A forgotten predicate returns nothing
instead of another tenant's rows.
**Where.** `jdlib.persistence.session`, `jdlib.persistence.strategies.rls`,
[`jdlib/03-isolation-invariants.md`](../jdlib/03-isolation-invariants.md).

## Allow-list, not deny-list

**Decision.** Span attributes and metric labels come from closed sets; anything else is dropped or
refused.
**Why.** A deny-list has to know every bad thing and fails open; an allow-list has to know every good
thing and fails closed. It is also shorter and reviewable.
**Where.** `jdlib.security.tracing`, `jdlib.security.telemetry.MetricLabelError`.

## Two roles, always

**Decision.** Migrations run as an owner role; the application connects as an application role that
the policy applies to.
**Why.** A single role makes row-level security decorative, and the mistake is invisible until an
audit.
**Where.** `JDLIB_RLS__APP_ROLE`; `jdlib rls verify`.

## The graph is derived

**Decision.** Neo4j holds relationships the relational plane cannot express efficiently, and it is
rebuilt from the relational plane rather than being its source of truth.
**Why.** Two authoritative stores for tenant data is two answers to "what is true", and the graph is
the one that can be rebuilt.
**Where.** `jdlib.graph`, [`jdlib/architecture/neo4j-flow.md`](../jdlib/architecture/neo4j-flow.md).

## Generated, not written, where a table would go stale

**Decision.** The matrices, the inventory and the API reference are generated from the tree and
checked by the gate.
**Why.** A hand-written table of line numbers is wrong the first time someone edits the file above it.
**Where.** `scripts/feature-matrix.py`, `scripts/docs-inventory.py`, `scripts/api-reference.py`.

## One authority per topic

**Decision.** Each topic has one design authority page; the portal routes to it instead of restating
it.
**Why.** Two pages that describe the same mechanism disagree eventually, and the reader has no way to
tell which is current.
**Where.** [`documentation.md`](documentation.md), and the
[inventory](documentation-inventory.md)'s alias table.
