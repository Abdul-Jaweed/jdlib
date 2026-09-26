# Feature guides

One guide per feature a developer consumes, in the shape the directive asks for: what it is, why it
exists, when to use it and when not to, how it works, its architecture, an example, and then the
operational half -- security, reliability, observability, audit, configuration, testing, common
mistakes and a production checklist.

**These guides are not the design authority.** Each one links to the page that is, and where the two
disagree the authority page and the code win. Two authorities for one topic is how documentation
starts lying.

**Which fourteen.** The directive names the set of feature guides; the list below is the library's
own surfaces -- one per feature a developer actually consumes -- because a guide for a feature the
library does not have would be the exact failure this programme exists to remove. Where the example
application does not use a feature (background jobs, for instance), the guide **says so** rather than
inventing an example: the evidence is then the library's own suites, named in the guide.

**Two features are cross-cutting** and documented where they live rather than in a guide of their
own: privileged access ([`../privileged-access.md`](../privileged-access.md)) is covered by
`authorization`'s security and production sections, and the error envelope
([`../../security/error-responses.md`](../../security/error-responses.md)) is covered by every
guide's security section -- it is the shape every failure takes, not a feature you opt into.

**These guides are checked.** `tests/unit/test_example_docs.py` asserts that every guide carries
every heading of the template, that every path it cites exists, and that every authority page it
names is real -- the same treatment the capability pages get from `tests/unit/test_successor_docs.py`.
A register that lies fails its own test.

| Guide | Design authority | Used by the example |
|---|---|---|
| [`authentication.md`](authentication.md) — authentication | [`docs/jdlib/authentication.md`](../authentication.md) | yes |
| [`authorization.md`](authorization.md) — authorization | [`docs/jdlib/authorization.md`](../authorization.md) | yes |
| [`tenancy.md`](tenancy.md) — tenancy | [`docs/jdlib/tenancy.md`](../tenancy.md) | yes |
| [`resource-management.md`](resource-management.md) — resource-management | [`docs/jdlib/resource-management.md`](../resource-management.md) | yes |
| [`query-system.md`](query-system.md) — query-system | [`docs/jdlib/query-system.md`](../query-system.md) | yes |
| [`credentials.md`](credentials.md) — credentials | [`docs/jdlib/credentials.md`](../credentials.md) | yes |
| [`caching.md`](caching.md) — caching | [`docs/jdlib/capabilities/caching.md`](../capabilities/caching.md) | yes |
| [`storage.md`](storage.md) — storage | [`docs/jdlib/capabilities/storage.md`](../capabilities/storage.md) | yes |
| [`connectors.md`](connectors.md) — connectors | [`docs/jdlib/connectors.md`](../connectors.md) | yes |
| [`graph.md`](graph.md) — graph | [`docs/jdlib/capabilities/graph.md`](../capabilities/graph.md) | yes |
| [`mcp.md`](mcp.md) — mcp | [`docs/jdlib/capabilities/mcp.md`](../capabilities/mcp.md) | yes |
| [`jobs.md`](jobs.md) — jobs | [`docs/jdlib/capabilities/jobs.md`](../capabilities/jobs.md) | **no** — said so in the guide |
| [`audit.md`](audit.md) — audit | [`docs/security/audit-hardening.md`](../../security/audit-hardening.md) | yes |
| [`observability.md`](observability.md) — observability | [`docs/security/observability-hardening.md`](../../security/observability-hardening.md) | yes |

## The template

Every guide carries these sections, in this order:

1. What it is
2. Why it exists
3. When to use it
4. When not to use it
5. How it works
6. Architecture
7. Example
8. Security
9. Reliability
10. Observability
11. Audit
12. Configuration
13. Testing
14. Common mistakes
15. Production checklist

The front-matter of each guide is machine-read: `guide`, `authority`, `modules`, `exports`,
`example` (when the example uses it) and `test_files`. Every one of those claims is checked against
the working tree, which is what makes the guide a statement about the repository rather than about
its author's memory.
