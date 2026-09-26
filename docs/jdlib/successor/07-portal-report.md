# The documentation portal: report

The portal is a MkDocs site over every authority page in this repository. This report is the
closing record: what was delivered, what the gate proves, and what remains honestly open.

## What was delivered

| Deliverable | Where |
|---|---|
| The site configuration and its navigation | `mkdocs.yml` (MkDocs Material, `--strict` in both gates) |
| The portal itself: 57 pages written for it, over the 90 authority pages it routes to | `docs/index.md`, `docs/getting-started/`, `docs/concepts/`, `docs/architecture/`, `docs/integrations/`, `docs/guides/`, `docs/reliability/`, `docs/observability/`, `docs/operations/`, `docs/reference/`, `docs/development/` |
| The examples it documents | `examples/minimal/`, `examples/enterprise/` (with `docs/jdlib/examples/`) |
| The validation: generators, checks and gates | `scripts/api-reference.py`, `scripts/docs-inventory.py`, `scripts/docs-matrix.py`, `scripts/feature-matrix.py`, `tests/unit/test_docs_portal.py`, `scripts/ci-local.sh`, `.github/workflows/ci.yml` |
| The README, updated to point at the portal and to say how to build it | `README.md` |

The reading order the site defines, which is the order the directive asks for:

```text
Getting Started -> Concepts -> Architecture -> Features -> Integrations -> Guides -> Examples
  -> Security -> Reliability -> Observability -> Operations -> API Reference -> Development
```

## The directive's success criteria, each against its evidence

| Criterion | Evidence |
|---|---|
| MkDocs site created | `mkdocs.yml`; `mkdocs build --strict` in both gates |
| Navigation complete | `tests/unit/test_docs_portal.py` fails when a published page is unreachable from the nav |
| Getting started exists | `docs/getting-started/` (install, quickstart, configuration, mental model) |
| High-level architecture documented | `docs/architecture/high-level-architecture.md` |
| Low-level architecture documented | `docs/architecture/component-architecture.md`, `docs/architecture/long-form-reference.md` |
| Component architecture documented | `docs/architecture/component-architecture.md` |
| Request lifecycle documented | `docs/architecture/request-lifecycle.md` |
| Authentication documented | `docs/jdlib/features/authentication.md`, `docs/integrations/identity.md` |
| SecurityContext documented | `docs/jdlib/features/tenancy.md`, `docs/architecture/security-architecture.md` |
| Authorization documented | `docs/jdlib/features/authorization.md` |
| Tenancy documented | `docs/jdlib/features/tenancy.md`, `docs/architecture/data-architecture.md` |
| Privilege model documented | `docs/jdlib/features/authorization.md`, `docs/jdlib/security-model.md` |
| PostgreSQL documented | `docs/jdlib/features/connectors.md`, `docs/integrations/postgresql.md` |
| Neo4j documented | `docs/jdlib/features/graph.md`, `docs/integrations/neo4j.md` |
| FastMCP documented | `docs/jdlib/features/mcp.md`, `docs/integrations/mcp.md` |
| Audit documented | `docs/jdlib/features/audit.md` |
| Reliability documented | `docs/reliability/` (seven pages) |
| Observability documented | `docs/jdlib/features/observability.md`, `docs/observability/` |
| Error model documented | `docs/reference/error-codes.md` |
| Health and readiness documented | `docs/operations/health-and-readiness.md` |
| Security architecture documented | `docs/architecture/security-architecture.md` |
| Production architecture documented | `docs/operations/deployment.md`, `docs/jdlib/architecture/example-architecture.md` |
| API reference documented | `docs/reference/public-api.md`, generated from the source by `scripts/api-reference.py` |
| Extension points documented | `docs/reference/extension-points.md` |
| Testing documented | `docs/development/testing.md`, `docs/jdlib/features/tenancy.md` |
| Deployment documented | `docs/operations/deployment.md` |
| Troubleshooting documented | `docs/operations/troubleshooting.md` (an eighteen-row symptom table) |
| Minimal example exists | `examples/minimal/`, `docs/jdlib/examples/minimal.md` |
| Enterprise example exists | `examples/enterprise/`, `docs/jdlib/examples/enterprise.md` |
| Neo4j examples exist | `examples/enterprise/app/graph.py`, `docs/jdlib/features/graph.md` |
| FastMCP examples exist | `examples/enterprise/app/mcp/`, `docs/jdlib/features/mcp.md` |
| Code examples use real APIs | `tests/unit/test_example_docs.py` resolves every symbol and `file:line` a page cites |
| Mermaid diagrams cover major flows | 37 diagrams; the matrix's Diagram column is earned per area |
| Diagrams reflect the implementation | each diagram is written from the page's own "How it works" text |
| Documentation does not invent functionality | the citation checks, the generated reference, and the inventory |
| No archived predecessor API names | `knowledge_base/` is excluded from the portal and marked archived in the README |
| MkDocs builds | `mkdocs build --strict` exits 0 in both gates |
| `--strict` passes | same run; 0 warnings |
| No broken links | the strict build fails on an unrecognised relative link |
| No unresolved warnings | 0 warnings, and `--strict` turns any into a failure |
| Documentation and source are consistent | `api-reference.py --check`, `docs-inventory.py --check`, `docs-matrix.py --check`, `feature-matrix.py --check` |
| Examples are validated | the example suites (unit, integration, security, e2e) plus the doc tests |
| Final documentation review completed | [The portal, reviewed from four chairs](../../development/portal-review.md) |

## What is open, and where it is recorded

* **The matrix has no empty cell left.** Every area earns its validated tick. The observability row
  named `jdlib.observability`, a module that never existed, which held the cell empty and hid the
  test that does assert the span allow-list; the namespace is now `jdlib.security.tracing`, earned
  by `tests/unit/test_boundary_spans.py` and `tests/infra/test_otel_infra.py`.
* **Mermaid syntax is checked structurally, not parsed.** Fences are checked for balance, type,
  content, and for a sequence keyword in a flowchart or an unclosed `subgraph`; a full parse is not
  run, so a diagram can still be wrong in a way only the renderer sees. Recorded in
  [how the portal is validated](../../development/portal-validation.md).
* **A rare resource warning, not reproduced.** Running the whole suite against every live lab
  (example and infra) failed once in nine runs on an unraisable `ResourceWarning`: an asyncpg
  connection to the example database collected while it was still open, which `-W error` turns into
  a failure. It has not reproduced since -- not in three further all-live gates, not in a forced
  `gc.collect()` at session end over each layer, and not in the e2e harness, which already closes
  the subprocess pipe deliberately. The asyncio-debug traceback (which names the connection's
  origin) is the next step if it returns; it is recorded here rather than left as a mystery flake.
* **The rendered site is not screenshotted.** The gate proves it builds and the links resolve; it
  does not judge appearance.
* **`knowledge_base/` stays archived.** It is a snapshot of an earlier commit and is deliberately
  outside the portal, which the README now says rather than leaving a reader to discover it.
