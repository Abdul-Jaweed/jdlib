# Documentation inventory

The audit the documentation directive asks for before anything is written: every public
namespace, whether it is documented, where the evidence is, and how many test files hold it.

**Generated** by `scripts/docs-inventory.py` - the counts are read from the tree, so this page
cannot drift from it. The rows that need judgement (experimental, deferred, internal, absent)
are in the second table, each with its reason and a citation the documentation test checks.

## How a row is classified

| Classification | The mechanical rule |
|---|---|
| **DOCUMENTED** | a capability page, a feature guide or an alias page exists **and** at least one test file names the namespace |
| **PARTIALLY DOCUMENTED** | the namespace is mentioned in `docs/` but lacks a capability page, a feature guide, or a test |
| **UNDOCUMENTED** | nothing under `docs/` mentions it |

The directive's other classifications - EXPERIMENTAL, DEPRECATED, IMPLEMENTED BUT INTERNAL,
NOT IMPLEMENTED - are judgements, so they are recorded as judgements in the table below
rather than inferred from a grep.

## The public surface

| Namespace | Public surface | Classification | Where it is documented | Test files |
|---|---|---|---|---:|
| `jdlib` | `__all__` (13) | DOCUMENTED | `docs/jdlib/architecture.md`, `docs/getting-started/configuration.md`, `docs/jdlib/security-model.md` | 158 |
| `jdlib.authn` | no declared exports | DOCUMENTED | `docs/jdlib/authentication.md`, `docs/jdlib/features/authentication.md` | 15 |
| `jdlib.authz` | no declared exports | DOCUMENTED | `docs/jdlib/authorization.md`, `docs/jdlib/features/authorization.md` | 15 |
| `jdlib.caching` | `__all__` (11) | DOCUMENTED | `docs/jdlib/capabilities/caching.md`, `docs/jdlib/features/caching.md` | 6 |
| `jdlib.credentials` | `__all__` (10) | DOCUMENTED | `docs/jdlib/capabilities/credentials.md`, `docs/jdlib/features/credentials.md` | 11 |
| `jdlib.data` | `__all__` (10) | DOCUMENTED | `docs/jdlib/capabilities/connectors.md`, `docs/jdlib/features/connectors.md` | 6 |
| `jdlib.graph` | `__all__` (32) | DOCUMENTED | `docs/jdlib/capabilities/graph.md`, `docs/jdlib/features/graph.md` | 15 |
| `jdlib.integrations` | no declared exports | DOCUMENTED | `docs/jdlib/architecture.md` | 15 |
| `jdlib.integrations.mcp` | `__all__` (16) | DOCUMENTED | `docs/jdlib/capabilities/mcp.md`, `docs/jdlib/features/mcp.md` | 9 |
| `jdlib.migrations` | no declared exports | DOCUMENTED | `docs/jdlib/production-readiness.md` | 7 |
| `jdlib.persistence` | no declared exports | DOCUMENTED | `docs/jdlib/03-isolation-invariants.md`, `docs/jdlib/06-strategy-matrix.md` | 35 |
| `jdlib.persistence.strategies` | no declared exports | DOCUMENTED | `docs/jdlib/06-strategy-matrix.md`, `docs/jdlib/03-isolation-invariants.md` | 14 |
| `jdlib.query` | `__all__` (21) | DOCUMENTED | `docs/jdlib/capabilities/query.md` | 4 |
| `jdlib.reliability` | `__all__` (11) | DOCUMENTED | `docs/reliability/overview.md`, `docs/reliability/circuit-breakers.md`, `docs/reliability/failure-modes.md` | 11 |
| `jdlib.resources` | `__all__` (4) | DOCUMENTED | `docs/jdlib/capabilities/resources.md` | 6 |
| `jdlib.security` | `__all__` (38) | DOCUMENTED | `docs/jdlib/security-model.md`, `docs/security/security-core.md` | 63 |
| `jdlib.security.audit` | `__all__` (26) | DOCUMENTED | `docs/jdlib/features/audit.md` | 16 |
| `jdlib.security.authn` | `__all__` (16) | DOCUMENTED | `docs/security/authentication-hardening.md` | 9 |
| `jdlib.security.authz` | `__all__` (8) | DOCUMENTED | `docs/security/authorization-hardening.md` | 7 |
| `jdlib.security.compliance` | `__all__` (22) | DOCUMENTED | `docs/compliance/README.md` | 4 |
| `jdlib.security.gateway` | `__all__` (5) | DOCUMENTED | `docs/security/gateway-hardening.md` | 4 |
| `jdlib.storage` | `__all__` (11) | DOCUMENTED | `docs/jdlib/capabilities/storage.md`, `docs/jdlib/features/storage.md` | 1 |
| `jdlib.tenancy` | no declared exports | DOCUMENTED | `docs/jdlib/features/tenancy.md` | 25 |
| `jdlib.testing` | `__all__` (3) | DOCUMENTED | `docs/development/testing.md` | 1 |

**24 namespaces are DOCUMENTED, 0 are PARTIALLY DOCUMENTED, and 0 are UNDOCUMENTED** (of 24 public namespaces).

## The rows that need judgement

| Namespace | Classification | Why | Evidence |
|---|---|---|---|
| `jdlib.data` | **PARTIALLY DOCUMENTED** | PostgreSQL is the only connector with an implementation; the other four engines are deferred by decision, not by omission. | `docs/jdlib/successor/05-roadmap.md` |
| `jdlib.query` | **PARTIALLY DOCUMENTED** | Two dialects exist (`PostgresDialect`, `MysqlDialect`) and only PostgreSQL is executed by any test: the MySQL dialect is implemented and unverified. | `docs/jdlib/examples/coverage-matrix.md` |
| `jdlib.storage` | **PARTIALLY DOCUMENTED** | S3 is verified against real MinIO. Google Cloud Storage and Azure Blob have **no module and no export** - a provider class in the public surface is a claim that it works, and a test asserts they are absent. | `docs/jdlib/successor/05-roadmap.md` |
| `jdlib.graph` | **DOCUMENTED** | One backend (Neo4j) and one live suite against a real instance; no second graph vendor is claimed anywhere. | `docs/jdlib/capabilities/graph.md` |
| `jdlib.tenancy` | **DOCUMENTED** | Tenant resolution, the lifecycle and the job envelope are covered; the queue itself is thedeployment's choice and is deliberately not implemented here. | `docs/jdlib/capabilities/jobs.md` |
| `jdlib.integrations.mcp` | **DOCUMENTED** | The tool surface is implemented and live-tested. `graph_search` is deliberately absent - afree-text search over a graph is a statement the closed vocabulary cannot express. | `docs/jdlib/capabilities/mcp.md` |
| `jdlib.authn` | **PARTIALLY DOCUMENTED** | API keys and OIDC are implemented. Other identity methods (SAML, Kerberos, mTLS) are **notimplemented**: `build_authenticator` wires what exists and refuses a method it does not have. | `docs/jdlib/features/authentication.md` |
| `jdlib.caching` | **DOCUMENTED** | Two providers (in-process and Redis) with the credential guard that refuses to cache a secret at all. | `docs/jdlib/capabilities/caching.md` |
| `jdlib.reliability` | **DOCUMENTED** | Breaker, retry budget, concurrency gate, shutdown coordinator and dead letter, each with its own test file. | `docs/jdlib/capabilities/README.md` |
| `jdlib.control` | **IMPLEMENTED BUT INTERNAL** | The control plane (tenant registry, platform audit, lifecycle) is public API for an operator, not for a request path; the operations page is its authority. | `docs/operations/README.md` |

## What is deliberately absent

* **Google Cloud Storage and Azure Blob backends.** No module, no export, and a test that
  asserts their absence: a provider class in the public surface is a claim that it works.
* **A job queue.** `jdlib.tenancy.job_envelope` gives work an authority and a lifetime; the
  queue, its retries and its dead-letter store are the deployment's.
* **A free-text graph search tool.** The MCP surface exposes the closed vocabulary instead.
* **SAML, Kerberos and mTLS authentication.** API keys and OIDC are what exists.
* **A second database vendor in the test suite.** The dialect seam exists; PostgreSQL is what
  is run, and no page claims otherwise.

## Pages that are archived rather than published

| Where | What | Why it is not in the portal |
|---|---|---|
| `knowledge_base/` | a source-derived knowledge base written at commit `a30601d` | it describes an earlier revision; the portal publishes current behaviour |
| `.recon/` | reconnaissance notes from the successor programme | working notes, not reference material |
| `docs/superpowers/plans/` | the phase plans the programme was executed from | working documents against earlier revisions; kept in the repository for the audit trail |

Regenerate with `python scripts/docs-inventory.py`; the documentation test fails when a
page is stale.