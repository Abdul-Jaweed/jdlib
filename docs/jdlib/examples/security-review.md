# The enterprise example's security review

Every check below names the control, the evidence, and what the evidence showed. The evidence is a
test that was run (with its line), or a command whose output is quoted. **Nothing here is a claim
without one** — where a control is not verified, the last section says so.

The lab for the live rows: PostgreSQL `127.0.0.1:45432/jdlib_enterprise` (two roles), Cerbos
`127.0.0.1:4592`, Neo4j `bolt://127.0.0.1:7688`.

## 1. Identity

| Check | Evidence | Result |
|---|---|---|
| A forged key is refused, on both surfaces | `tests/security/test_tenant_isolation.py:126` | pass — HTTP and MCP both answer the credential refusal, and the tool surface never reaches a handler |
| No credential is refused before any tenant exists | `tests/security/test_tenant_isolation.py:147` | pass — the refusal precedes resolution, so an unauthenticated caller cannot even probe which tenants exist |
| An identity claim in the request is ignored | `tests/security/test_tenant_isolation.py:98` | pass — a caller sending another tenant's slug in the header gets their *own* tenant's answer, measured against the application's own registry |
| The key that authenticated is the one in the control plane | `tests/integration/test_mcp_live.py:348` | pass — the hash the library compared is the row the operator step wrote |

## 2. Authorization

| Check | Evidence | Result |
|---|---|---|
| A denied write over HTTP is answered **and never happens** | `tests/security/test_denial_non_execution.py:79` | pass — 403 with the canonical code, and the row is read back **as the owner** unchanged |
| A denied tool call is refused and never happens | `tests/security/test_denial_non_execution.py:110` | pass — same measurement, over the MCP chain |
| The denial is the engine's, not a missing role | `tests/security/test_denial_non_execution.py:147` | pass — the same caller is allowed a different action, so the refusal is the policy's answer rather than a hole in the grants |
| A denied reader cannot read either | `tests/security/test_denial_non_execution.py:163` | pass |
| Both surfaces answer the same question the same way | `tests/security/test_tenant_isolation.py:80` | pass — one composition, asserted by collaborator identity |

## 3. Tenancy

| Check | Evidence | Result |
|---|---|---|
| A resource is invisible to another tenant | `tests/security/test_tenant_isolation.py:35` | pass — answered `409 INVALID_REFERENCE`, the library's own mapping, deliberately not re-mapped |
| A listing never crosses the tenant | `tests/security/test_tenant_isolation.py:59` | pass — the other tenant's rows are absent from the page |
| The tenant is the credential, not an argument | `tests/integration/test_mcp_live.py:316` | pass — a tool argument naming a tenant changes nothing |
| The database enforces the same rule | `tests/integration/test_tenant_plane_live.py:366` (refused) and `:388` (the scoped form beside it) | pass — an unscoped text statement is **refused**, and the scoped bulk update is the safe path that works |
| The policy alone hides another tenant's rows | `tests/integration/test_tenant_plane_live.py:272` | pass — with the policy and no application filter, the rows are still absent |
| The composite foreign key holds | `tests/integration/test_tenant_plane_live.py:324` | pass — a child row naming another tenant's parent is refused **by the database** |
| The write fence refuses a suspended tenant | `tests/integration/test_tenant_plane_live.py:433` | pass |

## 4. The graph plane

| Check | Evidence | Result |
|---|---|---|
| Another tenant's client cannot see the node | `tests/integration/test_graph_live.py:208` | pass |
| A statement for another tenant is refused by the client | `tests/integration/test_graph_live.py:231` | pass — `GraphTenantViolationError` rather than a filtered result |
| An undeclared label never reaches a statement | `tests/integration/test_graph_live.py:260` | pass — refused before the driver sees it |
| The identity constraint exists, so a projection is an update | `tests/integration/test_graph_live.py:315` | pass — and it was the mutation that turned the upsert into a create that showed the lab lacked it |

## 5. The error surface

| Check | Evidence | Result |
|---|---|---|
| No credential is a 401 in the envelope | `tests/security/test_error_surface.py:69` | pass — the four-key envelope, and the RFC 6750 challenge |
| A malformed credential is the same answer | `tests/security/test_error_surface.py:76` | pass — parameterised over the malformed forms |
| An unknown route is answered in the envelope | `tests/security/test_error_surface.py:90` | pass |
| A malformed body is a validation failure, not a traceback | `tests/security/test_error_surface.py:101` | pass |
| An unreachable row says so without saying where it is | `tests/security/test_error_surface.py:111` | pass — `409 INVALID_REFERENCE`, which confirms nothing about other tenants |
| A tool-call failure carries no internals either | `tests/security/test_error_surface.py:127` | pass |

## 6. The audit trail

| Check | Evidence | Result |
|---|---|---|
| A denial is recorded | `tests/security/test_denial_non_execution.py` (the delta assertion) | pass — the trail grows by the denial's events, read back from `jd_control.platform_audit_events` |
| A refused MCP call records **three** events | same file | pass — the boundary's request, the engine's decision and the chain's refusal |
| The trail is written as the platform, not the caller | `app/dataplane.py` (the operator grants) | pass — the runtime role can append and read what it needs, and cannot rewrite history |

## 7. Operational

| Check | Evidence | Result |
|---|---|---|
| Readiness asks the real dependencies | `tests/e2e/test_http_chain.py:179` | pass — a control-plane statement and a policy decision, not a constant |
| Liveness answers without credentials | `tests/e2e/test_http_chain.py:171` | pass |
| The documented command works as a process | `tests/e2e/test_http_chain.py:186` | pass — the whole chain over a real socket |
| A process started without its environment fails loudly | `tests/e2e/test_http_chain.py:277` | pass — refuses to start rather than serving unconfigured |
| A stop is clean | `tests/e2e/test_http_chain.py:256` | **skip on Windows** — POSIX signals; the skip reason says so rather than pretending to pass |

## 8. Build and supply chain

| Check | Evidence | Result |
|---|---|---|
| No secret is committed | `gitleaks detect` over the full history | pass — 257 commits, no findings |
| No test file carries a credential-shaped literal | the e2e and live layers generate their signing key per run and read passwords from the environment | pass — and a `gitleaks` finding is what would have caught a slip |
| The runner installs what the examples import | `.github/workflows/ci.yml`, `scripts/ci-local.sh` (the extras step) | pass — this is a fix: the runner previously installed `[dev,s3,redis]` and collection failed on `neo4j`/`fastmcp` |
| The gate runs the generated documentation check | `scripts/ci-local.sh` (`scripts/feature-matrix.py --check`) | pass |

## 9. What this review does **not** claim

* **No penetration test.** These are the controls the example asserts, not an adversarial assessment
  of the library by an independent party.
* **Fuzzing is limited to the parameterised malformed bodies** in the error-surface layer; there is
  no coverage-guided fuzzing of the request path.
* **The lab's Cerbos is not a hardened deployment** — it runs with its default driver and no TLS;
  the example's claim is about the *chain*, not about the lab's hardening.
* **One database vendor.** The dialect seam exists; PostgreSQL is what is run.
* **The graph is verified against one Neo4j instance** with the example's own credentials.
* **`SIGTERM` drain is unverified on Windows**, as the skip says.
