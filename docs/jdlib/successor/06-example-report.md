# The example application — the report

The directive's §18 milestone, closed. What landed, what was found, what was verified, and what
remains open.

## What landed

| Slice | Commit | What it is |
|---|---|---|
| E1 — the minimal example | `47caeb6` | `examples/minimal`: FastAPI → JDLib → PostgreSQL, 11 tests |
| E2/E3a — configuration, security, api, and the policy set | (E2/E3a) | `examples/enterprise/app/{configuration,security,api}`, `config/cerbos/policies/` with 21 engine tests |
| E3b — the tenant plane | `b5f8c42` | models, repositories, services, `dataplane.py`, the two-role lab, 11 live tests |
| E3c-i — the graph plane | `8f238f3` | `app/graph.py`, the closed vocabulary, the identity constraint, 7 live tests |
| E3c-ii — the MCP surface | `0032f25` | `app/mcp/`, one composition over two surfaces, 8 unit + 6 live tests |
| E4 — the four test layers | `a32e81f` | `tests/{unit,integration,security,e2e}` (24/29/16/8) over `tests/support/` |
| E5 — the feature guides | (this phase) | `docs/jdlib/features/`: 14 guides, 1,301 lines, verified front-matter |
| E6 — architecture and example docs | (this phase) | `docs/jdlib/architecture/` (6 pages), `docs/jdlib/examples/` (5 pages) |
| E7 — the documentation is checked, the matrices generated | (this phase) | `tests/unit/test_example_docs.py` (199 checks), `scripts/feature-matrix.py` (+ the gate step) |
| E8 — this review and report | (this phase) | `security-review.md`, this page |

## What was found — the point of the exercise

An example that is only described finds nothing. This one was run, and running it found:

1. **The runtime role could not reach the control plane at all.** The operator step granted
   privileges inside the tenant schema and nowhere else, while a serving process authenticates,
   resolves a tenant, reads roles and writes the trail — all control-plane rows. It surfaced as
   `"no credentials presented"` on every tool call, which is the wrong diagnosis for a grant
   problem; the fix is `grant_control_privileges` plus the one narrow `UPDATE` on the key's own
   `last_used_at`.
2. **The MCP chain asks its authorization question about the *tenant scope*.** A route knows which
   resource it is about; a tool call does not, because the id is an argument and authorization runs
   first. A policy set written only against route targets refuses every tool call. The policy set
   now carries the tool capabilities, and the engine's own tests grew 29 → 44.
3. **An unreachable row is answered `409 INVALID_REFERENCE`, not 404.** The library's mapping, kept
   deliberately: a 403 or 404 would confirm that the id exists somewhere.
4. **A denied MCP call writes three audit events** where HTTP writes one — the boundary's request,
   the engine's decision, the chain's refusal. Any trail assertion must be a delta, and the first
   version of the security test was wrong for exactly this reason.
5. **The lab's graph had no identity constraint**, so "project twice" created a second node rather
   than updating. The mutation that turned the upsert into a create succeeded at the database, which
   is what a mutation check is for.
6. **A suspicion that was disproved.** The MCP boundary was assumed to bind only a security context
   and not a tenant context; a live probe showed it binds both, the change was reverted, and the
   probe stayed as a test. Recording this matters as much as the defects: a review that only lists
   confirmations is not a review.
7. **A fixture that invented a tenant slug** passed every self-comparison and failed the one
   assertion that compared it with the application's own registry — a harness that fabricates its
   own facts tests itself.
8. **Two library defects found by the minimal example** (E1): a driver `ConnectionError` surfacing
   as 500 instead of 503, and the guard's `jdlib_permission` declaration not being readable by the
   route walk the tests use.
9. **A CI gap**: the runner installed `[dev,s3,redis]` while the examples import `neo4j` and
   `fastmcp`, so collection failed on the runner and not locally. Fixed in both the workflow and
   `ci-local.sh`, which now fails with the install command when the extras are missing.

## What was verified

* **The full local gate** (`bash scripts/ci-local.sh`): ruff, mypy over `src/jdlib examples`, the
  extras check, the generated-documentation check, `pytest -q -W error` with coverage, the sdist and
  wheel build, and a clean-venv install + import smoke with the console script answering.
* **The example's own layers with the lab up**: 24 unit + 29 integration + 16 security + 8 e2e
  (77 test functions; 76 passed, 1 skipped on Windows), plus the minimal example's 11.
* **Mutations**: 9/9 (E1), 2/2 (E2), 2/2 (E3a), 3/3 (E3b), 2/2 (E3c-i), 2/2 (E3c-ii), 2/2 (E4).
  Every mutation was restored, and the restored tree is the committed one.
* **gitleaks** over the full history: clean.
* **The documentation**: 199 checks in `tests/unit/test_example_docs.py`, the matrices regenerated
  and compared by the gate, and the 14 guides' front-matter verified against the tree before the
  files were written (the first pass cited 17 paths that did not exist).
* **CI**: every pushed commit's workflow run was watched to completion; the two failures
  (`8f238f3`'s missing extras) were diagnosed and fixed rather than re-run until green.

## What remains open, stated plainly

* **`SIGTERM` drain is unverified on this host.** The test exists and skips on Windows with that
  reason. On a POSIX runner it runs.
* **The example does not use every feature it documents.** Background jobs, caching, storage and
  connectors are library-only: their guides say so in their own Example sections, and the feature
  matrix marks those cells rather than implying an example that does not exist.
* **No second database vendor and no production-hardened lab.** Stated in the security review's last
  section, where a reader will look for it.
* **Coverage of the example is not a gate.** The library's coverage floor is enforced; the example's
  value is the defects it found, which is why they are listed above rather than summarised as
  "tests pass".
