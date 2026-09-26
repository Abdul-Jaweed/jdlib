# The coverage matrix

What each test layer covers, what it needs to run, and what it is for. Counts are **test
functions** (a deterministic property of a file); the number of *cases* depends on how the
suite was invoked, so it is not claimed here.

## The enterprise example

| Layer | Files | Tests | Needs | Answers |
|---|---|---|---|---|
| `tests/unit/` | 4 | 24 | nothing — no service, no lab | what is declared, and how it is wired: the tool inventory, the capabilities, the collaborator identity, the settings |
| `tests/integration/` | 4 | 29 | PostgreSQL + Cerbos (+ Neo4j for the graph, MCP for the surface) | does the real infrastructure answer: the tenant plane, RLS, the policy decisions, the graph projection, the MCP chain |
| `tests/security/` | 3 | 16 | PostgreSQL + Cerbos (+ Neo4j + MCP) | isolation across tenants over both surfaces, denial as non-execution, and what a failure is allowed to say |
| `tests/e2e/` | 1 | 8 | a POSIX host (the stop probe), PostgreSQL + Cerbos | does the documented command work as a process: readiness, the whole chain over a socket, and a refusal to start unconfigured |
| **total** | **12** | **77** | the lab up | |

### The files

| File | Tests |
|---|---|
| `examples/enterprise/tests/unit/test_app.py` | 5 |
| `examples/enterprise/tests/unit/test_authorization.py` | 6 |
| `examples/enterprise/tests/unit/test_bootstrap.py` | 5 |
| `examples/enterprise/tests/unit/test_mcp_surface.py` | 8 |
| `examples/enterprise/tests/integration/test_authorization_live.py` | 4 |
| `examples/enterprise/tests/integration/test_graph_live.py` | 7 |
| `examples/enterprise/tests/integration/test_mcp_live.py` | 6 |
| `examples/enterprise/tests/integration/test_tenant_plane_live.py` | 12 |
| `examples/enterprise/tests/security/test_denial_non_execution.py` | 4 |
| `examples/enterprise/tests/security/test_error_surface.py` | 6 |
| `examples/enterprise/tests/security/test_tenant_isolation.py` | 6 |
| `examples/enterprise/tests/e2e/test_http_chain.py` | 8 |

## The minimal example

| Files | Tests | Needs | Answers |
|---|---|---|---|
| 3 | 11 | PostgreSQL | the shape (the mount, the guard's declaration), the denial over a real chain, and the operator step |

| File | Tests |
|---|---|
| `examples/minimal/tests/test_app.py` | 8 |
| `examples/minimal/tests/test_bootstrap_live.py` | 1 |
| `examples/minimal/tests/test_denial_live.py` | 2 |

## What is *not* covered, stated rather than implied

* **`tests/e2e/test_http_chain.py::test_the_process_stops_on_sigterm` skips on Windows** — it
  uses POSIX signals, and it says so in its skip reason rather than pretending to pass.
* **Every live layer skips when its lab is absent**, naming the missing variable and the
  operator step that provides it. A suite that failed without a container would teach nothing.
* **No layer covers a second database vendor.** The dialect seam exists (`QueryDialect`,
  `MysqlDialect`); the example runs PostgreSQL, and no test claims otherwise.
* **Coverage of the *example* is not a gate.** The library's own coverage floor is enforced in
  CI; the example's layers exist to be run, and their value is the defects they found (see the
  README's "what writing it found").

Regenerate with `python scripts/feature-matrix.py`.