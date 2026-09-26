# The examples

Two runnable applications, and what each one is for.

| | [`examples/minimal`](https://github.com/Abdul-Jaweed/jdlib/tree/main/examples/minimal) | [`examples/enterprise`](https://github.com/Abdul-Jaweed/jdlib/tree/main/examples/enterprise) |
|---|---|---|
| **What it is** | the smallest correct JDLib application: FastAPI → JDLib → PostgreSQL | the whole surface: gateway-shaped HTTP, Cerbos, PostgreSQL, Neo4j, MCP, audit, reliability, observability |
| **Size** | one app, one route, one test file per layer | a layered application (`configuration/`, `security/`, `api/`, `services/`, `repositories/`, `models/`, `mcp/`) |
| **Infrastructure** | PostgreSQL | PostgreSQL (two roles) + Cerbos + Neo4j, all in `docker/docker-compose.yml` |
| **Tests** | 11 | 77 (unit / integration / security / e2e) |
| **Read it when** | you are starting an application and want the smallest thing that is right | you are wiring the security mechanisms into an existing one, or reviewing how they compose |
| **Run it** | [`minimal-example.md`](minimal-example.md) | [`enterprise-example.md`](enterprise-example.md) |

## What both examples have in common

* **The library is the only implementation of a security mechanism.** No example module parses a
  credential, decides an authorization question, checks a tenant or shapes an error body; the tests
  assert that by walking the routes and by asserting the identity of the collaborators.
* **The documented path is the tested path.** Every command in the READMEs is one the repository
  can run: the e2e layer starts `uvicorn` exactly as the README says, and the live layers use the
  DSNs the operator steps produce.
* **A lab is required for the live layers, and their absence is a skip with the reason.** A suite
  that fails because a container is missing teaches nothing; a suite that says *why* it skipped
  teaches the operator step.

## Where to read next

* the feature guides ([`../features/`](../features/README.md)) for how each mechanism is meant to be used;
* the architecture pages ([`../architecture/`](../architecture.md)) for how the enterprise example is
  put together and what happens between a request and a handler;
* [`with-and-without.md`](with-and-without.md) for what the library is doing for you, side by side
  with the code you would otherwise write;
* [`developer-journey.md`](developer-journey.md) for the order to adopt things in.
