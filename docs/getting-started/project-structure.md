# Project structure

What is where, and why the boundaries are where they are.

```
jdlib/
├── src/jdlib/            the library
├── tests/                the library's own suites, by layer
├── examples/             two runnable applications
├── docs/                 this documentation
├── scripts/              the gates and the generators
├── pyproject.toml        packaging, extras, and the tool configuration
└── mkdocs.yml            this site
```

## The library

| Package | What it is |
|---|---|
| `jdlib` | the public surface: configuration, the context types, `current_tenant()`, the error model |
| `jdlib.authn` | authentication: API keys, OIDC, the composite authenticator, and `build_authenticator` |
| `jdlib.authz` | authorization: the permission catalog, guards, the PDP, scopes, resource types |
| `jdlib.control` | the control plane: the tenant registry, the lifecycle, platform audit, migrations |
| `jdlib.tenancy` | tenant resolution, the middleware, the job envelope |
| `jdlib.persistence` | repositories, the unit of work, the isolation strategies, row-level security |
| `jdlib.security` | the security core: context, tracing, audit, the PEP, compliance |
| `jdlib.resources` | handles, connection configuration, the resolver |
| `jdlib.credentials` | the secret-provider chain, versions and rotation |
| `jdlib.caching` | the cache policy, the in-process and Redis providers, the credential guard |
| `jdlib.data` | the connector framework: policy, circuit breaker, registry |
| `jdlib.query` | the query compiler: specifications, the AST, dialects, identifier policy |
| `jdlib.storage` | object storage: keys, the S3 backend |
| `jdlib.graph` | the Neo4j plane: client, queries, repository, runner, policy |
| `jdlib.reliability` | breaker, retry budget, concurrency gate, shutdown coordinator, dead letter |
| `jdlib.integrations` | the edges: FastAPI, MCP, the CLI, the pytest kit |
| `jdlib.models`, `jdlib.migrations`, `jdlib.config`, `jdlib.errors`, `jdlib.context`, `jdlib.lint`, `jdlib.testing` | the shared types, the migration runner, configuration, the error model, the context types, the linters, the test kit |

The dependency rule is one-way: `integrations` may import anything, a mechanism package imports the
shared types and not another mechanism, and nothing imports `integrations`. That is what lets the
FastAPI and MCP surfaces share one composition — they both build the *same* collaborators rather
than each wiring their own.

## The tests

| Directory | What it holds | Needs |
|---|---|---|
| `tests/unit/` | the library's behaviour, in isolation | nothing |
| `tests/integration/` | real infrastructure: PostgreSQL, Cerbos, Redis, Neo4j, MCP | the service |
| `tests/infra/` | the local lab's own tests and the compose stack | Docker |
| `tests/unit/security/` | the security core's suites | nothing |
| `examples/*/tests/` | each example's own layers: `unit`, `integration`, `security`, `e2e` | as documented per layer |

Layers are selected **by directory**, not by marker: most suites are unmarked, and a marker-based
selection would silently run a subset. `pytest tests/unit` is the fast loop;
`bash scripts/ci-local.sh` is the gate.

## The examples

`examples/minimal/` is the smallest correct application and `examples/enterprise/` is the whole
surface — HTTP and MCP, PostgreSQL and Neo4j, a live policy engine. Their test layers and their
matrices are in [Examples](../jdlib/examples/overview.md).

## The documentation

`docs/` is published as this site. Each topic has one design authority and the portal routes to it;
`docs/development/documentation.md` states the rule, and `docs/development/documentation-inventory.md`
is the per-namespace audit of what is documented and where the evidence is.

## The gates

| Command | What it runs |
|---|---|
| `bash scripts/ci-local.sh` | everything: ruff, mypy, the documentation build, the generated-page checks, pytest with coverage, the build, and a clean-venv install smoke |
| `bash scripts/ci-local.sh --fast` | the same without packaging |
| `pytest tests/unit -q -W error` | the fast loop |
| `mkdocs build --strict` | the documentation build alone |

`scripts/feature-matrix.py` and `scripts/docs-inventory.py` generate pages from the tree, and the
gate fails when a generated page is stale — a hand-written table of line numbers is wrong the first
time someone edits the file above it.
