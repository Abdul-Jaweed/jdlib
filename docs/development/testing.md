# Testing

How the repository tests itself, and what to copy for your own application. The
[guides](../guides/test-your-integration.md) page is the how-to; this one is how the repository
does it.

## The layers

| Directory | Needs | What it holds |
|---|---|---|
| `tests/unit/` | nothing | the library's behaviour in isolation |
| `tests/unit/security/` | nothing | the security core's suites |
| `tests/integration/` | PostgreSQL, Cerbos, Redis, Neo4j or MCP | the same behaviour against the real thing |
| `tests/infra/` | Docker | the local lab and its own tests |
| `examples/*/tests/{unit,integration,security,e2e}/` | as documented per layer | the composed chain, measured |

**Select by directory, not by marker.** Most suites are unmarked, so a marker-based selection runs a
subset while looking like it ran everything.

## The gate

```bash
bash scripts/ci-local.sh          # ruff, mypy, the docs build, the generated pages, pytest, packaging
bash scripts/ci-local.sh --fast   # the same without the packaging steps
```

The same steps run in CI (`.github/workflows/ci.yml`), and the documentation build is one of them: a
page that breaks the site breaks the build.

## The generated pages

| Page | Generator | Checked by |
|---|---|---|
| the feature matrix | `scripts/feature-matrix.py` | `--check` in both gates |
| the coverage matrix | `scripts/feature-matrix.py` | `--check` in both gates |
| the documentation inventory | `scripts/docs-inventory.py` | `--check` in both gates, and a unit test |
| the public API reference | `scripts/api-reference.py` | `--check` in both gates |

A generated page that drifts from the tree is a lie with a table in it, so the gate fails rather than
warns.

## The document tests

| Suite | What it checks |
|---|---|
| `tests/unit/test_example_docs.py` | the example documentation: citations resolve, commands are runnable, the matrices' cells are true |
| `tests/unit/test_docs_portal.py` | the site: the navigation, the links, the diagram types, the generated pages |
| `tests/unit/test_successor_docs.py` | the programme documents: front-matter and structure |

## Running a single layer

```bash
pytest tests/unit -q -W error                 # the fast loop, no infrastructure
pytest tests/integration -q                   # against containers or the lab
pytest tests/unit/test_docs_portal.py -q      # the documentation checks alone
```

## Test support: `jdlib.testing`

`jdlib.testing` is a public namespace, and it holds three assertions for the property every other
guarantee rests on. A test of tenant-scoped code should reach for these rather than hand-writing the
check, so that "isolated" means the same thing in your suite as in the library's own:

| helper | what it asserts |
|---|---|
| `assert_tenant_isolated` | creates a row for one context and asserts another cannot see it; returns the id of the row it created |
| `assert_scoped_count` | a model has exactly the expected number of rows visible to a context |
| `assert_cross_tenant_write_rejected` | a row owned by another tenant cannot be flushed under the wrong context |

They are what the isolation suites are built from, and they are exported for exactly that reason.

## The rule

A test that needs infrastructure **skips** when the environment does not offer it, and says which
variable it wanted. That is why the repository can be cloned and tested without Docker, and why a
green suite means something: the layers that need infrastructure either ran against it or said so.
