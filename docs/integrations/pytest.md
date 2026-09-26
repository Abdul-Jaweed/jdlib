# The pytest integration

```bash
pip install -e ".[dev]"
```

`jdlib.testing` and `jdlib.integrations.pytest_plugin` are the test kit: fixtures for a
tenant-bound context, a control plane, and a unit of work — the pieces the library's own suites and
both examples are built on.

## What it gives a suite

| Fixture / helper | What it is |
|---|---|
| a bound security context | a `SecurityContext` with a real tenant, so a test does not hand-build one |
| a control-plane session | a session against a migrated control plane, or a refusal when the DSN is absent |
| a unit of work | tenant-bound, so a test exercises the same path the request does |
| an in-memory audit sink | the audit vocabulary without a database |

The plugin is registered through the `pytest11` entry point, so a project that installs the `dev`
extra gets the fixtures without importing anything.

## The rule the example suites follow

A test that needs a live dependency **skips** when the environment does not point at one, rather than
failing or faking it:

```python
pytestmark = pytest.mark.skipif(
    not os.environ.get("JDLIB_EXAMPLE_LIVE_DSN"),
    reason="needs a live PostgreSQL (JDLIB_EXAMPLE_LIVE_DSN)",
)
```

That rule is why the repository can be cloned and tested without Docker, and why a green suite in CI
means something: the layers that need infrastructure either ran against it or said they did not.

## The layers

| Directory | Needs | What it holds |
|---|---|---|
| `tests/unit/` | nothing | the library's behaviour in isolation |
| `tests/integration/` | PostgreSQL, Cerbos, Redis, Neo4j or MCP | the same behaviour against the real thing |
| `tests/infra/` | Docker | the local lab and its own tests |
| `examples/*/tests/{unit,integration,security,e2e}/` | as documented per layer | the composed chain, measured |

Select layers **by directory**, not by marker: most suites are unmarked, and a marker-based selection
would run a subset while looking like it ran everything.
