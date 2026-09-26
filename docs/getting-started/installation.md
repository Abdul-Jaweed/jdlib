# Installation

## Requirements

| | |
|---|---|
| Python | **3.12 or newer** (the library uses PEP 695 generics and `StrEnum`) |
| PostgreSQL | **15 or newer** for the control plane; the isolation strategies assume row-level security |
| Neo4j | 5.x, only if you use the graph plane |
| Cerbos | only if you use the reference policy engine — the PEP takes any decision point |

## Install

```bash
pip install jdlib                 # the core: config, tenancy, persistence, security, audit
pip install "jdlib[fastapi]"      # the FastAPI integration: install(), require(), get_context()
pip install "jdlib[cli]"          # the jdlib console script (Typer)
pip install "jdlib[graph]"        # the Neo4j client and repository
pip install "jdlib[mcp]"          # the MCP surface (FastMCP)
pip install "jdlib[redis]"        # the Redis cache provider
pip install "jdlib[s3]"           # the S3 object-storage backend
pip install -e ".[dev]"           # from a checkout, with tests, lint and types
```

The extras are deliberately separate: a deployment that serves HTTP should not install a graph
driver it never opens, and the library imports each optional dependency lazily so a missing extra is
a refusal with a name rather than an `ImportError` at startup.

## Verify the install

```bash
python -c "import jdlib; print(jdlib.__version__)"        # the version
python -c "import jdlib; print(len(jdlib.__all__))"       # the public surface resolves
jdlib --help                                              # the console script, with the cli extra
```

## From a checkout

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev,s3,redis,graph,mcp]"   # Windows
# .venv/bin/python -m pip install -e ".[dev,s3,redis,graph,mcp]"          # POSIX

bash scripts/ci-local.sh        # the whole gate: ruff, mypy, the docs build, pytest, packaging
bash scripts/ci-local.sh --fast # the same without the packaging steps
```

The gate is the same one CI runs, and the documentation build is part of it — a page that breaks the
site breaks the build. [Development → testing](../development/documentation.md) explains what each
step checks.

## What to configure next

Nothing in the library reads a file: configuration comes from the environment through
`TenancyConfig`, and it fails fast when a required value is missing. [Configuration](configuration.md)
is the reference, and the [quickstart](quickstart.md) is the shortest path to a running application.
