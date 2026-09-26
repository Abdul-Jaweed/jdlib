# The minimal example

The smallest application that is *correct*: FastAPI → JDLib → PostgreSQL, one tenant-scoped route,
one denial answered, and a probe that does not need a token.

## Run it

```bash
# 1. the database
docker run -d --name jdlib-minimal -p 5433:5432 \
  -e POSTGRES_PASSWORD=... -e POSTGRES_DB=jdlib_minimal postgres:16

# 2. the environment (see examples/minimal/README.md for the exact variables)
export JDLIB_CONTROL_DSN=postgresql://...

# 3. the operator step, then the app
python -m examples.minimal.app.bootstrap
uvicorn examples.minimal.app.asgi:app --host 127.0.0.1 --port 8001
```

## What it contains

```
examples/minimal/
├── app.py           the application: install(...), one guarded route, one unguarded probe
├── asgi.py          uvicorn examples.minimal.app.asgi:app
├── bootstrap.py     the operator step (the tenant, its tables, its record)
├── settings.py      the environment, validated at startup
└── tests/
    ├── test_app.py          the shape: the mount, the routes, the guard's declaration
    ├── test_denial_live.py  the denial over a real chain, with an allowing control
    └── test_bootstrap_live.py the operator step against a real database
```

## What it demonstrates, and what it deliberately leaves out

It demonstrates the parts an application cannot get wrong: the install (middleware, guard, error
envelope), one route whose permission is declared rather than checked inside the handler, a
denial answered in the canonical envelope, and a probe that answers without credentials.

It leaves out everything an application can add later: a policy engine (the example's enforcer is a
small in-process double, and the tests say so), a second tenant, a graph, MCP, and background jobs.
Adding those is what the enterprise example is for.

## What writing it found

Two library defects, both fixed in the library rather than worked around here: a `ConnectionError`
from the async driver was surfacing as a 500 instead of a 503, and the guard's `jdlib_permission`
declaration was not readable by the route walk the tests use. Both were found because the example
was *run* rather than described — which is the whole argument for having examples at all.
