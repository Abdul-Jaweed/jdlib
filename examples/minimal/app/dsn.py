"""One DSN from the operator, two drivers underneath.

PostgreSQL is reached twice in this application: synchronously by the migration runner (Alembic),
and asynchronously by everything that serves requests. The library normalises the **sync** side to
`psycopg` on its own (`jdlib/migrations/runner.py`); the **async** side is normalised here, to
`asyncpg`, because psycopg's async mode refuses Windows' default `ProactorEventLoop` -- a single
`postgresql+psycopg://` DSN handed to `create_async_engine` therefore works on Linux and fails on
Windows, which is the kind of difference that reaches production as a platform-specific outage.

So the operator writes one DSN in any common spelling (`postgres://`, `postgresql://`,
`postgresql+psycopg://`, `postgresql+asyncpg://`) and this module decides the driver per role.
"""

from __future__ import annotations

import sqlalchemy as sa

from jdlib import TenancyConfig

_POSTGRES = {"postgres", "postgresql"}


def async_dsn(database_url: str) -> str:
    """The same database over the async driver this application serves requests with."""
    url = sa.engine.make_url(database_url)
    if url.drivername.split("+")[0] in _POSTGRES:
        url = url.set(drivername="postgresql+asyncpg")
    return url.render_as_string(hide_password=False)


def control_dsn(config: TenancyConfig) -> str:
    """The control plane's DSN, with a missing one refused rather than dereferenced.

    The example ships no default DSN on purpose: a default is a database the operator did not
    choose, and it fails as a connection error at the first request instead of at startup.
    """
    dsn = config.control_dsn
    if dsn is None:
        raise RuntimeError(
            "JDLIB_CONTROL_DSN is required: the example ships no default, because a default is "
            "a database the operator did not choose."
        )
    return dsn.get_secret_value()
