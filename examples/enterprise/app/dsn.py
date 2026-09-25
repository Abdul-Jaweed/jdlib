"""One DSN from the operator, two drivers underneath.

The minimal example carries its own copy of this helper on purpose: an example is something a
reader copies whole, so each one stands alone rather than importing from its neighbour.

PostgreSQL is reached twice in this application: synchronously by the migration runner (Alembic),
and asynchronously by everything that serves requests. The library normalises the **sync** side to
`psycopg` on its own (`jdlib/migrations/runner.py`); the **async** side is normalised here, to
`asyncpg`, because psycopg's async mode refuses Windows' default `ProactorEventLoop` -- a single
`postgresql+psycopg://` DSN handed to `create_async_engine` therefore works on Linux and fails on
Windows.
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


def sync_dsn(database_url: str) -> str:
    """The same database over the synchronous driver DDL uses.

    The library normalises this itself for the migration runner; this module needs a synchronous
    engine of its own for the statements the library deliberately does not own — the privilege
    grants, which a deployment's own role performs.
    """
    url = sa.engine.make_url(database_url)
    if url.drivername.split("+")[0] in _POSTGRES:
        url = url.set(drivername="postgresql+psycopg")
    return url.render_as_string(hide_password=False)


def control_dsn(config: TenancyConfig) -> str:
    """The control plane's DSN, with a missing one refused rather than dereferenced."""
    dsn = config.control_dsn
    if dsn is None:
        raise RuntimeError(
            "JDLIB_CONTROL_DSN is required: the example ships no default, because a default is "
            "a database the operator did not choose."
        )
    return dsn.get_secret_value()
