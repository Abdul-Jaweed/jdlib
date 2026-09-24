from __future__ import annotations

import re
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from jdlib.control.base import CONTROL_SCHEMA
from jdlib.errors import ProvisioningError

_TENANT_SCHEMA_RE = re.compile(r"t_[a-z0-9][a-z0-9_]{0,50}")
DEPLOYMENT_SCHEMA_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")


_POSTGRES_DRIVERS = {
    "postgresql",
    "postgresql+asyncpg",
    "postgresql+psycopg2",
}


def _sync_url(database_url: str) -> str:
    url = sa.engine.make_url(database_url)
    if url.drivername in _POSTGRES_DRIVERS:
        url = url.set(drivername="postgresql+psycopg")
    return url.render_as_string(hide_password=False)


class MigrationRunner:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def _config(
        self,
        plane: str,
        *,
        tenant_schema: str | None = None,
        database_url: str | None = None,
    ) -> Config:
        config = Config()
        config.set_main_option(
            "script_location",
            str(Path(__file__).parent / plane),
        )
        config.set_main_option(
            "sqlalchemy.url",
            _sync_url(database_url or self._database_url).replace("%", "%%"),
        )
        config.attributes["tenant_schema"] = tenant_schema
        return config

    @staticmethod
    def _validate_tenant_schema(schema: str) -> None:
        if _TENANT_SCHEMA_RE.fullmatch(schema) is None:
            raise ProvisioningError(f"invalid tenant schema name: {schema!r}")

    @staticmethod
    def _validate_deployment_schema(schema: str) -> None:
        if DEPLOYMENT_SCHEMA_RE.fullmatch(schema) is None:
            raise ProvisioningError(f"invalid schema name: {schema!r}")

    def upgrade_control(self, revision: str = "head") -> None:
        engine = sa.create_engine(_sync_url(self._database_url), future=True)
        with engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(CONTROL_SCHEMA, if_not_exists=True))
        engine.dispose()
        command.upgrade(self._config("control"), revision)

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        self._validate_deployment_schema(schema)
        config = self._config("tenant", tenant_schema=schema)
        command.upgrade(config, revision)

    def upgrade_tenant_url(
        self, database_url: str, schema: str, revision: str = "head"
    ) -> None:
        self._validate_deployment_schema(schema)
        config = self._config("tenant", tenant_schema=schema, database_url=database_url)
        command.upgrade(config, revision)

    def provision_tenant_schema(self, schema: str, revision: str = "head") -> None:
        self._validate_tenant_schema(schema)
        engine = sa.create_engine(_sync_url(self._database_url), future=True)
        with engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(schema, if_not_exists=True))
        engine.dispose()
        self.upgrade_tenant(schema, revision)

    def tenant_version(self, schema: str) -> str | None:
        self._validate_deployment_schema(schema)
        engine = sa.create_engine(_sync_url(self._database_url), future=True)
        try:
            return self._read_version(engine, schema)
        finally:
            engine.dispose()

    def tenant_version_url(self, database_url: str, schema: str) -> str | None:
        self._validate_deployment_schema(schema)
        engine = sa.create_engine(_sync_url(database_url), future=True)
        try:
            return self._read_version(engine, schema)
        finally:
            engine.dispose()

    @staticmethod
    def _read_version(engine: sa.Engine, schema: str) -> str | None:
        with engine.begin() as connection:
            present = connection.execute(
                sa.text("SELECT to_regclass(:quoted)").bindparams(
                    quoted=f"{schema}.alembic_version"
                )
            ).scalar_one_or_none()
            if present is None:
                return None
            # Reviewed exception (docs/security/ci-security.md, SAST gate): `schema` is
            # validated against a strict allowlist regex by _validate_tenant_schema /
            # _validate_deployment_schema before any caller reaches this method, so the
            # interpolated identifier cannot carry SQL injection payloads.
            query = f'SELECT version_num FROM "{schema}".alembic_version LIMIT 1'  # nosec B608
            return connection.execute(sa.text(query)).scalar_one_or_none()
