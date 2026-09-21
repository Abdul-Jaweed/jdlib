from __future__ import annotations

import re
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from jdlib.control.base import CONTROL_SCHEMA
from jdlib.errors import ProvisioningError

_TENANT_SCHEMA_RE = re.compile(r"t_[a-z0-9][a-z0-9_]{0,50}")


class MigrationRunner:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def _config(self, plane: str, *, tenant_schema: str | None = None) -> Config:
        config = Config()
        config.set_main_option(
            "script_location",
            str(Path(__file__).parent / plane),
        )
        config.set_main_option("sqlalchemy.url", self._database_url)
        config.attributes["tenant_schema"] = tenant_schema
        return config

    @staticmethod
    def _validate_schema(schema: str) -> None:
        if _TENANT_SCHEMA_RE.fullmatch(schema) is None:
            raise ProvisioningError(f"invalid tenant schema name: {schema!r}")

    def upgrade_control(self, revision: str = "head") -> None:
        engine = sa.create_engine(self._database_url, future=True)
        with engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(CONTROL_SCHEMA, if_not_exists=True))
        engine.dispose()
        command.upgrade(self._config("control"), revision)

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        self._validate_schema(schema)
        config = self._config("tenant", tenant_schema=schema)
        command.upgrade(config, revision)

    def provision_tenant_schema(self, schema: str, revision: str = "head") -> None:
        self._validate_schema(schema)
        engine = sa.create_engine(self._database_url, future=True)
        with engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(schema, if_not_exists=True))
        engine.dispose()
        self.upgrade_tenant(schema, revision)
