from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from jdlib.control.base import CONTROL_SCHEMA


class MigrationRunner:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def _config(self, plane: str, **attributes: object) -> Config:
        config = Config()
        config.set_main_option(
            "script_location",
            str(Path(__file__).parent / plane),
        )
        config.set_main_option("sqlalchemy.url", self._database_url)
        config.attributes["tenant_schema"] = attributes.get("tenant_schema")
        return config

    def upgrade_control(self, revision: str = "head") -> None:
        import sqlalchemy as sa

        engine = sa.create_engine(self._database_url, future=True)
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f'CREATE SCHEMA IF NOT EXISTS "{CONTROL_SCHEMA}"'
            )
        engine.dispose()
        command.upgrade(self._config("control"), revision)

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        config = self._config("tenant", tenant_schema=schema)
        command.upgrade(config, revision)

    def provision_tenant_schema(self, schema: str, revision: str = "head") -> None:
        import sqlalchemy as sa

        engine = sa.create_engine(self._database_url, future=True)
        with engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        engine.dispose()
        self.upgrade_tenant(schema, revision)
