from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from jdlib.models import audit, org, settings  # noqa: F401
from jdlib.models.base import TenantBase

config = context.config
target_metadata = TenantBase.metadata
tenant_schema = config.attributes.get("tenant_schema")


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        version_table_schema=tenant_schema,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        if tenant_schema:
            quoted = connection.dialect.identifier_preparer.quote(tenant_schema)
            connection.exec_driver_sql(f"SET search_path TO {quoted}")
            connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=tenant_schema,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
