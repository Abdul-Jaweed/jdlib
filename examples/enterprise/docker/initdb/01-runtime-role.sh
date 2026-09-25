#!/bin/bash
# Create the runtime role: no superuser, no BYPASSRLS, no DDL.
#
# This is the role the application connects as, and the reason it is a *separate* role is that
# row-level security does not constrain a superuser: the lab's own POSTGRES_USER is one, so a
# single-role lab would install policies that apply to nobody. The library refuses to install them
# for such a role (`StrategyCapabilityError: RLS app role ... can bypass row level security`), which
# is how this was found.
#
# The password comes from the environment, never from this file.
set -euo pipefail

if [ -z "${JDLIB_ENTERPRISE_APP_PASSWORD:-}" ]; then
    echo "JDLIB_ENTERPRISE_APP_PASSWORD is required to create the runtime role" >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    CREATE ROLE jdlib_app LOGIN PASSWORD '${JDLIB_ENTERPRISE_APP_PASSWORD}'
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO jdlib_app;
SQL
