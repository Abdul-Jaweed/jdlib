"""The lab's environment: where it is, and what a test skips without.

Read once at import, deliberately. A test that re-read the environment at call time would answer a
different question depending on what ran before it, and the skip reasons below are the ones a reader
needs when a suite reports 0 tests collected rather than a failure.
"""

from __future__ import annotations

import os

import pytest

#: The runtime role's DSN: what a *serving* process connects with, and the role the policies
#: constrain. `jdlib_app`, per `docker/initdb/`.
RUNTIME_DSN = os.environ.get("JDLIB_EXAMPLE_LIVE_DSN", "")

#: The owner's DSN: migrations, tenant provisioning, and the RLS installation.
MIGRATION_DSN = os.environ.get("JDLIB_EXAMPLE_LIVE_MIGRATION_DSN", "")

#: The policy engine's HTTP endpoint.
CERBOS_ENDPOINT = os.environ.get("JDLIB_EXAMPLE_CERBOS_ENDPOINT", "")

#: The graph's bolt URI, when this deployment has one.
GRAPH_URI = os.environ.get("JDLIB_EXAMPLE_GRAPH_URI", "")

_HOW = (
    "docker compose -f examples/enterprise/docker/docker-compose.yml up -d, then export "
    "JDLIB_EXAMPLE_LIVE_DSN=postgresql://jdlib_app:<app-password>@127.0.0.1:45432/"
    "jdlib_enterprise, JDLIB_EXAMPLE_LIVE_MIGRATION_DSN=postgresql://jdlib:<password>"
    "@127.0.0.1:45432/jdlib_enterprise and JDLIB_EXAMPLE_CERBOS_ENDPOINT=http://127.0.0.1:4592 "
    "-- see examples/enterprise/README.md for the operator steps that come first"
)

#: The database is up (two DSNs), and nothing else is assumed.
requires_database: pytest.MarkDecorator = pytest.mark.skipif(
    not (RUNTIME_DSN and MIGRATION_DSN),
    reason=f"the database lab is not running: {_HOW}",
)

#: The database and the policy engine are up: the whole authorization chain is answerable.
requires_cerbos: pytest.MarkDecorator = pytest.mark.skipif(
    not (RUNTIME_DSN and MIGRATION_DSN and CERBOS_ENDPOINT),
    reason=f"the lab is not running: {_HOW}",
)

#: The graph lab is configured.
requires_graph: pytest.MarkDecorator = pytest.mark.skipif(
    not GRAPH_URI,
    reason="no graph configured: export JDLIB_EXAMPLE_GRAPH_URI=bolt://127.0.0.1:7688",
)
