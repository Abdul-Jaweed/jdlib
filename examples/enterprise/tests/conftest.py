"""The environment this slice's tests need, and the lab fixture the live layers share.

The environment fixture's values are placeholders and the signing key is generated per run: a
credential-shaped literal in a test file is a finding in every secret scan for the rest of the
repository's history, and there is no reason to plant one.

The `chain` fixture is the lab itself -- two tenants, a caller each, and the environment the
application reads -- and it lives here rather than in a module because three layers request it. A
fixture defined in one test module and imported by another is a fixture whose *name* collides with
the parameter that requests it, which is what the linter said when it was written that way.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator

import pytest

from examples.enterprise.tests.support.environment import GRAPH_URI, RUNTIME_DSN
from examples.enterprise.tests.support.lab import Chain, provision_chain


@pytest.fixture
def enterprise_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A complete, never-connected environment: URLs are parsed, never dialled.

    The owner's DSN is *removed*, not merely absent: the tests below are about a process that serves
    requests without it, and a shell that exported it — which is exactly what the README tells an
    operator to do before running the live suite — would otherwise decide whether they pass. A test
    whose premise the environment can supply is not measuring the code.
    """
    monkeypatch.delenv("JDLIB_EXAMPLE_MIGRATION_DSN", raising=False)
    monkeypatch.setenv("JDLIB_CONTROL_DSN", "postgresql+psycopg://example@127.0.0.1:5432/example")
    monkeypatch.setenv("JDLIB_CONTEXT__SIGNING_KEY", secrets.token_hex(32))
    monkeypatch.setenv("JDLIB_OIDC__ISSUER", "https://issuer.invalid/")
    monkeypatch.setenv("JDLIB_OIDC__AUDIENCE", "enterprise-example")
    monkeypatch.setenv("JDLIB_EXAMPLE_CERBOS_ENDPOINT", "http://127.0.0.1:3592")
    yield


@pytest.fixture(scope="module")
def chain() -> Iterator[Chain]:
    """The lab: two tenants, a caller each, and the environment the application reads.

    The environment variables are set here and restored afterwards, because `build_collaborators`
    reads them exactly as a deployment does -- pointing it at the lab is the test's job, and leaving
    them set would change what every later test in the process measures.
    """
    previous = {
        key: os.environ.get(key)
        for key in ("JDLIB_CONTROL_DSN", "JDLIB_EXAMPLE_GRAPH_URI", "JDLIB_CONTEXT__SIGNING_KEY")
    }
    os.environ["JDLIB_CONTROL_DSN"] = RUNTIME_DSN
    os.environ.setdefault("JDLIB_CONTEXT__SIGNING_KEY", secrets.token_hex(32))
    if GRAPH_URI:
        os.environ["JDLIB_EXAMPLE_GRAPH_URI"] = GRAPH_URI
    try:
        yield provision_chain()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
