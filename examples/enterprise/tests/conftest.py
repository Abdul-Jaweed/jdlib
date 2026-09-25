"""The environment this slice's tests need, and nothing more.

The values are placeholders and the signing key is generated per run: a credential-shaped literal
in a test file is a finding in every secret scan for the rest of the repository's history, and
there is no reason to plant one.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest


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
