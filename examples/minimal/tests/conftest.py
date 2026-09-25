"""The environment the minimal example needs, and nothing else.

The example reads no configuration of its own -- everything comes from the library's `JDLIB_*`
contract -- so these tests set exactly those variables. The signing key is generated per run rather
than written here: a credential-shaped literal in a test file is a finding in every secret scan for
the rest of the repository's history, and there is no reason to plant one.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator

import pytest


@pytest.fixture
def jdlib_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A complete, never-connected environment: the URL is only parsed, never dialled."""
    monkeypatch.setenv("JDLIB_CONTROL_DSN", "postgresql+psycopg://example@127.0.0.1:5432/example")
    monkeypatch.setenv("JDLIB_CONTEXT__SIGNING_KEY", secrets.token_hex(32))
    monkeypatch.setenv("JDLIB_OIDC__ISSUER", "https://issuer.invalid/")
    monkeypatch.setenv("JDLIB_OIDC__AUDIENCE", "minimal-example")
    yield


@pytest.fixture(scope="module")
def postgres_url() -> Iterator[str]:
    """A real PostgreSQL, from the lab when one is offered, otherwise a throwaway container.

    Module-scoped: the example's live tests share one database, and each seeds its own tenant, so
    they assert supersets filtered by their own slug rather than an exact global count.
    """
    if url := os.environ.get("JDLIB_EXAMPLE_DATABASE_URL"):
        yield url
        return
    try:
        from testcontainers.community.postgres import PostgresContainer
    except ImportError:  # pragma: no cover - the dev extra provides it
        pytest.skip("testcontainers is not installed")
    try:
        with PostgresContainer("postgres:16", driver="psycopg") as container:
            yield container.get_connection_url()
    except Exception as exc:  # pragma: no cover - Docker absent
        pytest.skip(f"Docker is unavailable: {type(exc).__name__}")


@pytest.fixture
def example_database(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Point the example at a real database through the library's own env contract."""
    monkeypatch.setenv("JDLIB_CONTROL_DSN", postgres_url)
    monkeypatch.setenv("JDLIB_CONTEXT__SIGNING_KEY", secrets.token_hex(32))
    monkeypatch.setenv("JDLIB_OIDC__ISSUER", "https://issuer.invalid/")
    monkeypatch.setenv("JDLIB_OIDC__AUDIENCE", "minimal-example")
    yield postgres_url

