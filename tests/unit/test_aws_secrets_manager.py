"""Secrets Manager provider tests (AWS directive §11, §38).

The client is injected, so these run without AWS and without boto3. What they assert is the part
that matters in production: a cached value expires, a rotated secret is picked up, a failure never
returns a value, and nothing that could be a secret appears in a repr or an exception message.
"""

from datetime import timedelta
from typing import Any

import pytest

from jdlib.persistence.secrets import EnvSecretProvider, MemorySecretProvider
from jdlib.persistence.secrets_manager import (
    SecretsManagerConfig,
    SecretsManagerSecretProvider,
)
from jdlib.security.errors import SecurityConfigurationError
from tests.support.context_fakes import FrozenClock

HANDLE = "jdlib/tenant-a/db"


class _Client:
    """A duck-typed Secrets Manager client that records calls."""

    def __init__(self, responses: dict[str, dict[str, object]] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[str] = []
        self.raises: BaseException | None = None

    def get_secret_value(self, **kwargs: object) -> dict[str, object]:
        secret_id = str(kwargs["SecretId"])
        self.calls.append(secret_id)
        if self.raises is not None:
            raise self.raises
        if secret_id not in self.responses:
            raise RuntimeError(f"ResourceNotFoundException: {secret_id}")
        return self.responses[secret_id]


def _provider(
    client: _Client, **overrides: Any
) -> tuple[SecretsManagerSecretProvider, FrozenClock]:
    clock = FrozenClock()
    config = SecretsManagerConfig(**overrides) if overrides else SecretsManagerConfig()
    return SecretsManagerSecretProvider(client=client, config=config, clock=clock), clock


def test_it_resolves_through_the_same_protocol_as_the_other_providers() -> None:
    client = _Client({HANDLE: {"SecretString": "s3cret"}})
    provider, _ = _provider(client)
    for other in (MemorySecretProvider({HANDLE: "x"}), EnvSecretProvider()):
        assert hasattr(other, "resolve")
    assert provider.resolve(HANDLE) == "s3cret"
    assert client.calls == [HANDLE]


def test_the_handle_is_the_secret_id_and_the_prefix_namespaces_it() -> None:
    client = _Client({"jdlib/prod/jdlib/tenant-a/db": {"SecretString": "v"}})
    provider, _ = _provider(client, prefix="jdlib/prod/")
    assert provider.resolve(HANDLE) == "v"
    assert client.calls == ["jdlib/prod/" + HANDLE]


def test_a_value_is_cached_and_a_second_resolution_does_not_call_aws() -> None:
    client = _Client({HANDLE: {"SecretString": "v"}})
    provider, _ = _provider(client)
    assert provider.resolve(HANDLE) == "v"
    assert provider.resolve(HANDLE) == "v"
    assert len(client.calls) == 1


def test_a_cached_value_expires_so_a_rotated_secret_is_picked_up() -> None:
    client = _Client({HANDLE: {"SecretString": "old"}})
    provider, clock = _provider(client, cache_ttl=timedelta(seconds=30))
    assert provider.resolve(HANDLE) == "old"

    client.responses[HANDLE] = {"SecretString": "new"}
    clock.advance(timedelta(seconds=31))
    assert provider.resolve(HANDLE) == "new"
    assert len(client.calls) == 2


def test_invalidate_drops_one_handle_or_all_of_them() -> None:
    client = _Client({HANDLE: {"SecretString": "v"}, "other": {"SecretString": "w"}})
    provider, _ = _provider(client)
    provider.resolve(HANDLE)
    provider.resolve("other")
    provider.invalidate(HANDLE)
    provider.resolve(HANDLE)
    assert client.calls == [HANDLE, "other", HANDLE]
    provider.invalidate()
    assert provider.resolve("other") == "w"
    assert client.calls[-1] == "other"


def test_an_unresolvable_handle_raises_key_error_like_the_other_providers() -> None:
    client = _Client()
    provider, _ = _provider(client)
    with pytest.raises(KeyError) as caught:
        provider.resolve(HANDLE)
    assert HANDLE in str(caught.value)


def test_a_client_failure_keeps_the_error_class_and_drops_the_message() -> None:
    # An SDK error can echo the secret value back, so the message and cause chain are dropped; the
    # exception class survives because it is what tells an operator what to fix.
    client = _Client()
    client.raises = RuntimeError("AccessDeniedException: value=super-secret-material")
    provider, _ = _provider(client)
    with pytest.raises(KeyError) as caught:
        provider.resolve(HANDLE)
    assert "super-secret-material" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert "RuntimeError" in str(caught.value)


def test_a_binary_secret_is_an_unsupported_handle_not_a_guess() -> None:
    client = _Client({HANDLE: {"SecretBinary": b"bytes"}})
    provider, _ = _provider(client)
    with pytest.raises(KeyError, match="no string value"):
        provider.resolve(HANDLE)


def test_nothing_that_could_be_a_secret_appears_in_repr() -> None:
    client = _Client({HANDLE: {"SecretString": "super-secret-material"}})
    provider, _ = _provider(client)
    provider.resolve(HANDLE)
    assert "super-secret-material" not in repr(provider)
    assert "cached=1" in repr(provider)


@pytest.mark.parametrize(
    "overrides",
    [
        {"cache_ttl": timedelta(0)},
        {"cache_ttl": timedelta(seconds=-1)},
        {"endpoint_url": "http://localhost:4566"},
    ],
)
def test_configuration_that_cannot_be_safe_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(SecurityConfigurationError):
        SecretsManagerConfig(**overrides)


def test_an_empty_handle_is_refused_rather_than_sent_to_aws() -> None:
    client = _Client()
    provider, _ = _provider(client)
    with pytest.raises(SecurityConfigurationError):
        provider.resolve("")
    assert client.calls == []
