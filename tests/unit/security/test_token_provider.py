"""Phase 2: outbound service-credential provider (spec #7, #59, #76, #78).

Directive requirements: client_credentials, private_key_jwt, caching, expiry,
reacquisition, invalidate(), single-flight, concurrency protection, timeouts,
retry policy, and no credential leakage anywhere.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from jdlib.security.authn.provider import (
    ClientAuthMethod,
    ClientCredentialsConfig,
    ClientCredentialsTokenProvider,
    TokenAcquisitionError,
    TokenEndpointUnavailable,
)
from jdlib.security.errors import SecurityConfigurationError
from jdlib.security.interfaces import TokenProvider

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
TOKEN_ENDPOINT = "https://id.example.com/oauth/v2/token"
CLIENT_SECRET = "client-secret-value-that-must-never-leak"
ACCESS_TOKEN = "access-token-value-that-must-never-leak"


class Clock:
    def __init__(self) -> None:
        self._now = NOW

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


class Endpoint:
    """Fake token endpoint: counts calls, records forms/headers, scriptable failures."""

    def __init__(self, expires_in: int = 300) -> None:
        self.calls = 0
        self.forms: list[dict[str, str]] = []
        self.headers: list[dict[str, str]] = []
        self.expires_in = expires_in
        self.error: Exception | None = None
        self.fail_times = 0
        self.hang = False

    async def __call__(
        self, form: Mapping[str, str], headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        self.calls += 1
        self.forms.append(dict(form))
        self.headers.append(dict(headers))
        if self.hang:
            await asyncio.Event().wait()
        if self.fail_times > 0:
            self.fail_times -= 1
            raise self.error or TokenEndpointUnavailable("503")
        if self.error is not None:
            raise self.error
        return {
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
        }


class Sleeps:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _config(**overrides: object) -> ClientCredentialsConfig:
    values: dict[str, object] = {
        "token_endpoint": TOKEN_ENDPOINT,
        "client_id": "jdlib-service",
        "client_secret": SecretStr(CLIENT_SECRET),
        "scopes": ("documents:read",),
        "audience": "jdlib-api",
    }
    values.update(overrides)
    return ClientCredentialsConfig(**values)  # type: ignore[arg-type]


def _provider(
    endpoint: Endpoint, *, clock: Clock | None = None, **overrides: object
) -> ClientCredentialsTokenProvider:
    return ClientCredentialsTokenProvider(
        config=_config(**overrides),
        fetch=endpoint,
        clock=clock or Clock(),
        sleeper=Sleeps(),
    )


# --- Caching and concurrency -------------------------------------------------


def test_cached_token_avoids_network_calls() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        provider = _provider(endpoint)
        first = await provider.token(audience="jdlib-api")
        second = await provider.token(audience="jdlib-api")
        assert first.value.get_secret_value() == second.value.get_secret_value()
        return endpoint.calls

    assert asyncio.run(scenario()) == 1


def test_one_hundred_concurrent_requests_acquire_once() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        provider = _provider(endpoint)
        results = await asyncio.gather(
            *[provider.token(audience="jdlib-api") for _ in range(100)]
        )
        assert len(results) == 100
        return endpoint.calls

    assert asyncio.run(scenario()) == 1


def test_expired_token_is_reacquired() -> None:
    async def scenario() -> int:
        clock = Clock()
        endpoint = Endpoint(expires_in=300)
        provider = _provider(endpoint, clock=clock, expiry_skew=timedelta(seconds=30))
        await provider.token(audience="jdlib-api")
        clock.advance(timedelta(seconds=280))  # inside skew -> still cached
        await provider.token(audience="jdlib-api")
        clock.advance(timedelta(seconds=60))  # past expiry+skew -> reacquire
        await provider.token(audience="jdlib-api")
        return endpoint.calls

    assert asyncio.run(scenario()) == 2


def test_invalidate_forces_reacquisition() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        provider = _provider(endpoint)
        await provider.token(audience="jdlib-api")
        await provider.invalidate()
        await provider.token(audience="jdlib-api")
        return endpoint.calls

    assert asyncio.run(scenario()) == 2


def test_cache_is_bounded() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        provider = _provider(endpoint, max_cache_entries=3)
        for index in range(10):
            await provider.token(audience=f"audience-{index}")
        return provider.cache_size()

    assert asyncio.run(scenario()) == 3


# --- Failure handling --------------------------------------------------------


def test_transient_failures_are_retried_with_bounded_jittered_backoff() -> None:
    async def scenario() -> tuple[int, list[float]]:
        endpoint = Endpoint()
        endpoint.fail_times = 2  # two transient 503s, then success
        sleeps = Sleeps()
        provider = ClientCredentialsTokenProvider(
            config=_config(retry_backoff=timedelta(milliseconds=100)),
            fetch=endpoint,
            clock=Clock(),
            sleeper=sleeps,
        )
        token = await provider.token(audience="jdlib-api")
        assert token.value.get_secret_value() == ACCESS_TOKEN
        return endpoint.calls, sleeps.delays

    calls, delays = asyncio.run(scenario())
    assert calls == 3
    assert len(delays) == 2
    # full jitter under an exponential ceiling: attempt 1 <= 100ms, attempt 2 <= 200ms
    ceilings = (0.1, 0.2)
    assert all(
        0.0 <= delay <= ceiling
        for delay, ceiling in zip(delays, ceilings, strict=True)
    )


def test_permanent_failure_is_not_retried() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        endpoint.error = TokenAcquisitionError("invalid_client")
        provider = _provider(endpoint)
        with pytest.raises(TokenAcquisitionError):
            await provider.token(audience="jdlib-api")
        return endpoint.calls

    assert asyncio.run(scenario()) == 1


def test_unavailable_endpoint_fails_closed_after_retries() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        endpoint.error = TokenEndpointUnavailable("connection refused")
        provider = _provider(endpoint, max_attempts=3)
        with pytest.raises(TokenEndpointUnavailable):
            await provider.token(audience="jdlib-api")
        return endpoint.calls

    assert asyncio.run(scenario()) == 3


def test_endpoint_timeout_does_not_hang() -> None:
    async def scenario() -> object:
        endpoint = Endpoint()
        endpoint.hang = True
        provider = _provider(endpoint, timeout=timedelta(milliseconds=50), max_attempts=1)
        try:
            await asyncio.wait_for(provider.token(audience="jdlib-api"), timeout=1.0)
        except BaseException as exc:  # noqa: BLE001 - asserting the cause
            return exc
        return None

    assert isinstance(asyncio.run(scenario()), TokenEndpointUnavailable)


def test_failed_acquisition_is_not_cached() -> None:
    async def scenario() -> int:
        endpoint = Endpoint()
        endpoint.error = TokenEndpointUnavailable("503")
        provider = _provider(endpoint, max_attempts=1)
        with pytest.raises(TokenEndpointUnavailable):
            await provider.token(audience="jdlib-api")
        endpoint.error = None
        await provider.token(audience="jdlib-api")
        return endpoint.calls

    assert asyncio.run(scenario()) == 2


# --- Client authentication methods ------------------------------------------


def test_client_secret_post_is_sent_in_the_body() -> None:
    async def scenario() -> dict[str, str]:
        endpoint = Endpoint()
        provider = _provider(endpoint, auth_method=ClientAuthMethod.CLIENT_SECRET_POST)
        await provider.token(audience="jdlib-api")
        return endpoint.forms[0]

    form = asyncio.run(scenario())
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == "jdlib-service"
    assert form["client_secret"] == CLIENT_SECRET
    assert form["audience"] == "jdlib-api"
    assert form["scope"] == "documents:read"


def test_client_secret_basic_uses_the_authorization_header() -> None:
    async def scenario() -> tuple[dict[str, str], dict[str, str]]:
        endpoint = Endpoint()
        provider = _provider(endpoint, auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC)
        await provider.token(audience="jdlib-api")
        return endpoint.forms[0], endpoint.headers[0]

    form, headers = asyncio.run(scenario())
    assert form["client_id"] == "jdlib-service"
    assert "client_secret" not in form
    expected = base64.b64encode(f"jdlib-service:{CLIENT_SECRET}".encode()).decode()
    assert headers["authorization"] == f"Basic {expected}"


def test_private_key_jwt_assertion_is_signed_and_time_bounded() -> None:
    async def scenario() -> tuple[dict[str, str], object]:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        endpoint = Endpoint()
        provider = _provider(
            endpoint,
            auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
            client_secret=None,
            private_key=SecretStr(pem),
            assertion_algorithm="RS256",
        )
        await provider.token(audience="jdlib-api")
        return endpoint.forms[0], private.public_key()

    form, public_key = asyncio.run(scenario())
    assert "client_secret" not in form
    assert form["client_assertion_type"] == (
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    claims = pyjwt.decode(
        form["client_assertion"],
        public_key,
        algorithms=["RS256"],
        audience=TOKEN_ENDPOINT,
        issuer="jdlib-service",
        options={"verify_exp": False},  # fake clock: expiry is asserted below
    )
    assert claims["sub"] == "jdlib-service"
    assert claims["exp"] > claims["iat"]
    assert claims["exp"] - claims["iat"] == 60
    assert claims["jti"]


# --- Configuration and leakage ----------------------------------------------


def test_configuration_requires_exactly_one_credential() -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(client_secret=None)
    with pytest.raises(SecurityConfigurationError):
        _config(
            auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
            private_key=None,
        )
    with pytest.raises(SecurityConfigurationError):
        _config(
            auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
            private_key=SecretStr("key"),
            client_secret=SecretStr("both"),
        )


@pytest.mark.parametrize("endpoint", ["http://id.example.com/token", "ftp://x/token", "not-a-url"])
def test_insecure_token_endpoints_are_rejected(endpoint: str) -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(token_endpoint=endpoint)


@pytest.mark.parametrize(
    "endpoint", ["http://localhost:8080/oauth/v2/token", "http://127.0.0.1:8080/oauth/v2/token"]
)
def test_local_endpoints_are_allowed_for_development(endpoint: str) -> None:
    assert _config(token_endpoint=endpoint).token_endpoint == endpoint


def test_timeout_must_be_positive() -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(timeout=timedelta(0))


def test_secrets_never_appear_in_repr_or_errors() -> None:
    endpoint = Endpoint()
    endpoint.error = TokenAcquisitionError("invalid_client")
    provider = _provider(endpoint)

    async def scenario() -> str:
        rendered = [repr(provider), repr(provider._config)]  # noqa: SLF001 - leakage probe
        try:
            await provider.token(audience="jdlib-api")
        except TokenAcquisitionError as exc:
            rendered.append(f"{exc!r} {exc}")
        return json.dumps(rendered)

    rendered = asyncio.run(scenario())
    assert CLIENT_SECRET not in rendered
    assert ACCESS_TOKEN not in rendered


def test_provider_implements_the_core_port() -> None:
    assert isinstance(_provider(Endpoint()), TokenProvider)


def test_token_response_without_expiry_is_rejected() -> None:
    async def scenario() -> BaseException | None:
        class NoExpiry(Endpoint):
            async def __call__(
                self, form: Mapping[str, str], headers: Mapping[str, str]
            ) -> Mapping[str, object]:
                await super().__call__(form, headers)
                return {"access_token": ACCESS_TOKEN, "token_type": "Bearer"}

        provider = _provider(NoExpiry(), max_attempts=1)
        try:
            await provider.token(audience="jdlib-api")
        except BaseException as exc:  # noqa: BLE001 - asserting the cause
            return exc
        return None

    assert isinstance(asyncio.run(scenario()), TokenAcquisitionError)
