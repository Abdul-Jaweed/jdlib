"""Outbound service credentials: ``client_credentials`` and ``private_key_jwt``.

Spec #7 (inbound vs outbound authentication are separate responsibilities),
#59 (caches have TTL, bounds, invalidation and failure behaviour), #76 (retry
policy for network dependencies; never retry authentication failures), #78
(explicit timeouts).

Design
------
* The transport is injected: ``fetch(form, headers)`` performs the HTTP call.
  The provider owns everything security-relevant around it (claim building,
  caching, single-flight, retry policy, timeouts) and never performs I/O
  itself, which keeps it testable without network access.
* Acquisition is single-flight under one lock: 100 concurrent callers cause
  exactly one token request.
* Cached tokens are bounded (``max_cache_entries``, LRU eviction) and expire
  ``expiry_skew`` before their stated lifetime, so a token is never used while
  it could already be invalid.
* Failures are never cached, and transient failures (endpoint unreachable,
  timeout, 5xx/429) are retried with bounded, jittered backoff; permanent
  failures (invalid credentials, malformed response) fail immediately.
* Credentials never leave the provider except as an :class:`OutboundToken`
  whose value is a ``SecretStr``; ``repr`` of the provider and its config
  contain no secret material (regression-tested).
"""

from __future__ import annotations

import asyncio
import base64
import random
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

import jwt as pyjwt
from pydantic import BaseModel, ConfigDict, SecretStr, model_validator

from jdlib.context import Clock, SystemClock
from jdlib.errors import JdlibError
from jdlib.security.authn.algorithms import assert_safe_algorithms
from jdlib.security.errors import SecurityConfigurationError
from jdlib.security.interfaces import OutboundToken

_LOCAL_HOSTS = ("localhost", "127.0.0.1")


class ClientAuthMethod(StrEnum):
    """How the client authenticates at the token endpoint."""

    CLIENT_SECRET_POST = "client_secret_post"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    PRIVATE_KEY_JWT = "private_key_jwt"


class TokenAcquisitionError(JdlibError):
    """Token acquisition failed permanently (credentials, malformed response)."""


class TokenEndpointUnavailable(TokenAcquisitionError):
    """Token endpoint is temporarily unreachable or failing."""


TokenFetch = Callable[
    [Mapping[str, str], Mapping[str, str]], Awaitable[Mapping[str, object]]
]


class _TokenFetcher(Protocol):
    async def __call__(
        self, form: Mapping[str, str], headers: Mapping[str, str]
    ) -> Mapping[str, object]: ...


class ClientCredentialsConfig(BaseModel):
    """Configuration for outbound client-credentials authentication."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_endpoint: str
    client_id: str
    client_secret: SecretStr | None = None
    private_key: SecretStr | None = None
    assertion_algorithm: str = "RS256"
    assertion_ttl: timedelta = timedelta(seconds=60)
    auth_method: ClientAuthMethod = ClientAuthMethod.CLIENT_SECRET_POST
    scopes: tuple[str, ...] = ()
    audience: str | None = None
    timeout: timedelta = timedelta(seconds=5)
    expiry_skew: timedelta = timedelta(seconds=30)
    max_attempts: int = 3
    retry_backoff: timedelta = timedelta(milliseconds=200)
    max_cache_entries: int = 16

    @model_validator(mode="after")
    def _validate(self) -> ClientCredentialsConfig:
        if not self.token_endpoint.startswith("https://") and not self.token_endpoint.startswith(
            tuple(f"http://{host}" for host in _LOCAL_HOSTS)
        ):
            raise SecurityConfigurationError(
                "token endpoint must use https (http is allowed only for localhost)"
            )
        if not self.client_id:
            raise SecurityConfigurationError("client_id must not be empty")
        if self.timeout <= timedelta(0):
            raise SecurityConfigurationError("timeout must be positive")
        if self.assertion_ttl <= timedelta(0):
            raise SecurityConfigurationError("assertion_ttl must be positive")
        if self.max_attempts < 1:
            raise SecurityConfigurationError("max_attempts must be at least 1")
        if self.max_cache_entries < 1:
            raise SecurityConfigurationError("max_cache_entries must be at least 1")
        assert_safe_algorithms([self.assertion_algorithm])
        if self.auth_method is ClientAuthMethod.PRIVATE_KEY_JWT:
            if self.private_key is None:
                raise SecurityConfigurationError(
                    "private_key_jwt requires a private_key"
                )
            if self.client_secret is not None:
                raise SecurityConfigurationError(
                    "private_key_jwt must not also carry a client_secret"
                )
        elif self.client_secret is None:
            raise SecurityConfigurationError("client secret authentication requires a secret")
        return self

    def effective_scopes(self, scopes: Sequence[str]) -> tuple[str, ...]:
        return tuple(scopes) if scopes else self.scopes


@dataclass(frozen=True, slots=True)
class _CachedToken:
    token: OutboundToken


class ClientCredentialsTokenProvider:
    """Acquires and caches outbound service tokens (spec #7, #76)."""

    def __init__(
        self,
        *,
        config: ClientCredentialsConfig,
        fetch: TokenFetch,
        clock: Clock | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float, float], float] | None = None,
    ) -> None:
        self._config = config
        self._fetch = fetch
        self._clock = clock or SystemClock()
        self._sleep: Callable[[float], Awaitable[None]] = sleeper or asyncio.sleep
        self._jitter: Callable[[float, float], float] = jitter or random.uniform
        self._cache: OrderedDict[tuple[str, tuple[str, ...]], _CachedToken] = OrderedDict()
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        return (
            f"ClientCredentialsTokenProvider(client_id={self._config.client_id!r}, "
            f"endpoint={self._config.token_endpoint!r}, cached={len(self._cache)})"
        )

    # -- Public API ---------------------------------------------------------

    async def token(self, *, audience: str, scopes: Sequence[str] = ()) -> OutboundToken:
        """Return a valid service token, acquiring one only when necessary."""
        key = (audience, tuple(sorted(self._config.effective_scopes(scopes))))
        async with self._lock:
            cached = self._cache.get(key)
            if cached is not None and self._is_fresh(cached.token):
                self._cache.move_to_end(key)
                return cached.token
            resolved_scopes = self._config.effective_scopes(scopes)
            token = await self._acquire(audience=audience, scopes=resolved_scopes)
            self._store(key, token)
            return token

    async def invalidate(self) -> None:
        """Drop all cached credentials (rotation, revocation, forced refresh)."""
        async with self._lock:
            self._cache.clear()

    def cache_size(self) -> int:
        """Number of cached credentials (bounded by ``max_cache_entries``)."""
        return len(self._cache)

    # -- Internals ----------------------------------------------------------

    def _is_fresh(self, token: OutboundToken) -> bool:
        return self._clock.now() < token.expires_at - self._config.expiry_skew

    def _store(self, key: tuple[str, tuple[str, ...]], token: OutboundToken) -> None:
        self._cache[key] = _CachedToken(token=token)
        self._cache.move_to_end(key)
        while len(self._cache) > self._config.max_cache_entries:
            self._cache.popitem(last=False)

    def _auth_header(self) -> Mapping[str, str]:
        config = self._config
        if config.auth_method is not ClientAuthMethod.CLIENT_SECRET_BASIC:
            return MappingProxyType({})
        assert config.client_secret is not None  # enforced by config validation
        raw = f"{config.client_id}:{config.client_secret.get_secret_value()}".encode()
        return MappingProxyType({"authorization": f"Basic {base64.b64encode(raw).decode()}"})

    def _assertion(self) -> str:
        config = self._config
        assert config.private_key is not None  # enforced by config validation
        now = self._clock.now()
        claims = {
            "iss": config.client_id,
            "sub": config.client_id,
            "aud": config.token_endpoint,
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + config.assertion_ttl).timestamp()),
        }
        return pyjwt.encode(
            claims,
            config.private_key.get_secret_value(),
            algorithm=config.assertion_algorithm,
        )

    def _form(self, *, audience: str, scopes: Sequence[str]) -> dict[str, str]:
        config = self._config
        form: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": config.client_id,
        }
        if config.auth_method is ClientAuthMethod.CLIENT_SECRET_POST:
            assert config.client_secret is not None  # enforced by config validation
            form["client_secret"] = config.client_secret.get_secret_value()
        elif config.auth_method is ClientAuthMethod.PRIVATE_KEY_JWT:
            form["client_assertion_type"] = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            form["client_assertion"] = self._assertion()
        resolved_audience = audience or config.audience
        if resolved_audience:
            form["audience"] = resolved_audience
        if scopes:
            form["scope"] = " ".join(scopes)
        return form

    async def _acquire(self, *, audience: str, scopes: Sequence[str]) -> OutboundToken:
        config = self._config
        form = self._form(audience=audience, scopes=scopes)
        headers = self._auth_header()
        last_error: TokenEndpointUnavailable | None = None
        for attempt in range(1, config.max_attempts + 1):
            try:
                response = await asyncio.wait_for(
                    self._fetch(form, headers), timeout=config.timeout.total_seconds()
                )
            except TokenEndpointUnavailable as exc:
                last_error = exc
            except TimeoutError as exc:
                last_error = TokenEndpointUnavailable("token endpoint timed out")
                last_error.__cause__ = exc
            except (OSError, ConnectionError) as exc:
                last_error = TokenEndpointUnavailable("token endpoint unreachable")
                last_error.__cause__ = exc
            except TokenAcquisitionError:
                raise
            except Exception as exc:  # noqa: BLE001 - unexpected transport failure
                raise TokenAcquisitionError(
                    f"token acquisition failed: {type(exc).__name__}"
                ) from exc
            else:
                return self._parse(response)
            if attempt < config.max_attempts:
                await self._sleep(self._backoff(attempt))
        assert last_error is not None
        raise last_error

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff ceiling with full jitter (AWS-style)."""
        ceiling = self._config.retry_backoff.total_seconds() * (2.0 ** (attempt - 1))
        delay = float(self._jitter(0.0, ceiling))
        return max(0.0, min(delay, ceiling))

    def _parse(self, response: Mapping[str, object]) -> OutboundToken:
        access_token = response.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise TokenAcquisitionError("token endpoint response has no access_token")
        expires_in = response.get("expires_in")
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
            raise TokenAcquisitionError("token endpoint response has no usable expiry")
        if expires_in <= 0:
            raise TokenAcquisitionError("token endpoint returned a non-positive lifetime")
        token_type = response.get("token_type")
        return OutboundToken(
            value=SecretStr(access_token),
            expires_at=self._clock.now() + timedelta(seconds=float(expires_in)),
            token_type=token_type if isinstance(token_type, str) and token_type else "Bearer",
        )


__all__ = [
    "ClientAuthMethod",
    "ClientCredentialsConfig",
    "ClientCredentialsTokenProvider",
    "TokenAcquisitionError",
    "TokenEndpointUnavailable",
    "TokenFetch",
]
