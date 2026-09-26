"""AWS Secrets Manager secret provider (AWS directive §11).

The third `SecretProvider`, beside `MemorySecretProvider` and `EnvSecretProvider`, and the same
one-method protocol: a tenant's credential resolves the same way wherever it is stored. Rotation,
caching and failure behaviour change; the interface the application sees does not.

Four properties are deliberate:

* **bounded caching.** Values are cached for a TTL so a request path does not call AWS on every
  resolution, and the cache entry expires rather than living forever, so a rotated secret is picked
  up without a restart. `invalidate()` drops one handle or all of them when a rotation is known to
  have happened.
* **no value ever escapes.** A failed resolution names the *handle* and the client exception's
  class, never its message: an SDK error can echo the secret value back, so the message and the
  cause chain are dropped while the class survives, because `ResourceNotFoundException` and
  `AccessDeniedException` need different fixes. `repr` reports how many entries are cached, not
  what is in them.
* **fail-closed, protocol-shaped.** A resolution that cannot be completed raises `KeyError`, which
  is what the existing providers raise, so callers have one failure shape to handle. There is no
  path that returns an empty string for a secret that could not be read.
* **the client is injected.** Duck-typed, the same idiom as the gateway and policy transports, so
  the adapter is testable without AWS and `boto3` stays out of the core dependency set -- the
  deployment passes a configured client, including its timeouts, which are botocore's business
  rather than this class's.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Protocol

from pydantic import BaseModel, ConfigDict, model_validator

from jdlib.context import Clock, SystemClock
from jdlib.security.errors import SecurityConfigurationError


class SecretsManagerClient(Protocol):
    """The one client method this adapter needs, so any duck-typed client works."""

    def get_secret_value(self, **kwargs: object) -> Mapping[str, object]: ...


class SecretsManagerConfig(BaseModel):
    """Secrets Manager settings (AWS directive §11)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Handle namespace, so one deployment can separate environments without changing callers.
    prefix: str = ""
    region: str | None = None
    endpoint_url: str | None = None
    cache_ttl: timedelta = timedelta(minutes=5)

    @model_validator(mode="after")
    def _validate(self) -> SecretsManagerConfig:
        if self.cache_ttl <= timedelta(0):
            raise SecurityConfigurationError("cache_ttl must be positive")
        if self.endpoint_url is not None and not self.endpoint_url.startswith("https://"):
            raise SecurityConfigurationError("endpoint_url must use https")
        return self

    def resolved_secret_id(self, handle: str) -> str:
        """The SecretId sent to AWS for a handle."""
        if not handle:
            raise SecurityConfigurationError("a secret handle must not be empty")
        return f"{self.prefix}{handle}"


class SecretsManagerSecretProvider:
    """Resolves secrets from AWS Secrets Manager, with a bounded cache."""

    def __init__(
        self,
        *,
        client: SecretsManagerClient,
        config: SecretsManagerConfig | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._client = client
        self._config = config or SecretsManagerConfig()
        self._clock = clock or SystemClock()
        self._entries: dict[str, tuple[str, datetime]] = {}

    def __repr__(self) -> str:
        """Report cache size, never contents."""
        return (
            f"SecretsManagerSecretProvider(prefix={self._config.prefix!r}, "
            f"cached={len(self._entries)})"
        )

    def resolve(self, handle: str) -> str:
        secret_id = self._config.resolved_secret_id(handle)
        cached = self._entries.get(secret_id)
        if cached is not None:
            value, fetched_at = cached
            if self._clock.now() - fetched_at <= self._config.cache_ttl:
                return value
        return self._fetch(secret_id)

    def invalidate(self, handle: str | None = None) -> None:
        """Drop one handle from the cache, or all of them."""
        if handle is None:
            self._entries.clear()
            return
        self._entries.pop(self._config.resolved_secret_id(handle), None)

    def _fetch(self, secret_id: str) -> str:
        try:
            response = self._client.get_secret_value(SecretId=secret_id)
        except Exception as exc:  # noqa: BLE001 - any client failure is an unresolvable handle
            # The handle is safe to name; the client's message is not, because an SDK error can echo
            # the secret value back. The exception *class* is kept -- ResourceNotFoundException and
            # AccessDeniedException need different fixes -- and the message and cause chain are not.
            raise KeyError(
                f"secret {secret_id!r} could not be resolved ({type(exc).__name__})"
            ) from None
        value = response.get("SecretString")
        if not isinstance(value, str) or not value:
            # SecretBinary exists in the API, but this protocol returns str, so a binary secret is
            # an unsupported handle rather than something to decode on a guess.
            raise KeyError(f"secret {secret_id!r} has no string value")
        self._entries[secret_id] = (value, self._clock.now())
        return value


__all__ = [
    "SecretsManagerClient",
    "SecretsManagerConfig",
    "SecretsManagerSecretProvider",
]
