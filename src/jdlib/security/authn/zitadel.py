"""ZITADEL adapter (directive §12, spec #8).

Configuration and wiring only: ZITADEL endpoints are derived from the issuer,
and the resulting objects are the generic, already-tested validator and
provider. ZITADEL-specific behaviour does not leak into the core, so a
different identity provider can be wired the same way.

Secrets are held as ``SecretStr``; the configuration's ``repr``, ``model_dump``
and ``model_dump_json`` never contain them (regression-tested).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator

from jdlib.authn.oidc import JwksCache
from jdlib.context import Clock
from jdlib.security.authn.algorithms import assert_safe_algorithms
from jdlib.security.authn.jwt import JwtClaimMapping, JwtTokenValidator
from jdlib.security.authn.provider import (
    ClientAuthMethod,
    ClientCredentialsConfig,
    ClientCredentialsTokenProvider,
    TokenFetch,
)
from jdlib.security.errors import SecurityConfigurationError

_LOCAL_PREFIXES = ("http://localhost", "http://127.0.0.1")

JwksFetch = Callable[[str], Awaitable[Mapping[str, object]]]


class ZitadelConfig(BaseModel):
    """ZITADEL integration settings (spec #8)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: str
    audience: str
    algorithms: tuple[str, ...] = ("RS256",)
    jwks_uri: str | None = None
    token_endpoint: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    private_key: SecretStr | None = None
    auth_method: ClientAuthMethod = ClientAuthMethod.CLIENT_SECRET_POST
    assertion_algorithm: str = "RS256"
    scopes: tuple[str, ...] = ()
    jwks_ttl: timedelta = timedelta(hours=1)
    leeway: timedelta = timedelta(seconds=60)
    timeout: timedelta = timedelta(seconds=5)
    max_attempts: int = 3

    @model_validator(mode="after")
    def _validate(self) -> ZitadelConfig:
        if not self.issuer:
            raise SecurityConfigurationError("zitadel issuer must not be empty")
        if not self.issuer.startswith("https://") and not self.issuer.startswith(_LOCAL_PREFIXES):
            raise SecurityConfigurationError(
                "zitadel issuer must use https (http is allowed only for localhost)"
            )
        if self.jwks_ttl <= timedelta(0):
            raise SecurityConfigurationError("jwks_ttl must be positive")
        if self.timeout <= timedelta(0):
            raise SecurityConfigurationError("timeout must be positive")
        if self.max_attempts < 1:
            raise SecurityConfigurationError("max_attempts must be at least 1")
        assert_safe_algorithms(self.algorithms)
        assert_safe_algorithms([self.assertion_algorithm])
        return self

    def _issuer_base(self) -> str:
        return self.issuer.rstrip("/")

    def resolved_jwks_uri(self) -> str:
        """JWKS location, defaulting to ZITADEL's ``/oauth/v2/keys``."""
        return self.jwks_uri or f"{self._issuer_base()}/oauth/v2/keys"

    def resolved_token_endpoint(self) -> str:
        """Token endpoint, defaulting to ZITADEL's ``/oauth/v2/token``."""
        return self.token_endpoint or f"{self._issuer_base()}/oauth/v2/token"


def build_zitadel_token_validator(
    config: ZitadelConfig,
    *,
    fetch: JwksFetch,
    clock: Clock | None = None,
) -> JwtTokenValidator:
    """Wire a hardened JWT validator to the ZITADEL JWKS endpoint."""
    cache = JwksCache(
        url=config.resolved_jwks_uri(),
        ttl=config.jwks_ttl,
        fetcher=fetch,
        clock=clock,
        timeout=config.timeout,
    )
    return JwtTokenValidator(
        mapping=JwtClaimMapping(
            issuer=config.issuer,
            audience=config.audience,
            algorithms=config.algorithms,
        ),
        keys=cache,
        clock=clock,
        leeway=config.leeway,
    )


def zitadel_provider_config(config: ZitadelConfig) -> ClientCredentialsConfig:
    """Translate ZITADEL settings into the generic outbound-auth configuration."""
    if not config.client_id:
        raise SecurityConfigurationError(
            "zitadel client_id is required for outbound authentication"
        )
    if config.auth_method is ClientAuthMethod.PRIVATE_KEY_JWT:
        if config.private_key is None:
            raise SecurityConfigurationError(
                "zitadel private_key_jwt requires a private_key"
            )
    elif config.client_secret is None:
        raise SecurityConfigurationError(
            "zitadel client secret authentication requires a client_secret"
        )
    return ClientCredentialsConfig(
        token_endpoint=config.resolved_token_endpoint(),
        client_id=config.client_id,
        client_secret=config.client_secret,
        private_key=config.private_key,
        auth_method=config.auth_method,
        assertion_algorithm=config.assertion_algorithm,
        scopes=config.scopes,
        audience=config.audience,
        timeout=config.timeout,
        max_attempts=config.max_attempts,
    )


def build_zitadel_token_provider(
    config: ZitadelConfig,
    *,
    fetch: TokenFetch,
    clock: Clock | None = None,
) -> ClientCredentialsTokenProvider:
    """Wire the generic token provider to the ZITADEL token endpoint."""
    return ClientCredentialsTokenProvider(
        config=zitadel_provider_config(config),
        fetch=fetch,
        clock=clock,
    )


__all__ = [
    "JwksFetch",
    "ZitadelConfig",
    "build_zitadel_token_provider",
    "build_zitadel_token_validator",
    "zitadel_provider_config",
]
