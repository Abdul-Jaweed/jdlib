"""Phase 2: ZITADEL adapter (directive §12, spec #8).

The adapter is configuration + wiring only: ZITADEL endpoints are derived from
the issuer, and the resulting objects are the generic, tested validator and
provider. No ZITADEL-specific behaviour leaks into the core.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr

from jdlib.security.authn.provider import (
    ClientAuthMethod,
    ClientCredentialsConfig,
    ClientCredentialsTokenProvider,
)
from jdlib.security.authn.zitadel import (
    ZitadelConfig,
    build_zitadel_token_provider,
    build_zitadel_token_validator,
    zitadel_provider_config,
)
from jdlib.security.errors import SecurityConfigurationError
from jdlib.security.interfaces import TokenProvider, TokenValidator

ISSUER = "https://zitadel.example.com"
CLIENT_SECRET = "zitadel-client-secret-value"


def _config(**overrides: object) -> ZitadelConfig:
    values: dict[str, object] = {
        "issuer": ISSUER,
        "audience": "jdlib-api",
        "client_id": "service-account-1",
        "client_secret": SecretStr(CLIENT_SECRET),
        "scopes": ("openid", "profile"),
    }
    values.update(overrides)
    return ZitadelConfig(**values)  # type: ignore[arg-type]


# --- Endpoint derivation -----------------------------------------------------


def test_endpoints_are_derived_from_the_issuer() -> None:
    config = _config()
    assert config.resolved_jwks_uri() == f"{ISSUER}/oauth/v2/keys"
    assert config.resolved_token_endpoint() == f"{ISSUER}/oauth/v2/token"


def test_explicit_endpoints_win() -> None:
    config = _config(
        jwks_uri="https://keys.example.com/jwks.json",
        token_endpoint="https://tokens.example.com/token",
    )
    assert config.resolved_jwks_uri() == "https://keys.example.com/jwks.json"
    assert config.resolved_token_endpoint() == "https://tokens.example.com/token"


def test_trailing_slash_in_issuer_is_normalised() -> None:
    assert _config(issuer=f"{ISSUER}/").resolved_jwks_uri() == f"{ISSUER}/oauth/v2/keys"


@pytest.mark.parametrize(
    "issuer", ["http://zitadel.example.com", "zitadel.example.com", "ftp://zitadel.example.com"]
)
def test_insecure_issuer_is_rejected(issuer: str) -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(issuer=issuer)


def test_local_issuer_is_allowed_for_development() -> None:
    config = _config(issuer="http://localhost:8080")
    assert config.resolved_token_endpoint() == "http://localhost:8080/oauth/v2/token"


def test_defaults_match_zitadel_expectations() -> None:
    config = _config()
    assert config.algorithms == ("RS256",)
    assert config.auth_method is ClientAuthMethod.CLIENT_SECRET_POST
    assert config.jwks_ttl == timedelta(hours=1)
    assert config.timeout == timedelta(seconds=5)
    assert config.leeway == timedelta(seconds=60)


def test_unsafe_algorithms_are_rejected() -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(algorithms=("none",))
    with pytest.raises(SecurityConfigurationError):
        _config(algorithms=("HS256",))


def test_secrets_never_appear_in_repr_or_dump() -> None:
    config = _config()
    rendered = f"{config!r} {config.model_dump()} {config.model_dump_json()}"
    assert CLIENT_SECRET not in rendered


# --- Wiring ------------------------------------------------------------------


def test_validator_is_wired_to_the_zitadel_jwks_uri() -> None:
    validator = build_zitadel_token_validator(_config(), fetch=lambda url: None)  # type: ignore[arg-type]
    assert isinstance(validator, TokenValidator)
    assert validator.keys.url == f"{ISSUER}/oauth/v2/keys"


def test_provider_config_maps_zitadel_settings() -> None:
    provider_config = zitadel_provider_config(_config())
    assert isinstance(provider_config, ClientCredentialsConfig)
    assert provider_config.token_endpoint == f"{ISSUER}/oauth/v2/token"
    assert provider_config.client_id == "service-account-1"
    assert provider_config.audience == "jdlib-api"
    assert provider_config.scopes == ("openid", "profile")
    assert provider_config.auth_method is ClientAuthMethod.CLIENT_SECRET_POST


def test_provider_requires_credentials() -> None:
    with pytest.raises(SecurityConfigurationError):
        zitadel_provider_config(_config(client_id=None))
    with pytest.raises(SecurityConfigurationError):
        zitadel_provider_config(_config(client_secret=None))


def test_built_provider_implements_the_core_port() -> None:
    provider = build_zitadel_token_provider(_config(), fetch=lambda f, h: None)  # type: ignore[arg-type]
    assert isinstance(provider, ClientCredentialsTokenProvider)
    assert isinstance(provider, TokenProvider)


def test_private_key_jwt_configuration_is_supported() -> None:
    placeholder_key = "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----"
    config = _config(
        client_secret=None,
        auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
        private_key=SecretStr(placeholder_key),
    )
    provider_config = zitadel_provider_config(config)
    assert provider_config.auth_method is ClientAuthMethod.PRIVATE_KEY_JWT
