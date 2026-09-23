"""Authentication adapters built on the security core (spec #7-#10, #39).

Deliberate public surface of the authentication layer:

* :mod:`jdlib.security.authn.algorithms` — JWT algorithm allowlist policy,
* :class:`JwtTokenValidator` — inbound token validation (spec #7),
* :class:`ClientCredentialsTokenProvider` — outbound service credentials,
* :class:`ZitadelConfig` and builders — ZITADEL wiring (spec #8).

Import safety (spec #74): no optional dependency is imported here.
"""

from jdlib.security.authn.algorithms import ASYMMETRIC_ALGORITHMS, assert_safe_algorithms
from jdlib.security.authn.jwt import JwtClaimMapping, JwtTokenValidator, SigningKeySource
from jdlib.security.authn.provider import (
    ClientAuthMethod,
    ClientCredentialsConfig,
    ClientCredentialsTokenProvider,
    TokenAcquisitionError,
    TokenEndpointUnavailable,
    TokenFetch,
)
from jdlib.security.authn.zitadel import (
    JwksFetch,
    ZitadelConfig,
    build_zitadel_token_provider,
    build_zitadel_token_validator,
    zitadel_provider_config,
)

__all__ = [
    "ASYMMETRIC_ALGORITHMS",
    "ClientAuthMethod",
    "ClientCredentialsConfig",
    "ClientCredentialsTokenProvider",
    "JwksFetch",
    "JwtClaimMapping",
    "JwtTokenValidator",
    "SigningKeySource",
    "TokenAcquisitionError",
    "TokenEndpointUnavailable",
    "TokenFetch",
    "ZitadelConfig",
    "assert_safe_algorithms",
    "build_zitadel_token_provider",
    "build_zitadel_token_validator",
    "zitadel_provider_config",
]
