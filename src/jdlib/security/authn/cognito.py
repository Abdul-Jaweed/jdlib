"""Amazon Cognito adapter (AWS directive §5).

Configuration and wiring only: Cognito endpoints are derived from the issuer, and the resulting
objects are the generic, already-tested validator. Cognito-specific behaviour does not leak into the
core, so a different identity provider is wired the same way.

AWS documents token verification as the application's job and recommends a JWT library, so this
adapter does not verify signatures. It supplies discovery, issuer, audience and the algorithm
allow-list to :class:`JwtTokenValidator`, and adds the one check that validator does not make: the
``token_use`` claim, read from a token the validator has already verified.

Three Cognito facts shape this file, and none of them are ZITADEL's:

* **Two key pairs, one JWKS.** A user pool keeps a separate RSA key pair for access tokens and for
  ID tokens, so the two token types carry different ``kid`` values and both are resolved from the
  same JWKS document. Nothing here assumes one key.
* **No documented clock-skew tolerance.** AWS documents the five-minute grace period for *identity
  pools* validating third-party OIDC tokens, not for application-side user-pool validation, so the
  default ``leeway`` is zero rather than the library's usual minute. A deployment that needs skew
  tolerance sets it explicitly, and that choice is visible in configuration.
* **The audience claim depends on the token type.** An ID token carries ``aud`` (the app client ID);
  an access token carries ``client_id``, and ``aud`` only when a resource binding is in play. The
  generic validator checks the audience claim, so ``token_use="id"`` is the default here — the token
  type whose audience check the validator can actually make. Validating access tokens is supported,
  but the deployment must then supply an audience claim the verifier can see, and
  :func:`token_client_id` is the access-token check that AWS documents (``client_id`` against the
  app client) for the cases where it cannot.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta
from typing import Literal

import jwt as pyjwt
from pydantic import BaseModel, ConfigDict, model_validator

from jdlib.authn.oidc import JwksCache
from jdlib.context import Clock
from jdlib.errors import InvalidToken
from jdlib.security.authn.algorithms import assert_safe_algorithms
from jdlib.security.authn.jwt import JwtClaimMapping, JwtTokenValidator
from jdlib.security.errors import SecurityConfigurationError
from jdlib.security.interfaces import ValidatedToken

JwksFetch = Callable[[str], Awaitable[Mapping[str, object]]]

#: Cognito signs user-pool tokens with RS256; its JWKS advertises ``alg: RS256, kty: RSA``.
COGNITO_ALGORITHMS: tuple[str, ...] = ("RS256",)


class CognitoConfig(BaseModel):
    """Amazon Cognito user-pool settings (AWS directive §5)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: str
    audience: str
    region: str | None = None
    user_pool_id: str | None = None
    algorithms: tuple[str, ...] = COGNITO_ALGORITHMS
    jwks_uri: str | None = None
    #: Which token the deployment expects on the wire; see the module docstring.
    token_use: Literal["id", "access"] = "id"
    jwks_ttl: timedelta = timedelta(hours=1)
    #: AWS documents no skew tolerance for user-pool JWT validation; zero is the documented default.
    leeway: timedelta = timedelta(0)
    timeout: timedelta = timedelta(seconds=5)

    @model_validator(mode="after")
    def _validate(self) -> CognitoConfig:
        if not self.issuer:
            raise SecurityConfigurationError("cognito issuer must not be empty")
        if not self.issuer.startswith("https://"):
            raise SecurityConfigurationError("cognito issuer must use https")
        if not self.audience:
            raise SecurityConfigurationError("cognito audience (app client id) must not be empty")
        if self.jwks_ttl <= timedelta(0):
            raise SecurityConfigurationError("jwks_ttl must be positive")
        if self.timeout <= timedelta(0):
            raise SecurityConfigurationError("timeout must be positive")
        if self.leeway < timedelta(0):
            raise SecurityConfigurationError("leeway must not be negative")
        if self.region and f"cognito-idp.{self.region}." not in self.issuer:
            raise SecurityConfigurationError("cognito region does not match the issuer")
        if self.user_pool_id and not self.issuer.rstrip("/").endswith(self.user_pool_id):
            raise SecurityConfigurationError("cognito user_pool_id does not match the issuer")
        assert_safe_algorithms(self.algorithms)
        return self

    def _issuer_base(self) -> str:
        return self.issuer.rstrip("/")

    def resolved_jwks_uri(self) -> str:
        """JWKS location, defaulting to Cognito's ``/.well-known/jwks.json``."""
        return self.jwks_uri or f"{self._issuer_base()}/.well-known/jwks.json"

    def expected_token_use(self) -> str:
        """The ``token_use`` value a token must carry."""
        return self.token_use


def build_cognito_token_validator(
    config: CognitoConfig,
    *,
    fetch: JwksFetch,
    clock: Clock | None = None,
) -> JwtTokenValidator:
    """Wire a hardened JWT validator to the Cognito JWKS endpoint."""
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


def unverified_claims(token: str) -> dict[str, object]:
    """Read a Cognito token's claims **after** the validator has verified it.

    Not a second verification path: this exists because the generic validator returns metadata
    rather than raw claims, and Cognito's ``token_use`` is a claim the deployment must check.
    """
    try:
        claims = pyjwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
    except pyjwt.PyJWTError as exc:
        raise InvalidToken("malformed token payload") from exc
    if not isinstance(claims, dict):
        raise InvalidToken("malformed token payload")
    return claims


def token_use_of(token: str) -> str | None:
    """The ``token_use`` claim, or ``None`` when the token does not carry one."""
    value = unverified_claims(token).get("token_use")
    return value if isinstance(value, str) else None


def token_client_id(token: str) -> str | None:
    """The ``client_id`` claim — what an access token carries instead of ``aud``."""
    value = unverified_claims(token).get("client_id")
    return value if isinstance(value, str) else None


async def validate_cognito_token(
    validator: JwtTokenValidator,
    config: CognitoConfig,
    token: str,
) -> ValidatedToken:
    """Validate a Cognito token, then enforce the token type the deployment expects.

    The generic validator has already checked signature, issuer, audience and time claims by the
    time the type is checked; a token of the wrong type is rejected rather than reinterpreted,
    because the two token types carry different claims and different key pairs.
    """
    validated = await validator.validate(token)
    actual = token_use_of(token)
    if actual is None:
        raise InvalidToken("token has no token_use claim")
    expected = config.expected_token_use()
    if actual != expected:
        raise InvalidToken(f"token_use is {actual}, expected {expected}")
    if expected == "access":
        client_id = token_client_id(token)
        if client_id != config.audience:
            raise InvalidToken("access token was issued for a different app client")
    return validated


__all__ = [
    "COGNITO_ALGORITHMS",
    "CognitoConfig",
    "JwksFetch",
    "build_cognito_token_validator",
    "token_client_id",
    "token_use_of",
    "unverified_claims",
    "validate_cognito_token",
]
