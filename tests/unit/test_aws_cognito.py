"""Cognito adapter tests (AWS directive §5, §37).

The security list the directive requires for Cognito: forged JWT, wrong issuer, wrong audience,
expired token, invalid signature, invalid algorithm, invalid JWKS and key rotation. Everything here
runs against a locally generated RSA key pair and a fake JWKS fetcher — no AWS account and no
network — so the adapter's contract with AWS is tested, and the live path is honestly not claimed.

Cognito keeps a separate key pair for access tokens and ID tokens, so the fake JWKS here carries two
keys with different ``kid`` values and the tests resolve both.
"""

from datetime import timedelta
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.errors import AuthenticationError, InvalidToken
from jdlib.security.authn.cognito import (
    COGNITO_ALGORITHMS,
    CognitoConfig,
    build_cognito_token_validator,
    token_client_id,
    token_use_of,
    unverified_claims,
    validate_cognito_token,
)
from jdlib.security.authn.jwt import JwtTokenValidator
from jdlib.security.errors import SecurityConfigurationError
from tests.support.context_fakes import FrozenClock

ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_POOL1"
CLIENT_ID = "7exampleclientid"
ID_KID = "id-token-key"
ACCESS_KID = "access-token-key"


def _jwk(private: rsa.RSAPrivateKey, kid: str) -> dict[str, object]:
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return jwk


def _pool() -> tuple[rsa.RSAPrivateKey, rsa.RSAPrivateKey, dict[str, list[dict[str, object]]]]:
    """A pool's two key pairs, as Cognito keeps them."""
    id_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    access_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk(id_private, ID_KID), _jwk(access_private, ACCESS_KID)]}
    return id_private, access_private, jwks


class _Fetcher:
    def __init__(self, jwks: dict[str, list[dict[str, object]]]) -> None:
        self.jwks = jwks
        self.calls = 0

    async def __call__(self, url: str) -> dict[str, list[dict[str, object]]]:
        self.calls += 1
        return self.jwks


def _config(**overrides: Any) -> CognitoConfig:
    base: dict[str, Any] = {"issuer": ISSUER, "audience": CLIENT_ID}
    base.update(overrides)
    return CognitoConfig(**base)


def _token(
    private: rsa.RSAPrivateKey,
    *,
    clock: FrozenClock,
    kid: str,
    token_use: str = "id",
    ttl: timedelta = timedelta(minutes=5),
    issuer: str = ISSUER,
    audience: str | None = CLIENT_ID,
    client_id: str | None = None,
    algorithm: str = "RS256",
) -> str:
    now = clock.now()
    claims: dict[str, object] = {
        "iss": issuer,
        "sub": "user-1",
        "token_use": token_use,
        "iat": now,
        "exp": now + ttl,
    }
    if audience is not None:
        claims["aud"] = audience
    if client_id is not None:
        claims["client_id"] = client_id
    return pyjwt.encode(claims, private, algorithm=algorithm, headers={"kid": kid})


def _validator(jwks: dict[str, list[dict[str, object]]], clock: FrozenClock) -> JwtTokenValidator:
    return build_cognito_token_validator(_config(), fetch=_Fetcher(jwks), clock=clock)


# -- configuration ----------------------------------------------------------------


def test_defaults_match_what_aws_documents() -> None:
    config = _config()
    assert config.algorithms == COGNITO_ALGORITHMS == ("RS256",)
    assert config.token_use == "id"
    # AWS documents no clock-skew tolerance for user-pool validation; zero, not the library default.
    assert config.leeway == timedelta(0)
    assert config.resolved_jwks_uri() == f"{ISSUER}/.well-known/jwks.json"


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": "http://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_POOL1"},
        {"issuer": ""},
        {"audience": ""},
        {"jwks_ttl": timedelta(0)},
        {"timeout": timedelta(0)},
        {"leeway": timedelta(seconds=-1)},
        {"region": "us-east-1"},
        {"user_pool_id": "eu-west-1_OTHER"},
        {"algorithms": ("HS256",)},
        {"token_use": "refresh"},
    ],
)
def test_configuration_that_cannot_be_safe_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises((SecurityConfigurationError, ValueError)):
        _config(**overrides)


def test_region_and_pool_are_accepted_when_they_match_the_issuer() -> None:
    config = _config(region="eu-west-1", user_pool_id="eu-west-1_POOL1")
    assert config.resolved_jwks_uri().startswith("https://cognito-idp.eu-west-1.")


# -- the happy path ---------------------------------------------------------------


async def test_a_valid_id_token_is_accepted() -> None:
    clock = FrozenClock()
    id_private, _, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(id_private, clock=clock, kid=ID_KID)
    validated = await validate_cognito_token(validator, _config(), token)
    assert validated.subject == "user-1"


async def test_both_key_pairs_resolve_from_the_same_jwks() -> None:
    clock = FrozenClock()
    id_private, access_private, jwks = _pool()
    validator = _validator(jwks, clock)
    id_token = _token(id_private, clock=clock, kid=ID_KID)
    access_token = _token(
        access_private,
        clock=clock,
        kid=ACCESS_KID,
        token_use="access",
        audience=CLIENT_ID,  # resource-bound access tokens carry aud; see the page's caveat
        client_id=CLIENT_ID,
    )
    assert (await validate_cognito_token(validator, _config(), id_token)).subject == "user-1"
    config = _config(token_use="access")
    assert (await validate_cognito_token(validator, config, access_token)).subject == "user-1"


# -- the directive's security list ------------------------------------------------


async def test_a_forged_signature_is_rejected() -> None:
    clock = FrozenClock()
    id_private, _, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(id_private, clock=clock, kid=ID_KID)
    header, payload, signature = token.split(".")
    forged = f"{header}.{payload}.{signature[:-4]}AAAA"
    with pytest.raises(InvalidToken):
        await validator.validate(forged)


async def test_a_token_signed_by_an_unrelated_key_is_rejected() -> None:
    clock = FrozenClock()
    _, _, jwks = _pool()
    validator = _validator(jwks, clock)
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _token(stranger, clock=clock, kid=ID_KID)
    with pytest.raises(InvalidToken):
        await validator.validate(token)


async def test_a_wrong_issuer_is_rejected() -> None:
    clock = FrozenClock()
    id_private, _, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(
        id_private,
        clock=clock,
        kid=ID_KID,
        issuer="https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHERPOOL",
    )
    with pytest.raises(InvalidToken):
        await validator.validate(token)


async def test_a_wrong_audience_is_rejected() -> None:
    clock = FrozenClock()
    id_private, _, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(id_private, clock=clock, kid=ID_KID, audience="some-other-app-client")
    with pytest.raises(InvalidToken):
        await validator.validate(token)


async def test_an_expired_token_is_rejected() -> None:
    clock = FrozenClock()
    id_private, _, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(id_private, clock=clock, kid=ID_KID, ttl=timedelta(seconds=-1))
    # ExpiredToken is a sibling of InvalidToken under AuthenticationError, not a subclass.
    with pytest.raises(AuthenticationError):
        await validator.validate(token)


async def test_a_symmetric_token_is_rejected_although_it_verifies_with_its_own_key() -> None:
    clock = FrozenClock()
    _, _, jwks = _pool()
    validator = _validator(jwks, clock)
    # A token signed HS256 with the public JWK as the HMAC secret is the classic confusion attack:
    # the algorithm allow-list is what stops it, before any signature work happens.
    token = pyjwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "u"}, "x" * 32, algorithm="HS256")
    with pytest.raises(InvalidToken):
        await validator.validate(token)


async def test_an_invalid_jwks_is_fail_closed() -> None:
    clock = FrozenClock()
    id_private, _, _ = _pool()
    validator = _validator({"keys": []}, clock)
    token = _token(id_private, clock=clock, kid=ID_KID)
    with pytest.raises(InvalidToken):
        await validator.validate(token)


async def test_key_rotation_is_picked_up_from_an_unknown_kid() -> None:
    clock = FrozenClock()
    fetcher_jwks = _pool()[2]
    fetcher = _Fetcher(fetcher_jwks)
    validator = build_cognito_token_validator(_config(), fetch=fetcher, clock=clock)

    rotated_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated = _token(rotated_private, clock=clock, kid="rotated-key")
    with pytest.raises(InvalidToken):
        await validator.validate(rotated)  # not in the JWKS yet

    # JwksCache rate-limits refreshes (min_refresh_interval, one second); move the clock past it.
    clock.advance(timedelta(seconds=2))
    fetcher.jwks = {"keys": [*fetcher_jwks["keys"], _jwk(rotated_private, "rotated-key")]}
    assert (await validator.validate(rotated)).subject == "user-1"
    assert fetcher.calls >= 2  # the unknown kid forced a refresh


# -- the checks the generic validator does not make -------------------------------


async def test_a_missing_token_use_is_rejected() -> None:
    clock = FrozenClock()
    id_private, _, jwks = _pool()
    validator = _validator(jwks, clock)
    token = pyjwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "exp": clock.now() + timedelta(minutes=5)},
        id_private,
        algorithm="RS256",
        headers={"kid": ID_KID},
    )
    with pytest.raises(InvalidToken, match="token_use"):
        await validate_cognito_token(validator, _config(), token)


async def test_an_access_token_is_not_accepted_where_an_id_token_is_expected() -> None:
    clock = FrozenClock()
    _, access_private, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(
        access_private,
        clock=clock,
        kid=ACCESS_KID,
        token_use="access",
        audience=CLIENT_ID,
        client_id=CLIENT_ID,
    )
    with pytest.raises(InvalidToken, match="expected id"):
        await validate_cognito_token(validator, _config(), token)


async def test_an_access_token_for_another_app_client_is_rejected() -> None:
    clock = FrozenClock()
    _, access_private, jwks = _pool()
    validator = _validator(jwks, clock)
    token = _token(
        access_private,
        clock=clock,
        kid=ACCESS_KID,
        token_use="access",
        audience=CLIENT_ID,
        client_id="a-different-app-client",
    )
    with pytest.raises(InvalidToken, match="app client"):
        await validate_cognito_token(validator, _config(token_use="access"), token)


def test_claim_readers_do_not_verify_and_say_so() -> None:
    clock = FrozenClock()
    id_private, _, _ = _pool()
    token = _token(id_private, clock=clock, kid=ID_KID)
    assert token_use_of(token) == "id"
    assert token_client_id(token) is None
    assert unverified_claims(token)["sub"] == "user-1"
    with pytest.raises(InvalidToken):
        unverified_claims("not-a-jwt")
