from datetime import timedelta

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.authn.oidc import ClaimMapper, IdentityClaims, JwksCache, TokenVerifier
from jdlib.config import OidcConfig
from jdlib.errors import ExpiredToken, InvalidToken
from tests.support.context_fakes import FrozenClock

ISSUER = "https://idp.example.com"
AUDIENCE = "jdlib"


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk["kid"] = "key-1"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return private, {"keys": [jwk]}


def _config(**overrides) -> OidcConfig:
    base = {"issuer": ISSUER, "audience": AUDIENCE}
    base.update(overrides)
    return OidcConfig(**base)


def _token(
    private,
    *,
    clock,
    subject="user-1",
    email=None,
    verified=None,
    ttl=timedelta(minutes=5),
    nbf=None,
    iat=None,
):
    now = clock.now()
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "iat": now if iat is None else iat,
        "exp": now + ttl,
    }
    if nbf is not None:
        claims["nbf"] = nbf
    if email is not None:
        claims["email"] = email
        claims["email_verified"] = verified
    return pyjwt.encode(claims, private, algorithm="RS256", headers={"kid": "key-1"})


class _Fetcher:
    def __init__(self, jwks) -> None:
        self.jwks = jwks
        self.calls = 0

    async def __call__(self, url: str):
        self.calls += 1
        return self.jwks


def _cache(fetcher, clock) -> JwksCache:
    return JwksCache(
        url="https://idp.example.com/.well-known/jwks.json",
        ttl=timedelta(hours=1),
        fetcher=fetcher,
        clock=clock,
    )


async def test_jwks_cache_caches_and_rotates():
    clock = FrozenClock()
    private, jwks = _keypair()
    fetcher = _Fetcher(jwks)
    cache = _cache(fetcher, clock)
    assert await cache.signing_key("key-1") is not None
    assert await cache.signing_key("key-1") is not None
    assert fetcher.calls == 1
    clock.advance(timedelta(hours=2))
    assert await cache.signing_key("key-1") is not None
    assert fetcher.calls == 2
    assert await cache.signing_key("missing") is None


async def test_verifier_accepts_valid_token_and_maps_claims():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    verifier = TokenVerifier(_config(), clock)
    claims = verifier.verify(
        _token(private, clock=clock, email="a@b.c", verified=True),
        await cache.signing_key("key-1"),
    )
    mapped = ClaimMapper(_config()).map(claims)
    assert mapped == IdentityClaims(
        issuer=ISSUER, subject="user-1", email="a@b.c", email_verified=True
    )


async def test_verifier_rejects_expired_and_tampered():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    verifier = TokenVerifier(_config(), clock)
    key = await cache.signing_key("key-1")
    expired = _token(private, clock=clock, ttl=timedelta(minutes=-10))
    with pytest.raises(ExpiredToken):
        verifier.verify(expired, key)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock)[:-3] + "aaa", key)


async def test_verifier_rejects_wrong_audience_and_issuer():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    key = await cache.signing_key("key-1")
    verifier = TokenVerifier(_config(audience="other"), clock)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock), key)
    verifier = TokenVerifier(_config(issuer="https://other.example.com"), clock)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock), key)


async def test_jwks_cache_returns_none_for_malformed_key():
    clock = FrozenClock()
    jwks = {"keys": [{"kty": "RSA", "kid": "bad", "n": "!!!", "e": "AQAB"}]}
    cache = _cache(_Fetcher(jwks), clock)
    assert await cache.signing_key("bad") is None


async def test_verifier_enforces_nbf_and_iat_leeway():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    verifier = TokenVerifier(_config(), clock)
    key = await cache.signing_key("key-1")
    now = clock.now()
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock, nbf=now + timedelta(minutes=5)), key)
    verifier.verify(_token(private, clock=clock, nbf=now + timedelta(seconds=30)), key)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock, iat=now + timedelta(minutes=5)), key)
    verifier.verify(_token(private, clock=clock, iat=now + timedelta(seconds=30)), key)


async def test_verifier_leeway_applies_to_exp():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    key = await cache.signing_key("key-1")
    recently_expired = _token(private, clock=clock, ttl=timedelta(seconds=-30))
    TokenVerifier(_config(), clock).verify(recently_expired, key)
    with pytest.raises(ExpiredToken):
        TokenVerifier(_config(leeway=timedelta(0)), clock).verify(recently_expired, key)


async def test_claim_mapper_rejects_missing_subject():
    with pytest.raises(InvalidToken, match="missing subject"):
        ClaimMapper(_config()).map({"iss": ISSUER})


async def test_jwks_cache_unknown_kid_refetch_is_floored():
    clock = FrozenClock()
    fetcher = _Fetcher({"keys": []})
    cache = JwksCache(
        url="https://idp.example.com/.well-known/jwks.json",
        ttl=timedelta(hours=1),
        fetcher=fetcher,
        clock=clock,
        min_refresh_interval=timedelta(seconds=5),
    )
    assert await cache.signing_key("missing") is None
    assert fetcher.calls == 1
    for _ in range(3):
        assert await cache.signing_key("missing") is None
        assert await cache.signing_key("other") is None
    assert fetcher.calls == 1
    clock.advance(timedelta(seconds=4))
    assert await cache.signing_key("missing") is None
    assert fetcher.calls == 1
    clock.advance(timedelta(seconds=1))
    assert await cache.signing_key("missing") is None
    assert fetcher.calls == 2
