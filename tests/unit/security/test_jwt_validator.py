"""Phase 2: JWT token validation with explicit claim mapping.

Spec refs: #10 (token security: iss/aud/sub/exp/nbf/iat/jti/scope/scp/
client_id/azp, explicit claim mapping, no automatic privilege claims),
#56 (authentication test categories: invalid signature, expired, future nbf,
wrong issuer, wrong audience, wrong algorithm, unknown kid), #7 (inbound
authentication), #75 (fail closed with typed errors).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import to_base64url_uint

from jdlib.errors import ExpiredToken, InvalidToken
from jdlib.security.authn.jwt import JwtClaimMapping, JwtTokenValidator
from jdlib.security.errors import SecurityConfigurationError
from jdlib.security.interfaces import TokenValidator

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
ISSUER = "https://id.example.com"
AUDIENCE = "jdlib-api"
KID = "key-1"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_jwk() -> dict[str, object]:
    public = _PRIVATE_KEY.public_key().public_numbers()
    return {
        "kid": KID,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": to_base64url_uint(public.n).decode(),
        "e": to_base64url_uint(public.e).decode(),
    }


class KeySource:
    """Deterministic stand-in for a JWKS cache (structural port)."""

    def __init__(self, jwk: dict[str, object] | None = None) -> None:
        self._jwk = jwk if jwk is not None else _public_jwk()
        self.lookups: list[str] = []

    async def signing_key(self, kid: str) -> object | None:
        self.lookups.append(kid)
        if kid != self._jwk["kid"]:
            return None
        return pyjwt.PyJWK.from_dict(self._jwk).key

    async def ready(self) -> bool:
        return True


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def _claims(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    values.update(overrides)
    return values


def _token(**overrides: object) -> str:
    claims = _claims(
        iat=int(NOW.timestamp()),
        nbf=int(NOW.timestamp()),
        jti=str(uuid.uuid4()),
        scope="documents:read documents:write",
    )
    claims.update(overrides)
    return pyjwt.encode(claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})


def _mapping(**overrides: object) -> JwtClaimMapping:
    values: dict[str, object] = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "algorithms": ("RS256",),
    }
    values.update(overrides)
    return JwtClaimMapping(**values)  # type: ignore[arg-type]


def _validator(**overrides: object) -> JwtTokenValidator:
    return JwtTokenValidator(
        mapping=_mapping(**overrides),
        keys=KeySource(),
        clock=Clock(),
        leeway=timedelta(seconds=60),
    )


# --- Happy path and claim mapping -------------------------------------------


def test_valid_token_yields_metadata_without_the_raw_token() -> None:
    import asyncio

    token = _token()
    result = asyncio.run(_validator().validate(token))
    assert result.subject == "user-123"
    assert result.metadata.issuer == ISSUER
    assert result.metadata.audience == AUDIENCE
    assert result.metadata.jti is not None
    assert result.metadata.expires_at is not None
    assert token not in repr(result)
    assert token not in str(result.metadata)


def test_scope_claim_becomes_scopes() -> None:
    import asyncio

    result = asyncio.run(_validator().validate(_token(scope="a:read b:write")))
    assert result.scopes == frozenset({"a:read", "b:write"})


def test_scp_list_claim_becomes_scopes() -> None:
    import asyncio

    result = asyncio.run(_validator().validate(_token(scope="", scp=["a:read", "b:write"])))
    assert result.scopes == frozenset({"a:read", "b:write"})


def test_arbitrary_claims_never_become_privileges() -> None:
    import asyncio

    token = _token(
        roles=["admin", "tenant-owner"],
        permissions=["*:*"],
        groups=["platform-admins"],
        ent=["everything"],
        is_admin=True,
    )
    result = asyncio.run(_validator().validate(token))
    assert result.scopes == frozenset({"documents:read", "documents:write"})
    assert "admin" not in result.scopes


def test_client_id_prefers_client_id_then_azp() -> None:
    import asyncio

    first = asyncio.run(_validator().validate(_token(client_id="app-1")))
    assert first.metadata.client_id == "app-1"
    second = asyncio.run(_validator().validate(_token(azp="app-2")))
    assert second.metadata.client_id == "app-2"


# --- Negative cases (spec #56) ---------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"exp": int((NOW - timedelta(minutes=5)).timestamp())}, ExpiredToken),
        ({"nbf": int((NOW + timedelta(minutes=10)).timestamp())}, InvalidToken),
        ({"iat": int((NOW + timedelta(minutes=10)).timestamp())}, InvalidToken),
        ({"iss": "https://evil.example.com"}, InvalidToken),
        ({"aud": "other-api"}, InvalidToken),
        ({"sub": None}, InvalidToken),
    ],
)
def test_invalid_tokens_fail_closed(
    overrides: dict[str, object], expected: type[Exception]
) -> None:
    import asyncio

    with pytest.raises(expected):
        asyncio.run(_validator().validate(_token(**overrides)))


def test_invalid_signature_fails_closed() -> None:
    import asyncio

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = pyjwt.encode(
        _claims(),
        other_key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(InvalidToken):
        asyncio.run(_validator().validate(forged))


def test_unsigned_token_is_never_accepted() -> None:
    import asyncio

    unsigned = pyjwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u"},
        key=None,
        algorithm="none",
        headers={"kid": KID},
    )
    with pytest.raises(InvalidToken):
        asyncio.run(_validator().validate(unsigned))


def test_symmetric_algorithm_is_never_accepted_for_public_keys() -> None:
    import asyncio

    symmetric = pyjwt.encode(
        _claims(),
        "shared-secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
        headers={"kid": KID},
    )
    with pytest.raises(InvalidToken):
        asyncio.run(_validator().validate(symmetric))


def test_unknown_kid_fails_closed() -> None:
    import asyncio

    token = pyjwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "u",
            "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        },
        _PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": "rotated-away"},
    )
    validator = JwtTokenValidator(mapping=_mapping(), keys=KeySource(), clock=Clock())
    with pytest.raises(InvalidToken):
        asyncio.run(validator.validate(token))


def test_malformed_token_fails_closed() -> None:
    import asyncio

    with pytest.raises(InvalidToken):
        asyncio.run(_validator().validate("not-a-jwt"))


# --- Configuration and contract --------------------------------------------


@pytest.mark.parametrize("algorithm", ["none", "HS256"])
def test_unsafe_algorithm_configuration_is_rejected(algorithm: str) -> None:
    with pytest.raises(SecurityConfigurationError):
        _mapping(algorithms=(algorithm,))


def test_validator_implements_the_core_port() -> None:
    assert isinstance(_validator(), TokenValidator)


def test_ready_reflects_key_availability() -> None:
    import asyncio

    class Empty:
        async def signing_key(self, kid: str) -> object | None:
            return None

        async def ready(self) -> bool:
            return False

    validator = JwtTokenValidator(mapping=_mapping(), keys=Empty(), clock=Clock())
    assert asyncio.run(validator.ready()) is False
    assert asyncio.run(_validator().ready()) is True
