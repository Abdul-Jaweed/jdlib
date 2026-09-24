import uuid
from datetime import timedelta

import jwt as pyjwt
import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.authn.oidc import ClaimMapper, JwksCache, OidcAuthenticator, TokenVerifier
from jdlib.config import OidcConfig
from jdlib.context import PrincipalKind
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.errors import AuthenticationUnavailable, TenantNotFound
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock

ISSUER = "https://idp"


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "k", "alg": "RS256", "use": "sig"})
    return private, {"keys": [jwk]}


def _token(private, *, clock, kid: str | None = "k") -> str:
    headers = {"kid": kid} if kid is not None else {}
    return pyjwt.encode(
        {"iss": ISSUER, "aud": "a", "sub": "s", "exp": clock.now() + timedelta(minutes=5)},
        private,
        algorithm="RS256",
        headers=headers,
    )


def _authenticator(
    *,
    jwks,
    linker,
    audit,
    clock,
    fetcher=None,
) -> OidcAuthenticator:
    config = OidcConfig(issuer=ISSUER, audience="a")
    if fetcher is None:

        async def fetcher(url):
            return jwks

    cache = JwksCache(url="u", ttl=timedelta(hours=1), fetcher=fetcher, clock=clock)
    return OidcAuthenticator(
        config=config,
        cache=cache,
        verifier=TokenVerifier(config, clock),
        mapper=ClaimMapper(config),
        linker=linker,
        audit=audit,
    )


class _User:
    id = uuid.uuid4()
    email = "u@example.com"
    status = "active"


class _Linker:
    def __init__(self, user) -> None:
        self._user = user

    async def link(self, claims):
        return self._user


def _request(token: str | None) -> RequestInfo:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return RequestInfo(headers=headers, query={}, path="/", host="h")


async def test_authenticator_returns_user_principal():
    clock = FrozenClock()
    private, jwks = _keypair()
    audit = RecordingPlatformAudit()
    authenticator = _authenticator(
        jwks=jwks, linker=_Linker(_User()), audit=audit, clock=clock
    )
    principal = await authenticator.authenticate(_request(_token(private, clock=clock)))
    assert principal is not None
    assert principal.kind is PrincipalKind.USER
    assert principal.id == _User.id
    assert principal.user_id == _User.id
    assert audit.entries == []


async def test_authenticator_ignores_tokens_outside_its_scheme_without_audit():
    clock = FrozenClock()
    private, jwks = _keypair()
    audit = RecordingPlatformAudit()
    authenticator = _authenticator(
        jwks=jwks, linker=_Linker(_User()), audit=audit, clock=clock
    )
    tokens = (None, "not-a-token", "jd.keyid.secret", _token(private, clock=clock, kid=None))
    for token in tokens:
        assert await authenticator.authenticate(_request(token)) is None
    assert audit.entries == []


async def test_authenticator_audits_jwt_failures_without_token_material():
    clock = FrozenClock()
    private, jwks = _keypair()
    other_private, _ = _keypair()
    audit = RecordingPlatformAudit()
    authenticator = _authenticator(
        jwks=jwks, linker=_Linker(None), audit=audit, clock=clock
    )
    tampered = _token(other_private, clock=clock)
    assert await authenticator.authenticate(_request(tampered)) is None
    assert await authenticator.authenticate(_request(_token(private, clock=clock))) is None
    assert [entry["metadata"]["reason"] for entry in audit.entries] == [
        "InvalidToken",
        "unlinked_identity",
    ]
    for entry in audit.entries:
        assert set(entry["metadata"]) == {"reason"}
    assert tampered not in str(audit.entries)


async def test_authenticator_fails_closed_when_jwks_fetch_raises():
    """A failed key lookup is an outage, and still never an authentication.

    The property is unchanged - nothing is authenticated when the key set cannot
    be read - but the answer changed from "no credential" to "provider
    unavailable". `None` became `401 no credentials presented` at the middleware,
    which tells a caller with a perfectly good token to go and fix it, and hides
    an outage behind a credential metric. See
    `tests/unit/security/test_adversarial_authn_outage.py` for the claim and the
    guard against over-blocking.
    """
    clock = FrozenClock()
    private, jwks = _keypair()

    async def failing_fetch(url):
        raise RuntimeError("jwks unavailable")

    audit = RecordingPlatformAudit()
    authenticator = _authenticator(
        jwks=jwks,
        linker=_Linker(_User()),
        audit=audit,
        clock=clock,
        fetcher=failing_fetch,
    )
    token = _token(private, clock=clock)
    with pytest.raises(AuthenticationUnavailable) as raised:
        await authenticator.authenticate(_request(token))
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert [entry["metadata"]["reason"] for entry in audit.entries] == ["RuntimeError"]
    assert token not in str(audit.entries)


async def test_authenticator_fails_closed_when_linking_raises():
    clock = FrozenClock()
    private, jwks = _keypair()

    class _BrokenLinker:
        def __init__(self, exc) -> None:
            self._exc = exc

        async def link(self, claims):
            raise self._exc

    for exc, reason in (
        (TenantNotFound("x"), "TenantNotFound"),
        (sa.exc.SQLAlchemyError("db down"), "SQLAlchemyError"),
    ):
        audit = RecordingPlatformAudit()
        authenticator = _authenticator(
            jwks=jwks, linker=_BrokenLinker(exc), audit=audit, clock=clock
        )
        token = _token(private, clock=clock)
        assert await authenticator.authenticate(_request(token)) is None
        assert [entry["metadata"]["reason"] for entry in audit.entries] == [reason]
        assert token not in str(audit.entries)
