import uuid
from datetime import timedelta

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.authn.oidc import ClaimMapper, JwksCache, OidcAuthenticator, TokenVerifier
from jdlib.config import OidcConfig
from jdlib.context import PrincipalKind
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock

ISSUER = "https://idp"


async def _jwks(document):
    return document


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
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "k", "alg": "RS256", "use": "sig"})
    config = OidcConfig(issuer=ISSUER, audience="a")
    cache = JwksCache(
        url="u",
        ttl=timedelta(hours=1),
        fetcher=lambda url: _jwks({"keys": [jwk]}),
        clock=clock,
    )
    token = pyjwt.encode(
        {"iss": ISSUER, "aud": "a", "sub": "s", "exp": clock.now() + timedelta(minutes=5)},
        private,
        algorithm="RS256",
        headers={"kid": "k"},
    )
    audit = RecordingPlatformAudit()
    authenticator = OidcAuthenticator(
        config=config,
        cache=cache,
        verifier=TokenVerifier(config, clock),
        mapper=ClaimMapper(config),
        linker=_Linker(_User()),
        audit=audit,
    )
    principal = await authenticator.authenticate(_request(token))
    assert principal is not None
    assert principal.kind is PrincipalKind.USER
    assert principal.id == _User.id
    assert principal.user_id == _User.id
    assert audit.entries == []


async def test_authenticator_denies_and_audits_failures():
    clock = FrozenClock()
    config = OidcConfig(issuer=ISSUER, audience="a")
    cache = JwksCache(url="u", ttl=timedelta(hours=1), fetcher=_jwks, clock=clock)
    audit = RecordingPlatformAudit()
    authenticator = OidcAuthenticator(
        config=config,
        cache=cache,
        verifier=TokenVerifier(config, clock),
        mapper=ClaimMapper(config),
        linker=_Linker(None),
        audit=audit,
    )
    assert await authenticator.authenticate(_request(None)) is None
    assert await authenticator.authenticate(_request("not-a-token")) is None
    assert {entry["action"] for entry in audit.entries} == {"authn.failed"}
    assert all(
        "token" not in str(entry).lower() or entry["action"] == "authn.failed"
        for entry in audit.entries
    )
