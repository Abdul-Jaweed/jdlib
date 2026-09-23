import uuid
from datetime import timedelta

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret
from jdlib.authn.composite import CompositeAuthenticator
from jdlib.authn.oidc import ClaimMapper, JwksCache, OidcAuthenticator, TokenVerifier
from jdlib.config import OidcConfig
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import ApiKey, ServiceAccount, Tenant
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock

ISSUER = "https://idp"


class _User:
    id = uuid.uuid4()


class _Linker:
    def __init__(self, user) -> None:
        self._user = user

    async def link(self, claims):
        return self._user


def _request(token: str) -> RequestInfo:
    return RequestInfo(headers={"authorization": f"Bearer {token}"}, query={}, path="/", host="h")


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "k", "alg": "RS256", "use": "sig"})
    return private, {"keys": [jwk]}


def _jwt(private, *, clock) -> str:
    return pyjwt.encode(
        {"iss": ISSUER, "aud": "a", "sub": "s", "exp": clock.now() + timedelta(minutes=5)},
        private,
        algorithm="RS256",
        headers={"kid": "k"},
    )


def _oidc_authenticator(*, clock, audit, linker, jwks=None, fetcher=None):
    config = OidcConfig(issuer=ISSUER, audience="a")
    if fetcher is None:

        async def fetcher(url):
            return jwks

    return OidcAuthenticator(
        config=config,
        cache=JwksCache(url="u", ttl=timedelta(hours=1), fetcher=fetcher, clock=clock),
        verifier=TokenVerifier(config, clock),
        mapper=ClaimMapper(config),
        linker=linker,
        audit=audit,
    )


async def _seed_api_key(control_session_factory):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    prefix = f"jd.k{uuid.uuid4().hex[:8]}"
    secret = "secret-abc"
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"cx-{tenant_id.hex[:8]}", name="CX", status="active")
        )
        await session.flush()
        session.add(
            ServiceAccount(tenant_id=tenant_id, id=account_id, name="svc", status="active")
        )
        await session.flush()
        session.add(
            ApiKey(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                service_account_id=account_id,
                key_prefix=prefix,
                key_hash=hash_api_key_secret(secret),
                status="active",
            )
        )
        await session.commit()
    return account_id, f"{prefix}.{secret}"


async def test_valid_jwt_through_api_key_first_composite_audits_nothing(
    control_session_factory,
):
    clock = FrozenClock()
    private, jwks = _keypair()
    audit = RecordingPlatformAudit()
    user = _User()
    composite = CompositeAuthenticator(
        [
            ApiKeyAuthenticator(
                session_factory=control_session_factory, audit=audit, clock=FrozenClock()
            ),
            _oidc_authenticator(clock=clock, audit=audit, linker=_Linker(user), jwks=jwks),
        ]
    )
    principal = await composite.authenticate(_request(_jwt(private, clock=clock)))
    assert principal is not None
    assert principal.id == user.id
    assert audit.entries == []


async def test_valid_api_key_through_oidc_first_composite_audits_nothing(
    control_session_factory,
):
    account_id, token = await _seed_api_key(control_session_factory)
    clock = FrozenClock()
    audit = RecordingPlatformAudit()

    async def _never_fetched(url):
        raise AssertionError("jwks must not be fetched for an api key")

    composite = CompositeAuthenticator(
        [
            _oidc_authenticator(
                clock=clock, audit=audit, linker=_Linker(_User()), fetcher=_never_fetched
            ),
            ApiKeyAuthenticator(
                session_factory=control_session_factory, audit=audit, clock=FrozenClock()
            ),
        ]
    )
    principal = await composite.authenticate(_request(token))
    assert principal is not None
    assert principal.id == account_id
    assert audit.entries == []
