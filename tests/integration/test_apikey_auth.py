import uuid
from datetime import timedelta

import sqlalchemy as sa

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret
from jdlib.context import PrincipalKind
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import ApiKey, ServiceAccount, Tenant
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock


def _request(token: str | None) -> RequestInfo:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return RequestInfo(headers=headers, query={}, path="/", host="h")


async def _seed_key(control_session_factory, *, status="active", expired=False, sa_status="active"):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    prefix = f"jd.{uuid.uuid4().hex[:12]}"
    secret = "secret-abc"
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"ak-{tenant_id.hex[:8]}", name="AK", status="active")
        )
        await session.flush()
        session.add(
            ServiceAccount(tenant_id=tenant_id, id=account_id, name="svc", status=sa_status)
        )
        await session.flush()
        session.add(
            ApiKey(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                service_account_id=account_id,
                key_prefix=prefix,
                key_hash=hash_api_key_secret(secret),
                scopes=["resource:read"],
                status=status,
                expires_at=(FrozenClock().now() - timedelta(days=1)) if expired else None,
            )
        )
        await session.commit()
    return tenant_id, account_id, prefix, secret


async def test_valid_key_returns_pinned_service_account(control_session_factory):
    tenant_id, account_id, prefix, secret = await _seed_key(control_session_factory)
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    principal = await authenticator.authenticate(_request(f"{prefix}.{secret}"))
    assert principal is not None
    assert principal.kind is PrincipalKind.SERVICE_ACCOUNT
    assert principal.id == account_id
    assert principal.tenant_id == tenant_id
    assert principal.scopes == frozenset({"resource:read"})
    async with control_session_factory() as session:
        stored = (
            await session.execute(sa.select(ApiKey.last_used_at).where(ApiKey.key_prefix == prefix))
        ).scalar_one()
    assert stored is not None


async def test_wrong_secret_revoked_expired_and_suspended_denied(control_session_factory):
    _, _, prefix, secret = await _seed_key(control_session_factory)
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    assert await authenticator.authenticate(_request(f"{prefix}.wrong")) is None
    assert await authenticator.authenticate(_request("jd.unknown.key")) is None
    assert {entry["action"] for entry in audit.entries} == {"authn.failed"}
    _, _, revoked_prefix, revoked_secret = await _seed_key(
        control_session_factory, status="revoked"
    )
    assert (
        await authenticator.authenticate(_request(f"{revoked_prefix}.{revoked_secret}")) is None
    )
    _, _, expired_prefix, expired_secret = await _seed_key(control_session_factory, expired=True)
    assert (
        await authenticator.authenticate(_request(f"{expired_prefix}.{expired_secret}")) is None
    )
    _, _, suspended_prefix, suspended_secret = await _seed_key(
        control_session_factory, sa_status="suspended"
    )
    assert (
        await authenticator.authenticate(_request(f"{suspended_prefix}.{suspended_secret}")) is None
    )
