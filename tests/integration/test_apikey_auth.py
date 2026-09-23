import uuid
from datetime import timedelta
from typing import NamedTuple

import sqlalchemy as sa

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret
from jdlib.context import PrincipalKind
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import ApiKey, ServiceAccount, Tenant
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock


class _SeededKey(NamedTuple):
    tenant_id: uuid.UUID
    account_id: uuid.UUID
    prefix: str
    secret: str
    key_hash: str


def _request(token: str | None) -> RequestInfo:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return RequestInfo(headers=headers, query={}, path="/", host="h")


def _header_request(value: str | None) -> RequestInfo:
    headers = {} if value is None else {"authorization": value}
    return RequestInfo(headers=headers, query={}, path="/", host="h")


async def _seed_key(
    control_session_factory, *, status="active", expired=False, sa_status="active"
) -> _SeededKey:
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    prefix = f"jd.{uuid.uuid4().hex[:12]}"
    secret = "secret-abc"
    key_hash = hash_api_key_secret(secret)
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
                key_hash=key_hash,
                scopes=["resource:read"],
                status=status,
                expires_at=(FrozenClock().now() - timedelta(days=1)) if expired else None,
            )
        )
        await session.commit()
    return _SeededKey(tenant_id, account_id, prefix, secret, key_hash)


async def test_valid_key_returns_pinned_service_account(control_session_factory):
    seeded = await _seed_key(control_session_factory)
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    principal = await authenticator.authenticate(_request(f"{seeded.prefix}.{seeded.secret}"))
    assert principal is not None
    assert principal.kind is PrincipalKind.SERVICE_ACCOUNT
    assert principal.id == seeded.account_id
    assert principal.tenant_id == seeded.tenant_id
    assert principal.scopes == frozenset({"resource:read"})
    async with control_session_factory() as session:
        stored = (
            await session.execute(
                sa.select(ApiKey.last_used_at).where(ApiKey.key_prefix == seeded.prefix)
            )
        ).scalar_one()
    assert stored is not None
    assert audit.entries == []


async def test_every_denial_path_audits_exact_reason_without_key_material(
    control_session_factory,
):
    seeded = await _seed_key(control_session_factory)
    revoked = await _seed_key(control_session_factory, status="revoked")
    expired = await _seed_key(control_session_factory, expired=True)
    suspended = await _seed_key(control_session_factory, sa_status="suspended")
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    attempts = (
        (_request("not-a-key"), "InvalidToken"),
        (_request("jd.unknown.key"), "invalid_api_key"),
        (_request(f"{seeded.prefix}.wrong"), "invalid_api_key"),
        (_request(f"{revoked.prefix}.{revoked.secret}"), "invalid_api_key"),
        (_request(f"{expired.prefix}.{expired.secret}"), "invalid_api_key"),
        (_request(f"{suspended.prefix}.{suspended.secret}"), "invalid_api_key"),
    )
    for request, _reason in attempts:
        assert await authenticator.authenticate(request) is None
    assert len(audit.entries) == len(attempts)
    assert [entry["action"] for entry in audit.entries] == ["authn.failed"] * len(attempts)
    assert [entry["metadata"] for entry in audit.entries] == [
        {"reason": reason} for _request_value, reason in attempts
    ]
    assert [entry["tenant_id"] for entry in audit.entries] == [None] * len(attempts)
    assert [entry["actor_id"] for entry in audit.entries] == [None] * len(attempts)
    rendered = repr(audit.entries)
    material = (
        "not-a-key",
        "jd.unknown.key",
        seeded.prefix,
        seeded.secret,
        seeded.key_hash,
        f"{seeded.prefix}.{seeded.secret}",
        f"{seeded.prefix}.wrong",
        revoked.prefix,
        revoked.secret,
        revoked.key_hash,
        f"{revoked.prefix}.{revoked.secret}",
        expired.prefix,
        expired.secret,
        expired.key_hash,
        f"{expired.prefix}.{expired.secret}",
        suspended.prefix,
        suspended.secret,
        suspended.key_hash,
        f"{suspended.prefix}.{suspended.secret}",
    )
    for value in material:
        assert value not in rendered


async def test_missing_or_malformed_bearer_header_denies_without_audit(
    control_session_factory,
):
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    for value in (None, "", "Basic abc", "Bearer", "Bearer "):
        assert await authenticator.authenticate(_header_request(value)) is None
    assert audit.entries == []
