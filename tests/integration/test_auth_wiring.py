import uuid

import pytest

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret
from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
)
from jdlib.authz.reader import ControlAccessReader
from jdlib.config import ContextConfig
from jdlib.context import (
    ContextFactory,
    EnvelopeCodec,
    Principal,
    PrincipalKind,
    TenantContext,
    TenantRef,
    current_tenant,
)
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import (
    ApiKey,
    Membership,
    ServiceAccount,
    Tenant,
    TenantMigrationState,
    TenantPlacement,
    User,
)
from jdlib.control.registry import TenantRegistry
from jdlib.errors import UnknownPrincipal
from jdlib.tenancy.jobs import ContextPropagator
from jdlib.tenancy.middleware import TenantMiddleware
from jdlib.tenancy.resolution import ApiKeyResolver, HeaderResolver, ResolverChain
from tests.support.context_fakes import FrozenClock, RecordingPrivilegeAudit


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return "0002_security_audit_columns"


class _OperatorStub:
    async def authorize(self, principal: Principal, capability: str) -> bool:
        return False


async def _seed_placed_tenant(session, tenant_id: uuid.UUID, slug: str) -> None:
    session.add(Tenant(id=tenant_id, slug=slug, name=slug, status="active"))
    await session.flush()
    session.add(
        TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default")
    )
    session.add(
        TenantMigrationState(
            tenant_id=tenant_id,
            current_version="0002_security_audit_columns",
            desired_version="0002_security_audit_columns",
            status="success",
        )
    )


async def test_tenant_directory_and_entitlement_adapters(control_session_factory):
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        audit=RecordingPlatformAudit(),
        desired_version="0002_security_audit_columns",
    )
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    outsider_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"wire-{tenant_id.hex[:8]}", name="W", status="active")
        )
        await session.flush()
        session.add(
            TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default")
        )
        session.add(
            TenantMigrationState(
                tenant_id=tenant_id,
                current_version="0002_security_audit_columns",
                desired_version="0002_security_audit_columns",
                status="success",
            )
        )
        session.add(User(id=user_id, status="active"))
        session.add(User(id=outsider_id, status="active"))
        await session.flush()
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=user_id, status="active")
        )
        await session.commit()
    directory = TenantDirectoryAdapter(registry)
    record = await directory.get(TenantRef(id=tenant_id))
    assert record is not None and record.status.value == "active"
    assert await directory.get(TenantRef()) is None
    assert await directory.get(TenantRef(slug="missing")) is None
    reader = ControlAccessReader(control_session_factory)
    principals = PrincipalDirectoryAdapter(reader)
    principal = Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)
    assert await principals.is_active(principal) is True
    assert await principals.is_active(Principal(kind=PrincipalKind.USER, id=uuid.uuid4())) is False
    entitlements = EntitlementAdapter(reader)
    assert await entitlements.can_act(principal, tenant_id) is True
    outsider = Principal(kind=PrincipalKind.USER, id=outsider_id, user_id=outsider_id)
    assert await entitlements.can_act(outsider, tenant_id) is False


async def test_api_key_principal_through_middleware(control_session_factory):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    secret = "s3cret"
    prefix = f"jd.k{uuid.uuid4().hex[:8]}"
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"mw-{tenant_id.hex[:8]}", name="MW", status="active")
        )
        await session.flush()
        session.add(
            TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default")
        )
        session.add(
            TenantMigrationState(
                tenant_id=tenant_id,
                current_version="0002_security_audit_columns",
                desired_version="0002_security_audit_columns",
                status="success",
            )
        )
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
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        audit=RecordingPlatformAudit(),
        desired_version="0002_security_audit_columns",
    )
    reader = ControlAccessReader(control_session_factory)
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=_OperatorStub(),
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )
    seen: list[uuid.UUID] = []

    async def inner(scope, receive, send):
        seen.append(current_tenant().tenant_id)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = TenantMiddleware(
        inner,
        factory=factory,
        chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug"), ApiKeyResolver()]),
        principal_provider=authenticator.authenticate,
    )

    async def receive():
        return {"type": "http.request"}

    sent: list[dict[str, object]] = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"authorization", f"Bearer {prefix}.{secret}".encode())],
    }
    await middleware(scope, receive, send)
    assert next(m["status"] for m in sent if m["type"] == "http.response.start") == 200
    assert seen == [tenant_id]


async def test_api_key_pinned_to_tenant_a_presenting_tenant_b_gets_404(
    control_session_factory,
):
    pinned_tenant = uuid.uuid4()
    other_tenant = uuid.uuid4()
    pinned_slug = f"pin-a-{pinned_tenant.hex[:8]}"
    other_slug = f"pin-b-{other_tenant.hex[:8]}"
    account_id = uuid.uuid4()
    secret = "s3cret"
    prefix = f"jd.k{uuid.uuid4().hex[:8]}"
    async with control_session_factory() as session:
        for tenant_id, slug in ((pinned_tenant, pinned_slug), (other_tenant, other_slug)):
            session.add(Tenant(id=tenant_id, slug=slug, name=slug, status="active"))
            await session.flush()
            session.add(
                TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default")
            )
            session.add(
                TenantMigrationState(
                    tenant_id=tenant_id,
                    current_version="0002_security_audit_columns",
                    desired_version="0002_security_audit_columns",
                    status="success",
                )
            )
        session.add(
            ServiceAccount(tenant_id=pinned_tenant, id=account_id, name="svc", status="active")
        )
        await session.flush()
        session.add(
            ApiKey(
                tenant_id=pinned_tenant,
                id=uuid.uuid4(),
                service_account_id=account_id,
                key_prefix=prefix,
                key_hash=hash_api_key_secret(secret),
                status="active",
            )
        )
        await session.commit()
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        audit=RecordingPlatformAudit(),
        desired_version="0002_security_audit_columns",
    )
    reader = ControlAccessReader(control_session_factory)
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=_OperatorStub(),
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )
    seen: list[uuid.UUID] = []

    async def inner(scope, receive, send):
        seen.append(current_tenant().tenant_id)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = TenantMiddleware(
        inner,
        factory=factory,
        chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug"), ApiKeyResolver()]),
        principal_provider=authenticator.authenticate,
    )

    async def receive():
        return {"type": "http.request"}

    sent: list[dict[str, object]] = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {prefix}.{secret}".encode()),
            (b"x-tenant-slug", other_slug.encode()),
        ],
    }
    await middleware(scope, receive, send)
    assert next(m["status"] for m in sent if m["type"] == "http.response.start") == 404
    assert seen == []


async def test_entitlement_adapter_denies_service_account_outside_its_tenant(
    control_session_factory,
):
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    account_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_a, slug=f"sa-a-{tenant_a.hex[:8]}", name="SA", status="active")
        )
        session.add(
            Tenant(id=tenant_b, slug=f"sa-b-{tenant_b.hex[:8]}", name="SB", status="active")
        )
        await session.flush()
        session.add(
            ServiceAccount(tenant_id=tenant_a, id=account_id, name="bot", status="active")
        )
        await session.commit()
    entitlements = EntitlementAdapter(ControlAccessReader(control_session_factory))
    pinned = Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id, tenant_id=tenant_a
    )
    assert await entitlements.can_act(pinned, tenant_a) is True
    assert await entitlements.can_act(pinned, tenant_b) is False
    unpinned = Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id)
    assert await entitlements.can_act(unpinned, tenant_a) is False


async def test_reconstruct_denies_service_account_absent_from_envelope_tenant(
    control_session_factory,
):
    envelope_tenant = uuid.uuid4()
    account_tenant = uuid.uuid4()
    envelope_slug = f"job-a-{envelope_tenant.hex[:8]}"
    account_id = uuid.uuid4()
    async with control_session_factory() as session:
        await _seed_placed_tenant(session, envelope_tenant, envelope_slug)
        await _seed_placed_tenant(session, account_tenant, f"job-b-{account_tenant.hex[:8]}")
        session.add(
            ServiceAccount(
                tenant_id=account_tenant, id=account_id, name="bot", status="active"
            )
        )
        await session.commit()
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        audit=RecordingPlatformAudit(),
        desired_version="0002_security_audit_columns",
    )
    reader = ControlAccessReader(control_session_factory)
    codec = EnvelopeCodec(config=ContextConfig(signing_key="k"), clock=FrozenClock())
    propagator = ContextPropagator(
        codec=codec,
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
    )
    token = codec.encode(
        TenantContext(
            tenant_id=envelope_tenant,
            tenant_slug=envelope_slug,
            strategy=PlacementStrategy.SHARED,
            principal=Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id),
            request_id="req-1",
            correlation_id="corr-1",
        )
    )
    with pytest.raises(UnknownPrincipal):
        await propagator.reconstruct(token)
