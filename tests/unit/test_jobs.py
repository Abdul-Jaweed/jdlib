import uuid

import pytest

from jdlib.config import ContextConfig
from jdlib.context import (
    EnvelopeCodec,
    Principal,
    PrincipalKind,
    TenantContext,
    TenantRecord,
    current_tenant,
)
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import (
    InvalidToken,
    MissingTenantContext,
    TenantAccessDenied,
    TenantSuspended,
    UnknownPrincipal,
)
from jdlib.tenancy.jobs import ContextPropagator, tenant_job
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()


def _record() -> TenantRecord:
    return TenantRecord(
        id=TENANT_ID, slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=USER_ID),
        request_id="req-1",
        correlation_id="corr-1",
    )


def _propagator(
    *,
    active: set[uuid.UUID] | None = None,
    suspended: set[uuid.UUID] | None = None,
    allowed: bool = True,
) -> tuple[ContextPropagator, EnvelopeCodec]:
    codec = EnvelopeCodec(config=ContextConfig(signing_key="k"), clock=FrozenClock())
    propagator = ContextPropagator(
        codec=codec,
        principals=StaticPrincipals(active if active is not None else {USER_ID}),
        tenants=DictTenants([_record()]),
        servability=ServabilityStub(suspended),
        entitlements=EntitlementsStub({(USER_ID, TENANT_ID)} if allowed else set()),
    )
    return propagator, codec


async def test_reconstruct_rebuilds_context_without_privilege():
    propagator, codec = _propagator()
    context = await propagator.reconstruct(codec.encode(_context()))
    assert context.tenant_id == TENANT_ID
    assert context.principal.kind is PrincipalKind.USER
    assert context.principal.id == USER_ID
    assert context.privilege is None
    assert context.request_id == "req-1"
    assert context.correlation_id == "corr-1"


async def test_reconstruct_rejects_deactivated_principal():
    propagator, codec = _propagator(active=set())
    with pytest.raises(UnknownPrincipal):
        await propagator.reconstruct(codec.encode(_context()))


async def test_reconstruct_rejects_revoked_membership():
    propagator, codec = _propagator(allowed=False)
    with pytest.raises(TenantAccessDenied):
        await propagator.reconstruct(codec.encode(_context()))


async def test_reconstruct_rejects_suspended_tenant():
    propagator, codec = _propagator(suspended={TENANT_ID})
    with pytest.raises(TenantSuspended):
        await propagator.reconstruct(codec.encode(_context()))


async def test_tenant_job_installs_and_clears_context():
    propagator, codec = _propagator()

    @tenant_job(propagator)
    async def handler() -> str:
        return str(current_tenant().tenant_id)

    assert await handler(codec.encode(_context())) == str(TENANT_ID)
    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_tenant_job_clears_context_on_error():
    propagator, codec = _propagator()

    @tenant_job(propagator)
    async def handler() -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await handler(codec.encode(_context()))
    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_tenant_job_rejects_bad_envelope():
    propagator, _ = _propagator()

    @tenant_job(propagator)
    async def handler() -> None:
        raise AssertionError("must not run")

    with pytest.raises(InvalidToken):
        await handler("garbage")
