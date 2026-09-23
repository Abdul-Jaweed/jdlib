import uuid
from datetime import timedelta

import pytest

from jdlib.config import ContextConfig
from jdlib.context import (
    ContextFactory,
    Principal,
    PrincipalKind,
    PrivilegeKind,
    TenantRecord,
    TenantRef,
)
from jdlib.control.enums import OperatorLevel, PlacementStrategy, TenantStatus
from jdlib.errors import (
    AuthorizationError,
    TenantAccessDenied,
    TenantNotFound,
    TenantSuspended,
    UnknownPrincipal,
)
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    OperatorsStub,
    RecordingPrivilegeAudit,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
OTHER_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000bb")
USER_ID = uuid.uuid4()
OPERATOR_ID = uuid.uuid4()
SERVICE_ACCOUNT_ID = uuid.uuid4()


def _record() -> TenantRecord:
    return TenantRecord(
        id=TENANT_ID, slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )


def _factory(
    *,
    active: set[uuid.UUID] | None = None,
    suspended: set[uuid.UUID] | None = None,
    allowed: set[tuple[uuid.UUID, uuid.UUID]] | None = None,
    capabilities: set[str] | None = None,
    allow_test: bool = False,
) -> tuple[ContextFactory, RecordingPrivilegeAudit]:
    audit = RecordingPrivilegeAudit()
    factory = ContextFactory(
        config=ContextConfig(
            signing_key="test-key", allow_test_contexts=allow_test
        ),
        principals=StaticPrincipals(active if active is not None else {USER_ID, OPERATOR_ID}),
        tenants=DictTenants([_record()]),
        servability=ServabilityStub(suspended),
        entitlements=EntitlementsStub(
            allowed if allowed is not None else {(USER_ID, TENANT_ID)}
        ),
        operators=OperatorsStub(capabilities or set()),
        audit=audit,
        clock=FrozenClock(),
    )
    return factory, audit


def _user() -> Principal:
    return Principal(kind=PrincipalKind.USER, id=USER_ID, user_id=USER_ID)


async def test_for_principal_happy_path():
    factory, _ = _factory()
    context = await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")
    assert context.tenant_id == TENANT_ID
    assert context.tenant_slug == "acme"
    assert context.strategy is PlacementStrategy.SHARED
    assert context.principal is not None
    assert context.privilege is None


async def test_for_principal_rejects_inactive_principal():
    factory, _ = _factory(active=set())
    with pytest.raises(UnknownPrincipal):
        await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")


async def test_for_principal_rejects_unknown_tenant():
    factory, _ = _factory()
    with pytest.raises(TenantNotFound):
        await factory.for_principal(_user(), TenantRef(slug="ghost"), request_id="req-1")


async def test_for_principal_rejects_non_servable_tenant():
    factory, _ = _factory(suspended={TENANT_ID})
    with pytest.raises(TenantSuspended):
        await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")


async def test_for_principal_rejects_unentitled_principal():
    factory, _ = _factory(allowed=set())
    with pytest.raises(TenantAccessDenied):
        await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")


def _service_account(tenant_id: uuid.UUID | None) -> Principal:
    return Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=SERVICE_ACCOUNT_ID, tenant_id=tenant_id)


def _pin_factory(
    *,
    allowed: set[tuple[uuid.UUID, uuid.UUID]],
    suspended: set[uuid.UUID] | None = None,
) -> ContextFactory:
    other = TenantRecord(
        id=OTHER_TENANT_ID,
        slug="other",
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SHARED,
    )
    return ContextFactory(
        config=ContextConfig(signing_key="test-key"),
        principals=StaticPrincipals({SERVICE_ACCOUNT_ID}),
        tenants=DictTenants([_record(), other]),
        servability=ServabilityStub(suspended),
        entitlements=EntitlementsStub(allowed),
        operators=OperatorsStub(),
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )


async def test_for_principal_allows_matching_service_account_tenant_pin():
    factory = _pin_factory(allowed={(SERVICE_ACCOUNT_ID, TENANT_ID)})
    context = await factory.for_principal(
        _service_account(TENANT_ID), TenantRef(slug="acme"), request_id="req-1"
    )
    assert context.tenant_id == TENANT_ID
    assert context.principal.tenant_id == TENANT_ID


async def test_for_principal_denies_mismatched_service_account_tenant_pin():
    factory = _pin_factory(
        allowed={(SERVICE_ACCOUNT_ID, OTHER_TENANT_ID)}, suspended={OTHER_TENANT_ID}
    )
    with pytest.raises(TenantAccessDenied):
        await factory.for_principal(
            _service_account(TENANT_ID), TenantRef(slug="other"), request_id="req-1"
        )


async def test_for_principal_denies_mismatched_pin_before_entitlement_and_servability():
    factory = _pin_factory(
        allowed={(SERVICE_ACCOUNT_ID, TENANT_ID)}, suspended={TENANT_ID}
    )
    with pytest.raises(TenantAccessDenied):
        await factory.for_principal(
            _service_account(OTHER_TENANT_ID), TenantRef(slug="acme"), request_id="req-1"
        )


async def test_for_operator_requires_platform_operator_kind():
    factory, _ = _factory()
    operator = Principal(kind=PrincipalKind.USER, id=OPERATOR_ID)
    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="ticket-1", request_id="req-1",
        )


async def test_for_operator_requires_justification_and_capability():
    factory, _ = _factory()
    operator = Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="  ", request_id="req-1",
        )
    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="ticket-1", request_id="req-1",
        )


async def test_for_operator_creates_audited_expiring_privilege():
    factory, audit = _factory(capabilities={"platform.tenant.access"})
    operator = Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    context = await factory.for_operator(
        operator, TenantRef(slug="acme"), "platform.tenant.access",
        justification="ticket-1", request_id="req-1",
    )
    assert context.privilege is not None
    assert context.privilege.kind is PrivilegeKind.OPERATOR
    assert context.privilege.expires_at is not None
    assert context.privilege.expires_at > context.privilege.issued_at
    assert audit.records == [
        {
            "kind": PrivilegeKind.OPERATOR,
            "capability": "platform.tenant.access",
            "justification": "ticket-1",
            "actor_id": OPERATOR_ID,
            "tenant_id": TENANT_ID,
        }
    ]


async def test_for_operator_rejects_ttl_above_maximum():
    factory, _ = _factory(capabilities={"platform.tenant.access"})
    operator = Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )

    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="ticket-1", ttl=timedelta(hours=2), request_id="req-1",
        )


async def test_for_operator_rejects_non_positive_ttl():
    factory, _ = _factory(capabilities={"platform.tenant.access"})
    operator = Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    for ttl in (timedelta(0), timedelta(seconds=-1)):
        with pytest.raises(AuthorizationError):
            await factory.for_operator(
                operator, TenantRef(slug="acme"), "platform.tenant.access",
                justification="ticket-1", ttl=ttl, request_id="req-1",
            )


async def test_for_operator_accepts_ttl_at_maximum():
    factory, _ = _factory(capabilities={"platform.tenant.access"})
    operator = Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    context = await factory.for_operator(
        operator, TenantRef(slug="acme"), "platform.tenant.access",
        justification="ticket-1", ttl=timedelta(minutes=30), request_id="req-1",
    )
    assert context.privilege is not None
    assert context.privilege.expires_at is not None
    assert context.privilege.expires_at - context.privilege.issued_at == timedelta(minutes=30)


async def test_for_system_requires_issuer_capability():
    factory, audit = _factory()
    with pytest.raises(AuthorizationError):
        await factory.for_system(
            _record(),
            purpose="migration",
            issuer=object(),  # type: ignore[arg-type]
        )
    from jdlib.context import PRIVILEGE_ISSUER

    context = await factory.for_system(_record(), purpose="migration", issuer=PRIVILEGE_ISSUER)
    assert context.privilege is not None
    assert context.privilege.kind is PrivilegeKind.SYSTEM
    assert context.privilege.capability == "migration"
    assert audit.records == [
        {
            "kind": PrivilegeKind.SYSTEM,
            "capability": "migration",
            "justification": None,
            "actor_id": context.privilege.actor.id,
            "tenant_id": TENANT_ID,
        }
    ]


async def test_for_test_is_gated_by_config():
    factory, audit = _factory()
    from jdlib.context import PRIVILEGE_ISSUER

    with pytest.raises(AuthorizationError):
        await factory.for_test(_record(), principal=_user(), issuer=PRIVILEGE_ISSUER)
    assert audit.records == []
    factory, audit = _factory(allow_test=True)
    context = await factory.for_test(_record(), principal=_user(), issuer=PRIVILEGE_ISSUER)
    assert context.privilege is not None
    assert context.privilege.kind is PrivilegeKind.TEST
    assert audit.records == [
        {
            "kind": PrivilegeKind.TEST,
            "capability": None,
            "justification": None,
            "actor_id": USER_ID,
            "tenant_id": TENANT_ID,
        }
    ]


async def test_for_test_rejects_non_issuer():
    factory, _ = _factory(allow_test=True)
    with pytest.raises(AuthorizationError):
        await factory.for_test(
            _record(),
            principal=_user(),
            issuer=object(),  # type: ignore[arg-type]
        )
