"""The identifiers a privilege grant was made under, on the row that records it.

`for_operator` has always taken ``request_id``/``correlation_id``/``trace_id`` and put
them on the tenant context it returns. The audit row written beside that context carried
none of them, and the reason matters: the platform sink accepts all three (falling back
to the ambient tenant context), but the operator surface deliberately runs *outside* the
tenant middleware, so there is no ambient context to fall back to. The one row a reviewer
would look for by request id was the row with no request id.

Found by inspecting a real row (`jd_control.platform_audit_events`, action
``privilege.operator``) after a gateway walkthrough: the `AUTHZ_ALLOW` rows beside it
carried both identifiers.
"""

from __future__ import annotations

import uuid

from jdlib.config import ContextConfig
from jdlib.context import ContextFactory, Principal, PrincipalKind, TenantRecord, TenantRef
from jdlib.control.audit import PrivilegeAuditAdapter, RecordingPlatformAudit
from jdlib.control.enums import OperatorLevel, PlacementStrategy, TenantStatus
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    OperatorsStub,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
OPERATOR_ID = uuid.uuid4()
CAPABILITY = "platform.tenant.access"


def _factory() -> tuple[ContextFactory, RecordingPlatformAudit]:
    """The real privilege-audit adapter over a recording *platform* sink."""
    sink = RecordingPlatformAudit()
    factory = ContextFactory(
        config=ContextConfig(signing_key="test-key"),
        principals=StaticPrincipals({OPERATOR_ID}),
        tenants=DictTenants(
            [
                TenantRecord(
                    id=TENANT_ID,
                    slug="acme",
                    status=TenantStatus.ACTIVE,
                    strategy=PlacementStrategy.SHARED,
                )
            ]
        ),
        servability=ServabilityStub(),
        entitlements=EntitlementsStub(set()),
        operators=OperatorsStub({CAPABILITY}),
        audit=PrivilegeAuditAdapter(sink),
        clock=FrozenClock(),
    )
    return factory, sink


def _operator() -> Principal:
    return Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )


async def test_the_operator_row_carries_the_ids_the_grant_was_made_under() -> None:
    factory, sink = _factory()

    await factory.for_operator(
        _operator(),
        TenantRef(slug="acme"),
        CAPABILITY,
        justification="ticket-1",
        request_id="req-1",
        correlation_id="corr-1",
        trace_id="trace-1",
    )

    entry = sink.entries[-1]
    assert entry["action"] == "privilege.operator"
    assert entry["request_id"] == "req-1"
    assert entry["correlation_id"] == "corr-1"
    assert entry["trace_id"] == "trace-1"


async def test_the_row_still_records_when_only_some_ids_are_known() -> None:
    """A correlation id is not always there; the row must not be lost without one."""
    factory, sink = _factory()

    await factory.for_operator(
        _operator(),
        TenantRef(slug="acme"),
        CAPABILITY,
        justification="ticket-1",
        request_id="req-2",
    )

    entry = sink.entries[-1]
    assert entry["request_id"] == "req-2"
    assert entry["correlation_id"] is None
    assert entry["tenant_id"] == TENANT_ID
    assert entry["actor_id"] == OPERATOR_ID
