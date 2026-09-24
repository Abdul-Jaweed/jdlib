"""Phase 6.5: the control plane already announces what it does — map it.

`jdlib.control` and its authentication helpers call `PlatformAudit.record(action=…)`
at every security-relevant transition: tenant lifecycle, authentication failures,
role and grant changes. Those call sites need no change; this adapter is the
seam's audit implementation and turns each action into a vocabulary event.

The mapping is the contract, so it is pinned two ways: every action the library
emits today must map (a test enumerates them), and an action nobody has seen
before must not crash the control plane — it is reported rather than invented
into a wrong category.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

import pytest

from jdlib.context import Principal, PrincipalKind, PrivilegeKind
from jdlib.security.audit import (
    AuditControlPlaneAudit,
    AuditOutcome,
    SecurityAuditEvent,
    SecurityEventType,
)

TENANT_A = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
ACTOR = uuid.UUID("99999999-8888-7777-6666-555555555555")

# Every action string the library records today (`grep -rn 'action=' src/jdlib`).
KNOWN_ACTIONS = (
    "tenant.created",
    "tenant.activated",
    "tenant.resumed",
    "tenant.suspended",
    "tenant.archived",
    "tenant.deprovisioned",
    "tenant.purge",
    "tenant.migration.succeeded",
    "tenant.migration.failed",
    "authn.failed",
    "role.created",
    "role.deleted",
    "role.permissions_changed",
    "resource.owner_changed",
)


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


async def _record(sink: _RecordingSink, action: str, **overrides) -> SecurityAuditEvent:
    adapter = AuditControlPlaneAudit(sink)
    kwargs = {
        "action": action,
        "tenant_id": TENANT_A,
        "actor_id": ACTOR,
        "metadata": None,
        "session": None,
        "actor_type": "user",
    }
    kwargs.update(overrides)
    await adapter.record(**kwargs)
    (event,) = sink.events
    return event


@pytest.mark.parametrize(
    ("action", "expected", "outcome"),
    (
        ("tenant.created", SecurityEventType.TENANT_CREATED, AuditOutcome.SUCCESS),
        ("tenant.activated", SecurityEventType.TENANT_RESUMED, AuditOutcome.SUCCESS),
        ("tenant.resumed", SecurityEventType.TENANT_RESUMED, AuditOutcome.SUCCESS),
        ("tenant.suspended", SecurityEventType.TENANT_SUSPENDED, AuditOutcome.SUCCESS),
        ("tenant.archived", SecurityEventType.TENANT_ARCHIVED, AuditOutcome.SUCCESS),
        ("tenant.deprovisioned", SecurityEventType.TENANT_DEPROVISIONED, AuditOutcome.SUCCESS),
        ("tenant.purge", SecurityEventType.TENANT_PURGED, AuditOutcome.SUCCESS),
        ("tenant.migration.succeeded", SecurityEventType.TENANT_PROVISIONED, AuditOutcome.SUCCESS),
        ("tenant.migration.failed", SecurityEventType.TENANT_PROVISIONED, AuditOutcome.FAILURE),
        ("authn.failed", SecurityEventType.AUTH_LOGIN_FAILURE, AuditOutcome.FAILURE),
        ("role.created", SecurityEventType.ROLE_ASSIGNED, AuditOutcome.SUCCESS),
        ("role.deleted", SecurityEventType.ROLE_REVOKED, AuditOutcome.SUCCESS),
        ("role.permissions_changed", SecurityEventType.PERMISSION_CHANGED, AuditOutcome.SUCCESS),
        ("resource.owner_changed", SecurityEventType.PERMISSION_CHANGED, AuditOutcome.SUCCESS),
    ),
)
async def test_every_action_the_library_records_maps_to_an_event(
    action: str, expected: SecurityEventType, outcome: AuditOutcome
) -> None:
    event = await _record(_RecordingSink(), action)
    assert event.event_type is expected
    assert event.outcome is outcome
    assert event.tenant_id == TENANT_A
    assert event.principal_id == ACTOR
    assert event.principal_kind == "user"
    assert event.metadata["control_action"] == action


def test_the_mapping_covers_the_whole_known_action_set() -> None:
    from jdlib.security.audit.adapters import CONTROL_ACTION_EVENTS

    missing = [action for action in KNOWN_ACTIONS if action not in CONTROL_ACTION_EVENTS]
    assert not missing, f"unmapped control actions: {missing}"


async def test_credential_actions_map_when_a_deployment_uses_them() -> None:
    for action, expected in (
        ("credential.created", SecurityEventType.CREDENTIAL_CREATED),
        ("credential.revoked", SecurityEventType.CREDENTIAL_REVOKED),
        ("credential.rotated", SecurityEventType.CREDENTIAL_ROTATED),
        ("privilege.expired", SecurityEventType.PRIVILEGE_EXPIRED),
        ("cross_tenant.denied", SecurityEventType.CROSS_TENANT_ACCESS_REJECTED),
        ("security.configuration_changed", SecurityEventType.SECURITY_CONFIGURATION_CHANGED),
    ):
        event = await _record(_RecordingSink(), action)
        assert event.event_type is expected, action


async def test_an_unknown_action_is_reported_not_invented() -> None:
    sink = _RecordingSink()
    await AuditControlPlaneAudit(sink).record(
        action="tenant.something_new",
        tenant_id=TENANT_A,
        actor_id=ACTOR,
        metadata={"why": "future"},
        session=None,
        actor_type="user",
    )
    assert sink.events == [], "an unmapped action must not be guessed into a category"


async def test_platform_level_actions_without_a_tenant_are_recorded() -> None:
    # Provisioning a tenant happens *before* the tenant exists, so tenant_id is
    # legitimately absent; the event must still be written.
    event = await _record(_RecordingSink(), "tenant.created", tenant_id=None, actor_id=None)
    assert event.event_type is SecurityEventType.TENANT_CREATED
    assert event.tenant_id is None


async def test_control_metadata_is_kept_and_sanitized() -> None:
    event = await _record(
        _RecordingSink(),
        "tenant.created",
        metadata={"slug": "acme", "dsn": "postgresql+asyncpg://app:s3cr3t-pw@db:5432/x"},
    )
    assert event.metadata["slug"] == "acme"
    assert "s3cr3t-pw" not in str(event.metadata)


async def test_the_adapter_also_serves_the_privilege_seat() -> None:
    # The control-plane sink is also the PrivilegeAudit implementation, so the
    # adapter must satisfy both seats without a second wiring step.
    sink = _RecordingSink()
    adapter = AuditControlPlaneAudit(sink)
    await adapter.record_privilege(
        kind=PrivilegeKind.OPERATOR,
        capability="platform.raw_sql",
        justification="incident",
        actor=Principal(id=ACTOR, kind=PrincipalKind.PLATFORM_OPERATOR),
        tenant_id=TENANT_A,
    )
    (event,) = sink.events
    assert event.event_type is SecurityEventType.PRIVILEGE_ISSUED
    assert event.metadata["control_action"] == "privilege.issued"


async def test_a_control_metadata_mapping_is_accepted() -> None:
    # The control plane passes mappings, not dicts; the adapter must not care.
    metadata: Mapping[str, object] = {"placement": "dedicated"}
    event = await _record(_RecordingSink(), "tenant.created", metadata=metadata)
    assert event.metadata["placement"] == "dedicated"
