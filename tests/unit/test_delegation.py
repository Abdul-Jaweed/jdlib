"""Delegated and privileged access (successor Phase 5). RED first. ADR-3.

Delegation is not a second privilege model: it is ``PrivilegeContext`` with
``kind=DELEGATION``, validated against the descriptor the operator path already uses. Six
adversarial cases, one named test each: TTL expiry, absent justification, capability
mismatch, replay, a cross-tenant target, and use after the actor has been suspended.

There is no new enforcement point. ``validate_delegation`` decides nothing by itself - it
refuses, and the caller's existing enforcement point is the one that acts on that. The
positive controls at the end are as important as the refusals: a well-formed delegation must
pass, and an operator privilege must be untouched by a validator that is not about it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.context import (
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    validate_delegation,
)
from jdlib.errors import DelegationRefusedError

NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
CAPABILITY = "tenant.provision"


def _actor(tenant_id: uuid.UUID = TENANT_ID) -> Principal:
    return Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=tenant_id)


def _delegation(**overrides):
    values = {
        "kind": PrivilegeKind.DELEGATION,
        "capability": CAPABILITY,
        "justification": "ticket OPS-1234, break-glass for the acme migration",
        "actor": _actor(),
        "issued_at": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(minutes=25),
        "delegation_id": "dlg-0001",
    }
    values.update(overrides)
    return PrivilegeContext(**values)


def _validate(privilege, **overrides):
    kwargs = {
        "capability": CAPABILITY,
        "target_tenant_id": TENANT_ID,
        "now": NOW,
    }
    kwargs.update(overrides)
    return validate_delegation(privilege, **kwargs)


# --- the gate's six, one named test each ---------------------------------------------------


def test_an_expired_delegation_is_refused() -> None:
    """TTL is enforced through the descriptor's own liveness, not a parallel rule."""
    privilege = _delegation(expires_at=NOW - timedelta(seconds=1))

    with pytest.raises(DelegationRefusedError):
        _validate(privilege)


def test_a_delegation_without_justification_is_refused() -> None:
    for absent in (None, "", "   "):
        with pytest.raises(DelegationRefusedError):
            _validate(_delegation(justification=absent))


def test_a_delegation_for_another_capability_is_refused() -> None:
    with pytest.raises(DelegationRefusedError):
        _validate(_delegation(capability="tenant.destroy"))


def test_a_replayed_delegation_is_refused() -> None:
    privilege = _delegation()

    _validate(privilege, seen=set())

    with pytest.raises(DelegationRefusedError):
        _validate(privilege, seen={"dlg-0001"})


def test_a_delegation_targeting_another_tenant_is_refused() -> None:
    """The actor's tenant and the target must be the same; a delegation is not a skeleton key."""
    with pytest.raises(DelegationRefusedError):
        _validate(_delegation(), target_tenant_id=OTHER_TENANT_ID)

    with pytest.raises(DelegationRefusedError):
        _validate(_delegation(actor=_actor(OTHER_TENANT_ID)), target_tenant_id=TENANT_ID)


def test_a_delegation_is_refused_once_the_actor_is_suspended() -> None:
    with pytest.raises(DelegationRefusedError):
        _validate(_delegation(), is_suspended=lambda actor_id: True)


# --- positive controls: the refusals must not be indiscriminate ----------------------------


def test_a_well_formed_delegation_is_accepted() -> None:
    _validate(_delegation(), is_suspended=lambda actor_id: False)


def test_a_delegation_without_an_identifier_is_refused() -> None:
    """Replay protection is worthless if the identifier is optional in practice."""
    for absent in (None, ""):
        with pytest.raises(DelegationRefusedError):
            _validate(_delegation(delegation_id=absent))


def test_an_operator_privilege_is_not_subject_to_delegation_rules() -> None:
    """The validator is about delegations; the operator path keeps its own semantics."""
    operator = PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability=CAPABILITY,
        justification="platform incident",
        actor=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=TENANT_ID),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )

    _validate(operator)
