"""Phase 2: service identity formalisation (directive §13, spec #39).

Identities are never collapsed into a generic "user": human users, service
accounts, operator identities, system identities and anonymous principals are
distinct and are checked explicitly. Activities of one kind never satisfy a
check for another.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.context import Principal, PrincipalKind
from jdlib.errors import AuthorizationError, InvalidToken, TenantAccessDenied
from jdlib.security.identity import (
    IdentityKind,
    ServiceIdentity,
    assert_service_may_act,
    identity_kind,
    service_principal,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
OTHER_TENANT = uuid.UUID("33333333-3333-3333-3333-333333333333")


def _identity(**overrides: object) -> ServiceIdentity:
    values: dict[str, object] = {
        "principal_id": uuid.uuid4(),
        "tenant_id": TENANT_ID,
        "scopes": frozenset({"documents:read"}),
        "expires_at": NOW + timedelta(hours=1),
        "revoked_at": None,
    }
    values.update(overrides)
    return ServiceIdentity(**values)  # type: ignore[arg-type]


# --- Kind mapping ------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (PrincipalKind.USER, IdentityKind.HUMAN_USER),
        (PrincipalKind.SERVICE_ACCOUNT, IdentityKind.SERVICE_ACCOUNT),
        (PrincipalKind.PLATFORM_OPERATOR, IdentityKind.OPERATOR),
        (PrincipalKind.ANONYMOUS, IdentityKind.ANONYMOUS),
    ],
)
def test_principal_kinds_map_to_distinct_identity_kinds(
    kind: PrincipalKind, expected: IdentityKind
) -> None:
    principal = Principal(kind=kind, id=uuid.uuid4())
    assert identity_kind(principal) is expected


def test_unknown_principal_kind_fails_closed() -> None:
    class FakeKind:
        value = "smuggled"

    principal = Principal(kind=FakeKind(), id=uuid.uuid4())  # type: ignore[arg-type]
    with pytest.raises(AuthorizationError):
        identity_kind(principal)


# --- Service identity lifecycle ---------------------------------------------


def test_active_service_identity_may_act_in_its_tenant() -> None:
    identity = _identity()
    assert identity.is_active(NOW) is True
    assert_service_may_act(identity, tenant_id=TENANT_ID, now=NOW)


def test_expired_service_identity_is_rejected() -> None:
    identity = _identity(expires_at=NOW - timedelta(seconds=1))
    assert identity.is_active(NOW) is False
    with pytest.raises(InvalidToken):
        assert_service_may_act(identity, tenant_id=TENANT_ID, now=NOW)


def test_revoked_service_identity_is_rejected() -> None:
    identity = _identity(revoked_at=NOW - timedelta(minutes=1))
    assert identity.is_active(NOW) is False
    with pytest.raises(InvalidToken):
        assert_service_may_act(identity, tenant_id=TENANT_ID, now=NOW)


def test_service_identity_is_tenant_bound() -> None:
    identity = _identity()
    with pytest.raises(TenantAccessDenied):
        assert_service_may_act(identity, tenant_id=OTHER_TENANT, now=NOW)


def test_service_identity_cannot_be_unbound() -> None:
    with pytest.raises(ValueError):
        _identity(tenant_id=None)


def test_service_principal_keeps_its_kind() -> None:
    identity = _identity()
    principal = service_principal(identity)
    assert principal.kind is PrincipalKind.SERVICE_ACCOUNT
    assert principal.tenant_id == TENANT_ID
    assert principal.id == identity.principal_id
    assert principal.scopes == identity.scopes
    assert identity_kind(principal) is IdentityKind.SERVICE_ACCOUNT
    # never collapsed into "user"
    assert identity_kind(principal) is not IdentityKind.HUMAN_USER


def test_service_assertion_rejects_non_service_principals() -> None:
    human = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=TENANT_ID)
    with pytest.raises(AuthorizationError):
        assert_service_may_act(human, tenant_id=TENANT_ID, now=NOW)  # type: ignore[arg-type]
