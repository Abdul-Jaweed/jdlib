"""Service identity formalisation (directive §13, spec #39).

Human users, service accounts, operator identities, system identities and
anonymous principals stay distinct; a check for one kind is never satisfied by
another. Service identities are tenant-bound, scope-limited and time-bounded,
and support revocation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from jdlib.context import Principal, PrincipalKind
from jdlib.errors import AuthorizationError, InvalidToken, TenantAccessDenied


class IdentityKind(StrEnum):
    """Externally meaningful identity categories (never collapsed into "user")."""

    HUMAN_USER = "human_user"
    SERVICE_ACCOUNT = "service_account"
    OPERATOR = "operator"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


_KINDS: dict[PrincipalKind, IdentityKind] = {
    PrincipalKind.USER: IdentityKind.HUMAN_USER,
    PrincipalKind.SERVICE_ACCOUNT: IdentityKind.SERVICE_ACCOUNT,
    PrincipalKind.PLATFORM_OPERATOR: IdentityKind.OPERATOR,
    PrincipalKind.ANONYMOUS: IdentityKind.ANONYMOUS,
}


def identity_kind(principal: Principal) -> IdentityKind:
    """Map a principal onto its identity kind, failing closed when unknown."""
    try:
        return _KINDS[principal.kind]
    except (KeyError, TypeError):
        raise AuthorizationError(f"unknown principal kind: {principal.kind!r}") from None


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    """A service account: tenant-bound, scoped, time-bounded, revocable."""

    principal_id: uuid.UUID
    tenant_id: uuid.UUID
    scopes: frozenset[str]
    expires_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.tenant_id is None:
            raise ValueError("a service identity must be bound to a tenant")
        if self.principal_id is None:
            raise ValueError("a service identity must have a principal id")

    def is_active(self, now: datetime) -> bool:
        """Return whether the identity may currently be used."""
        if self.revoked_at is not None:
            return False
        return now < self.expires_at


def service_principal(identity: ServiceIdentity) -> Principal:
    """Build the principal for a service identity, keeping its kind."""
    return Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT,
        id=identity.principal_id,
        tenant_id=identity.tenant_id,
        scopes=identity.scopes,
    )


def assert_service_may_act(
    identity: ServiceIdentity | Principal,
    *,
    tenant_id: uuid.UUID,
    now: datetime,
) -> None:
    """Fail closed unless a live service identity is acting in its own tenant.

    * human, operator or anonymous principals are rejected outright,
    * expired or revoked service identities are rejected,
    * a service identity may never act in another tenant.
    """
    if isinstance(identity, Principal):
        if identity_kind(identity) is not IdentityKind.SERVICE_ACCOUNT:
            raise AuthorizationError(
                "only service accounts may act as service identities"
            )
        if identity.tenant_id != tenant_id:
            raise TenantAccessDenied(
                f"service account {identity.id} is not bound to tenant {tenant_id}"
            )
        return
    if not identity.is_active(now):
        raise InvalidToken("service identity is expired or revoked")
    if identity.tenant_id != tenant_id:
        raise TenantAccessDenied(
            f"service identity {identity.principal_id} is not bound to tenant {tenant_id}"
        )


__all__ = [
    "IdentityKind",
    "ServiceIdentity",
    "assert_service_may_act",
    "identity_kind",
    "service_principal",
]
